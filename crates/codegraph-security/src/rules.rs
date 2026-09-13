//! Rule files: taint questions written in YAML, in the shape Semgrep users
//! know.
//!
//! ```yaml
//! rules:
//!   - id: go-command-injection
//!     message: Request data reaches a shell command
//!     severity: ERROR
//!     languages: [go]
//!     mode: taint                 # taint (value flow, the default) | callgraph
//!     metadata: { cwe: CWE-78 }
//!     paths:
//!       exclude: [_test.go, tests/integration/]
//!     pattern-sources:
//!       - pattern: "*Request*"     # any name containing `Request`
//!       - pattern: FormValue
//!     pattern-sinks:
//!       - pattern: exec.Command    # the member `Command` of the package `exec`
//!       - pattern: exec.CommandContext
//!     pattern-sanitizers:
//!       - pattern: shellescape.Quote
//!     pattern-not:
//!       - pattern: xorm.Exec       # a symbol a pattern picked up that is not meant
//! ```
//!
//! A `pattern` names **symbols**, not code: the graph is already the parse.
//! `Name` is an exact name; `Name*` a prefix; `*Name` a suffix; `*Name*`
//! anything containing it; `Owner.Name` a member of a type or package
//! (`os/exec` answers to `exec`; `a::b` splits like `a.b`). The long forms
//! `name:`, `prefix:`, `suffix:`, `contains:`, `member: [Owner, Name]` and
//! `path:` (every symbol in files whose path contains it) say the same
//! thing without the glob. Names fold case.
//!
//! What a rule cannot say, because the analysis does not do it: a pattern
//! over the *text* of an expression (`$X = request.args[...]`), propagators
//! beyond the library summaries, or a metavariable. What it says instead is
//! what the graph knows — which symbols produce untrusted values, which
//! consume them dangerously, which make them safe — and the engine does the
//! rest: flow-, field- and predicate-sensitive within a function,
//! call-site-matched across calls.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::spec::{Matcher, Mode, TaintSpec};

/// How much a finding under a rule matters. Ordered: `Info < Warning < Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    #[default]
    Warning,
    Error,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "INFO" | "LOW" => Some(Self::Info),
            "WARNING" | "WARN" | "MEDIUM" => Some(Self::Warning),
            "ERROR" | "HIGH" | "CRITICAL" => Some(Self::Error),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
        }
    }
}

/// One rule as written.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub message: String,
    #[serde(default, deserialize_with = "de_severity")]
    pub severity: Severity,
    /// Restrict sources, sinks and sanitisers to symbols in files of these
    /// languages (`python`, `go`, `typescript`, …). Library stubs, which
    /// have no file, always pass.
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default = "taint", deserialize_with = "de_mode")]
    pub mode: Mode,
    #[serde(default, rename = "max-hops")]
    pub max_hops: Option<u32>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub paths: Paths,
    #[serde(default, rename = "pattern-sources")]
    pub sources: Vec<Pattern>,
    #[serde(default, rename = "pattern-sinks")]
    pub sinks: Vec<Pattern>,
    #[serde(default, rename = "pattern-sanitizers")]
    pub sanitizers: Vec<Pattern>,
    /// Symbols a source or sink pattern picked up that are not meant.
    #[serde(default, rename = "pattern-not")]
    pub excludes: Vec<Pattern>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    /// Only symbols in files whose path contains one of these.
    #[serde(default)]
    pub include: Vec<String>,
    /// No symbols in files whose path contains one of these.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// A symbol pattern: a glob string, or one explicit key.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum Pattern {
    Glob(String),
    Explicit(Explicit),
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Explicit {
    pub pattern: Option<String>,
    pub name: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub contains: Option<String>,
    /// `[Owner, Name]`, or `"Owner.Name"`.
    pub member: Option<MemberSpec>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum MemberSpec {
    Pair(Vec<String>),
    Dotted(String),
}

/// A rule is a taint question unless it says otherwise.
fn taint() -> Mode {
    Mode::DataFlow
}

fn de_severity<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Severity, D::Error> {
    let s = String::deserialize(d)?;
    Severity::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown severity {s:?}; use ERROR, WARNING or INFO")))
}

fn de_mode<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Mode, D::Error> {
    let s = String::deserialize(d)?;
    match s.to_ascii_lowercase().as_str() {
        "taint" | "dataflow" => Ok(Mode::DataFlow),
        "callgraph" | "call-graph" | "reachability" => Ok(Mode::CallGraph),
        _ => Err(serde::de::Error::custom(format!("unknown mode {s:?}; use taint or callgraph"))),
    }
}

/// A file of rules.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub rules: Vec<Rule>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("{path}: rule {id:?}: {message}")]
    Invalid { path: PathBuf, id: String, message: String },
}

/// Turn a glob-style pattern into a matcher.
pub fn parse_pattern(p: &str) -> Result<Matcher, String> {
    let p = p.trim();
    if p.is_empty() {
        return Err("empty pattern".into());
    }
    let inner = p.trim_matches('*');
    if inner.is_empty() || inner.contains('*') {
        return Err(format!("pattern {p:?}: a `*` may only lead or trail the name"));
    }
    match (p.starts_with('*'), p.ends_with('*')) {
        (true, true) => return Ok(Matcher::contains(inner)),
        (true, false) => return Ok(Matcher::suffix(inner)),
        (false, true) => return Ok(Matcher::prefix(inner)),
        (false, false) => {}
    }
    // `Owner.Name`, `a.b.Name`, `a::b::Name`, `pkg/sub.Name`: the last
    // segment is the name, the one before it the owner.
    let dotted = inner.replace("::", ".");
    if let Some((owner, name)) = dotted.rsplit_once('.') {
        let owner = owner.rsplit(['.', '/']).next().unwrap_or(owner);
        if owner.is_empty() || name.is_empty() {
            return Err(format!("pattern {p:?}: empty owner or name"));
        }
        return Ok(Matcher::member(owner, name));
    }
    Ok(Matcher::name(inner))
}

impl Pattern {
    pub fn to_matcher(&self) -> Result<Matcher, String> {
        match self {
            Pattern::Glob(s) => parse_pattern(s),
            Pattern::Explicit(e) => {
                let mut given: Vec<Matcher> = Vec::new();
                if let Some(p) = &e.pattern {
                    given.push(parse_pattern(p)?);
                }
                if let Some(n) = &e.name {
                    given.push(Matcher::name(n));
                }
                if let Some(n) = &e.prefix {
                    given.push(Matcher::prefix(n));
                }
                if let Some(n) = &e.suffix {
                    given.push(Matcher::suffix(n));
                }
                if let Some(n) = &e.contains {
                    given.push(Matcher::contains(n));
                }
                if let Some(m) = &e.member {
                    given.push(match m {
                        MemberSpec::Pair(v) if v.len() == 2 => Matcher::member(&v[0], &v[1]),
                        MemberSpec::Pair(v) => return Err(format!("member: expected [Owner, Name], got {v:?}")),
                        MemberSpec::Dotted(s) => match parse_pattern(s)? {
                            m @ Matcher::Member { .. } => m,
                            _ => return Err(format!("member: {s:?} is not Owner.Name")),
                        },
                    });
                }
                if let Some(p) = &e.path {
                    given.push(Matcher::in_path(p));
                }
                match given.len() {
                    1 => Ok(given.pop().expect("one")),
                    0 => Err("a pattern needs one of pattern, name, prefix, suffix, contains, member, path".into()),
                    _ => Err("a pattern takes exactly one of pattern, name, prefix, suffix, contains, member, path".into()),
                }
            }
        }
    }
}

impl Rule {
    /// The taint question this rule asks.
    pub fn to_spec(&self) -> Result<TaintSpec, String> {
        let all = |ps: &[Pattern]| -> Result<Vec<Matcher>, String> { ps.iter().map(Pattern::to_matcher).collect() };
        let mut spec = TaintSpec::new(&self.id).mode(self.mode);
        spec.sources = all(&self.sources)?;
        spec.sinks = all(&self.sinks)?;
        spec.sanitizers = all(&self.sanitizers)?;
        spec.excludes = all(&self.excludes)?;
        spec.excludes.extend(self.paths.exclude.iter().map(|p| Matcher::in_path(p)));
        spec.includes = self.paths.include.iter().map(|p| Matcher::in_path(p)).collect();
        spec.languages = self.languages.iter().map(|l| canonical_language(l)).collect();
        if let Some(h) = self.max_hops {
            spec.max_hops = h;
        }
        if spec.sources.is_empty() {
            return Err("no pattern-sources".into());
        }
        if spec.sinks.is_empty() {
            return Err("no pattern-sinks".into());
        }
        for l in &self.languages {
            if language_extensions(&canonical_language(l)).is_empty() {
                return Err(format!("unknown language {l:?}"));
            }
        }
        Ok(spec)
    }
}

/// The spelling a language goes by here.
pub fn canonical_language(l: &str) -> String {
    match l.to_ascii_lowercase().as_str() {
        "py" | "python" | "python3" => "python",
        "js" | "javascript" => "javascript",
        "ts" | "typescript" => "typescript",
        "tsx" => "tsx",
        "java" => "java",
        "c" => "c",
        "cpp" | "c++" | "cxx" => "cpp",
        "go" | "golang" => "go",
        "rs" | "rust" => "rust",
        "cs" | "csharp" | "c#" => "csharp",
        "rb" | "ruby" => "ruby",
        other => other,
    }
    .to_string()
}

/// File extensions a language goes by; empty for an unknown language.
pub fn language_extensions(l: &str) -> &'static [&'static str] {
    match l {
        "python" => &["py"],
        "javascript" => &["js", "jsx", "mjs", "cjs"],
        "typescript" => &["ts", "mts", "cts"],
        "tsx" => &["tsx"],
        "java" => &["java"],
        "c" => &["c", "h"],
        "cpp" => &["cpp", "cc", "cxx", "hpp", "hh", "hxx"],
        "go" => &["go"],
        "rust" => &["rs"],
        "csharp" => &["cs"],
        "ruby" => &["rb"],
        _ => &[],
    }
}

/// Does a file path belong to one of these languages? A path with no
/// extension we know (a library stub has no path at all) is not excluded.
pub fn path_in_languages(path: &str, languages: &[String]) -> bool {
    if languages.is_empty() || path.is_empty() {
        return true;
    }
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    languages.iter().any(|l| language_extensions(l).contains(&ext.as_str()))
}

/// Parse one rule file's text.
pub fn parse_rules(text: &str, path: &Path) -> Result<Vec<Rule>, RuleError> {
    let file: RuleFile = serde_yaml_ng::from_str(text).map_err(|e| RuleError::Parse { path: path.to_path_buf(), message: e.to_string() })?;
    let mut seen = std::collections::HashSet::new();
    for r in &file.rules {
        if r.id.trim().is_empty() {
            return Err(RuleError::Invalid { path: path.to_path_buf(), id: r.id.clone(), message: "a rule needs an id".into() });
        }
        if !seen.insert(r.id.clone()) {
            return Err(RuleError::Invalid { path: path.to_path_buf(), id: r.id.clone(), message: "duplicate id".into() });
        }
        r.to_spec().map_err(|message| RuleError::Invalid { path: path.to_path_buf(), id: r.id.clone(), message })?;
    }
    Ok(file.rules)
}

/// Load rules from a file, or every `*.yaml` / `*.yml` under a directory.
pub fn load_rules(path: &Path) -> Result<Vec<Rule>, RuleError> {
    let io = |e: std::io::Error| RuleError::Io { path: path.to_path_buf(), source: e };
    if path.is_dir() {
        let mut files: Vec<PathBuf> = Vec::new();
        let mut stack = vec![path.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).map_err(io)?.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                    files.push(p);
                }
            }
        }
        files.sort();
        let mut rules = Vec::new();
        for f in files {
            rules.extend(load_rules(&f)?);
        }
        return Ok(rules);
    }
    let text = std::fs::read_to_string(path).map_err(io)?;
    parse_rules(&text, path)
}

/// The rule files a tree carries by convention: `.codegraph-rules.yaml`
/// and everything under `.codegraph-rules/`.
pub fn tree_rule_paths(root: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for name in [".codegraph-rules.yaml", ".codegraph-rules.yml"] {
        let p = root.join(name);
        if p.is_file() {
            v.push(p);
        }
    }
    let dir = root.join(".codegraph-rules");
    if dir.is_dir() {
        v.push(dir);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_read_as_documented() {
        assert_eq!(parse_pattern("Exec").unwrap(), Matcher::name("exec"));
        assert_eq!(parse_pattern("Get*").unwrap(), Matcher::prefix("get"));
        assert_eq!(parse_pattern("*Request").unwrap(), Matcher::suffix("request"));
        assert_eq!(parse_pattern("*Request*").unwrap(), Matcher::contains("request"));
        assert_eq!(parse_pattern("exec.Command").unwrap(), Matcher::member("exec", "command"));
        assert_eq!(parse_pattern("os.path.join").unwrap(), Matcher::member("path", "join"));
        assert_eq!(parse_pattern("code.gitea.io/gitea/modules/git.Command").unwrap(), Matcher::member("git", "command"));
        assert_eq!(parse_pattern("std::process::Command").unwrap(), Matcher::member("process", "command"));
        assert!(parse_pattern("a*b").is_err());
        assert!(parse_pattern("").is_err());
    }

    #[test]
    fn a_rule_file_parses_and_validates() {
        let text = r#"
rules:
  - id: cmd
    message: shell
    severity: error
    languages: [go, python]
    metadata: { cwe: CWE-78 }
    paths: { exclude: [_test.go] }
    pattern-sources:
      - pattern: "*Request*"
      - name: input
    pattern-sinks:
      - pattern: exec.Command
      - member: [subprocess, Popen]
    pattern-sanitizers:
      - contains: quote
    pattern-not:
      - path: vendor/
"#;
        let rules = parse_rules(text, Path::new("t.yaml")).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.severity, Severity::Error);
        assert_eq!(r.mode, Mode::DataFlow);
        let spec = r.to_spec().unwrap();
        assert_eq!(spec.sources, vec![Matcher::contains("request"), Matcher::name("input")]);
        assert_eq!(spec.sinks, vec![Matcher::member("exec", "command"), Matcher::member("subprocess", "popen")]);
        assert_eq!(spec.sanitizers, vec![Matcher::contains("quote")]);
        assert_eq!(spec.excludes, vec![Matcher::in_path("vendor/"), Matcher::in_path("_test.go")]);
        assert_eq!(spec.languages, vec!["go".to_string(), "python".to_string()]);
        assert_eq!(r.metadata.get("cwe").map(String::as_str), Some("CWE-78"));
    }

    #[test]
    fn a_bad_rule_says_which_and_why() {
        let no_sinks = "rules:\n  - id: x\n    pattern-sources: [a]\n";
        let e = parse_rules(no_sinks, Path::new("r.yaml")).unwrap_err().to_string();
        assert!(e.contains("\"x\"") && e.contains("no pattern-sinks"), "{e}");
        let unknown_key = "rules:\n  - id: x\n    pattern-sources: [a]\n    pattern-sinks: [b]\n    patern-not: [c]\n";
        let e = parse_rules(unknown_key, Path::new("r.yaml")).unwrap_err().to_string();
        assert!(e.contains("patern-not"), "{e}");
        let dup = "rules:\n  - id: x\n    pattern-sources: [a]\n    pattern-sinks: [b]\n  - id: x\n    pattern-sources: [a]\n    pattern-sinks: [b]\n";
        let e = parse_rules(dup, Path::new("r.yaml")).unwrap_err().to_string();
        assert!(e.contains("duplicate"), "{e}");
        let lang = "rules:\n  - id: x\n    languages: [cobol]\n    pattern-sources: [a]\n    pattern-sinks: [b]\n";
        let e = parse_rules(lang, Path::new("r.yaml")).unwrap_err().to_string();
        assert!(e.contains("cobol"), "{e}");
    }

    #[test]
    fn languages_filter_by_extension_and_let_stubs_through() {
        let go = vec!["go".to_string()];
        assert!(path_in_languages("a/b.go", &go));
        assert!(!path_in_languages("a/b.py", &go));
        assert!(path_in_languages("", &go), "a stub has no path");
        assert!(path_in_languages("a/b.py", &[]));
    }
}
