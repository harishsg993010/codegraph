//! Running a set of rules and reporting what they found, the same way from
//! the CLI and the server: one section per rule, one line per finding with
//! its path, and a JSON form for anything downstream.

use std::collections::BTreeMap;

use codegraph_index::IndexQuery;
use codegraph_query::SymbolInfo;

use crate::rules::{Rule, Severity};
use crate::spec::{Mode, TaintSpec};
use crate::{Analysis, Security};

/// A rule ready to run: the question, and how to report its answers.
#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub metadata: BTreeMap<String, String>,
    pub spec: TaintSpec,
    /// From a rule file (`true`) or a built-in starter spec.
    pub from_file: bool,
}

impl RuleSpec {
    pub fn from_rule(rule: &Rule) -> Result<Self, String> {
        Ok(RuleSpec {
            id: rule.id.clone(),
            message: rule.message.clone(),
            severity: rule.severity,
            metadata: rule.metadata.clone(),
            spec: rule.to_spec()?,
            from_file: true,
        })
    }

    /// A starter spec, in the mode asked for.
    pub fn from_preset(spec: TaintSpec, mode: Mode) -> Self {
        RuleSpec {
            id: spec.name.clone(),
            message: "starter spec — a starting point, not a policy".into(),
            severity: Severity::Warning,
            metadata: BTreeMap::new(),
            spec: spec.mode(mode),
            from_file: false,
        }
    }
}

/// What one rule found.
#[derive(Debug)]
pub struct RuleResult {
    pub rule: RuleSpec,
    pub analysis: Option<Analysis>,
    pub error: Option<String>,
    pub millis: f64,
}

/// Run every rule.
pub fn run_rules<I: IndexQuery>(sec: &Security<'_, I>, rules: &[RuleSpec], max_findings: usize) -> Vec<RuleResult> {
    rules
        .iter()
        .map(|r| {
            let t = std::time::Instant::now();
            let (analysis, error) = match sec.analyse(&r.spec, max_findings) {
                Ok(a) => (Some(a), None),
                Err(e) => (None, Some(e.to_string())),
            };
            RuleResult { rule: r.clone(), analysis, error, millis: t.elapsed().as_secs_f64() * 1e3 }
        })
        .collect()
}

/// The highest severity among the findings, if any.
pub fn worst(results: &[RuleResult]) -> Option<Severity> {
    results
        .iter()
        .filter(|r| r.analysis.as_ref().is_some_and(|a| !a.findings.is_empty()))
        .map(|r| r.rule.severity)
        .max()
}

/// The text report. `place` renders a symbol with its location.
pub fn render_text(results: &[RuleResult], place: &dyn Fn(&SymbolInfo) -> String) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for r in results {
        let dataflow = r.rule.spec.mode == Mode::DataFlow;
        let Some(a) = &r.analysis else {
            let _ = writeln!(out, "\n{} [{}]: failed: {}", r.rule.id, r.rule.severity.as_str(), r.error.as_deref().unwrap_or("?"));
            continue;
        };
        let _ = write!(out, "\n{} [{}]", r.rule.id, r.rule.severity.as_str());
        if !r.rule.message.is_empty() {
            let _ = write!(out, " — {}", r.rule.message);
        }
        if dataflow {
            let _ = writeln!(
                out,
                "\n  {} sources x {} sinks, {} sinks searched, {} finding(s) ({:.0} ms)",
                a.sources,
                a.sinks,
                a.pairs_searched,
                a.findings.len(),
                r.millis
            );
        } else {
            let _ = writeln!(
                out,
                "\n  {} sources x {} sinks, {:.1}% rejected by index, {} finding(s) ({:.0} ms)",
                a.sources,
                a.sinks,
                a.rejection_rate() * 100.0,
                a.findings.len(),
                r.millis
            );
        }
        for f in &a.findings {
            let _ = writeln!(
                out,
                "  {} -> {}  [{} hops, {:?}{}]",
                place(&f.source),
                place(&f.sink),
                f.depth(),
                f.confidence,
                if f.reachable_from_entrypoint { ", live" } else { ", unreachable" }
            );
            let via: Vec<String> = f.path.iter().map(|s| s.name.clone()).collect();
            let _ = writeln!(out, "      via {}", via.join(" -> "));
        }
    }
    out
}

/// The JSON report: one object per rule with its findings, each finding
/// with source, sink and the path between them.
pub fn render_json(results: &[RuleResult]) -> String {
    use serde_json::json;
    let sym = |s: &SymbolInfo| {
        json!({
            "name": s.name,
            "kind": s.kind.to_string(),
            "path": s.path,
            "line": s.line,
            "external": s.external,
        })
    };
    let rules: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            let findings: Vec<serde_json::Value> = r
                .analysis
                .as_ref()
                .map(|a| {
                    a.findings
                        .iter()
                        .map(|f| {
                            json!({
                                "source": sym(&f.source),
                                "sink": sym(&f.sink),
                                "hops": f.depth(),
                                "confidence": format!("{:?}", f.confidence).to_lowercase(),
                                "live": f.reachable_from_entrypoint,
                                "path": f.path.iter().map(sym).collect::<Vec<_>>(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "id": r.rule.id,
                "severity": r.rule.severity.as_str(),
                "message": r.rule.message,
                "metadata": r.rule.metadata,
                "mode": if r.rule.spec.mode == Mode::DataFlow { "taint" } else { "callgraph" },
                "sources": r.analysis.as_ref().map(|a| a.sources),
                "sinks": r.analysis.as_ref().map(|a| a.sinks),
                "error": r.error,
                "findings": findings,
            })
        })
        .collect();
    let total: usize = results.iter().filter_map(|r| r.analysis.as_ref()).map(|a| a.findings.len()).sum();
    serde_json::to_string_pretty(&json!({
        "rules": rules,
        "findings": total,
        "worst": worst(results).map(Severity::as_str),
    }))
    .unwrap_or_default()
}
