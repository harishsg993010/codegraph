//! Phase 0 probe.
//!
//! Two questions this answers, and nothing else:
//!   1. Do the grammars we intend to depend on actually load together against one
//!      `tree-sitter` runtime? crates.io metadata says they share the
//!      `tree-sitter-language` ABI; only linking them proves it.
//!   2. What parse throughput does that combination give on a real tree? That
//!      number is the baseline every later phase is measured against.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use rayon::prelude::*;
use tree_sitter::{Language, Parser};

/// One grammar: display name, its `LanguageFn`, and the extensions it claims.
struct Grammar {
    name: &'static str,
    lang: fn() -> Language,
    exts: &'static [&'static str],
}

const GRAMMARS: &[Grammar] = &[
    Grammar { name: "python",     lang: || tree_sitter_python::LANGUAGE.into(),                exts: &["py", "pyi"] },
    Grammar { name: "javascript", lang: || tree_sitter_javascript::LANGUAGE.into(),            exts: &["js", "mjs", "cjs", "jsx"] },
    Grammar { name: "typescript", lang: || tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), exts: &["ts", "mts", "cts"] },
    Grammar { name: "tsx",        lang: || tree_sitter_typescript::LANGUAGE_TSX.into(),        exts: &["tsx"] },
    Grammar { name: "java",       lang: || tree_sitter_java::LANGUAGE.into(),                  exts: &["java"] },
    Grammar { name: "c",          lang: || tree_sitter_c::LANGUAGE.into(),                     exts: &["c", "h"] },
    Grammar { name: "cpp",        lang: || tree_sitter_cpp::LANGUAGE.into(),                   exts: &["cpp", "cc", "cxx", "hpp", "hh", "hxx"] },
    Grammar { name: "go",         lang: || tree_sitter_go::LANGUAGE.into(),                    exts: &["go"] },
    Grammar { name: "rust",       lang: || tree_sitter_rust::LANGUAGE.into(),                  exts: &["rs"] },
    Grammar { name: "c_sharp",    lang: || tree_sitter_c_sharp::LANGUAGE.into(),               exts: &["cs"] },
    Grammar { name: "ruby",       lang: || tree_sitter_ruby::LANGUAGE.into(),                  exts: &["rb"] },

    // --- Tier 2 ---
    Grammar { name: "kotlin",     lang: || tree_sitter_kotlin_ng::LANGUAGE.into(),             exts: &["kt", "kts"] },
    Grammar { name: "scala",      lang: || tree_sitter_scala::LANGUAGE.into(),                 exts: &["scala", "sc"] },
    Grammar { name: "php",        lang: || tree_sitter_php::LANGUAGE_PHP.into(),               exts: &["php"] },
    Grammar { name: "swift",      lang: || tree_sitter_swift::LANGUAGE.into(),                 exts: &["swift"] },
    Grammar { name: "lua",        lang: || tree_sitter_lua::LANGUAGE.into(),                   exts: &["lua"] },
    Grammar { name: "groovy",     lang: || tree_sitter_groovy::LANGUAGE.into(),                exts: &["groovy", "gradle"] },
    Grammar { name: "bash",       lang: || tree_sitter_bash::LANGUAGE.into(),                  exts: &["sh", "bash"] },
    Grammar { name: "json",       lang: || tree_sitter_json::LANGUAGE.into(),                  exts: &["json"] },
    Grammar { name: "markdown",   lang: || tree_sitter_md::LANGUAGE.into(),                    exts: &["md"] },
    Grammar { name: "html",       lang: || tree_sitter_html::LANGUAGE.into(),                  exts: &["html"] },
    Grammar { name: "css",        lang: || tree_sitter_css::LANGUAGE.into(),                   exts: &["css"] },
    Grammar { name: "svelte",     lang: || tree_sitter_svelte_ng::LANGUAGE.into(),             exts: &["svelte"] },

    // --- Tier 3 ---
    Grammar { name: "fortran",    lang: || tree_sitter_fortran::LANGUAGE.into(),               exts: &["f90", "f95", "f03"] },
    Grammar { name: "verilog",    lang: || tree_sitter_verilog::LANGUAGE.into(),               exts: &["v", "sv", "svh"] },
    Grammar { name: "julia",      lang: || tree_sitter_julia::LANGUAGE.into(),                 exts: &["jl"] },
    Grammar { name: "elixir",     lang: || tree_sitter_elixir::LANGUAGE.into(),                exts: &["ex", "exs"] },
    Grammar { name: "zig",        lang: || tree_sitter_zig::LANGUAGE.into(),                   exts: &["zig"] },
    Grammar { name: "objc",       lang: || tree_sitter_objc::LANGUAGE.into(),                  exts: &["m", "mm"] },
    Grammar { name: "ocaml",      lang: || tree_sitter_ocaml::LANGUAGE_OCAML.into(),           exts: &["ml", "mli"] },
    Grammar { name: "commonlisp", lang: || tree_sitter_commonlisp::LANGUAGE_COMMONLISP.into(),            exts: &["lisp", "cl"] },
    Grammar { name: "powershell", lang: || tree_sitter_powershell::LANGUAGE.into(),            exts: &["ps1", "psm1", "psd1"] },
    Grammar { name: "sql",        lang: || tree_sitter_sequel::LANGUAGE.into(),                exts: &["sql"] },
    Grammar { name: "hcl",        lang: || tree_sitter_hcl::LANGUAGE.into(),                   exts: &["tf", "tfvars", "hcl"] },
    Grammar { name: "dart",       lang: || tree_sitter_dart::LANGUAGE.into(),                  exts: &["dart"] },
    Grammar { name: "pascal",     lang: || tree_sitter_pascal::LANGUAGE.into(),                exts: &["pas", "pp"] },
    Grammar { name: "apex",       lang: || tree_sitter_sfapex::apex::LANGUAGE.into(),           exts: &["cls", "trigger"] },
    Grammar { name: "toml",       lang: || tree_sitter_toml_ng::LANGUAGE.into(),               exts: &["toml"] },
    Grammar { name: "xml",        lang: || tree_sitter_xml::LANGUAGE_XML.into(),               exts: &["xml", "csproj", "xaml"] },
    Grammar { name: "yaml",       lang: || tree_sitter_yaml::LANGUAGE.into(),                  exts: &["yaml", "yml"] },
];

/// Load every grammar and report its ABI version. A mismatch here is the whole
/// reason this probe exists: the runtime accepts a *range* of ABI versions, so
/// two grammars can both be "current" on crates.io and still not co-exist.
fn check_abi() -> Result<()> {
    println!("{:<12} {:>4}  {:>7}  {:>7}", "grammar", "abi", "nodes", "fields");
    println!("{}", "-".repeat(38));
    let mut min = usize::MAX;
    let mut max = 0usize;
    for g in GRAMMARS {
        let lang = (g.lang)();
        let abi = lang.abi_version();
        min = min.min(abi);
        max = max.max(abi);
        // set_language is the real gate — it rejects an out-of-range ABI.
        let mut p = Parser::new();
        p.set_language(&lang)
            .map_err(|e| anyhow::anyhow!("{}: runtime rejected grammar: {e}", g.name))?;
        println!(
            "{:<12} {:>4}  {:>7}  {:>7}",
            g.name,
            abi,
            lang.node_kind_count(),
            lang.field_count()
        );
    }
    println!("\nABI range across all grammars: {min}..={max}");
    println!("tree-sitter runtime accepts: {}..={}\n",
             tree_sitter::MIN_COMPATIBLE_LANGUAGE_VERSION,
             tree_sitter::LANGUAGE_VERSION);
    Ok(())
}

fn grammar_for(path: &Path) -> Option<&'static Grammar> {
    let ext = path.extension()?.to_str()?;
    GRAMMARS.iter().find(|g| g.exts.contains(&ext))
}

/// Directories that are never source we care about. Kept deliberately small —
/// this is a benchmark harness, not the real walker.
const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "__pycache__", "target", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build",
];

fn collect(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            collect(&path, out);
        } else if ft.is_file() && grammar_for(&path).is_some() {
            out.push(path);
        }
    }
}

struct Stat {
    files: usize,
    bytes: u64,
    nodes: u64,
    errors: usize,
}

fn parse_all(files: &[PathBuf], threads: usize) -> Stat {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("thread pool");

    pool.install(|| {
        files
            .par_iter()
            .fold(
                || Stat { files: 0, bytes: 0, nodes: 0, errors: 0 },
                |mut acc, path| {
                    let Ok(src) = std::fs::read(path) else { return acc };
                    let Some(g) = grammar_for(path) else { return acc };
                    // One parser per file is the pessimistic case; the real
                    // extractor will reuse a thread-local parser per language.
                    let mut p = Parser::new();
                    if p.set_language(&(g.lang)()).is_err() {
                        acc.errors += 1;
                        return acc;
                    }
                    match p.parse(&src, None) {
                        Some(tree) => {
                            acc.files += 1;
                            acc.bytes += src.len() as u64;
                            acc.nodes += count_nodes(&tree);
                            if tree.root_node().has_error() {
                                acc.errors += 1;
                            }
                        }
                        None => acc.errors += 1,
                    }
                    acc
                },
            )
            .reduce(
                || Stat { files: 0, bytes: 0, nodes: 0, errors: 0 },
                |a, b| Stat {
                    files: a.files + b.files,
                    bytes: a.bytes + b.bytes,
                    nodes: a.nodes + b.nodes,
                    errors: a.errors + b.errors,
                },
            )
    })
}

/// Full walk of the tree — this is what a real extractor pays, so counting it
/// keeps the benchmark honest rather than timing `parse()` alone.
fn count_nodes(tree: &tree_sitter::Tree) -> u64 {
    let mut cursor = tree.walk();
    let mut n: u64 = 0;
    loop {
        n += 1;
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return n;
            }
        }
    }
}

fn main() -> Result<()> {
    check_abi()?;

    let roots: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if roots.is_empty() {
        println!("no corpus given; ABI check only.");
        println!("usage: codegraph-probe <dir>...");
        return Ok(());
    }

    let mut files = Vec::new();
    let t = Instant::now();
    for r in &roots {
        collect(r, &mut files);
    }
    println!("walked {} file(s) in {:.2}s", files.len(), t.elapsed().as_secs_f64());
    if files.is_empty() {
        return Ok(());
    }

    let max = rayon::current_num_threads();
    println!("\n{:>7}  {:>9}  {:>12}  {:>12}  {:>9}", "threads", "seconds", "files/s", "MB/s", "Mnodes/s");
    println!("{}", "-".repeat(58));
    for threads in [1usize, max] {
        let t = Instant::now();
        let s = parse_all(&files, threads);
        let secs = t.elapsed().as_secs_f64();
        println!(
            "{threads:>7}  {secs:>9.2}  {:>12.0}  {:>12.1}  {:>9.2}",
            s.files as f64 / secs,
            s.bytes as f64 / secs / 1e6,
            s.nodes as f64 / secs / 1e6,
        );
        if threads == max {
            println!(
                "\n{} files, {:.1} MB, {} AST nodes, {} with parse errors",
                s.files,
                s.bytes as f64 / 1e6,
                s.nodes,
                s.errors
            );
        }
        if max == 1 {
            break;
        }
    }
    Ok(())
}
