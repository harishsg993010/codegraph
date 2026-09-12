//! Per-language configuration for the generic walk.
//!
//! Every Tier-1 language is described by data rather than code: which node
//! kinds introduce a symbol, which introduce a *scope*, which are calls, which
//! are imports. The walk in [`crate::walk`] is then written once.
//!
//! That split is deliberate. A per-language walker duplicates the scope stack,
//! the name extraction, and the edge emission eleven times, and they drift —
//! one language ends up qualifying methods with their class and another does
//! not, which silently splits identity for half the corpus.

use codegraph_core::{Relation, SymbolKind};
use tree_sitter::Language;

/// One node kind that defines a symbol.
#[derive(Debug, Clone, Copy)]
pub struct Def {
    /// The tree-sitter node kind.
    pub node: &'static str,
    pub kind: SymbolKind,
    /// Does this symbol enclose others? A class scopes its methods; a function
    /// does not scope anything we index.
    pub scopes: bool,
    /// Sharpen `kind` by looking for a named child of one of these kinds.
    ///
    /// Go declares structs, interfaces and true aliases through the same
    /// `type_spec` node, and the difference matters: a struct owns methods and
    /// a type alias reads as one in a symbol list.
    pub refine: &'static [(&'static str, SymbolKind)],
}

impl Def {
    const fn scope(node: &'static str, kind: SymbolKind) -> Self {
        Self { node, kind, scopes: true, refine: &[] }
    }
    const fn leaf(node: &'static str, kind: SymbolKind) -> Self {
        Self { node, kind, scopes: false, refine: &[] }
    }
    const fn refined(
        node: &'static str,
        kind: SymbolKind,
        refine: &'static [(&'static str, SymbolKind)],
    ) -> Self {
        Self { node, kind, scopes: true, refine }
    }
}

/// Everything the walk needs to know about one language.
pub struct LangConfig {
    pub name: &'static str,
    pub language: fn() -> Language,
    pub extensions: &'static [&'static str],
    pub defs: &'static [Def],
    /// Node kinds that are a call. The callee is read from `callee_field` when
    /// present, else from the node's first named child.
    pub calls: &'static [&'static str],
    pub callee_field: &'static str,
    /// Node kinds that import something.
    pub imports: &'static [&'static str],
    /// Fields to try, in order, when reading a definition's name. `declarator`
    /// is listed for the C family, where the name is nested inside a declarator
    /// rather than sitting in a `name` field.
    pub name_fields: &'static [&'static str],
    /// Node kinds that count as an identifier when falling back to a scan.
    pub ident_kinds: &'static [&'static str],
    /// The field holding a method's receiver, where the language declares
    /// methods *outside* the type they belong to.
    ///
    /// Python, Java and Rust nest a method inside its class or `impl`, so the
    /// walk's enclosing-scope chain already names the owner. Go does not:
    /// `func (p *Permission) IsAdmin()` sits at file top level, and without
    /// reading the receiver every type's methods are unowned and two types'
    /// same-named methods are the same symbol.
    pub receiver_field: Option<&'static str>,
    /// The field holding an import's local alias, where the language has one.
    pub import_alias_field: Option<&'static str>,
    /// The field holding a definition's parameter list.
    ///
    /// Set only where the arity is actually used. Go needs it because a Go type
    /// satisfies an interface *structurally* — there is no `implements`
    /// keyword to read — so the method sets have to be compared, and comparing
    /// them on name alone matches far too much.
    pub params_field: Option<&'static str>,
    /// Node kinds that hold supertype references, and what relation each
    /// implies. Searched among a definition's descendants no deeper than two,
    /// which is where every language puts its heritage clause and is shallow
    /// enough that a call's argument list in the body cannot be mistaken for a
    /// base-class list.
    ///
    /// Unlike Go — where satisfaction is structural and has to be computed —
    /// these languages *declare* their supertypes, so the edge is read rather
    /// than inferred.
    pub supertypes: &'static [(&'static str, Relation)],
    /// Does this language decide interface satisfaction *structurally*, with
    /// no declaration to read?
    ///
    /// True for Go, where comparing method sets is the only way to find the
    /// edge. False for TypeScript — whose type system is also structural, but
    /// which has an `implements` clause stating the intent. Running the
    /// structural pass there would duplicate every declared edge and add one
    /// for every class that merely happens to share a method name.
    pub structural_interfaces: bool,
    /// Declarations, dataflow and control-flow syntax: see [`crate::syntax`].
    pub syntax: &'static crate::syntax::Syntax,
}

impl LangConfig {
    pub fn def_for(&self, node_kind: &str) -> Option<&Def> {
        self.defs.iter().find(|d| d.node == node_kind)
    }
    pub fn is_call(&self, node_kind: &str) -> bool {
        self.calls.contains(&node_kind)
    }
    pub fn is_import(&self, node_kind: &str) -> bool {
        self.imports.contains(&node_kind)
    }
}

const COMMON_IDENTS: &[&str] = &["identifier", "type_identifier", "field_identifier", "constant"];

pub static PYTHON: LangConfig = LangConfig {
    name: "python",
    language: || tree_sitter_python::LANGUAGE.into(),
    extensions: &["py", "pyi"],
    defs: &[
        Def::scope("class_definition", SymbolKind::Class),
        Def::leaf("function_definition", SymbolKind::Function),
    ],
    calls: &["call"],
    callee_field: "function",
    imports: &["import_statement", "import_from_statement"],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    // Python has one heritage list and no `implements` keyword. Which of these
    // is an implementation rather than an inheritance is decided later, from
    // whether the base is a Protocol or an ABC.
    supertypes: &[("argument_list", Relation::Inherits)],
    structural_interfaces: false,
    syntax: &crate::syntax::PYTHON,
    ident_kinds: COMMON_IDENTS,
};

pub static JAVASCRIPT: LangConfig = LangConfig {
    name: "javascript",
    language: || tree_sitter_javascript::LANGUAGE.into(),
    extensions: &["js", "mjs", "cjs", "jsx"],
    defs: &[
        Def::scope("class_declaration", SymbolKind::Class),
        Def::leaf("function_declaration", SymbolKind::Function),
        Def::leaf("method_definition", SymbolKind::Method),
        Def::leaf("generator_function_declaration", SymbolKind::Function),
    ],
    calls: &["call_expression", "new_expression"],
    callee_field: "function",
    imports: &["import_statement", "export_statement"],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::JAVASCRIPT,
    ident_kinds: &["identifier", "property_identifier", "shorthand_property_identifier"],
};

/// TypeScript and TSX share everything but the grammar, since TSX only differs
/// in how it parses JSX — the definition and call node kinds are identical.
pub static TYPESCRIPT: LangConfig = LangConfig {
    name: "typescript",
    language: || tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    extensions: &["ts", "mts", "cts"],
    defs: TS_DEFS,
    calls: &["call_expression", "new_expression"],
    callee_field: "function",
    imports: &["import_statement", "export_statement"],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: TS_SUPERTYPES,
    structural_interfaces: false,
    syntax: &crate::syntax::TYPESCRIPT,
    ident_kinds: &["identifier", "property_identifier", "type_identifier"],
};

pub static TSX: LangConfig = LangConfig {
    name: "tsx",
    language: || tree_sitter_typescript::LANGUAGE_TSX.into(),
    extensions: &["tsx"],
    defs: TS_DEFS,
    calls: &["call_expression", "new_expression"],
    callee_field: "function",
    imports: &["import_statement", "export_statement"],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: TS_SUPERTYPES,
    structural_interfaces: false,
    syntax: &crate::syntax::TYPESCRIPT,
    ident_kinds: &["identifier", "property_identifier", "type_identifier"],
};

/// `class C extends B implements I` states both, separately — so unlike
/// Python, no inference is needed to tell them apart. `extends_type_clause` is
/// an *interface* extending another interface.
static TS_SUPERTYPES: &[(&str, Relation)] = &[
    ("extends_clause", Relation::Inherits),
    ("extends_type_clause", Relation::Inherits),
    ("implements_clause", Relation::Implements),
];

static TS_DEFS: &[Def] = &[
    Def::scope("class_declaration", SymbolKind::Class),
    Def::scope("abstract_class_declaration", SymbolKind::Class),
    Def::scope("interface_declaration", SymbolKind::Interface),
    Def::scope("enum_declaration", SymbolKind::Enum),
    Def::scope("module", SymbolKind::Namespace),
    Def::leaf("function_declaration", SymbolKind::Function),
    Def::leaf("function_signature", SymbolKind::Function),
    Def::leaf("method_definition", SymbolKind::Method),
    Def::leaf("method_signature", SymbolKind::Method),
    Def::leaf("type_alias_declaration", SymbolKind::TypeAlias),
];

pub static JAVA: LangConfig = LangConfig {
    name: "java",
    language: || tree_sitter_java::LANGUAGE.into(),
    extensions: &["java"],
    defs: &[
        Def::scope("class_declaration", SymbolKind::Class),
        Def::scope("interface_declaration", SymbolKind::Interface),
        Def::scope("enum_declaration", SymbolKind::Enum),
        Def::scope("record_declaration", SymbolKind::Struct),
        Def::leaf("method_declaration", SymbolKind::Method),
        Def::leaf("constructor_declaration", SymbolKind::Method),
    ],
    calls: &["method_invocation", "object_creation_expression"],
    callee_field: "name",
    imports: &["import_declaration"],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::JAVA,
    ident_kinds: COMMON_IDENTS,
};

pub static C: LangConfig = LangConfig {
    name: "c",
    language: || tree_sitter_c::LANGUAGE.into(),
    extensions: &["c", "h"],
    defs: &[
        Def::scope("struct_specifier", SymbolKind::Struct),
        Def::scope("union_specifier", SymbolKind::Struct),
        Def::scope("enum_specifier", SymbolKind::Enum),
        Def::leaf("function_definition", SymbolKind::Function),
        Def::leaf("type_definition", SymbolKind::TypeAlias),
    ],
    calls: &["call_expression"],
    callee_field: "function",
    imports: &["preproc_include"],
    // C hides the name inside a declarator chain, so `declarator` is tried
    // before falling back to a scan.
    name_fields: &["name", "declarator"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::C,
    ident_kinds: COMMON_IDENTS,
};

pub static CPP: LangConfig = LangConfig {
    name: "cpp",
    language: || tree_sitter_cpp::LANGUAGE.into(),
    extensions: &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "cu", "cuh"],
    defs: &[
        Def::scope("class_specifier", SymbolKind::Class),
        Def::scope("struct_specifier", SymbolKind::Struct),
        Def::scope("union_specifier", SymbolKind::Struct),
        Def::scope("enum_specifier", SymbolKind::Enum),
        Def::scope("namespace_definition", SymbolKind::Namespace),
        Def::leaf("function_definition", SymbolKind::Function),
        Def::leaf("type_definition", SymbolKind::TypeAlias),
    ],
    calls: &["call_expression", "new_expression"],
    callee_field: "function",
    imports: &["preproc_include"],
    name_fields: &["name", "declarator"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::CPP,
    ident_kinds: &["identifier", "type_identifier", "field_identifier", "qualified_identifier"],
};

pub static GO: LangConfig = LangConfig {
    name: "go",
    language: || tree_sitter_go::LANGUAGE.into(),
    extensions: &["go"],
    defs: &[
        Def::leaf("function_declaration", SymbolKind::Function),
        Def::leaf("method_declaration", SymbolKind::Method),
        // A method *signature* inside an `interface`. Nested in the
        // `type_spec`, so the enclosing-scope chain names its interface.
        Def::leaf("method_elem", SymbolKind::Method),
        // `type A = int` is a `type_alias` node, not a `type_spec`.
        Def::scope("type_alias", SymbolKind::TypeAlias),
        Def::refined(
            "type_spec",
            SymbolKind::TypeAlias,
            &[("struct_type", SymbolKind::Struct), ("interface_type", SymbolKind::Interface)],
        ),
    ],
    calls: &["call_expression"],
    callee_field: "function",
    // `import_spec` only. `import_declaration` wraps the whole parenthesised
    // block, and matching it too recorded the entire block text as a single
    // bogus module.
    imports: &["import_spec"],
    name_fields: &["name"],
    receiver_field: Some("receiver"),
    import_alias_field: Some("name"),
    params_field: Some("parameters"),
    supertypes: &[],
    structural_interfaces: true,
    syntax: &crate::syntax::GO,
    ident_kinds: &["identifier", "type_identifier", "field_identifier", "package_identifier"],
};

pub static RUST: LangConfig = LangConfig {
    name: "rust",
    language: || tree_sitter_rust::LANGUAGE.into(),
    extensions: &["rs"],
    defs: &[
        Def::scope("struct_item", SymbolKind::Struct),
        Def::scope("enum_item", SymbolKind::Enum),
        Def::scope("trait_item", SymbolKind::Trait),
        Def::scope("mod_item", SymbolKind::Module),
        Def::scope("impl_item", SymbolKind::Class),
        Def::leaf("function_item", SymbolKind::Function),
        Def::leaf("type_item", SymbolKind::TypeAlias),
        Def::leaf("const_item", SymbolKind::Constant),
        Def::leaf("static_item", SymbolKind::Constant),
        Def::leaf("macro_definition", SymbolKind::Macro),
    ],
    calls: &["call_expression", "macro_invocation"],
    callee_field: "function",
    imports: &["use_declaration"],
    // `impl_item` names its subject with `type`, not `name`.
    name_fields: &["name", "type"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::RUST,
    ident_kinds: &["identifier", "type_identifier", "field_identifier", "scoped_identifier"],
};

pub static CSHARP: LangConfig = LangConfig {
    name: "csharp",
    language: || tree_sitter_c_sharp::LANGUAGE.into(),
    extensions: &["cs"],
    defs: &[
        Def::scope("class_declaration", SymbolKind::Class),
        Def::scope("interface_declaration", SymbolKind::Interface),
        Def::scope("struct_declaration", SymbolKind::Struct),
        Def::scope("enum_declaration", SymbolKind::Enum),
        Def::scope("record_declaration", SymbolKind::Struct),
        Def::scope("namespace_declaration", SymbolKind::Namespace),
        Def::leaf("method_declaration", SymbolKind::Method),
        Def::leaf("constructor_declaration", SymbolKind::Method),
        Def::leaf("property_declaration", SymbolKind::Field),
    ],
    calls: &["invocation_expression", "object_creation_expression"],
    callee_field: "function",
    imports: &["using_directive"],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::CSHARP,
    ident_kinds: COMMON_IDENTS,
};

/// Ruby has a known blind spot: a bare call with neither parentheses nor a
/// receiver (`helper`) parses as a plain `identifier`, not a `call`, because
/// the grammar cannot tell it from a local variable reference without
/// semantic analysis. Calls written `helper()`, `obj.helper`, or `helper arg`
/// are captured. Recovering the rest needs local scope tracking — knowing
/// which identifiers were bound as variables in this body — which is a
/// resolution concern rather than a walk concern.
pub static RUBY: LangConfig = LangConfig {
    name: "ruby",
    language: || tree_sitter_ruby::LANGUAGE.into(),
    extensions: &["rb", "rake"],
    defs: &[
        Def::scope("class", SymbolKind::Class),
        Def::scope("module", SymbolKind::Module),
        Def::leaf("method", SymbolKind::Method),
        Def::leaf("singleton_method", SymbolKind::Method),
    ],
    calls: &["call"],
    callee_field: "method",
    imports: &[],
    name_fields: &["name"],
    receiver_field: None,
    import_alias_field: None,
    params_field: None,
    supertypes: &[],
    structural_interfaces: false,
    syntax: &crate::syntax::RUBY,
    ident_kinds: &["identifier", "constant"],
};

/// Every configured language, in dispatch order.
pub static ALL: &[&LangConfig] = &[
    &PYTHON, &JAVASCRIPT, &TYPESCRIPT, &TSX, &JAVA, &C, &CPP, &GO, &RUST, &CSHARP, &RUBY,
];

/// The language for a file extension, if any.
pub fn for_extension(ext: &str) -> Option<&'static LangConfig> {
    let ext = ext.trim_start_matches('.');
    ALL.iter().copied().find(|c| c.extensions.contains(&ext))
}

/// The language for a path.
pub fn for_path(path: &std::path::Path) -> Option<&'static LangConfig> {
    for_extension(path.extension()?.to_str()?)
}

/// A stable numeric id for a language, stored in the segment's file table.
pub fn lang_id(config: &LangConfig) -> u8 {
    ALL.iter()
        .position(|c| std::ptr::eq(*c, config))
        .map_or(255, |i| i as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_language_loads() {
        for c in ALL {
            let lang = (c.language)();
            let mut p = tree_sitter::Parser::new();
            p.set_language(&lang)
                .unwrap_or_else(|e| panic!("{}: {e}", c.name));
            assert!(lang.node_kind_count() > 0, "{}", c.name);
        }
    }

    /// A node kind that does not exist in the grammar is dead configuration: it
    /// will silently never fire, and the language will quietly under-extract.
    #[test]
    fn every_configured_node_kind_exists_in_its_grammar() {
        for c in ALL {
            let lang = (c.language)();
            let known: std::collections::HashSet<&str> = (0..lang.node_kind_count())
                .filter_map(|i| lang.node_kind_for_id(i as u16))
                .collect();
            for d in c.defs {
                assert!(known.contains(d.node), "{}: unknown def node kind {:?}", c.name, d.node);
            }
            for k in c.calls {
                assert!(known.contains(k), "{}: unknown call node kind {k:?}", c.name);
            }
            for k in c.imports {
                assert!(known.contains(k), "{}: unknown import node kind {k:?}", c.name);
            }
            for k in c.syntax.all_kinds() {
                assert!(known.contains(k), "{}: unknown syntax node kind {k:?}", c.name);
            }
        }
    }

    #[test]
    fn extensions_dispatch_without_overlap() {
        let mut seen = std::collections::HashMap::new();
        for c in ALL {
            for e in c.extensions {
                if let Some(prev) = seen.insert(*e, c.name) {
                    panic!("extension {e:?} claimed by both {prev} and {}", c.name);
                }
            }
        }
        assert_eq!(for_extension("py").map(|c| c.name), Some("python"));
        assert_eq!(for_extension(".rs").map(|c| c.name), Some("rust"));
        assert_eq!(for_extension("zzz").map(|c| c.name), None);
    }

    #[test]
    fn language_ids_are_distinct_and_stable() {
        let ids: Vec<u8> = ALL.iter().map(|c| lang_id(c)).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "language ids collide");
        assert_eq!(lang_id(&PYTHON), 0, "python's id moved; stored files would be mislabelled");
    }
}
