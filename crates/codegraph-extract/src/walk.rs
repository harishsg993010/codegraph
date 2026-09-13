//! The generic AST walk.
//!
//! One traversal, driven by [`crate::lang::LangConfig`], produces every
//! language's symbols and facts. Written once on purpose: eleven hand-written
//! walkers drift, and the first thing to drift is whether a method gets
//! qualified by its class — which silently splits identity for that language.

use codegraph_core::{Relation, SymbolKind};
use tree_sitter::{Node, Parser, Tree};

use crate::lang::LangConfig;

/// A symbol as the walk found it, before any key is minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSymbol {
    pub name: String,
    /// Enclosing scope names, outermost first. This is what separates
    /// `Alpha.__init__` from `Beta.__init__`.
    pub scope: Vec<String>,
    pub kind: SymbolKind,
    /// 1-based.
    pub line: u32,
    /// Declared parameter count, where the language config asks for it.
    ///
    /// `None` means "not measured", which is different from zero and must not
    /// be compared as if it were.
    pub arity: Option<u32>,
    /// For a `Parameter`: its position in the parameter list. Stored as the
    /// context of the `contains` edge from the callable, so a call can bind
    /// its argument by position even when the callee is read back from the
    /// store.
    pub param_index: Option<u32>,
    /// A hash of the definition's text, whitespace collapsed: what `diff`
    /// compares to tell a body edit from a move. `0` = not recorded.
    pub hash: u64,
}

/// FNV-1a over the text with runs of whitespace collapsed to one space, so
/// a reformat is not a change. Never `0` for non-empty text.
pub fn definition_hash(text: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut in_space = false;
    for &b in text {
        let b = if b.is_ascii_whitespace() {
            if in_space {
                continue;
            }
            in_space = true;
            b' '
        } else {
            in_space = false;
            b
        };
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h.max(1)
}

impl RawSymbol {
    /// The dotted display form, for diagnostics and ranking.
    pub fn qualified(&self) -> String {
        if self.scope.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.scope.join("."), self.name)
        }
    }
}

/// A within-file structural edge: `contains` or `method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEdge {
    /// Index into [`FileExtract::symbols`].
    pub from: u32,
    pub to: u32,
    pub relation: Relation,
    pub line: u32,
}

/// A call site, unresolved. Binding it to a definition needs the whole corpus,
/// so that is left to resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCall {
    /// Index of the enclosing symbol, or `None` at file top level.
    pub caller: Option<u32>,
    /// The callee as written: the bare name for `foo()`, the trailing member
    /// for `obj.foo()`.
    pub callee: String,
    /// The receiver for a member call, when there is one. Resolution uses it to
    /// narrow which type's method is meant.
    pub receiver: Option<String>,
    pub line: u32,
    /// A library summary described this call (see `summaries`): the
    /// arguments' effect on the result and on what is written was recorded
    /// as facts at extraction, so if the callee turns out to be external
    /// its stub must not stand for "every input reaches the result" too.
    pub summarised: bool,
    /// The summary brings in external data (a read, a fetch): the stub is a
    /// value source, and its result edges carry no call-site tag.
    pub external: bool,
}

/// An import, unresolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawImport {
    /// The specifier exactly as written.
    pub module: String,
    /// The local name the module is referred to by, when it differs from the
    /// specifier's last segment: the `access_model` in
    /// `access_model "gitea.dev/models/perm/access"`.
    ///
    /// Needed to tell a package-qualified call from a method call. Without it
    /// `access_model.GetDoerRepoPermission(...)` looks like a method call on an
    /// unknown value.
    pub alias: Option<String>,
    pub line: u32,
}

/// A position in an argument list: by index, or by keyword.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArgPos {
    Index(u32),
    Name(String),
}

/// An end of a flow fact, before resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowNode {
    /// A parameter of the function, by symbol index.
    Param(u32),
    /// A name not local to the function: `(name, is a field of self)`.
    NonLocal(String, bool),
    /// The result of call `k` (index into [`FileExtract::calls`]).
    CallResult(u32),
    /// Argument `pos` of call `k`. `Index(u32::MAX)` is the receiver.
    Arg(u32, ArgPos),
    /// The function's return value.
    Return,
    /// A local variable of the function, by name. Appears only in
    /// [`FileExtract::local_flows`]: the flow facts themselves never name a
    /// local, they are what the locals were resolved through.
    Local(String),
}

/// A local variable of a callable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLocal {
    pub function: u32,
    pub name: String,
    /// The first definition's line.
    pub line: u32,
}

/// A value reaches a sink inside one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFlow {
    /// The callable, or `None` for top-level code.
    pub function: Option<u32>,
    pub source: FlowNode,
    pub sink: FlowNode,
    pub line: u32,
    /// For a local flow: the definition lines involved — the one
    /// definition for `origin -> local` (also `line`), and every definition
    /// of the local that reaches the sink for `local -> sink`, as
    /// `"12,15"`. What makes the stored local view flow-sensitive.
    pub context: Option<String>,
}

/// A body reads or writes a non-local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRef {
    pub function: Option<u32>,
    pub name: String,
    pub self_field: bool,
}

/// One basic block of a callable's CFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBlock {
    pub function: u32,
    pub index: u32,
    pub line: u32,
    /// `(successor index, label)`.
    pub succ: Vec<(u32, String)>,
    /// Non-local names written here: `(name, is self field)`.
    pub defines: Vec<(String, bool)>,
    pub uses: Vec<(String, bool)>,
    /// Locals written and read here.
    pub local_defines: Vec<String>,
    pub local_uses: Vec<String>,
}

/// Everything one file contributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileExtract {
    pub path: String,
    pub lang: &'static str,
    pub lang_id: u8,
    /// Copied from the language config: whether interface satisfaction has to
    /// be computed rather than read.
    pub structural_interfaces: bool,
    pub content_hash: u64,
    pub size: u64,
    /// Modification time of the source, when the caller knows it. Recorded so
    /// an incremental update can skip hashing a file whose mtime and size
    /// are unchanged. `0` when unknown; never used for identity.
    pub mtime_nanos: i64,
    pub symbols: Vec<RawSymbol>,
    pub edges: Vec<RawEdge>,
    pub calls: Vec<RawCall>,
    pub imports: Vec<RawImport>,
    /// The parse produced an error node. Recorded, not fatal: a file with a
    /// syntax error still yields most of its symbols, and dropping it would
    /// lose more than it protects.
    pub had_parse_error: bool,
    /// `(type index, supertype name, declared relation)`.
    ///
    /// Names, not symbols: a base class usually lives in another file, so
    /// binding it needs the whole corpus and belongs to resolution.
    pub supertypes: Vec<(u32, String, Relation)>,
    /// `(interface index, embedded interface name)`.
    ///
    /// `type ReadWriter interface { Reader; Writer }` states its requirements
    /// by reference. Without expanding those, the interface looks like it
    /// requires nothing, and every type in the corpus satisfies it.
    pub embeds: Vec<(u32, String)>,
    /// `(method index, receiver type name)`, awaiting the type's symbol.
    ///
    /// Not resolvable during the walk: Go lets a method be declared above the
    /// `type` it belongs to, so the owner may not exist yet.
    pending_methods: Vec<(u32, String)>,
    /// Flow facts, one per (function, source, sink).
    pub flows: Vec<RawFlow>,
    /// Non-local names each body touches.
    pub refs: Vec<RawRef>,
    /// Basic blocks of every callable.
    pub blocks: Vec<RawBlock>,
    /// The locals of every callable.
    pub locals: Vec<RawLocal>,
    /// Value flow through locals: `origin -> Local(name)` for what each
    /// local is ever assigned, `Local(name) -> sink` for where it is read.
    pub local_flows: Vec<RawFlow>,
    /// Callables whose flow facts exceeded the budget and were summarised
    /// through their own symbol (`None` = top-level code).
    pub summarised: Vec<Option<u32>>,
    /// `(scope, name)` of declared variables/fields, to keep a re-assignment
    /// from declaring a second symbol.
    declared: std::collections::HashSet<(Vec<String>, String)>,
}

/// How many parameters a parameter list declares.
///
/// Not the number of child nodes: Go lets one declaration name several
/// parameters (`func f(a, b int)` is one `parameter_declaration` holding two
/// identifiers), while an unnamed parameter (`func f(int)`) holds none. So the
/// count is the number of names, or one for an anonymous parameter.
fn param_arity(params: Node<'_>) -> u32 {
    let mut total = 0u32;
    let mut c = params.walk();
    for decl in params.named_children(&mut c) {
        let mut d = decl.walk();
        let names = decl.named_children(&mut d).filter(|n| n.kind() == "identifier").count();
        total += names.max(1) as u32;
    }
    total
}

/// Link each receiver-declared method to the type it belongs to.
///
/// Runs after the walk because Go permits a method above its `type`, so the
/// owner may not have been seen when the method was. Same-file only: a method
/// and its receiver type must be in the same package, and binding across files
/// on a bare type name is the ambiguity this project refuses everywhere else.
fn attach_methods(out: &mut FileExtract) {
    if out.pending_methods.is_empty() {
        return;
    }
    let mut types: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for (i, s) in out.symbols.iter().enumerate() {
        if is_type_like(s.kind) {
            types.entry(s.name.as_str()).or_insert(i as u32);
        }
    }
    let pending = std::mem::take(&mut out.pending_methods);
    for (method, type_name) in &pending {
        if let Some(&owner) = types.get(type_name.as_str()) {
            let line = out.symbols[*method as usize].line;
            out.edges.push(RawEdge { from: owner, to: *method, relation: Relation::Method, line });
        }
    }
    out.pending_methods = pending;
    out.pending_methods.clear();
}

/// Does `node` have a named child of this kind? One level only — a `type_spec`
/// holds its `struct_type` directly.
fn child_of_kind(node: Node<'_>, kind: &str) -> bool {
    named_child_of_kind(node, kind).is_some()
}

fn named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut c = node.walk();
    node.named_children(&mut c).find(|ch| ch.kind() == kind)
}

/// One entry of the enclosing-definition chain.
#[derive(Debug, Clone)]
struct Open {
    /// Index into [`FileExtract::symbols`].
    symbol: u32,
    /// The end of the definition's byte range. The walk visits nodes in
    /// document order, so "we have left this definition" is exactly
    /// `node.start_byte() >= end_byte` — an integer compare.
    ///
    /// The first version tested containment by walking the node's ancestor
    /// chain looking for the open definition's node id. That is correct but
    /// O(depth) *per AST node*, which made extraction 15x slower than parsing
    /// alone. This is O(1).
    end_byte: usize,
    /// Whether this definition qualifies the names of things inside it.
    scopes: bool,
}

/// Reusable parser + scratch state.
///
/// A parser is expensive to build and cheap to reuse, so extraction keeps one
/// per language per thread rather than allocating per file.
pub struct Walker {
    parser: Parser,
    config: &'static LangConfig,
}

impl Walker {
    pub fn new(config: &'static LangConfig) -> Result<Self, tree_sitter::LanguageError> {
        let mut parser = Parser::new();
        parser.set_language(&(config.language)())?;
        Ok(Self { parser, config })
    }

    pub fn config(&self) -> &'static LangConfig {
        self.config
    }

    /// Walk one file's source.
    pub fn extract(&mut self, path: &str, source: &[u8]) -> Option<FileExtract> {
        let tree: Tree = self.parser.parse(source, None)?;
        let mut out = FileExtract {
            path: path.to_string(),
            lang: self.config.name,
            lang_id: crate::lang::lang_id(self.config),
            structural_interfaces: self.config.structural_interfaces,
            content_hash: content_hash(source),
            size: source.len() as u64,
            had_parse_error: tree.root_node().has_error(),
            ..Default::default()
        };

        // The chain of enclosing *definitions*, innermost last. Holds leaf
        // definitions too, not only scoping ones: a call inside a method
        // belongs to the method, and keeping only scopes here would attribute
        // it to the enclosing class instead. Only entries marked `scopes`
        // contribute to a symbol's qualified name.
        //
        // The tree-sitter node id is how the walk knows it has left a
        // definition, without needing a recursive traversal.
        let mut open: Vec<Open> = Vec::new();
        let mut cursor = tree.walk();
        let mut descend = true;

        // Top-level statements: calls, references and flows with no owning
        // callable. The walk below never re-emits their calls.
        crate::flow::analyse_body(self.config, source, tree.root_node(), None, Vec::new(), None, Vec::new(), &mut out);

        loop {
            if descend {
                let node = cursor.node();
                // Leaving any scope whose node no longer contains this one.
                let start = node.start_byte();
                while open.last().is_some_and(|o| start >= o.end_byte) {
                    open.pop();
                }
                self.visit(node, source, &mut open, &mut out);
            }

            if descend && cursor.goto_first_child() {
                continue;
            }
            descend = true;
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    attach_methods(&mut out);
                    return Some(out);
                }
                if cursor.goto_next_sibling() {
                    descend = true;
                    break;
                }
            }
        }
    }

    /// The type named by a receiver, ignoring pointers and generics:
    /// `(p *Permission)` and `(s Store[T])` both give `Permission` / `Store`.
    ///
    /// A depth-first scan for the first type identifier, because the receiver's
    /// shape differs per language and the type name is always the first one in
    /// it — the parameter's own name is an `identifier`, a different kind.
    /// Read a definition's heritage clauses.
    ///
    /// Depth two, no further: Python's base list is a direct child, TypeScript
    /// nests its clauses one level inside `class_heritage`, and stopping there
    /// is what keeps a call's `argument_list` in a class body from being read
    /// as a base-class list.
    fn collect_supertypes(
        &self,
        node: Node<'_>,
        source: &[u8],
        owner: u32,
        out: &mut FileExtract,
    ) {
        let mut c1 = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut c1).collect();
        for child in children {
            for candidate in [child]
                .into_iter()
                .chain({
                    let mut c2 = child.walk();
                    child.named_children(&mut c2).collect::<Vec<_>>()
                })
            {
                let Some((_, relation)) =
                    self.config.supertypes.iter().find(|(k, _)| *k == candidate.kind())
                else {
                    continue;
                };
                let mut c3 = candidate.walk();
                let entries: Vec<Node<'_>> = candidate.named_children(&mut c3).collect();
                for entry in entries {
                    // `class C(Base, metaclass=Meta)`: a keyword argument is a
                    // class-creation option, not a base.
                    if entry.kind() == "keyword_argument" {
                        continue;
                    }
                    if let Some(name) = self.supertype_name_of(entry, source) {
                        out.supertypes.push((owner, name, *relation));
                    }
                }
            }
        }
    }

    /// The type named by one heritage entry.
    ///
    /// Two shapes pull in opposite directions and both appear here: a dotted
    /// name (`abc.ABC`, `models.Base`) means the *last* segment, while a
    /// parameterised one (`Generic[T]`, `Foo<T>`) means the *first*.
    fn supertype_name_of(&self, node: Node<'_>, source: &[u8]) -> Option<String> {
        let text = |n: Node<'_>| n.utf8_text(source).ok().map(str::to_string);
        match node.kind() {
            k if self.config.ident_kinds.contains(&k) => text(node),
            "attribute" | "member_expression" | "nested_type_identifier"
            | "scoped_type_identifier" | "qualified_type" => {
                let mut c = node.walk();
                let kids: Vec<Node<'_>> = node.named_children(&mut c).collect();
                kids.into_iter().rev().find_map(|k| self.supertype_name_of(k, source))
            }
            _ => {
                let mut c = node.walk();
                let kids: Vec<Node<'_>> = node.named_children(&mut c).collect();
                kids.into_iter().find_map(|k| self.supertype_name_of(k, source))
            }
        }
    }

    /// The interface named by a constraint element, if it names exactly one.
    ///
    /// A generic constraint (`~int | ~string`) names no interface; it yields
    /// several identifiers, and returning the first would be a guess. Those
    /// fall through to the resolver, which cannot match the name and drops the
    /// interface rather than comparing an incomplete requirement set.
    fn embedded_name_of(&self, node: Node<'_>, source: &[u8]) -> Option<String> {
        if node.kind() == "qualified_type" {
            return node.utf8_text(source).ok().map(str::to_string);
        }
        let mut found: Option<String> = None;
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if n.kind() == "qualified_type" || self.config.ident_kinds.contains(&n.kind()) {
                if found.is_some() {
                    return None;
                }
                found = n.utf8_text(source).ok().map(str::to_string);
                continue;
            }
            let mut c = n.walk();
            let kids: Vec<Node<'_>> = n.named_children(&mut c).collect();
            for k in kids.into_iter().rev() {
                stack.push(k);
            }
        }
        found
    }

    /// The receiver's *variable* name: the `p` in `(p *Permission)`. The first
    /// plain `identifier` in the receiver, as distinct from the
    /// `type_identifier` the type lives in.
    fn receiver_var_of(&self, receiver: Node<'_>, source: &[u8]) -> Option<String> {
        let mut stack = vec![receiver];
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" {
                return n.utf8_text(source).ok().map(str::to_string);
            }
            let mut c = n.walk();
            let kids: Vec<Node<'_>> = n.named_children(&mut c).collect();
            for k in kids.into_iter().rev() {
                stack.push(k);
            }
        }
        None
    }

    fn receiver_type_of(&self, receiver: Node<'_>, source: &[u8]) -> Option<String> {
        let mut stack = vec![receiver];
        while let Some(n) = stack.pop() {
            if n.kind() == "type_identifier" {
                return n.utf8_text(source).ok().map(str::to_string);
            }
            let mut c = n.walk();
            let kids: Vec<Node<'_>> = n.named_children(&mut c).collect();
            for k in kids.into_iter().rev() {
                stack.push(k);
            }
        }
        None
    }

    /// Declare a module-level variable/constant or a type-level field.
    fn declare(
        &self,
        node: Node<'_>,
        decl: &crate::syntax::VarDecl,
        source: &[u8],
        open: &[Open],
        out: &mut FileExtract,
    ) {
        let name_node = if decl.name_field.is_empty() { Some(node) } else { node.child_by_field_name(decl.name_field) };
        let Some(name_node) = name_node else { return };
        if !decl.name_kind.is_empty() && name_node.kind() != decl.name_kind {
            return;
        }
        // Go declares several names per spec; C declares through a chain.
        let names: Vec<(String, u32)> = if decl.name_field.is_empty() {
            self.decl_name(name_node, source).into_iter().map(|n| (n, node.start_position().row as u32 + 1)).collect()
        } else {
            let mut c = node.walk();
            node.children_by_field_name(decl.name_field, &mut c)
                .filter_map(|n| self.decl_name(n, source).map(|s| (s, n.start_position().row as u32 + 1)))
                .collect()
        };
        for (name, line) in names {
            let scope: Vec<String> = open
                .iter()
                .filter(|o| o.scopes)
                .filter_map(|o| out.symbols.get(o.symbol as usize).map(|s| s.name.clone()))
                .collect();
            if !out.declared.insert((scope.clone(), name.clone())) {
                continue;
            }
            let in_type = open.last().is_some_and(|o| is_type_like(out.symbols[o.symbol as usize].kind));
            let kind = if self.is_const(node, decl.constness, &name, source) {
                SymbolKind::Constant
            } else if in_type && decl.kind != SymbolKind::Constant {
                SymbolKind::Field
            } else if decl.kind == SymbolKind::Field && !in_type {
                SymbolKind::Variable
            } else {
                decl.kind
            };
            let idx = out.symbols.len() as u32;
            let hash = definition_hash(&source[node.start_byte()..node.end_byte()]);
            out.symbols.push(RawSymbol { name, scope, kind, line, arity: None, param_index: None, hash });
            if let Some(parent) = open.last().map(|o| o.symbol) {
                out.edges.push(RawEdge { from: parent, to: idx, relation: Relation::Contains, line });
            }
        }
    }

    /// A declared name: an identifier, or the identifier at the end of a
    /// declarator chain. `None` for patterns (`a, b = …`) and member targets.
    fn decl_name(&self, node: Node<'_>, source: &[u8]) -> Option<String> {
        if self.config.syntax.is_var_ref(node.kind()) || self.config.ident_kinds.contains(&node.kind()) {
            // Ruby: `@count` is the field `count`; `$x` the global `x`.
            return text(node, source).map(|t| t.trim_start_matches('@').trim_start_matches('$').to_string());
        }
        let mut cur = node;
        for _ in 0..8 {
            let Some(next) = cur.child_by_field_name("declarator") else { break };
            if let Some(n) = self.ident_text(next, source) {
                return Some(n);
            }
            cur = next;
        }
        None
    }

    fn is_const(&self, node: Node<'_>, rule: crate::syntax::ConstRule, name: &str, source: &[u8]) -> bool {
        use crate::syntax::ConstRule;
        match rule {
            ConstRule::Never => false,
            ConstRule::Always => true,
            ConstRule::AllCaps => {
                name.len() > 1
                    && name.chars().any(|c| c.is_ascii_uppercase())
                    && name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            }
            ConstRule::ParentKindField => node
                .parent()
                .and_then(|p| p.child_by_field_name("kind"))
                .and_then(|k| text(k, source))
                .is_some_and(|k| k == "const"),
            ConstRule::ModifierText(words) => {
                // Modifiers sit on the node, its parent, or its grandparent
                // (`field_declaration › variable_declaration › declarator`).
                let mut cur = Some(node);
                for _ in 0..3 {
                    let Some(n) = cur else { break };
                    let mut c = n.walk();
                    for ch in n.children(&mut c) {
                        let t = text(ch, source).unwrap_or("");
                        if matches!(ch.kind(), "modifiers" | "modifier" | "type_qualifier" | "storage_class_specifier")
                            && words.iter().any(|w| t.split_whitespace().any(|tok| tok == *w))
                        {
                            return true;
                        }
                        if !ch.is_named() && words.contains(&t) {
                            return true;
                        }
                    }
                    cur = n.parent();
                }
                false
            }
        }
    }

    /// Declare a callable's parameters as symbols; returns `(name, index)`.
    fn declare_params(
        &self,
        node: Node<'_>,
        source: &[u8],
        owner: u32,
        scope: &[String],
        out: &mut FileExtract,
    ) -> Vec<(String, u32)> {
        let syn = self.config.syntax;
        let mut params: Vec<(String, u32)> = Vec::new();
        let mut names: Vec<(String, u32)> = Vec::new();
        // A receiver declared outside the list (Go) comes first.
        if let Some(r) = self.config.receiver_field.and_then(|f| node.child_by_field_name(f))
            && let Some(name) = self.receiver_var_of(r, source) {
                names.push((name, r.start_position().row as u32 + 1));
            }
        // C and C++ hang the list off the declarator chain
        // (`function_definition › function_declarator › parameters`).
        let mut holder = node;
        let mut list = holder.child_by_field_name(syn.params_field);
        for _ in 0..6 {
            if list.is_some() {
                break;
            }
            let Some(next) = holder.child_by_field_name("declarator") else { break };
            holder = next;
            list = holder.child_by_field_name(syn.params_field);
        }
        if let Some(list) = list {
            let mut c = list.walk();
            for p in list.named_children(&mut c) {
                let Some(pk) = syn.param_kind(p.kind()) else {
                    // Rust `self` inside `parameters`, C++ `this`: any
                    // identifier-shaped node is still a parameter.
                    if let Some(n) = self.ident_text(p, source) {
                        names.push((n, p.start_position().row as u32 + 1));
                    }
                    continue;
                };
                let name_node = if p.kind() == "typed_parameter" {
                    // Python `x: int`: the name is the first child, the
                    // annotation an identifier too — not a second parameter.
                    p.named_child(0)
                } else if pk.name_field.is_empty() {
                    Some(p)
                } else {
                    p.child_by_field_name(pk.name_field)
                };
                let Some(nn) = name_node else { continue };
                let line = p.start_position().row as u32 + 1;
                if p.kind() == "self_parameter" {
                    names.push(("self".to_string(), line));
                    continue;
                }
                // Go: several names per declaration.
                let mut c2 = p.walk();
                let multi: Vec<Node<'_>> = if pk.name_field.is_empty() {
                    vec![nn]
                } else {
                    p.children_by_field_name(pk.name_field, &mut c2).collect()
                };
                for n in multi {
                    match self.decl_name(n, source) {
                        Some(name) => names.push((name, line)),
                        None => {
                            // A destructured parameter: every bound name.
                            for name in self.pattern_names(n, source) {
                                names.push((name, line));
                            }
                        }
                    }
                }
            }
        }
        for (i, (name, line)) in names.into_iter().enumerate() {
            let idx = out.symbols.len() as u32;
            out.symbols.push(RawSymbol {
                name: name.clone(),
                scope: scope.to_vec(),
                kind: SymbolKind::Parameter,
                line,
                hash: 0,
                arity: None,
                param_index: Some(i as u32),
            });
            out.edges.push(RawEdge { from: owner, to: idx, relation: Relation::Contains, line });
            params.push((name, idx));
        }
        params
    }

    /// Identifier leaves of a pattern.
    fn pattern_names(&self, node: Node<'_>, source: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if self.config.syntax.is_var_ref(n.kind()) {
                if let Some(t) = text(n, source) {
                    out.push(t.to_string());
                }
                continue;
            }
            if n.kind() == "pair_pattern" {
                if let Some(v) = n.child_by_field_name("value") {
                    stack.push(v);
                }
                continue;
            }
            let mut c = n.walk();
            let kids: Vec<Node<'_>> = n.named_children(&mut c).collect();
            for k in kids.into_iter().rev() {
                stack.push(k);
            }
        }
        out
    }

    /// Go named results: locals defined at entry and returned by a bare
    /// `return`.
    fn named_results(&self, node: Node<'_>, source: &[u8]) -> Vec<String> {
        let f = self.config.syntax.named_results_field;
        if f.is_empty() {
            return Vec::new();
        }
        let Some(list) = node.child_by_field_name(f) else { return Vec::new() };
        let mut out = Vec::new();
        let mut c = list.walk();
        for p in list.named_children(&mut c) {
            let mut c2 = p.walk();
            for n in p.children_by_field_name("name", &mut c2) {
                if let Some(t) = text(n, source) {
                    out.push(t.to_string());
                }
            }
        }
        out
    }

    /// `self.x = …` inside a method declares field `x` of the enclosing type
    /// if nothing else did. Idempotent by `(scope, name)`.
    fn declare_self_fields(&self, function: u32, enclosing_type: Option<u32>, line: u32, out: &mut FileExtract) {
        let Some(owner) = enclosing_type else { return };
        if !is_type_like(out.symbols[owner as usize].kind) {
            return;
        }
        let names: Vec<String> = out
            .refs
            .iter()
            .filter(|r| r.function == Some(function) && r.self_field)
            .map(|r| r.name.clone())
            .collect();
        let mut scope = out.symbols[owner as usize].scope.clone();
        scope.push(out.symbols[owner as usize].name.clone());
        for name in names {
            if !out.declared.insert((scope.clone(), name.clone())) {
                continue;
            }
            let idx = out.symbols.len() as u32;
            out.symbols.push(RawSymbol { name, scope: scope.clone(), kind: SymbolKind::Field, line, arity: None, param_index: None, hash: 0 });
            out.edges.push(RawEdge { from: owner, to: idx, relation: Relation::Contains, line });
        }
    }

    fn visit(
        &self,
        node: Node<'_>,
        source: &[u8],
        open: &mut Vec<Open>,
        out: &mut FileExtract,
    ) {
        let kind = node.kind();

        if let Some(def) = self.config.def_for(kind) {
            let Some(name) = self.name_of(node, source) else { return };
            // A receiver names the owning type directly, for languages that
            // declare methods outside it. That name *is* the scope: without it
            // `Permission.IsAdmin` and `Other.IsAdmin` are one symbol.
            let receiver_node =
                self.config.receiver_field.and_then(|f| node.child_by_field_name(f));
            let receiver_type = receiver_node.and_then(|r| self.receiver_type_of(r, source));
            let receiver_var = receiver_node.and_then(|r| self.receiver_var_of(r, source));

            // Only scoping definitions qualify a name. A function nested in a
            // function is still just its own name — Python allows it, and
            // qualifying by the outer function would make the key depend on
            // where a helper happened to be declared.
            let scope: Vec<String> = match &receiver_type {
                Some(t) => vec![t.clone()],
                None => open
                    .iter()
                    .filter(|o| o.scopes)
                    .filter_map(|o| out.symbols.get(o.symbol as usize).map(|s| s.name.clone()))
                    .collect(),
            };
            let idx = out.symbols.len() as u32;
            let line = node.start_position().row as u32 + 1;
            let kind = def
                .refine
                .iter()
                .find(|(child, _)| child_of_kind(node, child))
                .map_or(def.kind, |(_, k)| *k);
            if let Some(t) = receiver_type {
                out.pending_methods.push((idx, t));
            }
            // Declared supertypes: `class C(Base)`, `class C implements I`.
            if !self.config.supertypes.is_empty() {
                self.collect_supertypes(node, source, idx, out);
            }
            // An embedded interface is a bare type name sitting where a method
            // signature would be. Read off the same child the kind was refined
            // from, so this needs no extra configuration.
            if kind == SymbolKind::Interface
                && let Some(body) = def
                    .refine
                    .iter()
                    .find(|(_, k)| *k == SymbolKind::Interface)
                    .and_then(|(child, _)| named_child_of_kind(node, child))
            {
                let mut c = body.walk();
                for ch in body.named_children(&mut c) {
                    // Anything in the body that is not a method signature is a
                    // constraint written by reference. Go wraps it in a
                    // `type_elem`, so the name is a descendant, not the child.
                    if self.config.def_for(ch.kind()).is_some() {
                        continue;
                    }
                    if let Some(name) = self.embedded_name_of(ch, source) {
                        out.embeds.push((idx, name));
                    }
                }
            }
            let arity = self
                .config
                .params_field
                .and_then(|f| node.child_by_field_name(f))
                .map(param_arity);
            let hash = definition_hash(&source[node.start_byte()..node.end_byte()]);
            out.symbols.push(RawSymbol { name: name.clone(), scope: scope.clone(), kind, line, arity, param_index: None, hash });

            // Structural edge from the enclosing symbol. `method` when the
            // parent is a type and the child is callable, `contains`
            // otherwise — the distinction matters because resolution treats a
            // method's owner as a receiver type.
            if let Some(parent) = open.last().map(|o| o.symbol) {
                let parent_kind = out.symbols[parent as usize].kind;
                let relation = if is_type_like(parent_kind)
                    && matches!(kind, SymbolKind::Method | SymbolKind::Function)
                {
                    Relation::Method
                } else {
                    Relation::Contains
                };
                out.edges.push(RawEdge { from: parent, to: idx, relation, line });
            }

            // A callable: its parameters become symbols, and its body is
            // analysed for calls, references and flows.
            if matches!(kind, SymbolKind::Method | SymbolKind::Function) {
                let mut param_scope = scope.clone();
                param_scope.push(name.clone());
                let params = self.declare_params(node, source, idx, &param_scope, out);
                let named_results = self.named_results(node, source);
                if let Some(body) = node.child_by_field_name(self.config.syntax.body_field) {
                    let enclosing_type = open
                        .iter()
                        .rev()
                        .find(|o| is_type_like(out.symbols[o.symbol as usize].kind))
                        .map(|o| o.symbol)
                        .or_else(|| {
                            receiver_var.as_ref().map(|_| idx)
                        });
                    crate::flow::analyse_body(
                        self.config,
                        source,
                        body,
                        Some(idx),
                        params,
                        receiver_var.clone(),
                        named_results,
                        out,
                    );
                    self.declare_self_fields(idx, enclosing_type, line, out);
                }
            } else if is_type_like(kind)
                && let Some(body) = node.child_by_field_name(self.config.syntax.body_field)
            {
                // Statements in a type body (field initialisers, decorators)
                // belong to the type. No parameters, no blocks.
                crate::flow::analyse_body(self.config, source, body, Some(idx), Vec::new(), None, Vec::new(), out);
                out.blocks.retain(|b| b.function != idx);
            }

            open.push(Open { symbol: idx, end_byte: node.end_byte(), scopes: def.scopes });
            return;
        }

        // Calls are found by the body analysis, which also needs their
        // arguments; see `flow.rs`. Nothing here emits one.

        // A declared variable, constant or field. Only at module level or
        // directly inside a type: anything inside a callable is a local.
        if let Some(decl) = self.config.syntax.var_decl(kind) {
            let innermost = open.last().map(|o| out.symbols[o.symbol as usize].kind);
            let level = match innermost {
                None => Some(crate::syntax::DeclAt::Module),
                Some(k) if is_type_like(k) => Some(crate::syntax::DeclAt::Type),
                _ => None,
            };
            let fits = match (level, decl.at) {
                (None, _) => false,
                (Some(_), crate::syntax::DeclAt::Either) => true,
                (Some(l), at) => l == at,
            };
            if fits {
                self.declare(node, decl, source, open, out);
            }
        }

        if self.config.is_import(kind)
            && let Some(module) = self.module_of(node, source)
        {
            let alias = self
                .config
                .import_alias_field
                .and_then(|f| node.child_by_field_name(f))
                .and_then(|n| n.utf8_text(source).ok())
                .map(str::to_string)
                // `import . "x"` and `import _ "x"` are not names.
                .filter(|a| a != "." && a != "_");
            out.imports.push(RawImport {
                module,
                alias,
                line: node.start_position().row as u32 + 1,
            });
        }
    }

    /// A definition's name.
    ///
    /// Tries the configured fields in order, then descends any `declarator`
    /// chain (the C family nests the name arbitrarily deep inside pointers and
    /// parameter lists), then falls back to the first identifier-ish child.
    fn name_of(&self, node: Node<'_>, source: &[u8]) -> Option<String> {
        for field in self.config.name_fields {
            if let Some(child) = node.child_by_field_name(field) {
                if let Some(n) = self.ident_text(child, source) {
                    return Some(n);
                }
                // `declarator` nests; keep descending it.
                let mut cur = child;
                for _ in 0..8 {
                    let Some(next) = cur.child_by_field_name("declarator") else { break };
                    if let Some(n) = self.ident_text(next, source) {
                        return Some(n);
                    }
                    cur = next;
                }
            }
        }
        // Last resort: the first identifier-ish named child.
        let mut c = node.walk();
        node.named_children(&mut c)
            .find_map(|ch| self.ident_text(ch, source))
    }

    /// The text of `node` if it is (or directly wraps) an identifier.
    fn ident_text(&self, node: Node<'_>, source: &[u8]) -> Option<String> {
        if self.config.ident_kinds.contains(&node.kind()) {
            return text(node, source).map(str::to_string);
        }
        None
    }

    /// `(callee, receiver)` for a call node. The body analysis has its own
    /// copy of this reading; this one serves the tests.
    #[allow(dead_code)]
    fn callee_of(&self, node: Node<'_>, source: &[u8]) -> Option<(String, Option<String>)> {
        let target = node
            .child_by_field_name(self.config.callee_field)
            .or_else(|| node.named_child(0))?;

        // A plain identifier is the whole answer.
        if let Some(n) = self.ident_text(target, source) {
            return Some((n, None));
        }

        // A member expression: the trailing identifier is the method, whatever
        // precedes it is the receiver. Grammars spell this differently
        // (`attribute`, `member_expression`, `field_expression`,
        // `selector_expression`, `scoped_identifier`), so this reads positions
        // rather than matching each kind by name.
        let last = target.named_child(target.named_child_count().saturating_sub(1) as u32)?;
        let name = self.ident_text(last, source)?;
        let receiver = (target.named_child_count() >= 2)
            .then(|| target.named_child(0u32))
            .flatten()
            .and_then(|r| text(r, source))
            .map(str::to_string);
        Some((name, receiver))
    }

    /// The module specifier of an import node.
    ///
    /// Field order matters and is not arbitrary. Every entry before `name`
    /// exists because some language puts the module there and a *symbol* in
    /// `name`:
    ///
    /// - `module_name`: `from typing import Literal` — module `typing`, name
    ///   `Literal`. Trying `name` first records `Literal` as a dependency,
    ///   which is how `Any` and `TYPE_CHECKING` end up in a package list.
    /// - `path`: Go's `user_model "code.gitea.io/models/user"` — the module is
    ///   in `path`, `name` is the local *alias*.
    fn module_of(&self, node: Node<'_>, source: &[u8]) -> Option<String> {
        for field in ["module_name", "source", "path", "name", "argument"] {
            if let Some(c) = node.child_by_field_name(field) {
                // `import numpy as np` wraps the module in an alias node; the
                // module is its `name`, and taking the whole node yields
                // "numpy as np".
                let target = c.child_by_field_name("name").unwrap_or(c);
                if let Some(t) = text(target, source) {
                    let cleaned = strip_quotes(t);
                    if !cleaned.is_empty() {
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
        let mut c = node.walk();
        node.named_children(&mut c)
            .find_map(|ch| text(ch, source))
            .map(|t| strip_quotes(t).to_string())
    }
}

fn is_type_like(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Class
            | SymbolKind::Interface
            | SymbolKind::Trait
            | SymbolKind::Struct
            | SymbolKind::Enum
            | SymbolKind::Module
            | SymbolKind::Namespace
    )
}

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> Option<&'a str> {
    source
        .get(node.start_byte()..node.end_byte())
        .and_then(|b| std::str::from_utf8(b).ok())
}

fn strip_quotes(s: &str) -> &str {
    s.trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == '<' || c == '>')
}

/// Content hash, truncated to the 64 bits the file table stores.
pub fn content_hash(bytes: &[u8]) -> u64 {
    let h = blake3::hash(bytes);
    u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("blake3 is 32 bytes"))
}
