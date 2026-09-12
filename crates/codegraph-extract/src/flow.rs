//! Per-body control flow and dataflow.
//!
//! Runs once per callable body (and once for a file's top-level statements),
//! in memory, generic over [`Syntax`]. It produces four things the store
//! keeps: the calls in the body, the body's basic blocks with their
//! successors, the non-local names the body reads or writes, and the
//! **flow facts** — which non-local values reach which call arguments,
//! returns and non-local writes.
//!
//! # Shape
//!
//! 1. **CFG.** Statements are grouped into basic blocks; branches, loops,
//!    switches, `try` and jumps become successor edges with labels. Only
//!    structured control flow at statement level is modelled; control flow
//!    inside an expression (`?:`, `&&`) is straight-line, which is sound —
//!    both sides flow.
//! 2. **Ops.** Each statement is scanned into definitions (`x = e`), calls
//!    with their argument sources, and returns. Every identifier leaf of an
//!    expression is a source of whatever consumes the expression: a coarse
//!    rule that never drops a flow.
//! 3. **Reaching definitions.** A worklist over the CFG, so a use sees the
//!    definitions that can actually reach it: statement order, branches,
//!    loops (to a fixpoint) and kills all count. `x = input(); x = "safe";
//!    sink(x)` is clean. Each definition also carries the **predicate
//!    atoms** it was made under and picks up those of every branch it
//!    crosses; a definition whose atoms contradict each other cannot reach
//!    there, and is dropped. `if c: x = bad` … `if not c: sink(x)` is clean
//!    too. Only decidable atoms take part — see [`Atom`].
//! 4. **Facts.** At each sink, the reaching definitions of every variable
//!    used are followed back through their own sources to the non-local
//!    values they came from: parameters, module-level names, fields, call
//!    results. Locals never leave the function.
//!
//! # The soundness rule
//!
//! The analysis may report a flow that cannot happen; it must never miss one
//! that can. Every shortcut below is taken in that direction: an unknown
//! target is a *weak* definition (generates, kills nothing); a value passed by
//! reference or to an unknown callee is weakly redefined; a closure reads the
//! union of every definition of a captured name; anything the tables do not
//! describe contributes all of its identifier leaves.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::lang::LangConfig;
use crate::summaries::{self, Slot};
use crate::syntax::{Assign, Syntax};
use crate::walk::{ArgPos, FileExtract, FlowNode, RawBlock, RawCall, RawFlow, RawLocal, RawRef};

/// A value inside one body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Src {
    /// A local, read at this point: resolved through reaching definitions.
    Local(String),
    /// A local read from inside a closure: resolved to *every* definition.
    LocalAny(String),
    /// A non-local name: module-level, or a field of the enclosing instance.
    NonLocal(String, bool),
    /// The result of call `k`.
    CallResult(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Local(String),
    NonLocal(String, bool),
}

#[derive(Debug, Clone)]
enum Op {
    /// A definition. `weak` means the target may or may not actually be
    /// written (by-reference passing, shadowing, destructuring): it
    /// generates but does not kill.
    Def { target: Target, sources: Vec<Src>, weak: bool, line: u32 },
    /// Call `k`'s arguments, already registered in `FileExtract::calls`.
    Args { call: u32, args: Vec<(ArgPos, Vec<Src>)>, line: u32 },
    Return { sources: Vec<Src>, line: u32 },
}

/// A successor label: what the edge assumes.
#[derive(Debug, Clone)]
enum Label {
    Fall,
    Then(String),
    Else(String),
    Case(String),
    Default,
    Loop,
    Break,
    Continue,
    Exception,
    Finally,
    Return,
    Goto,
}

impl Label {
    fn text(&self) -> String {
        match self {
            Label::Fall => String::new(),
            Label::Then(c) => format!("then: {c}"),
            Label::Else(c) => format!("else: {c}"),
            Label::Case(p) => format!("case: {p}"),
            Label::Default => "default".into(),
            Label::Loop => "loop".into(),
            Label::Break => "break".into(),
            Label::Continue => "continue".into(),
            Label::Exception => "exception".into(),
            Label::Finally => "finally".into(),
            Label::Return => "return".into(),
            Label::Goto => "goto".into(),
        }
    }
}

/// A literal a local is compared against.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Lit {
    Int(i64),
    Str(String),
    Bool(bool),
    /// A literal the analysis does not interpret (a float, a symbol): two
    /// such literals are different when their text is, and that is all.
    Other(String),
}

/// One decidable fact about a local, as a branch establishes it.
///
/// The set is deliberately small: only atoms the analysis can decide
/// without knowing anything about the program beyond the literal in the
/// source. A condition that is not one of these — a call, a field, a
/// comparison of two variables — contributes nothing, and nothing is ever
/// pruned on it. Truthiness is never related to equality: `v == 0` and `v`
/// are independent atoms, because what is truthy is the language's business.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Atom {
    Truthy(String),
    Falsy(String),
    Eq(String, Lit),
    Ne(String, Lit),
    Lt(String, i64),
    Le(String, i64),
    Gt(String, i64),
    Ge(String, i64),
    Null(String),
    NotNull(String),
    /// A literal `false` condition: the edge cannot be taken.
    Never,
}

impl Atom {
    fn var(&self) -> Option<&str> {
        match self {
            Atom::Truthy(v) | Atom::Falsy(v) | Atom::Eq(v, _) | Atom::Ne(v, _) => Some(v),
            Atom::Lt(v, _) | Atom::Le(v, _) | Atom::Gt(v, _) | Atom::Ge(v, _) => Some(v),
            Atom::Null(v) | Atom::NotNull(v) => Some(v),
            Atom::Never => None,
        }
    }

    /// The atom the other branch establishes. `Never`'s negation is "no
    /// information", which the caller represents by not adding an atom.
    fn negated(&self) -> Option<Atom> {
        Some(match self {
            Atom::Truthy(v) => Atom::Falsy(v.clone()),
            Atom::Falsy(v) => Atom::Truthy(v.clone()),
            Atom::Eq(v, l) => Atom::Ne(v.clone(), l.clone()),
            Atom::Ne(v, l) => Atom::Eq(v.clone(), l.clone()),
            Atom::Lt(v, n) => Atom::Ge(v.clone(), *n),
            Atom::Le(v, n) => Atom::Gt(v.clone(), *n),
            Atom::Gt(v, n) => Atom::Le(v.clone(), *n),
            Atom::Ge(v, n) => Atom::Lt(v.clone(), *n),
            Atom::Null(v) => Atom::NotNull(v.clone()),
            Atom::NotNull(v) => Atom::Null(v.clone()),
            Atom::Never => return None,
        })
    }
}

/// The most atoms one definition carries. Past this, new atoms are not
/// added — fewer assumptions is the sound direction.
const MAX_ATOMS: usize = 4;

/// Can these atoms all hold at once? `false` is the only thing that ever
/// prunes a definition, so every case here must be a genuine impossibility.
fn contradictory(atoms: &[Atom]) -> bool {
    if atoms.contains(&Atom::Never) {
        return true;
    }
    for (i, a) in atoms.iter().enumerate() {
        for b in &atoms[i + 1..] {
            if a.var() != b.var() {
                continue;
            }
            let clash = match (a, b) {
                (Atom::Truthy(_), Atom::Falsy(_)) | (Atom::Falsy(_), Atom::Truthy(_)) => true,
                (Atom::Null(_), Atom::NotNull(_)) | (Atom::NotNull(_), Atom::Null(_)) => true,
                (Atom::Eq(_, x), Atom::Eq(_, y)) => same_type(x, y) && x != y,
                (Atom::Eq(_, x), Atom::Ne(_, y)) | (Atom::Ne(_, x), Atom::Eq(_, y)) => x == y,
                _ => false,
            };
            if clash {
                return true;
            }
        }
    }
    // Integer intervals: the bounds every atom about one variable imposes.
    let mut vars: Vec<&str> = atoms.iter().filter_map(Atom::var).collect();
    vars.sort_unstable();
    vars.dedup();
    for v in vars {
        let (mut lo, mut hi) = (i64::MIN, i64::MAX);
        for a in atoms {
            if a.var() != Some(v) {
                continue;
            }
            match a {
                Atom::Lt(_, n) => hi = hi.min(n.saturating_sub(1)),
                Atom::Le(_, n) => hi = hi.min(*n),
                Atom::Gt(_, n) => lo = lo.max(n.saturating_add(1)),
                Atom::Ge(_, n) => lo = lo.max(*n),
                Atom::Eq(_, Lit::Int(n)) => {
                    lo = lo.max(*n);
                    hi = hi.min(*n);
                }
                _ => {}
            }
        }
        if lo > hi {
            return true;
        }
        // `v != n` with the interval pinned to exactly `n`.
        if lo == hi && atoms.iter().any(|a| matches!(a, Atom::Ne(w, Lit::Int(n)) if w == v && *n == lo)) {
            return true;
        }
    }
    false
}

fn same_type(x: &Lit, y: &Lit) -> bool {
    matches!(
        (x, y),
        (Lit::Int(_), Lit::Int(_)) | (Lit::Str(_), Lit::Str(_)) | (Lit::Bool(_), Lit::Bool(_)) | (Lit::Other(_), Lit::Other(_))
    )
}

/// A conjunction of atoms as the tables produce it.
type Atoms = Vec<Atom>;

/// A conjunction of interned atoms — indices into the body's atom table —
/// sorted, deduplicated, at most [`MAX_ATOMS`]. What the fixpoint carries:
/// a handful of integers per fact, inline, no allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
struct Ids {
    n: u8,
    v: [u32; MAX_ATOMS],
}

impl Ids {
    fn is_empty(&self) -> bool {
        self.n == 0
    }
    fn as_slice(&self) -> &[u32] {
        &self.v[..self.n as usize]
    }
    fn contains(&self, x: u32) -> bool {
        self.as_slice().contains(&x)
    }
    /// Add `x`, keeping the slice sorted; a full set is left as it is.
    fn push(&mut self, x: u32) {
        if self.contains(x) || self.n as usize >= MAX_ATOMS {
            return;
        }
        let n = self.n as usize;
        let mut i = n;
        while i > 0 && self.v[i - 1] > x {
            self.v[i] = self.v[i - 1];
            i -= 1;
        }
        self.v[i] = x;
        self.n += 1;
    }
    fn from_sorted(ids: &[u32]) -> Self {
        let mut out = Ids::default();
        for &x in ids {
            out.push(x);
        }
        out
    }
    fn retain(&self, keep: impl Fn(u32) -> bool) -> Self {
        let mut out = Ids::default();
        for &x in self.as_slice() {
            if keep(x) {
                out.push(x);
            }
        }
        out
    }
}

/// `a ∧ b`, keeping `a`'s atoms when the cap is reached.
fn conjoin(a: &Ids, b: &Ids) -> Ids {
    let mut out = *a;
    for &x in b.as_slice() {
        out.push(x);
    }
    out
}

/// The atoms in both: what holds whichever way control arrived.
fn intersect(a: &Ids, b: &Ids) -> Ids {
    a.retain(|x| b.contains(x))
}

/// Pairwise contradictions between a body's atoms, computed once. A set
/// contradicts itself when some pair does; the three-atom cases
/// (`v >= 7 ∧ v <= 7 ∧ v != 7`) are not detected, which only prunes less.
struct Clashes {
    never: Vec<bool>,
    pair: Vec<bool>,
    k: usize,
}

impl Clashes {
    fn build(table: &[Atom]) -> Self {
        let k = table.len();
        let mut pair = vec![false; k * k];
        for a in 0..k {
            for b in a + 1..k {
                if contradictory(&[table[a].clone(), table[b].clone()]) {
                    pair[a * k + b] = true;
                    pair[b * k + a] = true;
                }
            }
        }
        Self { never: table.iter().map(|a| *a == Atom::Never).collect(), pair, k }
    }
    fn contradictory(&self, ids: &Ids) -> bool {
        let s = ids.as_slice();
        for (i, &a) in s.iter().enumerate() {
            if self.never[a as usize] {
                return true;
            }
            for &b in &s[i + 1..] {
                if self.pair[a as usize * self.k + b as usize] {
                    return true;
                }
            }
        }
        false
    }
}

/// A successor edge: where, why, and what it establishes.
#[derive(Debug, Clone)]
struct Succ {
    to: usize,
    label: Label,
    atoms: Ids,
}

#[derive(Default)]
struct Block<'a> {
    ops: Vec<Op>,
    succ: Vec<Succ>,
    line: u32,
    /// The nodes to scan into ops, in order, once the CFG is complete.
    stmts: Vec<Stmt<'a>>,
}

/// A statement as the CFG sees it.
#[derive(Clone)]
enum Stmt<'a> {
    Node(Node<'a>),
    /// A loop or handler binding: `target` gets `value`'s leaves.
    Bind { target: Node<'a>, value: Option<Node<'a>>, weak: bool },
    /// A returned expression (`return e`, a tail expression).
    Return(Option<Node<'a>>),
}

struct LoopCtx {
    break_to: usize,
    continue_to: usize,
}

/// One body under analysis.
struct Body<'a, 'o> {
    cfg: &'static LangConfig,
    syn: &'static Syntax,
    source: &'a [u8],
    /// The callable this body belongs to, or `None` for top-level code.
    function: Option<u32>,
    function_idx_for_calls: Option<u32>,
    /// The receiver variable name (`p` in `func (p *T)`) — a self name.
    receiver_var: Option<String>,
    /// Parameter names, in order, with their symbol indices.
    params: Vec<(String, u32)>,
    /// Go named results: what a bare `return` returns.
    named_results: Vec<String>,
    /// Every name bound anywhere in this body: parameters, assigned locals,
    /// loop/handler bindings, closure parameters.
    locals: HashSet<String>,
    blocks: Vec<Block<'a>>,
    exit: usize,
    out: &'o mut FileExtract,
    /// Nested definition nodes are not this body's business.
    stop_at: fn(&LangConfig, &str) -> bool,
    block_defines: Option<Vec<Vec<(String, bool)>>>,
    block_uses: Option<Vec<Vec<(String, bool)>>>,
    block_local_defines: Option<Vec<Vec<String>>>,
    block_local_uses: Option<Vec<Vec<String>>>,
    /// Locals bound to a closure, with the closure's parameter names: a
    /// later call through the local feeds those parameters.
    closure_locals: HashMap<String, Vec<String>>,
    /// Locals no atom may speak about: their address is taken, or a closure
    /// or nested function writes them. Such a local can change without a
    /// definition the analysis sees, so a fact about it may go stale, and a
    /// stale fact would prune what it must not.
    no_atoms: HashSet<String>,
    /// Every distinct atom an edge of this body establishes; edges and
    /// facts hold indices into it.
    atom_table: Vec<Atom>,
    atom_ids: HashMap<Atom, u32>,
}

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    std::str::from_utf8(&source[node.start_byte()..node.end_byte()]).unwrap_or("")
}

fn line_of(node: Node<'_>) -> u32 {
    node.start_position().row as u32 + 1
}

fn named_children<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut c = node.walk();
    node.named_children(&mut c).collect()
}

fn field<'a>(node: Node<'a>, name: &str) -> Option<Node<'a>> {
    if name.is_empty() { None } else { node.child_by_field_name(name) }
}

fn fields<'a>(node: Node<'a>, name: &str) -> Vec<Node<'a>> {
    if name.is_empty() {
        return Vec::new();
    }
    let mut c = node.walk();
    node.children_by_field_name(name, &mut c).collect()
}

/// Analyse one body and append its results to `out`.
///
/// `function` is the callable's symbol index (its parameters must already be
/// in `out.symbols`, given in `params`), or `None` for top-level code.
#[allow(clippy::too_many_arguments)]
pub(crate) fn analyse_body(
    cfg: &'static LangConfig,
    source: &[u8],
    body: Node<'_>,
    function: Option<u32>,
    params: Vec<(String, u32)>,
    receiver_var: Option<String>,
    named_results: Vec<String>,
    out: &mut FileExtract,
) {
    let syn = cfg.syntax;
    let mut b = Body {
        cfg,
        syn,
        source,
        function,
        function_idx_for_calls: function,
        receiver_var,
        locals: params.iter().map(|(n, _)| n.clone()).collect(),
        params,
        named_results: named_results.clone(),
        blocks: Vec::new(),
        exit: 0,
        out,
        stop_at: |c, k| c.def_for(k).is_some(),
        block_defines: None,
        block_uses: None,
        block_local_defines: None,
        block_local_uses: None,
        closure_locals: HashMap::new(),
        no_atoms: HashSet::new(),
        atom_table: Vec::new(),
        atom_ids: HashMap::new(),
    };
    b.locals.extend(named_results.iter().cloned());

    // Every name assigned anywhere in the body is a local, decided up front so
    // a read before the first write is still a local read (which then has no
    // reaching definition and contributes nothing — correct, since nothing
    // flowed into it).
    b.collect_locals(body);
    b.forbid_atoms_written_elsewhere(body);

    let entry = b.new_block(line_of(body));
    b.exit = b.new_block(body.end_position().row as u32 + 1);
    // Parameters and named results are defined at entry.
    let params_now = b.params.clone();
    for (name, _) in &params_now {
        b.blocks[entry].ops.push(Op::Def {
            target: Target::Local(name.clone()),
            sources: vec![Src::Local(format!("\0param:{name}"))],
            weak: false,
            line: line_of(body),
        });
    }
    for name in &named_results {
        b.blocks[entry].ops.push(Op::Def {
            target: Target::Local(name.clone()),
            sources: Vec::new(),
            weak: false,
            line: line_of(body),
        });
    }

    let ctx = LoopCtx { break_to: b.exit, continue_to: b.exit };
    let end = b.build_stmts(named_children(body), entry, &ctx, syn.implicit_tail);
    // Falling off the end: a Go bare `return` and the end of the body both
    // return the named results.
    if !named_results.is_empty() {
        let srcs: Vec<Src> = named_results.iter().map(|n| Src::Local(n.clone())).collect();
        let l = body.end_position().row as u32 + 1;
        b.blocks[end].ops.push(Op::Return { sources: srcs, line: l });
    }
    let exit = b.exit;
    b.link(end, exit, Label::Fall);

    b.scan_all();
    b.reaching_definitions_and_facts();
    b.emit_blocks();
}

impl<'a, 'o> Body<'a, 'o> {
    fn new_block(&mut self, line: u32) -> usize {
        self.blocks.push(Block { line, ..Default::default() });
        self.blocks.len() - 1
    }

    fn link(&mut self, from: usize, to: usize, label: Label) {
        self.link_with(from, to, label, Vec::new());
    }

    /// An edge that establishes `atoms`. A second edge between the same two
    /// blocks keeps only the atoms both establish: either may be taken.
    fn link_with(&mut self, from: usize, to: usize, label: Label, atoms: Atoms) {
        let mut raw: Vec<u32> = atoms.into_iter().map(|a| self.intern(a)).collect();
        raw.sort_unstable();
        let ids = Ids::from_sorted(&raw);
        if let Some(e) = self.blocks[from].succ.iter_mut().find(|e| e.to == to) {
            e.atoms = intersect(&e.atoms, &ids);
            return;
        }
        self.blocks[from].succ.push(Succ { to, label, atoms: ids });
    }

    fn intern(&mut self, a: Atom) -> u32 {
        if let Some(&id) = self.atom_ids.get(&a) {
            return id;
        }
        let id = self.atom_table.len() as u32;
        self.atom_table.push(a.clone());
        self.atom_ids.insert(a, id);
        id
    }

    // --- predicate atoms ---

    /// Locals written where the reaching-definitions pass cannot see the
    /// write as a definition at the right point: through their address, or
    /// by a closure or nested function that may run at any later call.
    fn forbid_atoms_written_elsewhere(&mut self, body: Node<'a>) {
        let mut stack = vec![body];
        while let Some(n) = stack.pop() {
            let kind = n.kind();
            let nested = n.id() != body.id() && (self.is_def_node(n) || self.syn.closure(kind).is_some());
            if nested {
                // Everything assigned inside, and Python's `nonlocal`/`global`
                // declarations, which name the outer local being written.
                let mut inner = vec![n];
                while let Some(m) = inner.pop() {
                    let k = m.kind();
                    if let Some(a) = self.syn.assign(k)
                        && let Some(lhs) = self.assign_left(m, a)
                    {
                        for name in self.binding_names(lhs) {
                            self.no_atoms.insert(name);
                        }
                    }
                    if matches!(k, "nonlocal_statement" | "global_statement") {
                        for c in named_children(m) {
                            self.no_atoms.insert(text(c, self.source).to_string());
                        }
                    }
                    self.note_address_taken(m);
                    inner.extend(named_children(m));
                }
                continue;
            }
            self.note_address_taken(n);
            stack.extend(named_children(n));
        }
    }

    /// Does a switch-arm pattern bind this name? Only in the languages whose
    /// arms are patterns, and only for a name that is not a variant, type
    /// or constant by convention.
    fn pattern_binding(&self, name: &str) -> bool {
        matches!(self.cfg.name, "rust" | "python" | "ruby" | "csharp")
            && name.chars().next().is_some_and(|c| c.is_lowercase() || c == '_')
    }

    /// `&x` anywhere: `x` may be written through the pointer.
    fn note_address_taken(&mut self, n: Node<'a>) {
        if self.syn.by_ref_args.contains(&n.kind()) && text(n, self.source).starts_with('&') {
            for name in self.binding_names(n) {
                self.no_atoms.insert(name);
            }
        }
    }

    /// May atoms speak about this name? A local of this body whose every
    /// write is a definition the analysis sees.
    fn atom_var(&self, node: Node<'a>) -> Option<String> {
        if !self.syn.is_var_ref(node.kind()) {
            return None;
        }
        let t = text(node, self.source);
        (self.locals.contains(t) && !self.no_atoms.contains(t) && !self.syn.is_self(t)).then(|| t.to_string())
    }

    /// The literal a node denotes, if it is one.
    fn literal_of(&self, node: Node<'a>) -> Option<Lit> {
        let l = &self.syn.literals;
        let kind = node.kind();
        let t = text(node, self.source);
        if l.int.contains(&kind) {
            return Some(parse_int(t).map_or_else(|| Lit::Other(t.to_string()), Lit::Int));
        }
        if l.string.contains(&kind) {
            let inner = t
                .strip_prefix(['"', '\'', '`'])
                .and_then(|r| r.strip_suffix(['"', '\'', '`']))
                .unwrap_or(t);
            return Some(Lit::Str(inner.to_string()));
        }
        if l.true_.contains(&kind) {
            return Some(Lit::Bool(true));
        }
        if l.false_.contains(&kind) {
            return Some(Lit::Bool(false));
        }
        if !l.bool_text.is_empty() && l.bool_text == kind {
            return Some(Lit::Bool(t == "true"));
        }
        if l.float.contains(&kind) {
            return Some(Lit::Other(t.to_string()));
        }
        // A negative number: a unary minus over an integer literal.
        if matches!(kind, "unary_expression" | "unary_operator" | "unary" | "prefix_unary_expression")
            && t.starts_with('-')
            && let Some(inner) = node.named_child(0)
            && l.int.contains(&inner.kind())
        {
            return parse_int(t.trim()).map(Lit::Int);
        }
        None
    }

    fn is_null_literal(&self, node: Node<'a>) -> bool {
        self.syn.literals.null.contains(&node.kind())
    }

    /// Strip the wrappers a condition comes in: parentheses, C++'s
    /// `condition_clause`, TypeScript's `as`/`!`.
    fn unwrap_condition(&self, mut node: Node<'a>) -> Node<'a> {
        loop {
            if !self.syn.condition_unwrap.contains(&node.kind()) {
                return node;
            }
            let inner = field(node, "value").or_else(|| node.named_child(0));
            match inner {
                Some(i) if i.id() != node.id() => node = i,
                _ => return node,
            }
        }
    }

    /// `(left, operator, right)` of a two-operand comparison.
    fn comparison_parts(&self, node: Node<'a>) -> Option<(Node<'a>, String, Node<'a>)> {
        let c = self.syn.comparison(node.kind())?;
        if c.left.is_empty() {
            // Python: operands positional, operators in a multi-field. A
            // chained `a < b < c` has three operands and is left alone.
            let ops = fields(node, c.operator);
            let operands = named_children(node);
            if ops.len() != 1 || operands.len() != 2 {
                return None;
            }
            return Some((operands[0], text(ops[0], self.source).to_string(), operands[1]));
        }
        let (l, r) = (field(node, c.left)?, field(node, c.right)?);
        let op = field(node, c.operator)
            .map(|o| text(o, self.source).to_string())
            .or_else(|| {
                // The operator is an anonymous token between the operands.
                let mut cur = node.walk();
                node.children(&mut cur).find(|ch| !ch.is_named()).map(|ch| text(ch, self.source).to_string())
            })?;
        Some((l, op, r))
    }

    /// The atoms `cond` establishes when it evaluates to `positive`.
    ///
    /// De Morgan, conjunctions only: `a and b` true gives both, false gives
    /// nothing (one of them is false, and a disjunction is not an atom);
    /// `a or b` false gives `¬a` and `¬b`, true gives nothing. `not c` swaps.
    /// Anything the tables do not describe gives nothing, so nothing is
    /// ever pruned on it.
    fn atoms_of(&self, cond: Node<'a>, positive: bool) -> Atoms {
        let node = self.unwrap_condition(cond);
        let kind = node.kind();
        let t = text(node, self.source);
        // Literal conditions.
        if self.syn.literals.true_.contains(&kind) || (self.syn.literals.bool_text == kind && t == "true") {
            return if positive { Vec::new() } else { vec![Atom::Never] };
        }
        if self.syn.literals.false_.contains(&kind) || (self.syn.literals.bool_text == kind && t == "false") {
            return if positive { vec![Atom::Never] } else { Vec::new() };
        }
        // Negation.
        if let Some(neg) = self.syn.negation(kind) {
            let op_text = if neg.operator.is_empty() {
                node.child(0).map(|c| text(c, self.source))
            } else {
                field(node, neg.operator).map(|c| text(c, self.source))
            };
            if op_text.is_some_and(|o| neg.not.contains(&o)) {
                let operand = if neg.operand.is_empty() { node.named_child(0) } else { field(node, neg.operand) };
                return operand.map(|o| self.atoms_of(o, !positive)).unwrap_or_default();
            }
        }
        // Boolean connectives.
        if let Some(b) = &self.syn.boolean
            && b.node == kind
            && let Some(op) = field(node, b.operator).map(|o| text(o, self.source))
            && (b.and.contains(&op) || b.or.contains(&op))
        {
            let (Some(l), Some(r)) = (field(node, b.left), field(node, b.right)) else { return Vec::new() };
            // `??` is listed with `or` for flow; it is not a disjunction.
            if op == "??" {
                return Vec::new();
            }
            let conj = if b.and.contains(&op) { positive } else { !positive };
            if !conj {
                return Vec::new();
            }
            let mut out = self.atoms_of(l, positive);
            for a in self.atoms_of(r, positive) {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
            out.sort();
            out.truncate(MAX_ATOMS);
            return out;
        }
        // Comparisons against a literal.
        if let Some((l, op, r)) = self.comparison_parts(node) {
            let (var, lit_node) = match (self.atom_var(l), self.atom_var(r)) {
                (Some(v), None) => (v, r),
                (None, Some(v)) => (v, l),
                _ => return Vec::new(),
            };
            let flipped = lit_node.id() == l.id();
            let atom = if self.is_null_literal(lit_node) {
                match op.as_str() {
                    "==" | "===" | "is" | "eq" => Some(Atom::Null(var)),
                    "!=" | "!==" | "is not" | "ne" => Some(Atom::NotNull(var)),
                    _ => None,
                }
            } else if let Some(lit) = self.literal_of(lit_node) {
                match (op.as_str(), &lit) {
                    ("==" | "===", _) => Some(Atom::Eq(var, lit)),
                    ("!=" | "!==", _) => Some(Atom::Ne(var, lit)),
                    ("<", Lit::Int(n)) => Some(if flipped { Atom::Gt(var, *n) } else { Atom::Lt(var, *n) }),
                    ("<=", Lit::Int(n)) => Some(if flipped { Atom::Ge(var, *n) } else { Atom::Le(var, *n) }),
                    (">", Lit::Int(n)) => Some(if flipped { Atom::Lt(var, *n) } else { Atom::Gt(var, *n) }),
                    (">=", Lit::Int(n)) => Some(if flipped { Atom::Le(var, *n) } else { Atom::Ge(var, *n) }),
                    _ => None,
                }
            } else {
                None
            };
            return match atom {
                Some(a) if positive => vec![a],
                Some(a) => a.negated().into_iter().collect(),
                None => Vec::new(),
            };
        }
        // A bare local: its truthiness.
        if let Some(v) = self.atom_var(node) {
            return vec![if positive { Atom::Truthy(v) } else { Atom::Falsy(v) }];
        }
        Vec::new()
    }

    fn is_def_node(&self, node: Node<'_>) -> bool {
        (self.stop_at)(self.cfg, node.kind())
    }

    // --- locals ---

    fn collect_locals(&mut self, node: Node<'a>) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if n.id() != node.id() && self.is_def_node(n) {
                continue;
            }
            let kind = n.kind();
            if let Some(a) = self.syn.assign(kind)
                && a.declares
                && let Some(lhs) = self.assign_left(n, a)
            {
                for name in self.binding_names(lhs) {
                    self.locals.insert(name);
                }
            }
            if self.syn.decl_stmts.contains(&kind) {
                for ch in named_children(n) {
                    // Nested declaration statements are visited on their own.
                    if ch.kind() == "type"
                        || ch.kind().ends_with("type")
                        || ch.kind().ends_with("modifier")
                        || self.syn.decl_stmts.contains(&ch.kind())
                    {
                        continue;
                    }
                    // A declarator with an initialiser: only its name side
                    // binds; the initialiser is an expression.
                    let target = match self.syn.assign(ch.kind()) {
                        Some(a) => self.assign_left(ch, a),
                        None => Some(ch),
                    };
                    if let Some(t) = target {
                        for name in self.binding_names(t) {
                            self.locals.insert(name);
                        }
                    }
                }
            }
            if let Some(l) = self.syn.loop_(kind)
                && let Some(t) = field(n, l.binds)
            {
                for name in self.binding_names(t) {
                    self.locals.insert(name);
                }
            }
            if let Some(c) = self.syn.closure(kind) {
                for (name, _) in self.closure_params(n, c) {
                    self.locals.insert(name);
                }
            }
            for t in self.syn.tries {
                if t.node == kind {
                    for h in named_children(n) {
                        if t.handlers.contains(&h.kind())
                            && let Some(bind) = field(h, t.handler_binding)
                        {
                            for name in self.binding_names(bind) {
                                self.locals.insert(name);
                            }
                        }
                    }
                }
            }
            for ch in named_children(n).into_iter().rev() {
                stack.push(ch);
            }
        }
    }

    /// The names an assignment target or pattern binds.
    fn binding_names(&self, node: Node<'a>) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let kind = n.kind();
            if self.syn.member(kind).is_some() || self.syn.subscript(kind).is_some() {
                // `a.b = …` binds nothing; it mutates `a`.
                continue;
            }
            if self.syn.is_var_ref(kind) && kind != "self" && kind != "this" {
                let t = text(n, self.source);
                // Ruby's sigilled names are never locals.
                if !self.syn.is_self(t) && !matches!(kind, "instance_variable" | "class_variable" | "global_variable" | "constant") {
                    out.push(t.to_string());
                }
                continue;
            }
            // C declarator chains and patterns: descend.
            if let Some(d) = field(n, "declarator") {
                stack.push(d);
                continue;
            }
            if kind == "pair_pattern" || kind == "keyed_element" {
                if let Some(v) = field(n, "value") {
                    stack.push(v);
                }
                continue;
            }
            for ch in named_children(n).into_iter().rev() {
                stack.push(ch);
            }
        }
        out
    }

    fn assign_left(&self, node: Node<'a>, a: &Assign) -> Option<Node<'a>> {
        if a.left.is_empty() { node.named_child(0) } else { field(node, a.left) }
    }

    fn assign_right(&self, node: Node<'a>, a: &Assign) -> Option<Node<'a>> {
        if !a.right.is_empty() {
            return field(node, a.right);
        }
        // C#: the initialiser is the unnamed expression child after `=`.
        let kids = named_children(node);
        let left = self.assign_left(node, a);
        kids.into_iter().rev().find(|k| Some(k.id()) != left.map(|l| l.id()) && k.kind() != "type")
    }

    fn closure_params(&self, node: Node<'a>, c: &crate::syntax::Closure) -> Vec<(String, Node<'a>)> {
        let mut out = Vec::new();
        let list = if c.params_field.is_empty() {
            None
        } else {
            field(node, c.params_field).or_else(|| field(node, "parameter"))
        };
        match list {
            // A bare name (`x => …`; C#'s `implicit_parameter`). An empty
            // list (`func() {}`) names nothing.
            Some(l) if self.syn.is_var_ref(l.kind()) || l.named_child_count() == 0 => {
                let t = text(l, self.source);
                if t.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '@') && !t.is_empty() {
                    out.push((t.to_string(), l));
                }
            }
            Some(l) => {
                for p in named_children(l) {
                    for name in self.binding_names(p) {
                        out.push((name, p));
                    }
                }
            }
            None => {}
        }
        out
    }

    // --- CFG construction ---

    /// Build the CFG for a statement list starting at `cur`; returns the
    /// block where control continues afterwards.
    fn build_stmts(&mut self, stmts: Vec<Node<'a>>, mut cur: usize, ctx: &LoopCtx, tail: bool) -> usize {
        let n = stmts.len();
        for (i, s) in stmts.into_iter().enumerate() {
            let is_last = i + 1 == n;
            cur = self.build(s, cur, ctx, tail && is_last);
        }
        cur
    }

    fn build(&mut self, node: Node<'a>, cur: usize, ctx: &LoopCtx, tail: bool) -> usize {
        let kind = node.kind();
        if self.is_def_node(node) {
            return cur;
        }
        let syn = self.syn;

        // A statement wrapper around structured control flow (Rust's
        // `expression_statement › if_expression`): look through it.
        if syn.statement_wrappers.contains(&kind) {
            if let Some(ch) = node.named_child(0)
                && (syn.branch(ch.kind()).is_some()
                    || syn.loop_(ch.kind()).is_some()
                    || syn.switch(ch.kind()).is_some()
                    || syn.try_(ch.kind()).is_some())
            {
                return self.build(ch, cur, ctx, tail);
            }
            if tail && syn.implicit_tail && !text(node, self.source).trim_end().ends_with(';')
                && let Some(ch) = node.named_child(0)
            {
                return self.build(ch, cur, ctx, tail);
            }
        }

        // Nested statement blocks (`{ … }`, Go `statement_list`).
        if syn.blocks.contains(&kind) || kind == "statement_list" || kind == "body_statement" && syn.try_(kind).is_none() {
            let kids = named_children(node);
            return self.build_stmts(kids, cur, ctx, tail);
        }

        if let Some(b) = syn.branch(kind) {
            return self.build_branch(node, *b, cur, ctx, tail);
        }
        if let Some(l) = syn.loop_(kind) {
            return self.build_loop(node, *l, cur, ctx);
        }
        if let Some(s) = syn.switch(kind) {
            return self.build_switch(node, *s, cur, ctx, tail);
        }
        if let Some(t) = syn.try_(kind) {
            return self.build_try(node, *t, cur, ctx, tail);
        }
        if syn.jumps.return_.contains(&kind) {
            let value = self.jump_value(node);
            self.blocks[cur].stmts.push(Stmt::Return(value));
            let exit = self.exit;
            self.link(cur, exit, Label::Return);
            return self.new_block(line_of(node));
        }
        if syn.jumps.throw.contains(&kind) {
            self.blocks[cur].stmts.push(Stmt::Node(node));
            let exit = self.exit;
            self.link(cur, exit, Label::Return);
            return self.new_block(line_of(node));
        }
        if syn.jumps.break_.contains(&kind) {
            // Rust `break value` carries a value; treat it as straight-line.
            self.blocks[cur].stmts.push(Stmt::Node(node));
            self.link(cur, ctx.break_to, Label::Break);
            return self.new_block(line_of(node));
        }
        if syn.jumps.continue_.contains(&kind) {
            self.link(cur, ctx.continue_to, Label::Continue);
            return self.new_block(line_of(node));
        }
        if kind == "goto_statement" {
            // Conservative: a goto may land anywhere in the function.
            self.blocks[cur].stmts.push(Stmt::Node(node));
            let all: Vec<usize> = (0..self.blocks.len()).collect();
            for t in all {
                self.link(cur, t, Label::Goto);
            }
            return self.new_block(line_of(node));
        }

        // Rust: a tail expression is the body's value.
        if tail && syn.implicit_tail && !syn.statement_wrappers.contains(&kind) {
            // Ruby: a trailing `if` is handled above; anything else is the
            // returned value.
            self.blocks[cur].stmts.push(Stmt::Return(Some(node)));
            return cur;
        }

        self.blocks[cur].stmts.push(Stmt::Node(node));
        cur
    }

    fn jump_value(&self, node: Node<'a>) -> Option<Node<'a>> {
        // `return e` has no field: the value is the first named child. Ruby
        // wraps it in an `argument_list`, whose children are the values.
        node.named_child(0)
    }

    fn condition_text(&self, cond: Option<Node<'a>>) -> String {
        cond.map(|c| text(c, self.source).chars().take(60).collect()).unwrap_or_default()
    }

    fn build_branch(&mut self, node: Node<'a>, b: crate::syntax::Branch, cur: usize, ctx: &LoopCtx, tail: bool) -> usize {
        // Go: `if x := f(); cond {` runs its initialiser first.
        if let Some(init) = field(node, "initializer") {
            self.blocks[cur].stmts.push(Stmt::Node(init));
        }
        let cond = field(node, b.condition);
        if let Some(c) = cond {
            // The condition is evaluated in the current block.
            self.blocks[cur].stmts.push(Stmt::Node(c));
        }
        let ctext = self.condition_text(cond);
        let then_b = self.new_block(line_of(node));
        let else_b = self.new_block(line_of(node));
        let join = self.new_block(node.end_position().row as u32 + 1);
        let (then_label, else_label) = if b.negated {
            (Label::Else(ctext.clone()), Label::Then(ctext))
        } else {
            (Label::Then(ctext.clone()), Label::Else(ctext))
        };
        // The consequence runs when the condition is true — or, for
        // `unless`, false.
        let (then_atoms, else_atoms) = match cond {
            Some(c) => (self.atoms_of(c, !b.negated), self.atoms_of(c, b.negated)),
            None => (Vec::new(), Vec::new()),
        };
        self.link_with(cur, then_b, then_label, then_atoms);
        self.link_with(cur, else_b, else_label, else_atoms);

        let end_then = match field(node, b.consequence) {
            Some(c) => self.build_body_like(c, then_b, ctx, tail),
            None => then_b,
        };
        self.link(end_then, join, Label::Fall);

        let alts = fields(node, b.alternative);
        let mut end_else = else_b;
        if alts.is_empty() {
            self.link(else_b, join, Label::Fall);
        } else {
            // Python lists every `elif`/`else` under `alternative`; the
            // clauses chain: each `elif` is a branch inside the previous else.
            for alt in alts {
                end_else = self.build_body_like(alt, end_else, ctx, tail);
            }
            self.link(end_else, join, Label::Fall);
        }
        join
    }

    /// A clause body: a block node, a bare statement, or an `else`/`elsif`
    /// wrapper whose children are statements.
    fn build_body_like(&mut self, node: Node<'a>, cur: usize, ctx: &LoopCtx, tail: bool) -> usize {
        let kind = node.kind();
        let syn = self.syn;
        if syn.branch(kind).is_some() {
            return self.build(node, cur, ctx, tail);
        }
        if syn.blocks.contains(&kind)
            || matches!(kind, "else_clause" | "else" | "then" | "do" | "statement_list" | "elif_clause")
        {
            // `else_clause` may hold a single block or statements; `else`
            // (Ruby/Python) holds statements or a `body`.
            if let Some(body) = field(node, "body") {
                return self.build_body_like(body, cur, ctx, tail);
            }
            return self.build_stmts(named_children(node), cur, ctx, tail);
        }
        self.build(node, cur, ctx, tail)
    }

    fn loop_condition(&self, node: Node<'a>, l: &crate::syntax::Loop) -> Option<Node<'a>> {
        if !l.condition.is_empty() {
            return field(node, l.condition);
        }
        // Go: `for_clause` child with a `condition` field, or a bare
        // expression child that is neither the body nor a clause.
        for ch in named_children(node) {
            if ch.kind() == "for_clause" {
                return field(ch, "condition");
            }
        }
        if l.binds.is_empty() {
            let body = field(node, l.body);
            return named_children(node)
                .into_iter()
                .find(|c| Some(c.id()) != body.map(|b| b.id()) && c.kind() != "range_clause");
        }
        None
    }

    fn build_loop(&mut self, node: Node<'a>, l: crate::syntax::Loop, cur: usize, _ctx: &LoopCtx) -> usize {
        let header = self.new_block(line_of(node));
        let body_b = self.new_block(line_of(node));
        let exit = self.new_block(node.end_position().row as u32 + 1);
        let cond = self.loop_condition(node, &l);
        let ctext = self.condition_text(cond);

        // Go's `for_clause` initialiser and update run around the header.
        for ch in named_children(node) {
            if ch.kind() == "for_clause"
                && let Some(init) = field(ch, "initializer") {
                    self.blocks[cur].stmts.push(Stmt::Node(init));
                }
        }
        if let Some(init) = field(node, "initializer").or_else(|| field(node, "init"))
            && init.kind() != "for_clause" {
                self.blocks[cur].stmts.push(Stmt::Node(init));
            }

        if let Some(c) = cond {
            self.blocks[header].stmts.push(Stmt::Node(c));
        }
        // For-in: the loop variable is bound at the header from the iterated
        // value. Go `range_clause` is an assignment the scanner already
        // knows; other languages need the binding made explicit.
        if !l.binds.is_empty()
            && let Some(t) = field(node, l.binds)
        {
            let over = field(node, l.over);
            self.blocks[header].stmts.push(Stmt::Bind { target: t, value: over, weak: false });
        }
        for ch in named_children(node) {
            if ch.kind() == "range_clause" {
                self.blocks[header].stmts.push(Stmt::Node(ch));
            }
        }

        if l.post_test {
            self.link(cur, body_b, Label::Loop);
        } else {
            self.link(cur, header, Label::Fall);
        }
        // `until` runs the body while the condition is false.
        let negated = l.node.starts_with("until");
        let (body_atoms, exit_atoms) = match cond {
            Some(c) => (self.atoms_of(c, !negated), self.atoms_of(c, negated)),
            None => (Vec::new(), Vec::new()),
        };
        self.link_with(header, body_b, Label::Then(ctext.clone()), body_atoms);
        self.link_with(header, exit, Label::Else(ctext), exit_atoms);

        let inner = LoopCtx { break_to: exit, continue_to: header };
        let end_body = match field(node, l.body) {
            Some(b) => self.build_body_like(b, body_b, &inner, false),
            None => body_b,
        };
        // Go `for_clause` update runs after the body.
        for ch in named_children(node) {
            if ch.kind() == "for_clause"
                && let Some(u) = field(ch, "update")
            {
                self.blocks[end_body].stmts.push(Stmt::Node(u));
            }
        }
        if let Some(u) = field(node, "update") {
            self.blocks[end_body].stmts.push(Stmt::Node(u));
        }
        self.link(end_body, header, Label::Loop);
        exit
    }

    fn build_switch(&mut self, node: Node<'a>, s: crate::syntax::Switch, cur: usize, ctx: &LoopCtx, tail: bool) -> usize {
        if let Some(init) = field(node, "initializer") {
            self.blocks[cur].stmts.push(Stmt::Node(init));
        }
        if let Some(v) = field(node, s.value) {
            self.blocks[cur].stmts.push(Stmt::Node(v));
        }
        let join = self.new_block(node.end_position().row as u32 + 1);
        // Arms live directly under the node or under its `body`.
        let container = field(node, "body").unwrap_or(node);
        let arms: Vec<(Node<'a>, crate::syntax::Arm)> = named_children(container)
            .into_iter()
            .filter_map(|c| s.arms.iter().find(|a| a.node == c.kind()).map(|a| (c, *a)))
            .collect();
        let inner = LoopCtx { break_to: join, continue_to: ctx.continue_to };
        let mut prev_end: Option<usize> = None;
        let mut has_default = false;
        // `case L:` on a local subject establishes `v == L`; the default arm,
        // when every other arm is one literal, establishes every `v != L`.
        let subject = field(node, s.value).and_then(|v| self.atom_var(self.unwrap_condition(v)));
        let arm_lit = |this: &Self, arm: Node<'a>, a: &crate::syntax::Arm| -> Option<Lit> {
            let pat = fields(arm, a.pattern);
            if pat.len() != 1 {
                return None;
            }
            let p = pat[0];
            let inner = if this.syn.is_literal(p.kind()) { p } else { p.named_child(0).filter(|_| p.named_child_count() == 1)? };
            this.literal_of(inner)
        };
        let all_lits: Option<Vec<Lit>> = subject.as_ref().and_then(|_| {
            arms.iter()
                .filter(|(arm, a)| !(a.is_default || (a.pattern.is_empty() && self.arm_is_default(*arm))))
                .map(|(arm, a)| arm_lit(self, *arm, a))
                .collect()
        });
        for (arm, a) in arms {
            let arm_b = self.new_block(line_of(arm));
            let pat = fields(arm, a.pattern);
            let is_default = a.is_default || (a.pattern.is_empty() && self.arm_is_default(arm));
            has_default |= is_default;
            let label = if is_default {
                Label::Default
            } else {
                Label::Case(pat.iter().map(|p| text(*p, self.source)).collect::<Vec<_>>().join(", ").chars().take(60).collect())
            };
            let atoms: Atoms = match (&subject, is_default) {
                (Some(v), false) => arm_lit(self, arm, &a).map(|l| vec![Atom::Eq(v.clone(), l)]).unwrap_or_default(),
                (Some(v), true) => all_lits
                    .as_ref()
                    .map(|ls| ls.iter().map(|l| Atom::Ne(v.clone(), l.clone())).collect())
                    .unwrap_or_default(),
                (None, _) => Vec::new(),
            };
            self.link_with(cur, arm_b, label, atoms);
            if s.fallthrough
                && let Some(p) = prev_end
            {
                self.link(p, arm_b, Label::Fall);
            }
            // Pattern bindings (Rust `Some(x)`, Python `case [x, y]`) are
            // weak locals; a case *value* (Go `case A:`, Java `case FOO:`)
            // binds nothing. Only a pattern language binds, and only a
            // lowercase name — `None`, `Foo::Bar` are variants and paths.
            for p in &pat {
                for name in self.binding_names(*p) {
                    if self.pattern_binding(&name) {
                        self.locals.insert(name);
                    }
                }
                self.blocks[arm_b].stmts.push(Stmt::Bind { target: *p, value: field(node, s.value), weak: true });
            }
            let end = if a.body.is_empty() {
                // Positional: everything after the labels.
                let kids: Vec<Node<'a>> = named_children(arm)
                    .into_iter()
                    .filter(|k| !pat.iter().any(|p| p.id() == k.id()) && !matches!(k.kind(), "switch_label" | "expression" | "pattern"))
                    .collect();
                self.build_stmts(kids, arm_b, &inner, tail)
            } else if let Some(b) = field(arm, a.body) {
                self.build_body_like(b, arm_b, &inner, tail)
            } else {
                arm_b
            };
            if !s.fallthrough {
                self.link(end, join, Label::Fall);
            }
            prev_end = Some(end);
        }
        if let Some(p) = prev_end {
            self.link(p, join, Label::Fall);
        }
        if !has_default {
            let atoms: Atoms = match (&subject, &all_lits) {
                (Some(v), Some(ls)) => ls.iter().map(|l| Atom::Ne(v.clone(), l.clone())).collect(),
                _ => Vec::new(),
            };
            self.link_with(cur, join, Label::Default, atoms);
        }
        join
    }

    /// Positional switch arms: a label with no expression/pattern is default.
    fn arm_is_default(&self, arm: Node<'a>) -> bool {
        let kids = named_children(arm);
        if arm.kind() == "switch_section" {
            return !kids.iter().any(|k| k.kind() != "block" && !k.kind().ends_with("statement") && !self.syn.blocks.contains(&k.kind()) && k.kind() != "local_declaration_statement");
        }
        if let Some(label) = kids.iter().find(|k| k.kind() == "switch_label") {
            return text(*label, self.source).trim().starts_with("default");
        }
        false
    }

    fn build_try(&mut self, node: Node<'a>, t: crate::syntax::Try, cur: usize, ctx: &LoopCtx, tail: bool) -> usize {
        let join = self.new_block(node.end_position().row as u32 + 1);
        let kids = named_children(node);
        let handlers: Vec<Node<'a>> = kids.iter().copied().filter(|k| t.handlers.contains(&k.kind())).collect();
        let finals: Vec<Node<'a>> = kids.iter().copied().filter(|k| t.finally.contains(&k.kind())).collect();
        let body_stmts: Vec<Node<'a>> = if t.body.is_empty() {
            kids.iter().copied().filter(|k| !t.handlers.contains(&k.kind()) && !t.finally.contains(&k.kind())).collect()
        } else {
            match field(node, t.body) {
                Some(b) if self.syn.blocks.contains(&b.kind()) || b.kind() == "body_statement" => named_children(b),
                Some(b) => vec![b],
                None => Vec::new(),
            }
        };

        // Handler blocks first, so every body statement can link to them.
        let handler_blocks: Vec<usize> = handlers.iter().map(|h| self.new_block(line_of(*h))).collect();
        let final_b = if finals.is_empty() { join } else { self.new_block(line_of(finals[0])) };

        // Every statement of the body is its own block: an exception may
        // occur after any of them, and the handler must see the state at
        // that point, not the state after the whole body.
        let mut b = cur;
        for s in body_stmts {
            let nb = self.new_block(line_of(s));
            self.link(b, nb, Label::Fall);
            for hb in &handler_blocks {
                self.link(nb, *hb, Label::Exception);
            }
            self.link(nb, final_b, Label::Exception);
            b = self.build(s, nb, ctx, tail);
        }
        self.link(b, final_b, Label::Fall);

        for (h, hb) in handlers.iter().zip(&handler_blocks) {
            if let Some(bind) = field(*h, t.handler_binding) {
                self.blocks[*hb].stmts.push(Stmt::Bind { target: bind, value: None, weak: true });
            }
            let hbody = field(*h, "body").unwrap_or(*h);
            let end = if hbody.id() == h.id() {
                let kids: Vec<Node<'a>> = named_children(*h)
                    .into_iter()
                    .filter(|k| Some(k.id()) != field(*h, t.handler_binding).map(|n| n.id()))
                    .collect();
                self.build_stmts(kids, *hb, ctx, tail)
            } else {
                self.build_body_like(hbody, *hb, ctx, tail)
            };
            self.link(end, final_b, Label::Fall);
        }
        if !finals.is_empty() {
            let mut fb = final_b;
            for f in finals {
                fb = self.build_body_like(f, fb, ctx, tail);
            }
            self.link(fb, join, Label::Finally);
        }
        join
    }

    // --- statement scanning ---

    fn scan_all(&mut self) {
        for i in 0..self.blocks.len() {
            let stmts = std::mem::take(&mut self.blocks[i].stmts);
            // Entry already holds the parameter definitions.
            let mut ops = std::mem::take(&mut self.blocks[i].ops);
            for s in stmts {
                match s {
                    Stmt::Node(n) => self.scan_node(n, &mut ops),
                    Stmt::Bind { target, value, weak } => {
                        let mut sources = Vec::new();
                        if let Some(v) = value {
                            sources = self.leaves(v, &mut ops);
                        }
                        // A binding defines a local; a name in a pattern that
                        // is not one (a constant compared against) is not
                        // written by it.
                        for name in self.binding_names(target) {
                            if self.locals.contains(&name) {
                                ops.push(Op::Def { target: Target::Local(name), sources: sources.clone(), weak, line: line_of(target) });
                            }
                        }
                    }
                    Stmt::Return(v) => {
                        let mut sources = v.map(|n| self.leaves(n, &mut ops)).unwrap_or_default();
                        if v.is_none() {
                            // Go: a bare `return` returns the named results.
                            sources.extend(self.named_results.iter().map(|n| Src::Local(n.clone())));
                        }
                        let line = v.map(line_of).unwrap_or(self.blocks[i].line);
                        ops.push(Op::Return { sources, line });
                    }
                }
            }
            self.blocks[i].ops = ops;
        }
    }

    /// Scan a statement node: definitions, calls, and any other expression
    /// (whose leaves are evaluated but flow nowhere).
    fn scan_node(&mut self, node: Node<'a>, ops: &mut Vec<Op>) {
        let kind = node.kind();
        if self.is_def_node(node) {
            return;
        }
        if let Some(a) = self.syn.assign(kind) {
            let a = *a;
            self.scan_assign(node, &a, ops);
            return;
        }
        if self.syn.statement_wrappers.contains(&kind) {
            for ch in named_children(node) {
                self.scan_node(ch, ops);
            }
            return;
        }
        // Declarations that carry an initialiser but are not in `assigns`
        // (C `declaration`, Java/C# local declarations, Go `var_declaration`)
        // hold declarators the scanner knows.
        if matches!(kind, "declaration" | "local_variable_declaration" | "local_declaration_statement" | "variable_declaration" | "var_declaration" | "lexical_declaration" | "field_declaration") {
            for ch in named_children(node) {
                self.scan_node(ch, ops);
            }
            return;
        }
        if kind == "var_spec_list" || kind == "expression_list" {
            for ch in named_children(node) {
                self.scan_node(ch, ops);
            }
            return;
        }
        // Rust `if let`, `while let`: the pattern binds from the value.
        // Anything else: evaluate for its calls; leaves flow nowhere.
        let _ = self.leaves(node, ops);
    }

    fn scan_assign(&mut self, node: Node<'a>, a: &Assign, ops: &mut Vec<Op>) {
        let Some(lhs) = self.assign_left(node, a) else { return };
        let rhs = self.assign_right(node, a);
        if let Some(r) = rhs
            && let Some(c) = self.syn.closure(r.kind())
            && self.syn.is_var_ref(lhs.kind())
        {
            let params: Vec<String> = self.closure_params(r, c).into_iter().map(|(n, _)| n).collect();
            self.closure_locals.insert(text(lhs, self.source).to_string(), params);
        }
        let mut sources = rhs.map(|r| self.leaves(r, ops)).unwrap_or_default();
        let targets = self.targets_of(lhs, ops);
        let line = line_of(node);
        // Positional lists (Go `a, b := f(), g()`; Python tuples): equal
        // lengths pair up, anything else gives every target every source.
        let rhs_items: Vec<Node<'a>> = rhs
            .filter(|r| matches!(r.kind(), "expression_list" | "tuple" | "array" | "expression_statement"))
            .map(named_children)
            .unwrap_or_default();
        let lhs_items: Vec<Node<'a>> = if matches!(lhs.kind(), "expression_list" | "pattern_list" | "tuple_pattern" | "left_assignment_list") {
            named_children(lhs)
        } else {
            Vec::new()
        };
        if !lhs_items.is_empty() && lhs_items.len() == rhs_items.len() && lhs_items.len() > 1 {
            for (l, r) in lhs_items.iter().zip(&rhs_items) {
                let srcs = self.leaves(*r, ops);
                for (t, weak) in self.targets_of(*l, ops) {
                    let mut s = srcs.clone();
                    if a.augmented { s.extend(self.target_as_src(&t)); }
                    ops.push(Op::Def { target: t, sources: s, weak, line });
                }
            }
            return;
        }
        for (t, weak) in targets {
            if a.augmented {
                sources.extend(self.target_as_src(&t));
            }
            // `p.x = v` / `p[i] = v` on a parameter mutates the caller's
            // object. The graph has no by-reference return, so the value is
            // treated as returned: sound, and what lets `strcpy(buf, x)` in
            // a callee reach the caller's `buf`.
            if weak
                && let Target::Local(name) = &t
                && self.params.iter().any(|(p, _)| p == name)
            {
                ops.push(Op::Return { sources: sources.clone(), line });
            }
            ops.push(Op::Def { target: t, sources: sources.clone(), weak, line });
        }
    }

    fn target_as_src(&self, t: &Target) -> Vec<Src> {
        match t {
            Target::Local(n) => vec![Src::Local(n.clone())],
            Target::NonLocal(n, s) => vec![Src::NonLocal(n.clone(), *s)],
        }
    }

    /// The targets an assignment writes, and whether each is weak.
    fn targets_of(&mut self, lhs: Node<'a>, _ops: &mut Vec<Op>) -> Vec<(Target, bool)> {
        let mut out = Vec::new();
        let mut stack = vec![(lhs, false)];
        while let Some((n, weak)) = stack.pop() {
            let kind = n.kind();
            if let Some(m) = self.syn.member(kind) {
                // `self.x = …` writes a field; `obj.x = …` mutates `obj`.
                let obj = field(n, m.object_field);
                let member = field(n, m.member_field);
                match (obj, member) {
                    (Some(o), Some(mem)) if self.is_self_node(o) => {
                        out.push((Target::NonLocal(text(mem, self.source).to_string(), true), false));
                    }
                    (Some(o), _) => {
                        for (t, _) in self.targets_of(o, _ops) {
                            out.push((t, true));
                        }
                    }
                    _ => {}
                }
                continue;
            }
            if let Some((_, obj_field)) = self.syn.subscript(kind) {
                let obj = if obj_field.is_empty() { n.named_child(0) } else { field(n, obj_field) };
                if let Some(o) = obj {
                    for (t, _) in self.targets_of(o, _ops) {
                        out.push((t, true));
                    }
                }
                continue;
            }
            if self.syn.is_var_ref(kind) {
                let t = text(n, self.source);
                if self.syn.is_self(t) || self.receiver_var.as_deref() == Some(t) {
                    continue;
                }
                let target = self.classify(t, kind);
                out.push((target, weak));
                continue;
            }
            if self.syn.unwrap.contains(&kind) {
                if let Some(ch) = n.named_child(0) {
                    stack.push((ch, weak));
                }
                continue;
            }
            if let Some(d) = field(n, "declarator") {
                stack.push((d, weak));
                continue;
            }
            if kind == "pair_pattern" || kind == "keyed_element" {
                if let Some(v) = field(n, "value") {
                    stack.push((v, true));
                }
                continue;
            }
            // Patterns, tuples, lists: every binding, weakly when the shape is
            // not a plain sequence.
            let kids = named_children(n);
            let plain = matches!(kind, "expression_list" | "pattern_list" | "tuple_pattern" | "left_assignment_list" | "mut_pattern");
            for k in kids.into_iter().rev() {
                stack.push((k, weak || !plain));
            }
        }
        out
    }

    fn is_self_node(&self, n: Node<'a>) -> bool {
        let t = text(n, self.source);
        self.syn.is_self(t) || self.receiver_var.as_deref() == Some(t) || n.kind() == "self" || n.kind() == "this"
    }

    /// A bare name is a local if it is bound anywhere in this body, else a
    /// non-local. Ruby's sigils decide directly.
    fn classify(&self, name: &str, kind: &str) -> Target {
        match kind {
            "instance_variable" | "class_variable" => {
                Target::NonLocal(name.trim_start_matches('@').to_string(), true)
            }
            "global_variable" => Target::NonLocal(name.trim_start_matches('$').to_string(), false),
            "constant" => Target::NonLocal(name.to_string(), false),
            _ if self.locals.contains(name) => Target::Local(name.to_string()),
            _ => Target::NonLocal(name.to_string(), false),
        }
    }

    fn classify_src(&self, name: &str, kind: &str) -> Src {
        match self.classify(name, kind) {
            Target::Local(n) => Src::Local(n),
            Target::NonLocal(n, s) => Src::NonLocal(n, s),
        }
    }

    /// The sources an expression yields, registering any calls inside it.
    fn leaves(&mut self, node: Node<'a>, ops: &mut Vec<Op>) -> Vec<Src> {
        let mut out = Vec::new();
        self.leaves_into(node, ops, &mut out, false);
        out
    }

    fn leaves_into(&mut self, node: Node<'a>, ops: &mut Vec<Op>, out: &mut Vec<Src>, in_closure: bool) {
        let kind = node.kind();
        if self.is_def_node(node) || self.syn.is_literal(kind) {
            return;
        }
        if self.syn.is_var_ref(kind) {
            let t = text(node, self.source);
            if self.syn.is_self(t) || self.receiver_var.as_deref() == Some(t) || kind == "self" || kind == "this" {
                return;
            }
            let src = self.classify_src(t, kind);
            out.push(match (src, in_closure) {
                (Src::Local(n), true) => Src::LocalAny(n),
                (s, _) => s,
            });
            return;
        }
        if let Some(m) = self.syn.member(kind) {
            let obj = field(node, m.object_field);
            let member = field(node, m.member_field);
            // Ruby: `a.b`, `a.b(args)` and `a.b { … }` are all `call`. With
            // arguments or a block it is a call; bare `a.b` reads through to
            // its receiver.
            if self.cfg.is_call(kind)
                && (field(node, self.syn.args_field).is_some() || field(node, "block").is_some())
            {
                self.scan_call(node, ops, out, in_closure);
                return;
            }
            match (obj, member) {
                (Some(o), Some(mem)) if self.is_self_node(o) => {
                    out.push(Src::NonLocal(text(mem, self.source).to_string(), true));
                }
                (Some(o), Some(mem)) if self.syn.is_var_ref(o.kind()) && !self.locals.contains(text(o, self.source)) => {
                    // `lib.MAX` — a member of something that is not a local:
                    // an imported module's variable, a type's static. The
                    // resolver splits the dotted name against the file's
                    // imports; the object itself is read too, so a package
                    // used as a value is still a reference to the package.
                    let (o_text, m_text) = (text(o, self.source), text(mem, self.source));
                    if !self.syn.is_self(o_text) {
                        out.push(Src::NonLocal(format!("{o_text}.{m_text}"), false));
                    }
                    self.leaves_into(o, ops, out, in_closure);
                }
                (Some(o), _) => self.leaves_into(o, ops, out, in_closure),
                (None, Some(mem)) if self.cfg.is_call(kind) => {
                    // Ruby bare `foo` command call without receiver.
                    let _ = mem;
                    self.scan_call(node, ops, out, in_closure);
                }
                _ => {}
            }
            return;
        }
        if self.cfg.is_call(kind) {
            self.scan_call(node, ops, out, in_closure);
            return;
        }
        if let Some((_, obj_field)) = self.syn.subscript(kind) {
            let obj = if obj_field.is_empty() { node.named_child(0) } else { field(node, obj_field) };
            if let Some(o) = obj {
                self.leaves_into(o, ops, out, in_closure);
            }
            return;
        }
        if let Some(c) = self.syn.closure(kind) {
            let c = *c;
            self.scan_closure(node, &c, ops, out, None);
            return;
        }
        if let Some(a) = self.syn.assign(kind) {
            // An assignment used as an expression (`x = y = z`, walrus).
            let a = *a;
            self.scan_assign(node, &a, ops);
            if let Some(lhs) = self.assign_left(node, &a) {
                self.leaves_into(lhs, ops, out, in_closure);
            }
            return;
        }
        for ch in named_children(node) {
            self.leaves_into(ch, ops, out, in_closure);
        }
    }

    fn scan_call(&mut self, node: Node<'a>, ops: &mut Vec<Op>, out: &mut Vec<Src>, in_closure: bool) {
        let Some((callee, mut receiver)) = self.callee_of(node) else {
            for ch in named_children(node) {
                self.leaves_into(ch, ops, out, in_closure);
            }
            return;
        };
        if let (Some(r), Some(rv)) = (receiver.as_deref(), self.receiver_var.as_deref())
            && r == rv
        {
            receiver = Some("self".to_string());
        }
        let line = line_of(node);
        let idx = self.out.calls.len() as u32;
        self.out.calls.push(RawCall {
            caller: self.function_idx_for_calls,
            callee: callee.clone(),
            receiver: receiver.clone(),
            line,
            summarised: false,
            external: false,
        });

        // The receiver's value flows into the call too (a method sees its
        // object), and an unresolved call may write through it.
        let target = node
            .child_by_field_name(self.cfg.callee_field)
            .or_else(|| node.named_child(0));
        let mut receiver_srcs = Vec::new();
        // The receiver's node, for a summary that writes through it.
        let mut recv_node: Option<Node<'a>> = None;
        // Ruby (`receiver`) and Java (`object`) keep the receiver in its own
        // field rather than inside the callee expression.
        if let Some(r) = field(node, "receiver").or_else(|| field(node, "object")) {
            recv_node = Some(r);
            if !self.is_self_node(r) {
                self.leaves_into(r, ops, &mut receiver_srcs, in_closure);
            }
        } else if let Some(t) = target
            && !self.syn.is_var_ref(t.kind())
        {
            // A member callee: its object is the receiver value. Read the
            // object's leaves without treating the member as a variable.
            if let Some(m) = self.syn.member(t.kind()) {
                if let Some(o) = field(t, m.object_field) {
                    recv_node = Some(o);
                    if !self.is_self_node(o) {
                        self.leaves_into(o, ops, &mut receiver_srcs, in_closure);
                    }
                }
            } else {
                self.leaves_into(t, ops, &mut receiver_srcs, in_closure);
            }
        }

        let mut args: Vec<(ArgPos, Vec<Src>)> = Vec::new();
        let mut arg_nodes: Vec<(ArgPos, Node<'a>)> = Vec::new();
        let mut all_arg_srcs: Vec<Src> = receiver_srcs.clone();
        let mut closure_args: Vec<Node<'a>> = Vec::new();
        let mut by_ref: Vec<String> = Vec::new();
        if let Some(list) = field(node, self.syn.args_field) {
            let mut pos = 0u32;
            for arg in named_children(list) {
                let (pos_key, value) = match self.syn.keyword_arg {
                    Some(k) if k.node == arg.kind() => {
                        let name = field(arg, k.name_field).map(|n| text(n, self.source).trim_end_matches(':').to_string());
                        let value = if k.value_field.is_empty() {
                            named_children(arg).into_iter().next_back()
                        } else {
                            field(arg, k.value_field)
                        };
                        match name {
                            Some(n) => (ArgPos::Name(n), value),
                            None => {
                                let p = ArgPos::Index(pos);
                                pos += 1;
                                (p, value)
                            }
                        }
                    }
                    _ => {
                        let p = ArgPos::Index(pos);
                        pos += 1;
                        (p, Some(arg))
                    }
                };
                let Some(value) = value else { continue };
                // By-reference: `&x`, `ref x`, `out x`.
                let is_ref = self.syn.by_ref_args.contains(&value.kind())
                    && text(value, self.source).starts_with('&')
                    || (arg.kind() == "argument"
                        && arg.child(0).is_some_and(|c| matches!(text(c, self.source), "ref" | "out")));
                let mut srcs = Vec::new();
                if self.syn.closure(value.kind()).is_some() {
                    closure_args.push(value);
                } else {
                    self.leaves_into(value, ops, &mut srcs, in_closure);
                }
                if is_ref {
                    for name in self.binding_names(value) {
                        self.no_atoms.insert(name.clone());
                        by_ref.push(name);
                    }
                }
                all_arg_srcs.extend(srcs.iter().cloned());
                arg_nodes.push((pos_key.clone(), value));
                args.push((pos_key, srcs));
            }
        }
        // Ruby: a trailing block is an implicit closure argument.
        if let Some(b) = field(node, "block")
            && self.syn.closure(b.kind()).is_some()
        {
            closure_args.push(b);
        }
        // A call through a local that holds a closure: its arguments define
        // the closure's parameters (weakly — the closure may never run).
        if receiver.is_none()
            && let Some(cparams) = self.closure_locals.get(&callee).cloned()
        {
            for (i, pname) in cparams.iter().enumerate() {
                let sources: Vec<Src> = args
                    .iter()
                    .find(|(p, _)| *p == ArgPos::Index(i as u32))
                    .map(|(_, s)| s.clone())
                    .unwrap_or_default();
                ops.push(Op::Def { target: Target::Local(pname.clone()), sources, weak: true, line });
            }
        }
        // A library summary, when the table knows this call: which inputs
        // reach the result and what is written, instead of the default
        // "everything may reach everything".
        // Ruby and Java keep the receiver beside the callee rather than in
        // it, so `receiver` (the callee's own qualifier) may be empty while
        // the node is there.
        let recv_text: Option<String> =
            receiver.clone().or_else(|| recv_node.map(|n| text(n, self.source).to_string()));
        let qualifier = recv_text.as_deref().filter(|r| !self.syn.is_self(r) && is_dotted_name(r));
        let summary = summaries::lookup(self.cfg.name, qualifier, recv_text.is_some(), &callee);
        let mut summary_result: Vec<Src> = Vec::new();
        let mut summary_writes: Vec<(Target, Vec<Src>)> = Vec::new();
        if let Some(sm) = summary {
            let slot_srcs = |slot: &Slot| -> Vec<Src> {
                match slot {
                    Slot::Recv => receiver_srcs.clone(),
                    Slot::Arg(i) => args
                        .iter()
                        .find(|(p, _)| *p == ArgPos::Index(u32::from(*i)))
                        .map(|(_, s)| s.clone())
                        .unwrap_or_default(),
                    Slot::Rest(i) => args
                        .iter()
                        .filter(|(p, _)| !matches!(p, ArgPos::Index(k) if *k < u32::from(*i)))
                        .flat_map(|(_, s)| s.iter().cloned())
                        .collect(),
                    Slot::Ext => vec![Src::CallResult(idx)],
                }
            };
            for slot in sm.result {
                summary_result.extend(slot_srcs(slot));
            }
            for (target, from) in sm.writes {
                let sources: Vec<Src> = from.iter().flat_map(&slot_srcs).collect();
                let nodes: Vec<Node<'a>> = match target {
                    Slot::Recv => recv_node.into_iter().collect(),
                    Slot::Arg(i) => arg_nodes
                        .iter()
                        .filter(|(p, _)| *p == ArgPos::Index(u32::from(*i)))
                        .map(|(_, n)| *n)
                        .collect(),
                    Slot::Rest(i) => arg_nodes
                        .iter()
                        .filter(|(p, _)| !matches!(p, ArgPos::Index(k) if *k < u32::from(*i)))
                        .map(|(_, n)| *n)
                        .collect(),
                    Slot::Ext => Vec::new(),
                };
                for n in nodes {
                    // `&v`, `ref v`: the written thing is `v`.
                    let n = if self.syn.by_ref_args.contains(&n.kind()) && text(n, self.source).starts_with('&') {
                        n.named_child(0).unwrap_or(n)
                    } else {
                        n
                    };
                    for (t, _) in self.targets_of(n, ops) {
                        summary_writes.push((t, sources.clone()));
                    }
                }
            }
            let call = &mut self.out.calls[idx as usize];
            call.summarised = true;
            call.external = sm.external();
        }

        args.push((ArgPos::Index(u32::MAX), receiver_srcs.clone()));
        // Locals passed positionally, for the weak definitions below.
        let passed_locals: Vec<String> = args
            .iter()
            .flat_map(|(_, srcs)| srcs.iter())
            .filter_map(|s| if let Src::Local(n) = s { Some(n.clone()) } else { None })
            .collect();
        ops.push(Op::Args { call: idx, args, line });

        // A callback's parameters receive the receiver and the other
        // arguments; its body is scanned with the enclosing locals in scope.
        for c in closure_args {
            let cc = *self.syn.closure(c.kind()).expect("closure");
            let mut dummy = Vec::new();
            self.scan_closure(c, &cc, ops, &mut dummy, Some(&all_arg_srcs));
        }
        // Weak definitions for locals the callee may have written through.
        let mut written: Vec<String> = by_ref;
        if let Some(r) = target
            && let Some(m) = self.syn.member(r.kind())
            && let Some(o) = field(r, m.object_field)
            && self.syn.is_var_ref(o.kind())
        {
            let t = text(o, self.source);
            if self.locals.contains(t) {
                written.push(t.to_string());
            }
        }
        // A plain local passed positionally to any call may be written
        // through in languages with reference semantics; the resolver
        // cannot tell, and neither can this. Weak, so it costs nothing when
        // it does not happen.
        if matches!(self.cfg.name, "c" | "cpp" | "go" | "rust" | "csharp") {
            written.extend(passed_locals);
        }
        written.sort();
        written.dedup();
        // The weak definition carries only the call's result. The arguments
        // reach it through the callee — a stub's in- and out-edges share a
        // call-site tag, a resolved callee's mutated parameters flow to its
        // return — so listing them here too would make every local carry
        // every argument of every call, which on a 2,000-statement function
        // measured as a million facts.
        for name in written {
            // `&global` written through a call is a write to the global.
            let target = self.classify(&name, "identifier");
            ops.push(Op::Def { target, sources: vec![Src::CallResult(idx)], weak: true, line });
        }
        // What a summary says is written, from what — precise where the
        // rule above is not.
        for (target, sources) in summary_writes {
            ops.push(Op::Def { target, sources, weak: true, line });
        }
        // The result is the call's. What flows *through* an unknown callee
        // (`y = decode(x)`) is the resolver's business: it tags the edges into
        // and out of the stub with this call site, so a search can pass
        // through the stub without joining every caller to every other. A
        // summarised call adds the inputs its summary says reach the result
        // — and the resolver then keeps the stub from standing for the rest.
        // `CallResult` stays regardless: the callee may resolve to a corpus
        // function after all, whose return is this value.
        out.extend(summary_result);
        out.push(Src::CallResult(idx));
    }

    fn scan_closure(
        &mut self,
        node: Node<'a>,
        c: &crate::syntax::Closure,
        ops: &mut Vec<Op>,
        out: &mut Vec<Src>,
        param_sources: Option<&Vec<Src>>,
    ) {
        let line = line_of(node);
        for (name, _) in self.closure_params(node, c) {
            let sources = param_sources.cloned().unwrap_or_default();
            ops.push(Op::Def { target: Target::Local(name), sources, weak: true, line });
        }
        let body = if c.body_field.is_empty() {
            named_children(node).into_iter().last()
        } else {
            field(node, c.body_field)
        };
        if let Some(b) = body {
            // Flow-insensitive inside: statements are scanned in order into
            // the current block's ops, but captured locals read every def.
            self.scan_closure_body(b, ops, out);
        }
    }

    fn scan_closure_body(&mut self, node: Node<'a>, ops: &mut Vec<Op>, out: &mut Vec<Src>) {
        let kind = node.kind();
        if self.is_def_node(node) {
            return;
        }
        if let Some(a) = self.syn.assign(kind) {
            let a = *a;
            // Definitions inside a closure are weak: the closure may not run.
            let Some(lhs) = self.assign_left(node, &a) else { return };
            let mut sources = Vec::new();
            if let Some(r) = self.assign_right(node, &a) {
                self.leaves_into(r, ops, &mut sources, true);
            }
            for (t, _) in self.targets_of(lhs, ops) {
                if let Target::Local(name) = &t {
                    self.no_atoms.insert(name.clone());
                }
                ops.push(Op::Def { target: t, sources: sources.clone(), weak: true, line: line_of(node) });
            }
            return;
        }
        if self.syn.jumps.return_.contains(&kind) {
            // A closure's return is its value: the closure expression's leaves.
            if let Some(v) = node.named_child(0) {
                self.leaves_into(v, ops, out, true);
            }
            return;
        }
        if self.cfg.is_call(kind) || self.syn.member(kind).is_some() || self.syn.is_var_ref(kind) {
            self.leaves_into(node, ops, out, true);
            return;
        }
        for ch in named_children(node) {
            self.scan_closure_body(ch, ops, out);
        }
    }

    /// `(callee, receiver)` for a call node — the same reading `walk.rs`
    /// uses, so the resolver binds these calls exactly as before.
    fn callee_of(&self, node: Node<'a>) -> Option<(String, Option<String>)> {
        let target = node
            .child_by_field_name(self.cfg.callee_field)
            .or_else(|| node.named_child(0))?;
        if self.cfg.ident_kinds.contains(&target.kind()) {
            return Some((text(target, self.source).to_string(), None));
        }
        let last = target.named_child(target.named_child_count().saturating_sub(1) as u32)?;
        if !self.cfg.ident_kinds.contains(&last.kind()) {
            return None;
        }
        let name = text(last, self.source).to_string();
        let receiver = (target.named_child_count() >= 2)
            .then(|| target.named_child(0u32))
            .flatten()
            .map(|r| text(r, self.source).to_string());
        Some((name, receiver))
    }

    // --- reaching definitions ---

    fn reaching_definitions_and_facts(&mut self) {
        // Number every local definition.
        struct DefInfo {
            name: String,
            weak: bool,
            sources: Vec<Src>,
        }
        let mut defs: Vec<DefInfo> = Vec::new();
        // Per block: (op index, def id) for local defs, in op order.
        let mut block_defs: Vec<Vec<(usize, usize)>> = vec![Vec::new(); self.blocks.len()];
        let mut defs_of_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (bi, b) in self.blocks.iter().enumerate() {
            for (oi, op) in b.ops.iter().enumerate() {
                if let Op::Def { target: Target::Local(name), sources, weak, .. } = op {
                    let id = defs.len();
                    defs.push(DefInfo { name: name.clone(), weak: *weak, sources: sources.clone() });
                    block_defs[bi].push((oi, id));
                    defs_of_name.entry(name.clone()).or_default().push(id);
                }
            }
        }
        let n = self.blocks.len();
        let nd = defs.len();
        let words = nd.div_ceil(64).max(1);
        let bit = |v: &mut [u64], i: usize| v[i / 64] |= 1 << (i % 64);
        let has = |v: &[u64], i: usize| v[i / 64] & (1 << (i % 64)) != 0;

        // GEN/KILL per block, from a sequential pass.
        let mut gen_ = vec![vec![0u64; words]; n];
        let mut kill = vec![vec![0u64; words]; n];
        for bi in 0..n {
            for &(_, id) in &block_defs[bi] {
                let d = &defs[id];
                if !d.weak {
                    for &other in &defs_of_name[&d.name] {
                        if other != id {
                            bit(&mut kill[bi], other);
                            gen_[bi][other / 64] &= !(1 << (other % 64));
                        }
                    }
                }
                bit(&mut gen_[bi], id);
            }
        }
        // Incoming edges per block: `(predecessor, atoms the edge establishes)`.
        let mut preds: Vec<Vec<(usize, Ids)>> = vec![Vec::new(); n];
        for (bi, b) in self.blocks.iter().enumerate() {
            for e in &b.succ {
                preds[e.to].push((bi, e.atoms));
            }
        }
        // The locals each block defines: a definition of `v` invalidates
        // every atom about `v`, whether it kills or not.
        let block_def_names: Vec<HashSet<&str>> = (0..n)
            .map(|bi| block_defs[bi].iter().map(|&(_, id)| defs[id].name.as_str()).collect())
            .collect();
        // In a language where a value's truth or equality can change under
        // it — a Python list emptied by a callee that shares it, an object
        // with its own `__eq__`, a JavaScript object coerced — a call can
        // change what an atom says without any definition the analysis
        // sees. There, a call invalidates every atom about a local that
        // could hold such a value: everything but the *scalars*, locals
        // whose every definition is built from literals and other scalars.
        // `found = False … found = True` is a scalar; a parameter never is.
        let invalidate_on_call = matches!(self.cfg.name, "python" | "ruby" | "javascript" | "typescript" | "tsx");
        let mut scalar: HashSet<String> = defs_of_name.keys().cloned().collect();
        let mut settled = false;
        while !settled {
            settled = true;
            let names: Vec<String> = scalar.iter().cloned().collect();
            for name in names {
                let ok = defs_of_name[&name].iter().all(|&d| {
                    defs[d].sources.iter().all(|src| match src {
                        Src::Local(m) | Src::LocalAny(m) => !m.starts_with("\0param:") && scalar.contains(m),
                        _ => false,
                    })
                });
                if !ok {
                    scalar.remove(&name);
                    settled = false;
                }
            }
        }
        let has_call: Vec<bool> =
            (0..n).map(|bi| self.blocks[bi].ops.iter().any(|op| matches!(op, Op::Args { .. }))).collect();
        let table = &self.atom_table;
        let clashes = Clashes::build(table);
        let drop_about = |atoms: &Ids, bi: usize| -> Ids {
            let names = &block_def_names[bi];
            let calls = invalidate_on_call && has_call[bi];
            if names.is_empty() && !calls {
                return *atoms;
            }
            atoms.retain(|a| table[a as usize].var().is_none_or(|v| !names.contains(v) && (!calls || scalar.contains(v))))
        };
        let any_atoms = preds.iter().flatten().any(|(_, a)| !a.is_empty());

        // The fixpoint. Per block: which definitions reach (a bitset), the
        // atoms each reaching definition is known to hold under (only the
        // conditional ones are stored), and the block's own path condition —
        // the atoms that hold on entry however control arrived, which a
        // definition made in the block starts out carrying.
        //
        // Along an edge every fact picks up the edge's atoms and is dropped
        // if they contradict; at a join a fact arriving from several edges
        // keeps only the atoms all of them agree on. Sets only ever shrink
        // at joins and facts only ever appear, so the iteration ascends and
        // stops. Everything here is monotone in the sound direction: fewer
        // atoms is a weaker fact, and a weaker fact reaches more.
        let mut inn = vec![vec![0u64; words]; n];
        let mut outv = vec![vec![0u64; words]; n];
        let mut cond_in: Vec<HashMap<usize, Ids>> = vec![HashMap::new(); n];
        let mut cond_out: Vec<HashMap<usize, Ids>> = vec![HashMap::new(); n];
        // The keys of `cond_out`, as a bitset, so an edge that establishes
        // nothing can pass the unconditional facts through word-wise.
        let mut cond_keys: Vec<Vec<u64>> = vec![vec![0u64; words]; n];
        let mut pc_in: Vec<Option<Ids>> = vec![None; n];
        let mut pc_out: Vec<Option<Ids>> = vec![None; n];
        pc_in[0] = Some(Ids::default());
        let mut changed = true;
        let mut rounds = 0;
        while changed && rounds < 10_000 {
            changed = false;
            rounds += 1;
            for bi in 0..n {
                let mut i = vec![0u64; words];
                if !any_atoms {
                    // No edge establishes anything: plain reaching
                    // definitions, word-wise.
                    for (p, _) in &preds[bi] {
                        for w in 0..words {
                            i[w] |= outv[*p][w];
                        }
                    }
                    let mut o = vec![0u64; words];
                    for w in 0..words {
                        o[w] = gen_[bi][w] | (i[w] & !kill[bi][w]);
                    }
                    if o != outv[bi] || i != inn[bi] {
                        changed = true;
                    }
                    inn[bi] = i;
                    outv[bi] = o;
                    continue;
                }
                let mut ci: HashMap<usize, Ids> = HashMap::new();
                // Defs that arrived unconditionally from some edge: whatever
                // the other edges say, nothing is assumed about them here.
                let mut uncond: Vec<u64> = vec![0u64; words];
                let mut pc: Option<Ids> = if bi == 0 { Some(Ids::default()) } else { None };
                let arrive = |d: usize, atoms: Ids, ci: &mut HashMap<usize, Ids>, uncond: &mut Vec<u64>| {
                    if uncond[d / 64] & (1 << (d % 64)) != 0 {
                        return;
                    }
                    if atoms.is_empty() {
                        uncond[d / 64] |= 1 << (d % 64);
                        ci.remove(&d);
                        return;
                    }
                    match ci.get(&d) {
                        None => {
                            ci.insert(d, atoms);
                        }
                        Some(cur) => {
                            let both = intersect(cur, &atoms);
                            if both.is_empty() {
                                uncond[d / 64] |= 1 << (d % 64);
                                ci.remove(&d);
                            } else {
                                ci.insert(d, both);
                            }
                        }
                    }
                };
                for (p, edge_atoms) in &preds[bi] {
                    // The path condition along this edge.
                    let Some(ppc) = &pc_out[*p] else { continue };
                    let epc = conjoin(ppc, edge_atoms);
                    if clashes.contradictory(&epc) {
                        continue;
                    }
                    pc = Some(match pc {
                        None => epc,
                        Some(cur) => intersect(&cur, &epc),
                    });
                    if edge_atoms.is_empty() {
                        // Nothing to add: unconditional facts stay so, the
                        // conditional ones arrive as they are.
                        for w in 0..words {
                            i[w] |= outv[*p][w];
                            uncond[w] |= outv[*p][w] & !cond_keys[*p][w];
                        }
                        for (d, a) in &cond_out[*p] {
                            arrive(*d, *a, &mut ci, &mut uncond);
                        }
                        continue;
                    }
                    for (w, &word) in outv[*p].iter().enumerate() {
                        let mut bits = word;
                        while bits != 0 {
                            let d = w * 64 + bits.trailing_zeros() as usize;
                            bits &= bits - 1;
                            let atoms = match cond_out[*p].get(&d) {
                                None => *edge_atoms,
                                Some(a) => conjoin(a, edge_atoms),
                            };
                            if clashes.contradictory(&atoms) {
                                continue;
                            }
                            i[d / 64] |= 1 << (d % 64);
                            arrive(d, atoms, &mut ci, &mut uncond);
                        }
                    }
                }
                // A def that arrived unconditionally somewhere holds nothing.
                ci.retain(|d, _| uncond[d / 64] & (1 << (d % 64)) == 0);
                let mut o = vec![0u64; words];
                for w in 0..words {
                    o[w] = gen_[bi][w] | (i[w] & !kill[bi][w]);
                }
                let mut co: HashMap<usize, Ids> = HashMap::new();
                for (d, atoms) in &ci {
                    if o[d / 64] & (1 << (d % 64)) != 0 && gen_[bi][d / 64] & (1 << (d % 64)) == 0 {
                        let kept = drop_about(atoms, bi);
                        if !kept.is_empty() {
                            co.insert(*d, kept);
                        }
                    }
                }
                let opc = pc.as_ref().map(|p| drop_about(p, bi));
                // A definition made here starts out under the block's path
                // condition. A weak one that also arrived from before is two
                // instances of one definition, and keeps what both hold under.
                let fresh: Ids = opc.unwrap_or_default();
                for &(_, d) in &block_defs[bi] {
                    if o[d / 64] & (1 << (d % 64)) == 0 {
                        continue;
                    }
                    let atoms = if defs[d].weak && i[d / 64] & (1 << (d % 64)) != 0 {
                        let old = ci.get(&d).map(|a| drop_about(a, bi)).unwrap_or_default();
                        intersect(&old, &fresh)
                    } else {
                        fresh
                    };
                    if atoms.is_empty() {
                        co.remove(&d);
                    } else {
                        co.insert(d, atoms);
                    }
                }
                let mut ck = vec![0u64; words];
                for d in co.keys() {
                    ck[d / 64] |= 1 << (d % 64);
                }
                if o != outv[bi] || i != inn[bi] || co != cond_out[bi] || ci != cond_in[bi] || pc != pc_in[bi] || opc != pc_out[bi] {
                    changed = true;
                }
                inn[bi] = i;
                outv[bi] = o;
                cond_in[bi] = ci;
                cond_out[bi] = co;
                cond_keys[bi] = ck;
                pc_in[bi] = pc;
                pc_out[bi] = opc;
            }
        }

        // --- origins ---
        //
        // Which non-local values each definition carries is a fixpoint over
        // the definitions, not a recursion from each use: a definition reads
        // its locals at *its own* point, and `x = f(a); y = g(x, x)` must not
        // expand `x` twice — on a chain of such lines the recursion is
        // exponential.
        //
        // `reads[d]`: the definitions of the locals `d` reads, as they reach
        // `d`'s own op. `direct[d]`: `d`'s non-local sources.
        let mut reads: Vec<Vec<usize>> = vec![Vec::new(); nd];
        let mut direct: Vec<Vec<FlowNode>> = vec![Vec::new(); nd];
        // Sinks: (block, op) with the defs reaching each of their local reads.
        struct Sink {
            block: usize,
            op: usize,
            reads: Vec<usize>,
            direct: Vec<FlowNode>,
        }
        let mut sinks: Vec<Sink> = Vec::new();
        let params = &self.params;
        let resolve_srcs = |srcs: &[Src], reaching: &[u64], reads: &mut Vec<usize>, direct: &mut Vec<FlowNode>| {
            for s in srcs {
                match s {
                    Src::NonLocal(name, sf) => direct.push(FlowNode::NonLocal(name.clone(), *sf)),
                    Src::CallResult(k) => direct.push(FlowNode::CallResult(*k)),
                    Src::Local(name) if name.starts_with("\0param:") => {
                        let pname = &name["\0param:".len()..];
                        if let Some((_, idx)) = params.iter().find(|(n, _)| n == pname) {
                            direct.push(FlowNode::Param(*idx));
                        }
                    }
                    Src::Local(name) => {
                        if let Some(ids) = defs_of_name.get(name) {
                            reads.extend(ids.iter().copied().filter(|&id| has(reaching, id)));
                        }
                    }
                    Src::LocalAny(name) => {
                        if let Some(ids) = defs_of_name.get(name) {
                            reads.extend(ids.iter().copied());
                        }
                    }
                }
            }
        };
        let mut refs: HashSet<(String, bool)> = HashSet::new();
        let mut block_defines: Vec<Vec<(String, bool)>> = vec![Vec::new(); n];
        let mut block_uses: Vec<Vec<(String, bool)>> = vec![Vec::new(); n];
        let mut block_local_defines: Vec<Vec<String>> = vec![Vec::new(); n];
        let mut block_local_uses: Vec<Vec<String>> = vec![Vec::new(); n];
        let is_param_src = |name: &str| name.starts_with("\0param:");
        for bi in 0..n {
            let mut reaching = inn[bi].clone();
            let mut next_def = 0usize;
            for (oi, op) in self.blocks[bi].ops.iter().enumerate() {
                let note_uses = |srcs: &[Src], refs: &mut HashSet<(String, bool)>, uses: &mut Vec<(String, bool)>| {
                    for s in srcs {
                        if let Src::NonLocal(nm, sf) = s {
                            refs.insert((nm.clone(), *sf));
                            uses.push((nm.clone(), *sf));
                        }
                    }
                };
                // Locals read by this op, for the stored CFG.
                let mut note_local_uses = |srcs: &[Src]| {
                    for s in srcs {
                        if let Src::Local(nm) | Src::LocalAny(nm) = s
                            && !is_param_src(nm)
                        {
                            block_local_uses[bi].push(nm.clone());
                        }
                    }
                };
                match op {
                    Op::Def { target, sources, .. } => {
                        note_local_uses(sources);
                        if let Target::Local(nm) = target {
                            block_local_defines[bi].push(nm.clone());
                        }
                    }
                    Op::Args { args, .. } => {
                        for (_, srcs) in args {
                            note_local_uses(srcs);
                        }
                    }
                    Op::Return { sources, .. } => note_local_uses(sources),
                }
                match op {
                    Op::Def { target: Target::Local(_), sources, weak, .. } => {
                        note_uses(sources, &mut refs, &mut block_uses[bi]);
                        let (_, id) = block_defs[bi][next_def];
                        next_def += 1;
                        resolve_srcs(sources, &reaching, &mut reads[id], &mut direct[id]);
                        if !*weak {
                            for &other in &defs_of_name[&defs[id].name] {
                                if other != id {
                                    reaching[other / 64] &= !(1 << (other % 64));
                                }
                            }
                        }
                        bit(&mut reaching, id);
                    }
                    Op::Def { target: Target::NonLocal(name, sf), sources, .. } => {
                        note_uses(sources, &mut refs, &mut block_uses[bi]);
                        refs.insert((name.clone(), *sf));
                        block_defines[bi].push((name.clone(), *sf));
                        let mut s = Sink { block: bi, op: oi, reads: Vec::new(), direct: Vec::new() };
                        resolve_srcs(sources, &reaching, &mut s.reads, &mut s.direct);
                        sinks.push(s);
                    }
                    Op::Args { args, .. } => {
                        for (_, srcs) in args {
                            note_uses(srcs, &mut refs, &mut block_uses[bi]);
                        }
                        // One sink per argument position: recorded as the op
                        // plus a per-argument read set, below.
                        for (ai, (_, srcs)) in args.iter().enumerate() {
                            let mut s = Sink { block: bi, op: oi, reads: Vec::new(), direct: Vec::new() };
                            resolve_srcs(srcs, &reaching, &mut s.reads, &mut s.direct);
                            // Encode the argument position in `op` high bits.
                            s.op = oi | (ai << 40);
                            sinks.push(s);
                        }
                    }
                    Op::Return { sources, .. } => {
                        note_uses(sources, &mut refs, &mut block_uses[bi]);
                        let mut s = Sink { block: bi, op: oi, reads: Vec::new(), direct: Vec::new() };
                        resolve_srcs(sources, &reaching, &mut s.reads, &mut s.direct);
                        sinks.push(s);
                    }
                }
            }
        }
        for r in &mut reads {
            r.sort_unstable();
            r.dedup();
        }

        // Fixpoint over bitsets: origins[d] = direct[d] ∪ origins of everything
        // d reads. Origins are interned so a set is a few words and a merge
        // is an OR — the dependency graph is dense (every by-reference weak
        // definition reads every argument), and set-of-struct merging here
        // measured in seconds per function.
        let mut origin_ids: HashMap<FlowNode, usize> = HashMap::new();
        let mut origin_list: Vec<FlowNode> = Vec::new();
        let mut intern = |n: &FlowNode| -> usize {
            if let Some(&i) = origin_ids.get(n) {
                return i;
            }
            let i = origin_list.len();
            origin_ids.insert(n.clone(), i);
            origin_list.push(n.clone());
            i
        };
        let direct_ids: Vec<Vec<usize>> = direct.iter().map(|ds| ds.iter().map(&mut intern).collect()).collect();
        let sink_direct_ids: Vec<Vec<usize>> = sinks.iter().map(|s| s.direct.iter().map(&mut intern).collect()).collect();
        let no = origin_list.len();
        let owords = no.div_ceil(64).max(1);
        let mut origins: Vec<Vec<u64>> = vec![vec![0u64; owords]; nd];
        for (d, ids) in direct_ids.iter().enumerate() {
            for &i in ids {
                origins[d][i / 64] |= 1 << (i % 64);
            }
        }
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); nd];
        for (d, rs) in reads.iter().enumerate() {
            for &r in rs {
                dependents[r].push(d);
            }
        }
        let mut work: Vec<usize> = (0..nd).collect();
        let mut in_work = vec![true; nd];
        while let Some(d) = work.pop() {
            in_work[d] = false;
            let mut merged = origins[d].clone();
            for &r in &reads[d] {
                for w in 0..owords {
                    merged[w] |= origins[r][w];
                }
            }
            if merged != origins[d] {
                origins[d] = merged;
                for &dep in &dependents[d] {
                    if !in_work[dep] {
                        in_work[dep] = true;
                        work.push(dep);
                    }
                }
            }
        }

        // Facts. A function whose facts would exceed the budget is summarised
        // through its own symbol — every origin flows to it, it flows to
        // every sink — which is sound (strictly more paths) and bounded.
        // Generated code and test tables hit this; hand-written functions
        // do not.
        const FACT_BUDGET: usize = 20_000;
        let function = self.function;
        let mut seen: HashSet<(usize, String)> = HashSet::new();
        let mut potential = 0usize;
        for (si, s) in sinks.iter().enumerate() {
            let mut set = vec![0u64; owords];
            for &i in &sink_direct_ids[si] {
                set[i / 64] |= 1 << (i % 64);
            }
            for &r in &s.reads {
                for w in 0..owords {
                    set[w] |= origins[r][w];
                }
            }
            potential += set.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        }
        if potential > FACT_BUDGET {
            let line = self.blocks.first().map_or(0, |b| b.line);
            for o in &origin_list {
                self.out.flows.push(RawFlow { function, source: o.clone(), sink: FlowNode::Return, line });
            }
            let mut sink_seen: HashSet<String> = HashSet::new();
            for s in &sinks {
                let op = &self.blocks[s.block].ops[s.op & 0xFF_FFFF_FFFF];
                let (sink_node, line) = match op {
                    Op::Def { target: Target::NonLocal(name, sf), line, .. } => (FlowNode::NonLocal(name.clone(), *sf), *line),
                    Op::Args { call, args, line } => (FlowNode::Arg(*call, args[s.op >> 40].0.clone()), *line),
                    Op::Return { .. } => continue,
                    _ => continue,
                };
                if sink_seen.insert(format!("{sink_node:?}")) {
                    self.out.flows.push(RawFlow { function, source: FlowNode::Return, sink: sink_node, line });
                }
            }
            self.out.summarised.push(function);
        }
        // The locals themselves: what each is ever assigned (its
        // definitions' origins) and where each is read (the sinks its
        // definitions reach). Flow-insensitive by construction — one name,
        // every definition — and recorded beside the facts, not in them.
        let param_names: HashSet<&str> = self.params.iter().map(|(n, _)| n.as_str()).collect();
        let is_local_row = |name: &str| !param_names.contains(name) && !is_param_src(name);
        if potential <= FACT_BUDGET && function.is_some() {
            let mut seen_in: HashSet<(usize, String)> = HashSet::new();
            for (d, info) in defs.iter().enumerate() {
                if !is_local_row(&info.name) {
                    continue;
                }
                for (i, o) in origin_list.iter().enumerate() {
                    if origins[d][i / 64] & (1 << (i % 64)) != 0 && seen_in.insert((i, info.name.clone())) {
                        self.out.local_flows.push(RawFlow {
                            function,
                            source: o.clone(),
                            sink: FlowNode::Local(info.name.clone()),
                            line: self.blocks[0].line,
                        });
                    }
                }
            }
            let mut seen_out: HashSet<(String, String)> = HashSet::new();
            for s in &sinks {
                let op = &self.blocks[s.block].ops[s.op & 0xFF_FFFF_FFFF];
                let (sink_node, line) = match op {
                    Op::Def { target: Target::NonLocal(name, sf), line, .. } => (FlowNode::NonLocal(name.clone(), *sf), *line),
                    Op::Args { call, args, line } => (FlowNode::Arg(*call, args[s.op >> 40].0.clone()), *line),
                    Op::Return { line, .. } => (FlowNode::Return, *line),
                    _ => continue,
                };
                for &r in &s.reads {
                    let name = &defs[r].name;
                    if is_local_row(name) && seen_out.insert((name.clone(), format!("{sink_node:?}"))) {
                        self.out.local_flows.push(RawFlow {
                            function,
                            source: FlowNode::Local(name.clone()),
                            sink: sink_node.clone(),
                            line,
                        });
                    }
                }
            }
        }
        if let Some(function) = function {
            // One row per local name, at its first definition.
            let mut first_line: HashMap<&str, u32> = HashMap::new();
            for b in &self.blocks {
                for op in &b.ops {
                    if let Op::Def { target: Target::Local(nm), line, .. } = op {
                        let e = first_line.entry(nm.as_str()).or_insert(*line);
                        *e = (*e).min(*line);
                    }
                }
            }
            let mut names: Vec<&String> = self.locals.iter().filter(|l| is_local_row(l)).collect();
            names.sort();
            for name in names {
                let line = first_line.get(name.as_str()).copied().unwrap_or(self.blocks[0].line);
                self.out.locals.push(RawLocal { function, name: name.clone(), line });
            }
        }
        for (si, s) in sinks.iter().enumerate() {
            if potential > FACT_BUDGET {
                break;
            }
            let op = &self.blocks[s.block].ops[s.op & 0xFF_FFFF_FFFF];
            let (sink_node, line) = match op {
                Op::Def { target: Target::NonLocal(name, sf), line, .. } => (FlowNode::NonLocal(name.clone(), *sf), *line),
                Op::Args { call, args, line } => {
                    let ai = s.op >> 40;
                    (FlowNode::Arg(*call, args[ai].0.clone()), *line)
                }
                Op::Return { line, .. } => (FlowNode::Return, *line),
                _ => continue,
            };
            let mut set = vec![0u64; owords];
            for &i in &sink_direct_ids[si] {
                set[i / 64] |= 1 << (i % 64);
            }
            for &r in &s.reads {
                for w in 0..owords {
                    set[w] |= origins[r][w];
                }
            }
            for (i, o) in origin_list.iter().enumerate() {
                if set[i / 64] & (1 << (i % 64)) == 0 {
                    continue;
                }
                if seen.insert((i, format!("{sink_node:?}"))) {
                    self.out.flows.push(RawFlow { function, source: o.clone(), sink: sink_node.clone(), line });
                }
            }
        }
        let mut refs: Vec<(String, bool)> = refs.into_iter().collect();
        refs.sort();
        for (name, self_field) in refs {
            self.out.refs.push(RawRef { function, name, self_field });
        }
        self.block_defines = Some(block_defines);
        self.block_uses = Some(block_uses);
        self.block_local_defines = Some(block_local_defines);
        self.block_local_uses = Some(block_local_uses);
    }

    fn emit_blocks(&mut self) {
        let Some(function) = self.function else { return };
        let defines = self.block_defines.take().unwrap_or_default();
        let uses = self.block_uses.take().unwrap_or_default();
        let ldefines = self.block_local_defines.take().unwrap_or_default();
        let luses = self.block_local_uses.take().unwrap_or_default();
        let param_names: HashSet<&str> = self.params.iter().map(|(n, _)| n.as_str()).collect();
        // Drop unreachable blocks (created after jumps with no predecessor)
        // from the stored CFG; keep indices stable by renumbering.
        let n = self.blocks.len();
        let mut reachable = vec![false; n];
        let mut stack = vec![0usize];
        reachable[0] = true;
        while let Some(b) = stack.pop() {
            for e in &self.blocks[b].succ {
                if !reachable[e.to] {
                    reachable[e.to] = true;
                    stack.push(e.to);
                }
            }
        }
        let mut renum = vec![u32::MAX; n];
        let mut next = 0u32;
        for i in 0..n {
            if reachable[i] {
                renum[i] = next;
                next += 1;
            }
        }
        for (i, b) in self.blocks.iter().enumerate() {
            if !reachable[i] {
                continue;
            }
            let mut d = defines.get(i).cloned().unwrap_or_default();
            let mut u = uses.get(i).cloned().unwrap_or_default();
            d.sort();
            d.dedup();
            u.sort();
            u.dedup();
            let tidy = |v: Option<&Vec<String>>| -> Vec<String> {
                let mut v: Vec<String> = v.cloned().unwrap_or_default().into_iter().filter(|n| !param_names.contains(n.as_str())).collect();
                v.sort();
                v.dedup();
                v
            };
            self.out.blocks.push(RawBlock {
                function,
                index: renum[i],
                line: b.line,
                succ: b.succ.iter().filter(|e| reachable[e.to]).map(|e| (renum[e.to], e.label.text())).collect(),
                defines: d,
                uses: u,
                local_defines: tidy(ldefines.get(i)),
                local_uses: tidy(luses.get(i)),
            });
        }
    }
}

/// An integer literal's value: decimal, `0x`, `0o`, `0b`, with `_`
/// separators and a sign, or nothing for anything else.
fn parse_int(t: &str) -> Option<i64> {
    let t = t.trim().replace('_', "");
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r.to_string()),
        None => (false, t.clone()),
    };
    let body = body.trim_end_matches(['l', 'L', 'u', 'U']);
    let v = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if let Some(o) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
        i64::from_str_radix(o, 8).ok()?
    } else if let Some(b) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
        i64::from_str_radix(b, 2).ok()?
    } else {
        body.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

/// `pkg`, `os.path`, `Foo::Bar` — an identifier chain, not an expression.
fn is_dotted_name(s: &str) -> bool {
    !s.is_empty()
        && s.split(['.', ':'])
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '@'))
}
