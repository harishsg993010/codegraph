//! Per-language syntax for declarations, dataflow, and control flow.
//!
//! Everything the flow analysis needs to know about a language is data here,
//! for the same reason the definition walk is data in [`crate::lang`]: one
//! analysis, written once, cannot drift between languages. Every node kind
//! named in these tables is checked to exist in its grammar by the
//! `every_configured_node_kind_exists_in_its_grammar` test, so a typo is a
//! failing build rather than a silently dead rule.
//!
//! Where a grammar has no field for something, the entry says so with an
//! empty string and the analysis falls back to a positional child. Those
//! fallbacks are the ones most worth reading the grammar for; each is noted.

use codegraph_core::SymbolKind;

/// Where a declaration counts as a stored symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclAt {
    /// Only at file top level (a module-level variable or constant).
    Module,
    /// Only directly inside a type body (a field).
    Type,
    /// Either.
    Either,
}

/// How a declaration decides it is a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstRule {
    /// Never; the kind is what the table says.
    Never,
    /// Always.
    Always,
    /// The *parent* node's `kind` field reads `const` (JavaScript's
    /// `lexical_declaration`).
    ParentKindField,
    /// An enclosing declaration has a modifier/qualifier child whose text is
    /// one of these (Java `static final`, C `const`, C# `const`).
    ModifierText(&'static [&'static str]),
    /// The name is ALL_CAPS (languages without a constant keyword).
    AllCaps,
}

/// A node that declares a named value.
#[derive(Debug, Clone, Copy)]
pub struct VarDecl {
    pub node: &'static str,
    /// Field holding the name; `""` means the declarator/identifier chain is
    /// followed from the node itself (C family) or the node *is* the name.
    pub name_field: &'static str,
    /// Field holding the initialiser; `""` means an unnamed expression child
    /// (C#'s `variable_declarator`) or no initialiser.
    pub value_field: &'static str,
    pub kind: SymbolKind,
    pub at: DeclAt,
    pub constness: ConstRule,
    /// Ruby: only when the name node is of this kind (`constant`,
    /// `instance_variable`, …); `""` = any.
    pub name_kind: &'static str,
}

/// An assignment or local declaration inside a body: a definition site.
#[derive(Debug, Clone, Copy)]
pub struct Assign {
    pub node: &'static str,
    /// Field of the target(s); `""` = the node's declarator chain / child 0.
    pub left: &'static str,
    /// Field of the value; `""` = the last unnamed expression child, or none.
    pub right: &'static str,
    /// `x += e`: the target is also a source.
    pub augmented: bool,
    /// Binding this target makes it a local of the enclosing body. True for
    /// declarations (`let z`, `int z = …`, `z := …`) and for languages where
    /// plain assignment declares (Python, Ruby); false for `z = …` in
    /// languages where an undeclared name is an outer variable.
    pub declares: bool,
}

/// One parameter node kind inside a parameter list.
#[derive(Debug, Clone, Copy)]
pub struct ParamKind {
    pub node: &'static str,
    /// Field holding the name; `""` = the node itself is the identifier, or
    /// its first identifier descendant.
    pub name_field: &'static str,
}

/// A keyword/named argument node.
#[derive(Debug, Clone, Copy)]
pub struct KeywordArg {
    pub node: &'static str,
    pub name_field: &'static str,
    /// `""` = unnamed child.
    pub value_field: &'static str,
}

/// Member access `a.b`.
#[derive(Debug, Clone, Copy)]
pub struct MemberAccess {
    pub node: &'static str,
    pub object_field: &'static str,
    pub member_field: &'static str,
}

/// A closure-like node: analysed with the enclosing function's locals in
/// scope, flow-insensitively.
#[derive(Debug, Clone, Copy)]
pub struct Closure {
    pub node: &'static str,
    /// Field holding its parameter list, or `""` when the parameters are the
    /// node's direct identifier children (JS `x => …` via `parameter`).
    pub params_field: &'static str,
    pub body_field: &'static str,
}

/// `if`-like: two successors.
#[derive(Debug, Clone, Copy)]
pub struct Branch {
    pub node: &'static str,
    pub condition: &'static str,
    pub consequence: &'static str,
    pub alternative: &'static str,
    /// Ruby `unless`: the condition is negated.
    pub negated: bool,
}

/// A loop: header with an optional condition, a body, back edge.
#[derive(Debug, Clone, Copy)]
pub struct Loop {
    pub node: &'static str,
    /// `""` = no condition field; the analysis looks for a `for_clause`
    /// child's `condition` or treats the loop as unconditional.
    pub condition: &'static str,
    pub body: &'static str,
    /// `do … while`: body runs before the first test.
    pub post_test: bool,
    /// For-in style: the field bound each iteration, and the iterated value.
    pub binds: &'static str,
    pub over: &'static str,
}

/// A switch/match: a header value and arms.
#[derive(Debug, Clone, Copy)]
pub struct Switch {
    pub node: &'static str,
    pub value: &'static str,
    /// Arm node kinds; `""` fields mean positional (labels first, then
    /// statements).
    pub arms: &'static [Arm],
    /// Arms fall through to the next when the language has C semantics.
    pub fallthrough: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Arm {
    pub node: &'static str,
    pub pattern: &'static str,
    pub body: &'static str,
    pub is_default: bool,
}

/// try/catch/finally.
#[derive(Debug, Clone, Copy)]
pub struct Try {
    pub node: &'static str,
    /// `""` = the statements are direct children (Ruby `begin`).
    pub body: &'static str,
    pub handlers: &'static [&'static str],
    pub finally: &'static [&'static str],
    /// A handler's bound exception name, if any (JS `parameter`, Python
    /// `alias`).
    pub handler_binding: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Jumps {
    pub break_: &'static [&'static str],
    pub continue_: &'static [&'static str],
    pub return_: &'static [&'static str],
    pub throw: &'static [&'static str],
}

/// A comparison node.
#[derive(Debug, Clone, Copy)]
pub struct Comparison {
    pub node: &'static str,
    /// `""` = operands positional and the operator in `operators` (Python).
    pub left: &'static str,
    pub operator: &'static str,
    pub right: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Boolean {
    pub node: &'static str,
    pub left: &'static str,
    pub operator: &'static str,
    pub right: &'static str,
    pub and: &'static [&'static str],
    pub or: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct Negation {
    pub node: &'static str,
    /// `""` = the operand is the first named child and the operator an
    /// anonymous token (Rust, C#).
    pub operator: &'static str,
    pub operand: &'static str,
    pub not: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct Literals {
    pub int: &'static [&'static str],
    pub float: &'static [&'static str],
    pub string: &'static [&'static str],
    pub true_: &'static [&'static str],
    pub false_: &'static [&'static str],
    /// A boolean literal kind whose *text* is `true`/`false` (Rust, C#).
    pub bool_text: &'static str,
    pub null: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct Ternary {
    pub node: &'static str,
    /// `""` = positional in Python's order: consequence, condition,
    /// alternative.
    pub condition: &'static str,
    pub consequence: &'static str,
    pub alternative: &'static str,
}

/// Everything the flow analysis needs about one language.
pub struct Syntax {
    pub var_decls: &'static [VarDecl],
    pub assigns: &'static [Assign],
    /// The field on a definition node holding its parameter list.
    pub params_field: &'static str,
    pub param_kinds: &'static [ParamKind],
    /// Go: the field holding the result list, whose named entries are locals
    /// defined at entry and used by a bare `return`.
    pub named_results_field: &'static str,
    /// Words that name the enclosing instance.
    pub self_names: &'static [&'static str],
    pub args_field: &'static str,
    pub keyword_arg: Option<KeywordArg>,
    /// Argument node kinds that mean "passed by reference": the argument is
    /// weakly redefined by the call.
    pub by_ref_args: &'static [&'static str],
    pub returns: &'static [&'static str],
    /// The last expression of a body is its value.
    pub implicit_tail: bool,
    pub member_access: &'static [MemberAccess],
    /// Subscript: `(node, object field)`; `""` = child 0.
    pub subscripts: &'static [(&'static str, &'static str)],
    /// Kinds that merely wrap an expression: child 0 is the value.
    pub unwrap: &'static [&'static str],
    /// The field on a definition holding its body.
    pub body_field: &'static str,
    /// Statement wrappers whose child 0 is the expression.
    pub statement_wrappers: &'static [&'static str],
    pub closures: &'static [Closure],
    pub branches: &'static [Branch],
    pub loops: &'static [Loop],
    pub switches: &'static [Switch],
    pub tries: &'static [Try],
    pub jumps: Jumps,
    /// Condition wrappers to strip before reading a predicate.
    pub condition_unwrap: &'static [&'static str],
    pub comparison: &'static [Comparison],
    pub boolean: Option<Boolean>,
    pub negation: &'static [Negation],
    pub literals: Literals,
    pub ternary: Option<Ternary>,
    /// Node kinds that are a variable reference in an expression.
    pub var_ref_kinds: &'static [&'static str],
    /// A block statement kind (a nested scope for shadowing purposes).
    pub blocks: &'static [&'static str],
    /// Declaration statements whose declarators bind locals even without an
    /// initialiser (`int z;`, `var z int`, `let z;`).
    pub decl_stmts: &'static [&'static str],
}

impl Syntax {
    pub fn var_decl(&self, kind: &str) -> Option<&VarDecl> {
        self.var_decls.iter().find(|d| d.node == kind)
    }
    pub fn assign(&self, kind: &str) -> Option<&Assign> {
        self.assigns.iter().find(|a| a.node == kind)
    }
    pub fn param_kind(&self, kind: &str) -> Option<&ParamKind> {
        self.param_kinds.iter().find(|p| p.node == kind)
    }
    pub fn member(&self, kind: &str) -> Option<&MemberAccess> {
        self.member_access.iter().find(|m| m.node == kind)
    }
    pub fn subscript(&self, kind: &str) -> Option<&(&'static str, &'static str)> {
        self.subscripts.iter().find(|s| s.0 == kind)
    }
    pub fn closure(&self, kind: &str) -> Option<&Closure> {
        self.closures.iter().find(|c| c.node == kind)
    }
    pub fn branch(&self, kind: &str) -> Option<&Branch> {
        self.branches.iter().find(|b| b.node == kind)
    }
    pub fn loop_(&self, kind: &str) -> Option<&Loop> {
        self.loops.iter().find(|l| l.node == kind)
    }
    pub fn switch(&self, kind: &str) -> Option<&Switch> {
        self.switches.iter().find(|s| s.node == kind)
    }
    pub fn try_(&self, kind: &str) -> Option<&Try> {
        self.tries.iter().find(|t| t.node == kind)
    }
    pub fn comparison(&self, kind: &str) -> Option<&Comparison> {
        self.comparison.iter().find(|c| c.node == kind)
    }
    pub fn negation(&self, kind: &str) -> Option<&Negation> {
        self.negation.iter().find(|n| n.node == kind)
    }
    pub fn is_var_ref(&self, kind: &str) -> bool {
        self.var_ref_kinds.contains(&kind)
    }
    pub fn is_self(&self, text: &str) -> bool {
        self.self_names.contains(&text)
    }
    pub fn is_literal(&self, kind: &str) -> bool {
        let l = &self.literals;
        l.int.contains(&kind)
            || l.float.contains(&kind)
            || l.string.contains(&kind)
            || l.true_.contains(&kind)
            || l.false_.contains(&kind)
            || l.null.contains(&kind)
            || (!l.bool_text.is_empty() && l.bool_text == kind)
    }

    /// Every node kind these tables name, for the grammar check.
    pub fn all_kinds(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = Vec::new();
        v.extend(self.var_decls.iter().map(|d| d.node));
        v.extend(self.assigns.iter().map(|a| a.node));
        v.extend(self.param_kinds.iter().map(|p| p.node));
        v.extend(self.keyword_arg.iter().map(|k| k.node));
        v.extend(self.by_ref_args.iter().copied());
        v.extend(self.returns.iter().copied());
        v.extend(self.member_access.iter().map(|m| m.node));
        v.extend(self.subscripts.iter().map(|s| s.0));
        v.extend(self.unwrap.iter().copied());
        v.extend(self.statement_wrappers.iter().copied());
        v.extend(self.closures.iter().map(|c| c.node));
        v.extend(self.branches.iter().map(|b| b.node));
        v.extend(self.loops.iter().map(|l| l.node));
        for s in self.switches {
            v.push(s.node);
            v.extend(s.arms.iter().map(|a| a.node));
        }
        for t in self.tries {
            v.push(t.node);
            v.extend(t.handlers.iter().copied());
            v.extend(t.finally.iter().copied());
        }
        v.extend(self.jumps.break_.iter().copied());
        v.extend(self.jumps.continue_.iter().copied());
        v.extend(self.jumps.return_.iter().copied());
        v.extend(self.jumps.throw.iter().copied());
        v.extend(self.condition_unwrap.iter().copied());
        v.extend(self.comparison.iter().map(|c| c.node));
        v.extend(self.boolean.iter().map(|b| b.node));
        v.extend(self.negation.iter().map(|n| n.node));
        let l = &self.literals;
        for k in [l.int, l.float, l.string, l.true_, l.false_, l.null] {
            v.extend(k.iter().copied());
        }
        if !l.bool_text.is_empty() {
            v.push(l.bool_text);
        }
        v.extend(self.ternary.iter().map(|t| t.node));
        v.extend(self.var_ref_kinds.iter().copied());
        v.extend(self.blocks.iter().copied());
        v.extend(self.decl_stmts.iter().copied());
        v
    }
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

pub static PYTHON: Syntax = Syntax {
    var_decls: &[VarDecl {
        node: "assignment",
        name_field: "left",
        value_field: "right",
        kind: SymbolKind::Variable,
        at: DeclAt::Either,
        constness: ConstRule::AllCaps,
        name_kind: "identifier",
    }],
    assigns: &[
        Assign { node: "assignment", left: "left", right: "right", augmented: false, declares: true },
        Assign { node: "augmented_assignment", left: "left", right: "right", augmented: true, declares: true },
        Assign { node: "named_expression", left: "name", right: "value", augmented: false, declares: true },
    ],
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "identifier", name_field: "" },
        ParamKind { node: "default_parameter", name_field: "name" },
        // `typed_parameter` has no name field: the name is its first child.
        ParamKind { node: "typed_parameter", name_field: "" },
        ParamKind { node: "typed_default_parameter", name_field: "name" },
        ParamKind { node: "list_splat_pattern", name_field: "" },
        ParamKind { node: "dictionary_splat_pattern", name_field: "" },
    ],
    named_results_field: "",
    self_names: &["self", "cls"],
    args_field: "arguments",
    keyword_arg: Some(KeywordArg { node: "keyword_argument", name_field: "name", value_field: "value" }),
    by_ref_args: &[],
    returns: &["return_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "attribute", object_field: "object", member_field: "attribute" }],
    subscripts: &[("subscript", "value")],
    unwrap: &["parenthesized_expression", "await"],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: &[Closure { node: "lambda", params_field: "parameters", body_field: "body" }],
    branches: &[
        Branch { node: "if_statement", condition: "condition", consequence: "consequence", alternative: "alternative", negated: false },
        Branch { node: "elif_clause", condition: "condition", consequence: "consequence", alternative: "", negated: false },
    ],
    loops: &[
        Loop { node: "while_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "for_statement", condition: "", body: "body", post_test: false, binds: "left", over: "right" },
    ],
    switches: &[Switch {
        node: "match_statement",
        value: "subject",
        arms: &[Arm { node: "case_clause", pattern: "", body: "consequence", is_default: false }],
        fallthrough: false,
    }],
    tries: &[Try {
        node: "try_statement",
        body: "body",
        handlers: &["except_clause"],
        finally: &["finally_clause", "else_clause"],
        handler_binding: "alias",
    }],
    jumps: Jumps {
        break_: &["break_statement"],
        continue_: &["continue_statement"],
        return_: &["return_statement"],
        throw: &["raise_statement"],
    },
    condition_unwrap: &["parenthesized_expression"],
    // Operands are positional; the operators live in a multi-field.
    comparison: &[Comparison { node: "comparison_operator", left: "", operator: "operators", right: "" }],
    boolean: Some(Boolean { node: "boolean_operator", left: "left", operator: "operator", right: "right", and: &["and"], or: &["or"] }),
    negation: &[Negation { node: "not_operator", operator: "", operand: "argument", not: &["not"] }],
    literals: Literals {
        int: &["integer"],
        float: &["float"],
        string: &["string", "concatenated_string"],
        true_: &["true"],
        false_: &["false"],
        bool_text: "",
        null: &["none"],
    },
    ternary: Some(Ternary { node: "conditional_expression", condition: "", consequence: "", alternative: "" }),
    var_ref_kinds: &["identifier"],
    decl_stmts: &[],
    blocks: &["block"],
};

// ---------------------------------------------------------------------------
// JavaScript
// ---------------------------------------------------------------------------

static JS_ASSIGNS: &[Assign] = &[
    Assign { node: "assignment_expression", left: "left", right: "right", augmented: false, declares: false },
    Assign { node: "augmented_assignment_expression", left: "left", right: "right", augmented: true, declares: false },
    Assign { node: "variable_declarator", left: "name", right: "value", augmented: false, declares: true },
];

static JS_PARAMS: &[ParamKind] = &[
    ParamKind { node: "identifier", name_field: "" },
    ParamKind { node: "assignment_pattern", name_field: "left" },
    ParamKind { node: "rest_pattern", name_field: "" },
    ParamKind { node: "object_pattern", name_field: "" },
    ParamKind { node: "array_pattern", name_field: "" },
];

static JS_CLOSURES: &[Closure] = &[
    Closure { node: "arrow_function", params_field: "parameters", body_field: "body" },
    Closure { node: "function_expression", params_field: "parameters", body_field: "body" },
];

static JS_BRANCHES: &[Branch] = &[Branch {
    node: "if_statement",
    condition: "condition",
    consequence: "consequence",
    alternative: "alternative",
    negated: false,
}];

static JS_LOOPS: &[Loop] = &[
    Loop { node: "while_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
    Loop { node: "do_statement", condition: "condition", body: "body", post_test: true, binds: "", over: "" },
    Loop { node: "for_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
    Loop { node: "for_in_statement", condition: "", body: "body", post_test: false, binds: "left", over: "right" },
];

static JS_SWITCHES: &[Switch] = &[Switch {
    node: "switch_statement",
    value: "value",
    arms: &[
        Arm { node: "switch_case", pattern: "value", body: "body", is_default: false },
        Arm { node: "switch_default", pattern: "", body: "body", is_default: true },
    ],
    fallthrough: true,
}];

static JS_TRIES: &[Try] = &[Try {
    node: "try_statement",
    body: "body",
    handlers: &["catch_clause"],
    finally: &["finally_clause"],
    handler_binding: "parameter",
}];

static JS_JUMPS: Jumps = Jumps {
    break_: &["break_statement"],
    continue_: &["continue_statement"],
    return_: &["return_statement"],
    throw: &["throw_statement"],
};

static JS_COMPARISON: &[Comparison] =
    &[Comparison { node: "binary_expression", left: "left", operator: "operator", right: "right" }];

static JS_BOOLEAN: Option<Boolean> = Some(Boolean {
    node: "binary_expression",
    left: "left",
    operator: "operator",
    right: "right",
    and: &["&&"],
    or: &["||", "??"],
});

static JS_NEGATION: &[Negation] =
    &[Negation { node: "unary_expression", operator: "operator", operand: "argument", not: &["!"] }];

static JS_LITERALS: Literals = Literals {
    int: &["number"],
    float: &[],
    string: &["string", "template_string"],
    true_: &["true"],
    false_: &["false"],
    bool_text: "",
    null: &["null", "undefined"],
};

static JS_TERNARY: Option<Ternary> = Some(Ternary {
    node: "ternary_expression",
    condition: "condition",
    consequence: "consequence",
    alternative: "alternative",
});

pub static JAVASCRIPT: Syntax = Syntax {
    var_decls: &[
        VarDecl {
            node: "variable_declarator",
            name_field: "name",
            value_field: "value",
            kind: SymbolKind::Variable,
            at: DeclAt::Module,
            constness: ConstRule::ParentKindField,
            name_kind: "",
        },
        VarDecl {
            node: "field_definition",
            name_field: "property",
            value_field: "value",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "",
        },
    ],
    assigns: JS_ASSIGNS,
    params_field: "parameters",
    param_kinds: JS_PARAMS,
    named_results_field: "",
    self_names: &["this"],
    args_field: "arguments",
    keyword_arg: None,
    by_ref_args: &[],
    returns: &["return_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "member_expression", object_field: "object", member_field: "property" }],
    subscripts: &[("subscript_expression", "object")],
    unwrap: &["parenthesized_expression", "await_expression"],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: JS_CLOSURES,
    branches: JS_BRANCHES,
    loops: JS_LOOPS,
    switches: JS_SWITCHES,
    tries: JS_TRIES,
    jumps: JS_JUMPS,
    condition_unwrap: &["parenthesized_expression"],
    comparison: JS_COMPARISON,
    boolean: JS_BOOLEAN,
    negation: JS_NEGATION,
    literals: JS_LITERALS,
    ternary: JS_TERNARY,
    var_ref_kinds: &["identifier", "this", "shorthand_property_identifier"],
    decl_stmts: &["lexical_declaration", "variable_declaration"],
    blocks: &["statement_block"],
};

// ---------------------------------------------------------------------------
// TypeScript / TSX
// ---------------------------------------------------------------------------

pub static TYPESCRIPT: Syntax = Syntax {
    var_decls: &[
        VarDecl {
            node: "variable_declarator",
            name_field: "name",
            value_field: "value",
            kind: SymbolKind::Variable,
            at: DeclAt::Module,
            constness: ConstRule::ParentKindField,
            name_kind: "",
        },
        VarDecl {
            node: "public_field_definition",
            name_field: "name",
            value_field: "value",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "",
        },
    ],
    assigns: JS_ASSIGNS,
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "required_parameter", name_field: "pattern" },
        ParamKind { node: "optional_parameter", name_field: "pattern" },
        ParamKind { node: "identifier", name_field: "" },
    ],
    named_results_field: "",
    self_names: &["this"],
    args_field: "arguments",
    keyword_arg: None,
    by_ref_args: &[],
    returns: &["return_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "member_expression", object_field: "object", member_field: "property" }],
    subscripts: &[("subscript_expression", "object")],
    unwrap: &[
        "parenthesized_expression",
        "await_expression",
        "non_null_expression",
        "as_expression",
        "satisfies_expression",
    ],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: JS_CLOSURES,
    branches: JS_BRANCHES,
    loops: JS_LOOPS,
    switches: JS_SWITCHES,
    tries: JS_TRIES,
    jumps: JS_JUMPS,
    condition_unwrap: &["parenthesized_expression", "non_null_expression", "as_expression"],
    comparison: JS_COMPARISON,
    boolean: JS_BOOLEAN,
    negation: JS_NEGATION,
    literals: JS_LITERALS,
    ternary: JS_TERNARY,
    var_ref_kinds: &["identifier", "this", "shorthand_property_identifier"],
    decl_stmts: &["lexical_declaration", "variable_declaration"],
    blocks: &["statement_block"],
};

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

pub static JAVA: Syntax = Syntax {
    var_decls: &[VarDecl {
        node: "variable_declarator",
        name_field: "name",
        value_field: "value",
        kind: SymbolKind::Field,
        at: DeclAt::Type,
        constness: ConstRule::ModifierText(&["final"]),
        name_kind: "",
    }],
    assigns: &[
        Assign { node: "assignment_expression", left: "left", right: "right", augmented: false, declares: false },
        Assign { node: "variable_declarator", left: "name", right: "value", augmented: false, declares: true },
    ],
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "formal_parameter", name_field: "name" },
        // The name sits inside the spread parameter's own declarator.
        ParamKind { node: "spread_parameter", name_field: "" },
        ParamKind { node: "receiver_parameter", name_field: "" },
        ParamKind { node: "identifier", name_field: "" },
    ],
    named_results_field: "",
    self_names: &["this"],
    args_field: "arguments",
    keyword_arg: None,
    by_ref_args: &[],
    returns: &["return_statement", "yield_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "field_access", object_field: "object", member_field: "field" }],
    subscripts: &[("array_access", "array")],
    unwrap: &["parenthesized_expression", "cast_expression"],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: &[Closure { node: "lambda_expression", params_field: "parameters", body_field: "body" }],
    branches: &[Branch {
        node: "if_statement",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
        negated: false,
    }],
    loops: &[
        Loop { node: "while_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "do_statement", condition: "condition", body: "body", post_test: true, binds: "", over: "" },
        Loop { node: "for_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "enhanced_for_statement", condition: "", body: "body", post_test: false, binds: "name", over: "value" },
    ],
    switches: &[Switch {
        node: "switch_expression",
        value: "condition",
        // Positional: labels first, then statements.
        arms: &[
            Arm { node: "switch_block_statement_group", pattern: "", body: "", is_default: false },
            Arm { node: "switch_rule", pattern: "", body: "", is_default: false },
        ],
        fallthrough: true,
    }],
    tries: &[
        Try {
            node: "try_statement",
            body: "body",
            handlers: &["catch_clause"],
            finally: &["finally_clause"],
            handler_binding: "",
        },
        Try {
            node: "try_with_resources_statement",
            body: "body",
            handlers: &["catch_clause"],
            finally: &["finally_clause"],
            handler_binding: "",
        },
    ],
    jumps: Jumps {
        break_: &["break_statement"],
        continue_: &["continue_statement"],
        return_: &["return_statement", "yield_statement"],
        throw: &["throw_statement"],
    },
    condition_unwrap: &["parenthesized_expression"],
    comparison: &[Comparison { node: "binary_expression", left: "left", operator: "operator", right: "right" }],
    boolean: Some(Boolean {
        node: "binary_expression",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&"],
        or: &["||"],
    }),
    negation: &[Negation { node: "unary_expression", operator: "operator", operand: "operand", not: &["!"] }],
    literals: Literals {
        int: &["decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal"],
        float: &["decimal_floating_point_literal", "hex_floating_point_literal"],
        string: &["string_literal", "character_literal"],
        true_: &["true"],
        false_: &["false"],
        bool_text: "",
        null: &["null_literal"],
    },
    ternary: Some(Ternary {
        node: "ternary_expression",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
    }),
    var_ref_kinds: &["identifier", "this"],
    decl_stmts: &["local_variable_declaration"],
    blocks: &["block"],
};

// ---------------------------------------------------------------------------
// C / C++
// ---------------------------------------------------------------------------

static C_ASSIGNS: &[Assign] = &[
    Assign { node: "assignment_expression", left: "left", right: "right", augmented: false, declares: false },
    Assign { node: "init_declarator", left: "declarator", right: "value", augmented: false, declares: true },
];

static C_LOOPS: &[Loop] = &[
    Loop { node: "while_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
    Loop { node: "do_statement", condition: "condition", body: "body", post_test: true, binds: "", over: "" },
    Loop { node: "for_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
];

static C_SWITCHES: &[Switch] = &[Switch {
    node: "switch_statement",
    value: "condition",
    arms: &[Arm { node: "case_statement", pattern: "value", body: "", is_default: false }],
    fallthrough: true,
}];

static C_COMPARISON: &[Comparison] =
    &[Comparison { node: "binary_expression", left: "left", operator: "operator", right: "right" }];

static C_NEGATION: &[Negation] =
    &[Negation { node: "unary_expression", operator: "operator", operand: "argument", not: &["!", "not"] }];

pub static C: Syntax = Syntax {
    var_decls: &[
        VarDecl {
            node: "init_declarator",
            name_field: "declarator",
            value_field: "value",
            kind: SymbolKind::Variable,
            at: DeclAt::Module,
            constness: ConstRule::ModifierText(&["const"]),
            name_kind: "",
        },
        VarDecl {
            node: "field_declaration",
            name_field: "declarator",
            value_field: "",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "",
        },
    ],
    assigns: C_ASSIGNS,
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "parameter_declaration", name_field: "declarator" },
        ParamKind { node: "identifier", name_field: "" },
    ],
    named_results_field: "",
    self_names: &[],
    args_field: "arguments",
    keyword_arg: None,
    // `&x` passed to a callee is written through.
    by_ref_args: &["pointer_expression"],
    returns: &["return_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "field_expression", object_field: "argument", member_field: "field" }],
    subscripts: &[("subscript_expression", "argument")],
    unwrap: &["parenthesized_expression", "cast_expression", "pointer_expression"],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: &[],
    branches: &[Branch {
        node: "if_statement",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
        negated: false,
    }],
    loops: C_LOOPS,
    switches: C_SWITCHES,
    tries: &[],
    jumps: Jumps {
        break_: &["break_statement"],
        continue_: &["continue_statement"],
        return_: &["return_statement"],
        throw: &[],
    },
    condition_unwrap: &["parenthesized_expression"],
    comparison: C_COMPARISON,
    boolean: Some(Boolean {
        node: "binary_expression",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&"],
        or: &["||"],
    }),
    negation: C_NEGATION,
    literals: Literals {
        int: &["number_literal"],
        float: &[],
        string: &["string_literal", "concatenated_string", "char_literal"],
        true_: &["true"],
        false_: &["false"],
        bool_text: "",
        null: &["null"],
    },
    ternary: Some(Ternary {
        node: "conditional_expression",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
    }),
    var_ref_kinds: &["identifier"],
    decl_stmts: &["declaration"],
    blocks: &["compound_statement"],
};

pub static CPP: Syntax = Syntax {
    var_decls: &[
        VarDecl {
            node: "init_declarator",
            name_field: "declarator",
            value_field: "value",
            kind: SymbolKind::Variable,
            at: DeclAt::Module,
            constness: ConstRule::ModifierText(&["const", "constexpr"]),
            name_kind: "",
        },
        VarDecl {
            node: "field_declaration",
            name_field: "declarator",
            value_field: "default_value",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "",
        },
    ],
    assigns: C_ASSIGNS,
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "parameter_declaration", name_field: "declarator" },
        ParamKind { node: "optional_parameter_declaration", name_field: "declarator" },
        ParamKind { node: "variadic_parameter_declaration", name_field: "declarator" },
        ParamKind { node: "identifier", name_field: "" },
    ],
    named_results_field: "",
    self_names: &["this"],
    args_field: "arguments",
    keyword_arg: None,
    by_ref_args: &["pointer_expression"],
    returns: &["return_statement", "co_return_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "field_expression", object_field: "argument", member_field: "field" }],
    subscripts: &[("subscript_expression", "argument")],
    unwrap: &["parenthesized_expression", "cast_expression", "pointer_expression"],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: &[Closure { node: "lambda_expression", params_field: "declarator", body_field: "body" }],
    branches: &[Branch {
        node: "if_statement",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
        negated: false,
    }],
    loops: &[
        Loop { node: "while_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "do_statement", condition: "condition", body: "body", post_test: true, binds: "", over: "" },
        Loop { node: "for_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "for_range_loop", condition: "", body: "body", post_test: false, binds: "declarator", over: "right" },
    ],
    switches: C_SWITCHES,
    tries: &[Try {
        node: "try_statement",
        body: "body",
        handlers: &["catch_clause"],
        finally: &[],
        handler_binding: "parameters",
    }],
    jumps: Jumps {
        break_: &["break_statement"],
        continue_: &["continue_statement"],
        return_: &["return_statement", "co_return_statement"],
        throw: &["throw_statement"],
    },
    // `if (x)` is a `condition_clause` whose `value` is the expression.
    condition_unwrap: &["parenthesized_expression", "condition_clause"],
    comparison: C_COMPARISON,
    boolean: Some(Boolean {
        node: "binary_expression",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&", "and"],
        or: &["||", "or"],
    }),
    negation: C_NEGATION,
    literals: Literals {
        int: &["number_literal"],
        float: &[],
        string: &["string_literal", "raw_string_literal", "concatenated_string", "char_literal"],
        true_: &["true"],
        false_: &["false"],
        bool_text: "",
        null: &["null"],
    },
    ternary: Some(Ternary {
        node: "conditional_expression",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
    }),
    var_ref_kinds: &["identifier", "this", "qualified_identifier"],
    decl_stmts: &["declaration"],
    blocks: &["compound_statement"],
};

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

pub static GO: Syntax = Syntax {
    var_decls: &[
        VarDecl {
            node: "var_spec",
            name_field: "name",
            value_field: "value",
            kind: SymbolKind::Variable,
            at: DeclAt::Module,
            constness: ConstRule::Never,
            name_kind: "",
        },
        VarDecl {
            node: "const_spec",
            name_field: "name",
            value_field: "value",
            kind: SymbolKind::Constant,
            at: DeclAt::Module,
            constness: ConstRule::Always,
            name_kind: "",
        },
        VarDecl {
            node: "field_declaration",
            name_field: "name",
            value_field: "",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "",
        },
    ],
    assigns: &[
        Assign { node: "short_var_declaration", left: "left", right: "right", augmented: false, declares: true },
        Assign { node: "assignment_statement", left: "left", right: "right", augmented: false, declares: false },
        Assign { node: "var_spec", left: "name", right: "value", augmented: false, declares: true },
        Assign { node: "range_clause", left: "left", right: "right", augmented: false, declares: true },
    ],
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "parameter_declaration", name_field: "name" },
        ParamKind { node: "variadic_parameter_declaration", name_field: "name" },
    ],
    named_results_field: "result",
    self_names: &[],
    args_field: "arguments",
    keyword_arg: None,
    // `&x` handed to a callee.
    by_ref_args: &["unary_expression"],
    returns: &["return_statement"],
    implicit_tail: false,
    member_access: &[MemberAccess { node: "selector_expression", object_field: "operand", member_field: "field" }],
    subscripts: &[("index_expression", "operand"), ("slice_expression", "operand")],
    unwrap: &["parenthesized_expression", "type_assertion_expression", "type_conversion_expression"],
    body_field: "body",
    statement_wrappers: &["expression_statement", "go_statement", "defer_statement"],
    closures: &[Closure { node: "func_literal", params_field: "parameters", body_field: "body" }],
    branches: &[Branch {
        node: "if_statement",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
        negated: false,
    }],
    // Go's `for` carries its condition in an unnamed `for_clause` or as a
    // bare expression child; the analysis looks for both.
    loops: &[Loop { node: "for_statement", condition: "", body: "body", post_test: false, binds: "", over: "" }],
    switches: &[
        Switch {
            node: "expression_switch_statement",
            value: "value",
            arms: &[
                Arm { node: "expression_case", pattern: "value", body: "", is_default: false },
                Arm { node: "default_case", pattern: "", body: "", is_default: true },
            ],
            fallthrough: false,
        },
        Switch {
            node: "type_switch_statement",
            value: "value",
            arms: &[
                Arm { node: "type_case", pattern: "type", body: "", is_default: false },
                Arm { node: "default_case", pattern: "", body: "", is_default: true },
            ],
            fallthrough: false,
        },
        Switch {
            node: "select_statement",
            value: "",
            arms: &[
                Arm { node: "communication_case", pattern: "communication", body: "", is_default: false },
                Arm { node: "default_case", pattern: "", body: "", is_default: true },
            ],
            fallthrough: false,
        },
    ],
    tries: &[],
    jumps: Jumps {
        break_: &["break_statement"],
        continue_: &["continue_statement"],
        return_: &["return_statement"],
        throw: &[],
    },
    condition_unwrap: &["parenthesized_expression"],
    comparison: &[Comparison { node: "binary_expression", left: "left", operator: "operator", right: "right" }],
    boolean: Some(Boolean {
        node: "binary_expression",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&"],
        or: &["||"],
    }),
    negation: &[Negation { node: "unary_expression", operator: "operator", operand: "operand", not: &["!"] }],
    literals: Literals {
        int: &["int_literal"],
        float: &["float_literal", "imaginary_literal"],
        string: &["interpreted_string_literal", "raw_string_literal", "rune_literal"],
        true_: &["true"],
        false_: &["false"],
        bool_text: "",
        null: &["nil"],
    },
    ternary: None,
    var_ref_kinds: &["identifier"],
    decl_stmts: &["var_declaration", "var_spec_list"],
    blocks: &["block"],
};

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

pub static RUST: Syntax = Syntax {
    // `const_item` / `static_item` are already definitions in `lang.rs`.
    var_decls: &[VarDecl {
        node: "field_declaration",
        name_field: "name",
        value_field: "",
        kind: SymbolKind::Field,
        at: DeclAt::Type,
        constness: ConstRule::Never,
        name_kind: "",
    }],
    assigns: &[
        Assign { node: "assignment_expression", left: "left", right: "right", augmented: false, declares: false },
        Assign { node: "compound_assignment_expr", left: "left", right: "right", augmented: true, declares: false },
        Assign { node: "let_declaration", left: "pattern", right: "value", augmented: false, declares: true },
        Assign { node: "let_condition", left: "pattern", right: "value", augmented: false, declares: true },
    ],
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "parameter", name_field: "pattern" },
        ParamKind { node: "self_parameter", name_field: "" },
    ],
    named_results_field: "",
    self_names: &["self"],
    args_field: "arguments",
    keyword_arg: None,
    by_ref_args: &["reference_expression"],
    returns: &["return_expression"],
    implicit_tail: true,
    member_access: &[MemberAccess { node: "field_expression", object_field: "value", member_field: "field" }],
    // `index_expression` has no fields: child 0 is the object.
    subscripts: &[("index_expression", "")],
    unwrap: &[
        "parenthesized_expression",
        "reference_expression",
        "try_expression",
        "await_expression",
        "type_cast_expression",
        "unary_expression",
    ],
    body_field: "body",
    statement_wrappers: &["expression_statement"],
    closures: &[Closure { node: "closure_expression", params_field: "parameters", body_field: "body" }],
    branches: &[Branch {
        node: "if_expression",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
        negated: false,
    }],
    loops: &[
        Loop { node: "while_expression", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "loop_expression", condition: "", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "for_expression", condition: "", body: "body", post_test: false, binds: "pattern", over: "value" },
    ],
    switches: &[Switch {
        node: "match_expression",
        value: "value",
        arms: &[Arm { node: "match_arm", pattern: "pattern", body: "value", is_default: false }],
        fallthrough: false,
    }],
    tries: &[],
    jumps: Jumps {
        break_: &["break_expression"],
        continue_: &["continue_expression"],
        return_: &["return_expression", "try_expression"],
        throw: &[],
    },
    condition_unwrap: &["parenthesized_expression"],
    comparison: &[Comparison { node: "binary_expression", left: "left", operator: "operator", right: "right" }],
    boolean: Some(Boolean {
        node: "binary_expression",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&"],
        or: &["||"],
    }),
    // No fields: an anonymous operator token, then the operand.
    negation: &[Negation { node: "unary_expression", operator: "", operand: "", not: &["!"] }],
    literals: Literals {
        int: &["integer_literal"],
        float: &["float_literal"],
        string: &["string_literal", "raw_string_literal", "char_literal"],
        true_: &[],
        false_: &[],
        bool_text: "boolean_literal",
        null: &[],
    },
    ternary: None,
    var_ref_kinds: &["identifier", "self", "scoped_identifier"],
    decl_stmts: &[],
    blocks: &["block", "unsafe_block", "async_block"],
};

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

pub static CSHARP: Syntax = Syntax {
    var_decls: &[VarDecl {
        // Under `field_declaration › variable_declaration`. The initialiser
        // is the unnamed expression child after `=`.
        node: "variable_declarator",
        name_field: "name",
        value_field: "",
        kind: SymbolKind::Field,
        at: DeclAt::Type,
        constness: ConstRule::ModifierText(&["const"]),
        name_kind: "",
    }],
    assigns: &[
        Assign { node: "assignment_expression", left: "left", right: "right", augmented: false, declares: false },
        Assign { node: "variable_declarator", left: "name", right: "", augmented: false, declares: true },
    ],
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "parameter", name_field: "name" },
        ParamKind { node: "implicit_parameter", name_field: "" },
    ],
    named_results_field: "",
    self_names: &["this", "base"],
    args_field: "arguments",
    keyword_arg: Some(KeywordArg { node: "argument", name_field: "name", value_field: "" }),
    // `ref`/`out` are anonymous tokens inside `argument`; detected by text.
    by_ref_args: &[],
    returns: &["return_statement", "yield_statement", "arrow_expression_clause"],
    implicit_tail: false,
    member_access: &[
        MemberAccess { node: "member_access_expression", object_field: "expression", member_field: "name" },
        MemberAccess { node: "conditional_access_expression", object_field: "condition", member_field: "" },
    ],
    subscripts: &[("element_access_expression", "expression")],
    unwrap: &["parenthesized_expression", "cast_expression", "await_expression", "checked_expression"],
    body_field: "body",
    statement_wrappers: &["expression_statement", "global_statement"],
    closures: &[
        Closure { node: "lambda_expression", params_field: "parameters", body_field: "body" },
        Closure { node: "anonymous_method_expression", params_field: "parameters", body_field: "" },
        Closure { node: "local_function_statement", params_field: "parameters", body_field: "body" },
    ],
    branches: &[Branch {
        node: "if_statement",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
        negated: false,
    }],
    loops: &[
        Loop { node: "while_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "do_statement", condition: "condition", body: "body", post_test: true, binds: "", over: "" },
        Loop { node: "for_statement", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "foreach_statement", condition: "", body: "body", post_test: false, binds: "left", over: "right" },
    ],
    switches: &[Switch {
        node: "switch_statement",
        value: "value",
        // No fields: leading expression/pattern children are labels.
        arms: &[Arm { node: "switch_section", pattern: "", body: "", is_default: false }],
        fallthrough: false,
    }],
    tries: &[Try {
        node: "try_statement",
        body: "body",
        handlers: &["catch_clause"],
        finally: &["finally_clause"],
        handler_binding: "",
    }],
    jumps: Jumps {
        break_: &["break_statement"],
        continue_: &["continue_statement"],
        return_: &["return_statement", "yield_statement"],
        throw: &["throw_statement", "throw_expression"],
    },
    condition_unwrap: &["parenthesized_expression"],
    comparison: &[Comparison { node: "binary_expression", left: "left", operator: "operator", right: "right" }],
    boolean: Some(Boolean {
        node: "binary_expression",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&"],
        or: &["||", "??"],
    }),
    negation: &[Negation { node: "prefix_unary_expression", operator: "", operand: "", not: &["!"] }],
    literals: Literals {
        int: &["integer_literal"],
        float: &["real_literal"],
        string: &["string_literal", "verbatim_string_literal", "raw_string_literal", "interpolated_string_expression", "character_literal"],
        true_: &[],
        false_: &[],
        bool_text: "boolean_literal",
        null: &["null_literal"],
    },
    ternary: Some(Ternary {
        node: "conditional_expression",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
    }),
    var_ref_kinds: &["identifier"],
    decl_stmts: &["local_declaration_statement", "variable_declaration", "declaration_expression"],
    blocks: &["block"],
};

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

pub static RUBY: Syntax = Syntax {
    var_decls: &[
        VarDecl {
            node: "assignment",
            name_field: "left",
            value_field: "right",
            kind: SymbolKind::Constant,
            at: DeclAt::Either,
            constness: ConstRule::Always,
            name_kind: "constant",
        },
        VarDecl {
            node: "assignment",
            name_field: "left",
            value_field: "right",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "class_variable",
        },
        VarDecl {
            node: "assignment",
            name_field: "left",
            value_field: "right",
            kind: SymbolKind::Field,
            at: DeclAt::Type,
            constness: ConstRule::Never,
            name_kind: "instance_variable",
        },
        VarDecl {
            node: "assignment",
            name_field: "left",
            value_field: "right",
            kind: SymbolKind::Variable,
            at: DeclAt::Either,
            constness: ConstRule::Never,
            name_kind: "global_variable",
        },
    ],
    assigns: &[
        Assign { node: "assignment", left: "left", right: "right", augmented: false, declares: true },
        Assign { node: "operator_assignment", left: "left", right: "right", augmented: true, declares: true },
    ],
    params_field: "parameters",
    param_kinds: &[
        ParamKind { node: "identifier", name_field: "" },
        ParamKind { node: "optional_parameter", name_field: "name" },
        ParamKind { node: "keyword_parameter", name_field: "name" },
        ParamKind { node: "splat_parameter", name_field: "name" },
        ParamKind { node: "hash_splat_parameter", name_field: "name" },
        ParamKind { node: "block_parameter", name_field: "name" },
    ],
    named_results_field: "",
    self_names: &["self"],
    args_field: "arguments",
    keyword_arg: Some(KeywordArg { node: "pair", name_field: "key", value_field: "value" }),
    by_ref_args: &[],
    returns: &["return"],
    implicit_tail: true,
    // `a.b` without arguments is a `call` with a receiver and no `arguments`.
    member_access: &[MemberAccess { node: "call", object_field: "receiver", member_field: "method" }],
    subscripts: &[("element_reference", "object")],
    unwrap: &["parenthesized_statements"],
    body_field: "body",
    statement_wrappers: &[],
    closures: &[
        Closure { node: "block", params_field: "parameters", body_field: "body" },
        Closure { node: "do_block", params_field: "parameters", body_field: "body" },
        Closure { node: "lambda", params_field: "parameters", body_field: "body" },
    ],
    branches: &[
        Branch { node: "if", condition: "condition", consequence: "consequence", alternative: "alternative", negated: false },
        Branch { node: "unless", condition: "condition", consequence: "consequence", alternative: "alternative", negated: true },
        Branch { node: "elsif", condition: "condition", consequence: "consequence", alternative: "alternative", negated: false },
        Branch { node: "if_modifier", condition: "condition", consequence: "body", alternative: "", negated: false },
        Branch { node: "unless_modifier", condition: "condition", consequence: "body", alternative: "", negated: true },
    ],
    loops: &[
        Loop { node: "while", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "until", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "while_modifier", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "until_modifier", condition: "condition", body: "body", post_test: false, binds: "", over: "" },
        Loop { node: "for", condition: "", body: "body", post_test: false, binds: "pattern", over: "value" },
    ],
    switches: &[
        Switch {
            node: "case",
            value: "value",
            arms: &[
                Arm { node: "when", pattern: "pattern", body: "body", is_default: false },
                Arm { node: "else", pattern: "", body: "", is_default: true },
            ],
            fallthrough: false,
        },
        Switch {
            node: "case_match",
            value: "value",
            arms: &[
                Arm { node: "in_clause", pattern: "pattern", body: "body", is_default: false },
                Arm { node: "else", pattern: "", body: "", is_default: true },
            ],
            fallthrough: false,
        },
    ],
    tries: &[
        Try { node: "begin", body: "", handlers: &["rescue"], finally: &["ensure", "else"], handler_binding: "variable" },
        Try { node: "body_statement", body: "", handlers: &["rescue"], finally: &["ensure", "else"], handler_binding: "variable" },
    ],
    jumps: Jumps {
        break_: &["break"],
        continue_: &["next", "redo"],
        return_: &["return"],
        throw: &[],
    },
    condition_unwrap: &["parenthesized_statements"],
    comparison: &[Comparison { node: "binary", left: "left", operator: "operator", right: "right" }],
    boolean: Some(Boolean {
        node: "binary",
        left: "left",
        operator: "operator",
        right: "right",
        and: &["&&", "and"],
        or: &["||", "or"],
    }),
    negation: &[Negation { node: "unary", operator: "operator", operand: "operand", not: &["!", "not"] }],
    literals: Literals {
        int: &["integer"],
        float: &["float", "rational", "complex"],
        string: &["string", "simple_symbol", "delimited_symbol"],
        true_: &["true"],
        false_: &["false"],
        bool_text: "",
        null: &["nil"],
    },
    ternary: Some(Ternary {
        node: "conditional",
        condition: "condition",
        consequence: "consequence",
        alternative: "alternative",
    }),
    var_ref_kinds: &["identifier", "constant", "instance_variable", "class_variable", "global_variable", "self"],
    decl_stmts: &[],
    blocks: &["then", "do", "else"],
};
