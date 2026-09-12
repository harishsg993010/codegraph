//! The closed vocabularies: relation, symbol kind, file type, confidence.
//!
//! Every one of these is stored as a `u8` in a column. The discriminants are
//! **permanent** — they appear in on-disk segments, so changing one silently
//! reinterprets every existing store. Add new variants at the end; never
//! renumber, never reuse a retired value.
//!
//! Each enum has an `Unknown = 255` arm so a reader can open a segment written
//! by a newer writer without either guessing or refusing. An unknown value is
//! preserved on read and never silently mapped onto a known one.

/// Generates the `u8` <-> enum conversions and a `&str` name, so the on-disk
/// discriminant and the human-facing spelling stay defined in one place.
macro_rules! byte_enum {
    (
        $(#[$m:meta])* $name:ident { $( $variant:ident = $value:expr => $text:literal ),+ $(,)? }
    ) => {
        $(#[$m])*
        // Deliberately NOT `FromBytes`: not every `u8` is a valid variant, so
        // claiming otherwise would be unsound. Columns store the raw `u8` and
        // convert at the boundary via `from_u8`, which maps anything
        // unrecognised to `Unknown` instead of conjuring a variant.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum $name {
            $( $variant = $value, )+
            /// A value written by a newer writer. Preserved, never guessed at.
            Unknown = 255,
        }

        impl $name {
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];

            #[inline]
            pub const fn as_u8(self) -> u8 { self as u8 }

            pub const fn from_u8(v: u8) -> Self {
                match v {
                    $( $value => $name::$variant, )+
                    _ => $name::Unknown,
                }
            }

            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $name::$variant => $text, )+
                    $name::Unknown => "unknown",
                }
            }

            /// Parse the wire spelling. Unrecognised text becomes `Unknown`
            /// rather than an error: an importer reading a foreign index should
            /// keep the row, not drop it.
            pub fn from_str_or_unknown(s: &str) -> Self {
                match s {
                    $( $text => $name::$variant, )+
                    _ => $name::Unknown,
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

byte_enum!(
    /// How two symbols relate. Stored inline in the CSR so a relation-masked
    /// traversal is a byte compare during iteration.
    ///
    /// Discriminants below 64 are maskable via [`RelationMask`]; that bound is
    /// asserted by a test, so adding a 64th relation fails loudly rather than
    /// silently falling out of every mask.
    Relation {
        Contains             = 0  => "contains",
        Calls                = 1  => "calls",
        Imports              = 2  => "imports",
        ImportsFrom          = 3  => "imports_from",
        Uses                 = 4  => "uses",
        Method               = 5  => "method",
        Inherits             = 6  => "inherits",
        RationaleFor         = 7  => "rationale_for",
        Implements           = 8  => "implements",
        Extends              = 9  => "extends",
        References           = 10 => "references",
        IndirectCall         = 11 => "indirect_call",
        DynamicImport        = 12 => "dynamic_import",
        ReExports            = 13 => "re_exports",
        MixesIn              = 14 => "mixes_in",
        Embeds               = 15 => "embeds",
        Requires             = 16 => "requires",
        DependsOn            = 17 => "depends_on",
        ParticipatesIn       = 18 => "participate_in",
        Forms                = 19 => "form",
        SemanticallySimilarTo = 20 => "semantically_similar_to",
        Mentions             = 21 => "mentions",
        // A value flows from the source to the target: a parameter into a
        // callee's parameter, a call result into a variable, an argument into
        // an external stub. A function symbol stands for its return value at
        // either end.
        FlowsTo              = 22 => "flows_to",
        // Control-flow successor between two CFG blocks of one function. The
        // edge context carries the branch label and predicate.
        Succeeds             = 23 => "succeeds",
        // A CFG block writes a non-local symbol.
        Defines              = 24 => "defines",
        // Storage plumbing, never a fact about the code: a proxy row's link
        // to the symbol it stands in for. A file that records a value flowing
        // *out of* a symbol another file defines cannot write that edge on
        // the symbol's own row — the row, and its edges, belong to the other
        // file — so it writes it on a proxy row of its own and links the
        // proxy here. The view folds the proxy's edges into the symbol's and
        // never reports this edge.
        StandsFor            = 25 => "stands_for",
        // Value flow through a local, for presentation: `origin -> local`
        // (the local takes this value somewhere in its function) and
        // `local -> sink` (the local is read here). Flow-insensitive — a
        // local is one row for every definition of the name — which is why
        // it is not a `flows_to` and in no reachability mask.
        LocalFlow            = 26 => "local_flow",
    }
);

impl Relation {
    /// Relations that carry a *specific* structural claim, as opposed to
    /// "these two appeared together". When a simple-graph collapse has to pick
    /// one edge for a pair, a generic relation must never win over a specific
    /// one — otherwise a real `calls` edge is replaced by a vague `references`.
    pub const fn is_generic(self) -> bool {
        matches!(self, Relation::References | Relation::Uses | Relation::Mentions)
    }

    /// Relations along which control or data can propagate — the default mask
    /// for reachability and taint queries. `contains` and `method` are
    /// deliberately absent: they describe nesting, not flow, and including them
    /// would make every symbol in a file reachable from every other.
    pub const TAINT: RelationMask = RelationMask::of(&[
        Relation::Calls,
        Relation::IndirectCall,
        Relation::Imports,
        Relation::ImportsFrom,
        Relation::DynamicImport,
        Relation::ReExports,
        Relation::Requires,
        Relation::DependsOn,
    ]);

    /// The reverse-dependency walk for "what breaks if I change this". Wider
    /// than [`Relation::TAINT`]: inheritance and mixin edges do not propagate a
    /// value, but a change to a base class certainly affects its subclasses.
    pub const BLAST_RADIUS: RelationMask = RelationMask::of(&[
        Relation::Calls,
        Relation::IndirectCall,
        Relation::References,
        Relation::Imports,
        Relation::ImportsFrom,
        Relation::DynamicImport,
        Relation::ReExports,
        Relation::Inherits,
        Relation::Extends,
        Relation::Implements,
        Relation::Uses,
        Relation::MixesIn,
        Relation::Embeds,
        Relation::Requires,
        // A package dependency is a blast-radius edge for the same reason it is
        // a taint edge: if a vulnerable dependency reaches our code, then a
        // change to that dependency reaches it too. The invariant test below
        // enforces that anything propagating taint is also in this set.
        Relation::DependsOn,
        // A value that flows from a symbol is affected when the symbol
        // changes.
        Relation::FlowsTo,
    ]);

    /// Value flow only. Kept apart from [`Relation::TAINT`] on purpose: the
    /// call-graph questions must keep answering exactly as they did, and a
    /// dataflow question is asked with this mask alone.
    pub const DATA_FLOW: RelationMask = RelationMask::of(&[Relation::FlowsTo]);

    /// The control-flow graph relations. In no default traversal mask: a
    /// walk from a function should not wander into its own blocks unless the
    /// caller asks for them.
    pub const CFG: RelationMask =
        RelationMask::of(&[Relation::Succeeds, Relation::Defines, Relation::Uses]);

    /// The local-variable relations: presentation only, in no default
    /// traversal.
    pub const LOCALS: RelationMask = RelationMask::of(&[Relation::LocalFlow]);
}

/// A set of [`Relation`]s as a 64-bit mask, so an edge scan tests membership
/// with a shift and an AND rather than a set lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelationMask(pub u64);

impl RelationMask {
    pub const EMPTY: Self = Self(0);
    pub const ALL: Self = Self(u64::MAX);

    /// `const` so the standard masks above are compile-time constants.
    pub const fn of(rels: &[Relation]) -> Self {
        let mut bits = 0u64;
        let mut i = 0;
        while i < rels.len() {
            let d = rels[i] as u8;
            // `Unknown` (255) and any future relation >= 64 cannot be masked;
            // skipping keeps this total instead of overflowing the shift.
            if d < 64 {
                bits |= 1u64 << d;
            }
            i += 1;
        }
        Self(bits)
    }

    #[inline]
    pub const fn contains(self, r: Relation) -> bool {
        let d = r as u8;
        d < 64 && (self.0 & (1u64 << d)) != 0
    }

    /// Test a raw discriminant straight out of a column, without converting to
    /// the enum first. This is the form the CSR scan uses.
    #[inline]
    pub const fn contains_raw(self, d: u8) -> bool {
        d < 64 && (self.0 & (1u64 << d)) != 0
    }

    /// Is every relation in `self` also in `other`?
    ///
    /// Load-bearing: a reachability index built over one mask can only answer
    /// queries whose mask it covers. Applying it to a wider query silently
    /// rejects real paths.
    #[inline]
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Everything in `self` that is not in `other`.
    #[inline]
    pub const fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

byte_enum!(
    /// What a symbol *is*. Part of [`crate::SymbolKey`], so a class and a
    /// function of the same name in the same file are distinct symbols.
    SymbolKind {
        File      = 0  => "file",
        Module    = 1  => "module",
        Namespace = 2  => "namespace",
        Class     = 3  => "class",
        Interface = 4  => "interface",
        Trait     = 5  => "trait",
        Struct    = 6  => "struct",
        Enum      = 7  => "enum",
        Function  = 8  => "function",
        Method    = 9  => "method",
        Field     = 10 => "field",
        Constant  = 11 => "constant",
        Variable  = 12 => "variable",
        TypeAlias = 13 => "type",
        Package   = 14 => "package",
        Macro     = 15 => "macro",
        Concept   = 16 => "concept",
        Rationale = 17 => "rationale",
        // A declared parameter of a callable, including the receiver. Its
        // scope is the callable; its position is carried by the `contains`
        // edge's context.
        Parameter = 18 => "parameter",
        // A basic block of a callable's control-flow graph.
        Block     = 19 => "block",
        // A local variable of one callable: analysed for value flow and
        // stored so it can be searched and explained. Never a taint
        // endpoint, never a hub, part of no file's API.
        Local     = 20 => "local",
    }
);

byte_enum!(
    /// The broad category of the artefact a symbol came from.
    FileType {
        Code      = 0 => "code",
        Document  = 1 => "document",
        Paper     = 2 => "paper",
        Image     = 3 => "image",
        Rationale = 4 => "rationale",
        Concept   = 5 => "concept",
    }
);

byte_enum!(
    /// How much the extractor stands behind an edge.
    Confidence {
        Extracted = 0 => "EXTRACTED",
        Inferred  = 1 => "INFERRED",
        Ambiguous = 2 => "AMBIGUOUS",
    }
);

impl Confidence {
    /// The numeric weight used for ranking. Kept here rather than at the call
    /// site so every consumer scores an edge the same way.
    pub const fn score(self) -> f32 {
        match self {
            Confidence::Extracted => 1.0,
            Confidence::Inferred => 0.55,
            Confidence::Ambiguous => 0.2,
            Confidence::Unknown => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_round_trip() {
        for r in Relation::ALL {
            assert_eq!(Relation::from_u8(r.as_u8()), *r);
        }
        for k in SymbolKind::ALL {
            assert_eq!(SymbolKind::from_u8(k.as_u8()), *k);
        }
        for f in FileType::ALL {
            assert_eq!(FileType::from_u8(f.as_u8()), *f);
        }
        for c in Confidence::ALL {
            assert_eq!(Confidence::from_u8(c.as_u8()), *c);
        }
    }

    #[test]
    fn wire_names_round_trip() {
        for r in Relation::ALL {
            assert_eq!(Relation::from_str_or_unknown(r.as_str()), *r);
        }
        for k in SymbolKind::ALL {
            assert_eq!(SymbolKind::from_str_or_unknown(k.as_str()), *k);
        }
        for c in Confidence::ALL {
            assert_eq!(Confidence::from_str_or_unknown(c.as_str()), *c);
        }
    }

    /// A value from a newer writer must survive as `Unknown`, not be mapped
    /// onto a real variant.
    #[test]
    fn unrecognised_values_become_unknown() {
        assert_eq!(Relation::from_u8(200), Relation::Unknown);
        assert_eq!(Relation::from_str_or_unknown("teleports_to"), Relation::Unknown);
        assert_eq!(SymbolKind::from_u8(199), SymbolKind::Unknown);
    }

    /// Discriminants are on-disk values. If this fires, someone renumbered an
    /// existing variant and every stored segment now means something else.
    #[test]
    fn discriminants_are_pinned() {
        assert_eq!(Relation::Contains.as_u8(), 0);
        assert_eq!(Relation::Calls.as_u8(), 1);
        assert_eq!(Relation::RationaleFor.as_u8(), 7);
        assert_eq!(Relation::FlowsTo.as_u8(), 22);
        assert_eq!(Relation::Succeeds.as_u8(), 23);
        assert_eq!(Relation::Defines.as_u8(), 24);
        assert_eq!(Relation::StandsFor.as_u8(), 25);
        assert_eq!(Relation::LocalFlow.as_u8(), 26);
        assert_eq!(SymbolKind::Local.as_u8(), 20);
        assert_eq!(SymbolKind::File.as_u8(), 0);
        assert_eq!(SymbolKind::Method.as_u8(), 9);
        assert_eq!(SymbolKind::Parameter.as_u8(), 18);
        assert_eq!(SymbolKind::Block.as_u8(), 19);
        assert_eq!(FileType::Code.as_u8(), 0);
        assert_eq!(Confidence::Extracted.as_u8(), 0);
    }

    /// `RelationMask` is 64 bits wide. A 64th relation would fall out of every
    /// mask silently, so it has to fail here instead.
    #[test]
    fn every_relation_is_maskable() {
        for r in Relation::ALL {
            assert!(
                r.as_u8() < 64,
                "{r} has discriminant {} — RelationMask holds only 64 bits",
                r.as_u8()
            );
        }
    }

    #[test]
    fn masks_contain_what_they_should() {
        assert!(Relation::TAINT.contains(Relation::Calls));
        assert!(Relation::TAINT.contains(Relation::IndirectCall));
        // Nesting is not flow.
        assert!(!Relation::TAINT.contains(Relation::Contains));
        assert!(!Relation::TAINT.contains(Relation::Method));
        // Value flow is asked for separately; the call-graph answers must not
        // move when dataflow lands.
        assert!(!Relation::TAINT.contains(Relation::FlowsTo));
        assert!(Relation::DATA_FLOW.contains(Relation::FlowsTo));
        assert!(Relation::BLAST_RADIUS.contains(Relation::FlowsTo));
        // The CFG stays out of every flow mask.
        for r in [Relation::Succeeds, Relation::Defines, Relation::Uses] {
            assert!(Relation::CFG.contains(r));
            assert!(!Relation::TAINT.contains(r), "{r} leaked into TAINT");
            assert!(!Relation::DATA_FLOW.contains(r), "{r} leaked into DATA_FLOW");
        }
        assert!(!RelationMask::ALL.minus(Relation::CFG).contains(Relation::Succeeds));
        assert!(RelationMask::ALL.minus(Relation::CFG).contains(Relation::Calls));
        // Blast radius is strictly wider than taint.
        for r in Relation::ALL {
            if Relation::TAINT.contains(*r) {
                assert!(
                    Relation::BLAST_RADIUS.contains(*r),
                    "{r} propagates taint but is not in the blast radius"
                );
            }
        }
    }

    #[test]
    fn raw_mask_matches_typed_mask() {
        for r in Relation::ALL {
            assert_eq!(
                Relation::TAINT.contains(*r),
                Relation::TAINT.contains_raw(r.as_u8())
            );
        }
    }

    #[test]
    fn subset_is_reflexive_and_ordered() {
        assert!(Relation::TAINT.is_subset_of(Relation::TAINT));
        assert!(Relation::TAINT.is_subset_of(RelationMask::ALL));
        assert!(RelationMask::EMPTY.is_subset_of(Relation::TAINT));
        // Blast radius is strictly wider, so it is not a subset of taint.
        assert!(!Relation::BLAST_RADIUS.is_subset_of(Relation::TAINT));
        assert!(!RelationMask::ALL.is_subset_of(Relation::TAINT));
    }

    #[test]
    fn unknown_is_never_in_a_mask() {
        assert!(!RelationMask::ALL.contains(Relation::Unknown));
        assert!(!Relation::TAINT.contains(Relation::Unknown));
    }

    #[test]
    fn generic_relations_are_the_denylist() {
        assert!(Relation::References.is_generic());
        assert!(Relation::Uses.is_generic());
        assert!(Relation::Mentions.is_generic());
        assert!(!Relation::Calls.is_generic());
        assert!(!Relation::Contains.is_generic());
    }

    #[test]
    fn confidence_scores_are_ordered() {
        assert!(Confidence::Extracted.score() > Confidence::Inferred.score());
        assert!(Confidence::Inferred.score() > Confidence::Ambiguous.score());
        assert_eq!(Confidence::Unknown.score(), 0.0);
    }

    #[test]
    fn enums_are_one_byte() {
        assert_eq!(size_of::<Relation>(), 1);
        assert_eq!(size_of::<SymbolKind>(), 1);
        assert_eq!(size_of::<FileType>(), 1);
        assert_eq!(size_of::<Confidence>(), 1);
    }
}
