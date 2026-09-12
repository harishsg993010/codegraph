//! The three id layers, and the content fingerprint that anchors them.
//!
//! - [`SymbolKey`] is the **primary key**: content-derived, stable across
//!   rebuilds, never rewritten.
//! - [`LocalId`] is a dense per-segment ordinal, used to index columns and CSR
//!   arrays. It is meaningful only inside one segment.
//! - [`FileId`] and [`StrId`] index the per-segment file and string tables.
//!
//! Only `SymbolKey` is stable across segments. Anything persisted that must
//! survive a rebuild stores a `SymbolKey`; anything internal to one segment
//! stores a `LocalId`, because a `u32` in a CSR array is the whole point.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

macro_rules! dense_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            FromBytes, IntoBytes, Immutable, KnownLayout,
        )]
        #[repr(transparent)]
        pub struct $name(pub u32);

        impl $name {
            /// The absent value. `u32::MAX` rather than `0`, because `0` is a
            /// perfectly good ordinal and using it as a sentinel makes "the
            /// first element" and "no element" indistinguishable.
            pub const NONE: Self = Self(u32::MAX);

            #[inline]
            pub const fn new(v: u32) -> Self {
                Self(v)
            }
            #[inline]
            pub const fn get(self) -> u32 {
                self.0
            }
            #[inline]
            pub const fn is_none(self) -> bool {
                self.0 == u32::MAX
            }
            #[inline]
            pub const fn index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

dense_id!(
    /// Dense ordinal of a symbol *within one segment*. Never persisted across
    /// segments — use [`SymbolKey`] for that.
    LocalId
);
dense_id!(
    /// Index into a segment's file table.
    FileId
);
dense_id!(
    /// Index into a segment's string arena.
    StrId
);

/// The inputs a [`SymbolKey`] is derived from.
///
/// `scope` is the chain of enclosing symbol names, outermost first — the
/// containing class for a method, the containing class chain for a nested type.
/// It is **not** optional in practice: Phase 0 measured a real corpus where
/// keying on `(path, name)` alone folded 26% of symbols together, because a file
/// with five classes has five `__init__` methods. The scope is what separates
/// them.
#[derive(Debug, Clone, Copy)]
pub struct SymbolKeyParts<'a> {
    /// Repo tag. Empty for a single-repo store.
    pub repo: &'a str,
    /// Repo-relative path, forward slashes, NFC-normalised. Never absolute —
    /// an absolute path would make the key differ per checkout.
    pub path: &'a str,
    pub kind: crate::vocab::SymbolKind,
    /// Enclosing scope names, outermost first.
    pub scope: &'a [&'a str],
    pub name: &'a str,
    /// Distinguishes genuine duplicates that agree on every field above — two
    /// conditionally-compiled definitions of the same function in one file, for
    /// instance. `0` for the common case.
    pub disambiguator: u32,
}

/// A 128-bit content fingerprint identifying a symbol.
///
/// Stability is the whole contract: the same symbol in the same place must hash
/// identically on every machine and every rebuild, so that an incremental update
/// can replace one file's symbols without disturbing the edges pointing at them.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
    FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(transparent)]
pub struct SymbolKey(pub u128);

impl SymbolKey {
    /// The absent key. All-ones rather than zero: zero is a plausible hash
    /// output, all-ones is too (but a collision on either is ~2^-128, and
    /// all-ones reads unmistakably as a sentinel in a hex dump).
    pub const NONE: Self = Self(u128::MAX);

    /// Derive a key from its parts.
    ///
    /// Every field is **length-prefixed** before hashing. Concatenating them
    /// raw would not be injective: `repo="ab", path="c"` and `repo="a",
    /// path="bc"` would produce identical input and therefore identical keys
    /// for two different symbols.
    pub fn new(parts: SymbolKeyParts<'_>) -> Self {
        /// Length-prefix then content, so field boundaries are unambiguous.
        fn field(h: &mut blake3::Hasher, bytes: &[u8]) {
            h.update(&(bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }

        let mut h = blake3::Hasher::new();
        field(&mut h, parts.repo.as_bytes());
        field(&mut h, parts.path.as_bytes());
        h.update(&[parts.kind as u8]);
        // The scope chain is length-prefixed as a whole *and* per element, so
        // `["a", "bc"]` and `["ab", "c"]` cannot collide either.
        h.update(&(parts.scope.len() as u64).to_le_bytes());
        for s in parts.scope {
            field(&mut h, s.as_bytes());
        }
        field(&mut h, parts.name.as_bytes());
        h.update(&parts.disambiguator.to_le_bytes());

        let out = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&out.as_bytes()[..16]);
        Self(u128::from_le_bytes(b))
    }

    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == u128::MAX
    }
}

impl std::fmt::Display for SymbolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocab::SymbolKind;

    fn parts<'a>(path: &'a str, scope: &'a [&'a str], name: &'a str) -> SymbolKeyParts<'a> {
        SymbolKeyParts {
            repo: "",
            path,
            kind: SymbolKind::Method,
            scope,
            name,
            disambiguator: 0,
        }
    }

    #[test]
    fn is_deterministic() {
        let a = SymbolKey::new(parts("src/a.py", &["Alpha"], "__init__"));
        let b = SymbolKey::new(parts("src/a.py", &["Alpha"], "__init__"));
        assert_eq!(a, b);
    }

    /// The Phase 0 finding, encoded as a test: same file, same method name,
    /// different owning class must be different symbols.
    #[test]
    fn scope_separates_same_named_methods() {
        let a = SymbolKey::new(parts("src/a.py", &["Alpha"], "__init__"));
        let b = SymbolKey::new(parts("src/a.py", &["Beta"], "__init__"));
        assert_ne!(a, b);
    }

    #[test]
    fn path_separates_same_named_symbols() {
        let a = SymbolKey::new(parts("src/a.py", &[], "run"));
        let b = SymbolKey::new(parts("src/b.py", &[], "run"));
        assert_ne!(a, b);
    }

    #[test]
    fn kind_is_part_of_identity() {
        let mut a = parts("src/a.py", &[], "Thing");
        a.kind = SymbolKind::Class;
        let mut b = parts("src/a.py", &[], "Thing");
        b.kind = SymbolKind::Function;
        assert_ne!(SymbolKey::new(a), SymbolKey::new(b));
    }

    #[test]
    fn disambiguator_separates_otherwise_identical_symbols() {
        let mut a = parts("src/a.py", &[], "run");
        let mut b = parts("src/a.py", &[], "run");
        a.disambiguator = 0;
        b.disambiguator = 1;
        assert_ne!(SymbolKey::new(a), SymbolKey::new(b));
    }

    /// Length-prefixing is not decorative: without it these two collide.
    #[test]
    fn field_boundaries_are_injective() {
        let a = SymbolKey::new(SymbolKeyParts {
            repo: "ab",
            path: "c",
            kind: SymbolKind::Function,
            scope: &[],
            name: "x",
            disambiguator: 0,
        });
        let b = SymbolKey::new(SymbolKeyParts {
            repo: "a",
            path: "bc",
            kind: SymbolKind::Function,
            scope: &[],
            name: "x",
            disambiguator: 0,
        });
        assert_ne!(a, b);
    }

    /// Same, for the scope chain.
    #[test]
    fn scope_boundaries_are_injective() {
        let a = SymbolKey::new(parts("p", &["a", "bc"], "n"));
        let b = SymbolKey::new(parts("p", &["ab", "c"], "n"));
        assert_ne!(a, b);
    }

    /// A nested scope must not be confusable with a flattened one.
    #[test]
    fn nesting_depth_matters() {
        let a = SymbolKey::new(parts("p", &["Outer", "Inner"], "m"));
        let b = SymbolKey::new(parts("p", &["Outer.Inner"], "m"));
        assert_ne!(a, b);
    }

    #[test]
    fn sentinels_are_recognisable() {
        assert!(SymbolKey::NONE.is_none());
        assert!(LocalId::NONE.is_none());
        assert!(!LocalId::new(0).is_none());
        assert!(!SymbolKey::new(parts("p", &[], "n")).is_none());
    }

    #[test]
    fn dense_ids_round_trip() {
        assert_eq!(LocalId::new(7).get(), 7);
        assert_eq!(FileId::new(0).index(), 0);
        assert_eq!(StrId::new(9).index(), 9);
    }
}
