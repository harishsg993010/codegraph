//! Ranking a candidate set against a query.
//!
//! Scoring is tiered rather than a single blended number: an exact name match
//! must always outrank a prefix match, which must always outrank a substring
//! match, no matter how the secondary signals fall. A blended score lets a
//! high-degree substring match displace an exact one, which reads as a bug to
//! anyone using it.

use codegraph_core::LocalId;

/// Match quality, best first. The discriminant *is* the precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Exact = 0,
    Prefix = 1,
    Substring = 2,
    PathOnly = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scored {
    pub id: LocalId,
    pub tier: Tier,
    /// Degree, used only to break ties *within* a tier.
    pub degree: u32,
    /// Shorter names win ties at equal degree: `get` is a better answer for
    /// "get" than `get_or_create_with_default`.
    pub name_len: u32,
}

/// Classify one candidate against a folded query.
pub fn classify(name: &str, path: &str, query: &str) -> Option<Tier> {
    if name == query {
        Some(Tier::Exact)
    } else if name.starts_with(query) {
        Some(Tier::Prefix)
    } else if name.contains(query) {
        Some(Tier::Substring)
    } else if path.contains(query) {
        Some(Tier::PathOnly)
    } else {
        None
    }
}

/// Order by tier, then degree descending, then shorter name, then id.
///
/// The final `id` term is not cosmetic: without it two equal candidates order
/// by whatever the sort happened to do, and the same query returns different
/// answers on different runs.
pub fn rank(mut hits: Vec<Scored>) -> Vec<Scored> {
    hits.sort_unstable_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then(b.degree.cmp(&a.degree))
            .then(a.name_len.cmp(&b.name_len))
            .then(a.id.get().cmp(&b.id.get()))
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(id: u32, tier: Tier, degree: u32, name_len: u32) -> Scored {
        Scored { id: LocalId::new(id), tier, degree, name_len }
    }

    #[test]
    fn classification_is_ordered_by_specificity() {
        assert_eq!(classify("get", "a.py", "get"), Some(Tier::Exact));
        assert_eq!(classify("get_all", "a.py", "get"), Some(Tier::Prefix));
        assert_eq!(classify("forget", "a.py", "get"), Some(Tier::Substring));
        assert_eq!(classify("zzz", "widgets.py", "get"), Some(Tier::PathOnly));
        assert_eq!(classify("zzz", "a.py", "get"), None);
    }

    /// The property the tiering exists for: a hugely popular substring match
    /// must not outrank an exact match.
    #[test]
    fn tier_beats_degree() {
        let out = rank(vec![
            s(1, Tier::Substring, 10_000, 3),
            s(2, Tier::Exact, 1, 3),
        ]);
        assert_eq!(out[0].id.get(), 2, "a substring match outranked an exact one");
    }

    #[test]
    fn degree_breaks_ties_within_a_tier() {
        let out = rank(vec![s(1, Tier::Exact, 5, 3), s(2, Tier::Exact, 50, 3)]);
        assert_eq!(out[0].id.get(), 2);
    }

    #[test]
    fn shorter_names_win_at_equal_degree() {
        let out = rank(vec![s(1, Tier::Prefix, 5, 30), s(2, Tier::Prefix, 5, 3)]);
        assert_eq!(out[0].id.get(), 2);
    }

    #[test]
    fn ordering_is_total_so_results_are_reproducible() {
        let a = rank(vec![s(9, Tier::Exact, 5, 3), s(2, Tier::Exact, 5, 3)]);
        let b = rank(vec![s(2, Tier::Exact, 5, 3), s(9, Tier::Exact, 5, 3)]);
        assert_eq!(a, b, "ranking depends on input order");
    }
}
