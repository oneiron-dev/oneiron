//! Predicate rewrite classifications carried by pack-source migration maps.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// How one affected predicate can be carried across a pack move.
///
/// The CLASSIFICATION lives on the map entry, supplied by whoever authored the
/// pack move, because only that author knows whether a rename preserves
/// meaning. The engine's job is to apply the ladder faithfully, not to guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PackPredicateRewrite {
    /// Pure rename. Auto-migrates.
    Rename {
        /// New predicate.
        to: String,
    },
    /// Different spelling, same meaning. Auto-rewrites with a notice.
    Equivalent {
        /// New predicate.
        to: String,
        /// Notice recorded on the receipt.
        note: String,
    },
    /// Meaning changed. Requires an owner proposal.
    SemanticsChanging {
        /// Proposed new predicate.
        to: String,
        /// What changed.
        note: String,
    },
}

/// Per-predicate rewrites for one pack move.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackMigrationMap {
    /// Old predicate to its rewrite.
    pub rewrites: BTreeMap<String, PackPredicateRewrite>,
}

/// One installed pack moving to another source, as the install door sees it.
pub(crate) struct PackMove<'a> {
    pub(crate) pack: &'a str,
    pub(crate) from_version: &'a str,
    pub(crate) to_version: &'a str,
    /// Content hash of the installed source.
    pub(crate) from_source: &'a str,
    /// Content hash of the new source.
    pub(crate) to_source: &'a str,
    /// Predicates the installed source declared.
    pub(crate) from_predicates: &'a BTreeSet<String>,
    /// Predicates the new source declares.
    pub(crate) to_predicates: &'a BTreeSet<String>,
    /// The map the new source ships for a move from the installed one.
    pub(crate) shipped: Option<PackMigrationMap>,
}
