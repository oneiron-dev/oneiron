//! Predicate rewrite classifications carried by pack-source migration maps.

use std::collections::BTreeMap;

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
