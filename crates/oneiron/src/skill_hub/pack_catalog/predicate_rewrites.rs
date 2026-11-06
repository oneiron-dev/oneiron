//! Predicate rewrite classifications carried by pack-source migration maps.

use std::collections::BTreeSet;

pub use crate::store::pack_predicate_rewrites::{PackMigrationMap, PackPredicateRewrite};

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
