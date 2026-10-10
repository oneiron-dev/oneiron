//! Pack drift (ARCH-0059 §4): what the repair ladder did to saved queries
//! when a pack moved under them: a migration, a rewrite and its notice, or a
//! proposal the query's owner decides. A query the ladder paused carries its
//! error on the query itself.

use oneiron::Vault;
use serde::Serialize;

use super::OwnerResult;
use super::stamp::rfc3339_secs;

#[derive(Debug, Serialize)]
pub(crate) struct Repair {
    pub(crate) id: String,
    pub(crate) query: String,
    pub(crate) summary: String,
    pub(crate) recorded_at: String,
    pub(crate) pack: String,
    pub(crate) from_version: String,
    pub(crate) to_version: String,
    /// The predicates the move touched in this query.
    pub(crate) predicates: Vec<String>,
}

pub(crate) fn repairs(vault: &Vault) -> OwnerResult<Vec<Repair>> {
    Ok(oneiron::saved_query::pack_drift_repairs(vault)?
        .into_iter()
        .map(|repair| Repair {
            id: repair.repair_ref.to_hex(),
            query: repair.query_ref.to_hex(),
            summary: repair.summary,
            recorded_at: rfc3339_secs(repair.recorded_at),
            pack: repair.drift.to_pack_id,
            from_version: repair.drift.from_version,
            to_version: repair.drift.to_version,
            predicates: repair.drift.affected_predicates,
        })
        .collect())
}
