//! `vault.policy.preflight` (primitive A, slice 6.4e): what the caller's own
//! read lets it do with each of a list of refs, before it acts.
//!
//! The act `read` answers, per ref, `readable` (with the row's version and
//! the source-audience policies the caller's read of it meets, along its
//! lineage, which a row derived from it reads under too) or `withheld`. A
//! withheld ref says nothing more: no reason, no audience, and an absent
//! id answers the same, so the answer never tells a row the caller may not
//! read from one that does not exist. The caller's ceiling (requested,
//! ceiling and applied axes) is the read's own receipt.
//!
//! It is observation only: it mints, grants and writes nothing, and the real
//! act is judged again when it is made.

use serde::{Deserialize, Serialize};

use super::source_version::{SourceVersion, source_version_in_txn};
use crate::EntityId;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::memory::{Memory, MemoryError, MemoryResult};

/// The most refs one `vault.policy.preflight` request names.
pub const POLICY_PREFLIGHT_MAX_REFS: usize = 100;

/// The act a preflight asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreflightAct {
    /// Reading each ref through the caller's own scoped read.
    Read,
}

/// One `vault.policy.preflight` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyPreflightRequest {
    /// The refs, at most [`POLICY_PREFLIGHT_MAX_REFS`]; each is answered in
    /// this order.
    pub refs: Vec<EntityId>,
    /// The act the caller means to take on them.
    pub act: PolicyPreflightAct,
}

/// What the caller's read lets it do with one ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PolicyPreflightRef {
    /// The caller reads the row.
    Readable {
        /// The ref.
        entity: EntityId,
        /// The row as the caller's read serves it now.
        version: SourceVersion,
        /// The source-audience policies the caller's read of the row meets,
        /// along the lineage that read judges: those carried to it and the
        /// one binding it, and those of every row its words came from (of a
        /// CLAIM's supports, each one the caller reads). A row derived from
        /// it reads under them too. Empty for a row no source policy reaches.
        audience: Vec<EntityId>,
    },
    /// The caller does not read the row, or no such row is live. Nothing
    /// more is said.
    Withheld {
        /// The ref.
        entity: EntityId,
    },
}

/// The answer to one preflight, ref by ref, in the request's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyPreflight {
    /// The act judged.
    pub act: PolicyPreflightAct,
    /// One answer per ref.
    pub refs: Vec<PolicyPreflightRef>,
}

/// Refuses a request with no refs or more than [`POLICY_PREFLIGHT_MAX_REFS`].
///
/// # Errors
///
/// `BAD_REQUEST` for either.
pub fn validate_policy_preflight(input: &PolicyPreflightRequest) -> MemoryResult<()> {
    if input.refs.is_empty() {
        return Err(MemoryError::bad_request(
            "a preflight names at least one ref",
        ));
    }
    if input.refs.len() > POLICY_PREFLIGHT_MAX_REFS {
        return Err(MemoryError::bad_request(format!(
            "at most {POLICY_PREFLIGHT_MAX_REFS} refs per preflight"
        )));
    }
    Ok(())
}

/// `vault.policy.preflight`: each ref judged in one snapshot under the
/// caller's own read.
///
/// # Errors
///
/// A request that fails [`validate_policy_preflight`], the caller's read
/// lane, and storage errors.
pub fn policy_preflight(
    memory: &Memory<'_>,
    input: &PolicyPreflightRequest,
) -> MemoryResult<ScopedReadResult<PolicyPreflight>> {
    validate_policy_preflight(input)?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let points: Vec<PointRead<'_>> = input.refs.iter().copied().map(PointRead::id).collect();
    let vault = memory.vault();
    // The viewers the read's own source-audience judgment asks of.
    let viewers: Vec<EntityId> = read.actor_key().authenticated_person().into_iter().collect();
    let dbs = read.store_read();
    read.read_projected(
        &points,
        None,
        |txn, _rows| -> MemoryResult<PolicyPreflight> {
            let mut refs = Vec::with_capacity(input.refs.len());
            for entity in &input.refs {
                let Some((version, _)) = source_version_in_txn(&read, txn, entity)? else {
                    refs.push(PolicyPreflightRef::Withheld { entity: *entity });
                    continue;
                };
                let audience =
                    crate::source_audience::read_audience_in(vault, &dbs, txn, entity, &viewers)?;
                refs.push(PolicyPreflightRef::Readable {
                    entity: *entity,
                    version,
                    audience: audience.into_iter().collect(),
                });
            }
            Ok(PolicyPreflight {
                act: input.act,
                refs,
            })
        },
    )
}
