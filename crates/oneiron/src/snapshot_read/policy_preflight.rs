//! `vault.policy.preflight` (primitive A, slices 6.4e and 6.4e-2): what the
//! caller's own read lets it do with each of a list of refs, before it acts.
//!
//! The act `read` answers, per ref, `readable` (with the row's version and
//! the source-audience policies the caller's read of it meets, along its
//! lineage, which a row derived from it reads under too) or `withheld`. A
//! withheld ref says nothing more: no reason, no audience, and an absent
//! id answers the same, so the answer never tells a row the caller may not
//! read from one that does not exist. The caller's ceiling (requested,
//! ceiling and applied axes) is the read's own receipt.
//!
//! The acts `derive` and `archive` answer the same, and a readable ref also
//! carries the derive verdict on it: whether a derivation item of the
//! caller's that changes the row (`derive`: settle, supersede, link or
//! publish an artifact about it; `archive`: archive it) passes the caller's
//! live grant now, with the grant it is judged by or the refusal's stable
//! token. It is [`crate::gate::derive_verdict_in_txn`], the one judge a
//! `vault.derive.commit` item meets, with the same tokens, asked in the
//! read's own snapshot (ENGINE CALL S64E-JUDGE = A). An item's own checks
//! (an archive's score and pins, a settlement's open marker) are judged at
//! the commit, and a new claim item meets the claim gate there. A withheld
//! ref carries no verdict.
//!
//! It is observation only: it mints, grants and writes nothing, and the real
//! act is judged again when it is made.

use serde::{Deserialize, Serialize};

use super::source_version::{SourceVersion, source_version_in_txn};
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault, WriteActor};

/// The most refs one `vault.policy.preflight` request names.
pub const POLICY_PREFLIGHT_MAX_REFS: usize = 100;

/// The act a preflight asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreflightAct {
    /// Reading each ref through the caller's own scoped read.
    Read,
    /// Changing each ref by a derivation item: settling, superseding or
    /// linking it, or publishing an artifact about it (the Steward `derive`
    /// verb).
    Derive,
    /// Archiving each ref, reversibly, by a derivation item (the Steward
    /// `archive` verb).
    Archive,
}

impl PolicyPreflightAct {
    /// The capability the derive verdict judges for this act; none for
    /// `read`.
    const fn derive_capability(self) -> Option<DeriveCapability> {
        match self {
            Self::Read => None,
            Self::Derive => Some(DeriveCapability::Derive),
            Self::Archive => Some(DeriveCapability::Archive),
        }
    }
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

/// The derive verdict on one readable ref, for the acts `derive` and
/// `archive`: what a `vault.derive.commit` item of the caller's that changes
/// the row would be told by its grant, judged now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PolicyPreflightVerdict {
    /// The caller's live grant allows the act.
    Allowed {
        /// The grant a commit's receipt names: the newest standing Steward
        /// grant row's id, or the policy rows' ref for a base agent no grant
        /// row names yet.
        grant: String,
    },
    /// The caller's live grant refuses the act.
    Refused {
        /// The stable refusal token a commit's receipt carries
        /// (`gate.deny.derive.*`).
        reason: String,
    },
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
        /// CLAIM's supports, each one the caller reads; of a witnessed TURN,
        /// each MESSAGE row its text was read from). A row derived from it
        /// reads under them too. Empty for a row no source policy reaches.
        audience: Vec<EntityId>,
        /// For the acts `derive` and `archive`, the derive verdict on the
        /// row. Absent for the act `read`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verdict: Option<PolicyPreflightVerdict>,
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
/// caller's own read, and for the acts `derive` and `archive` under the
/// derive verdict of the actor the caller writes as.
///
/// # Errors
///
/// A request that fails [`validate_policy_preflight`], the caller's read
/// lane, a policy manifest that does not resolve, and storage errors.
pub fn policy_preflight(
    memory: &Memory<'_>,
    input: &PolicyPreflightRequest,
) -> MemoryResult<ScopedReadResult<PolicyPreflight>> {
    validate_policy_preflight(input)?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let points: Vec<PointRead<'_>> = input.refs.iter().copied().map(PointRead::id).collect();
    let vault = memory.vault();
    let capability = input.act.derive_capability();
    // The actor a derivation commit of this caller's is stamped with.
    let actor = memory.write_actor();
    // The viewers the read's own source-audience judgment asks of.
    let viewers: Vec<EntityId> = read
        .actor_key()
        .authenticated_person()
        .into_iter()
        .collect();
    let dbs = read.store_read();
    read.read_projected(
        &points,
        None,
        |txn, _rows| -> MemoryResult<PolicyPreflight> {
            let mut refs = Vec::with_capacity(input.refs.len());
            for entity in &input.refs {
                let Some((version, text)) = source_version_in_txn(&read, txn, entity)? else {
                    refs.push(PolicyPreflightRef::Withheld { entity: *entity });
                    continue;
                };
                // A witnessed TURN's words are its MESSAGE rows', each read
                // through the caller's read; their lineage is the TURN's
                // audience too (review of #6985, round 2).
                let mut roots = vec![*entity];
                if let Some(text) = &text {
                    roots.extend(text.message_ids());
                }
                let audience =
                    crate::source_audience::read_audience_in(vault, &dbs, txn, &roots, &viewers)?;
                let verdict = capability
                    .map(|capability| verdict_in_txn(vault, txn, actor, capability, *entity))
                    .transpose()?;
                refs.push(PolicyPreflightRef::Readable {
                    entity: *entity,
                    version,
                    audience: audience.into_iter().collect(),
                    verdict,
                });
            }
            Ok(PolicyPreflight {
                act: input.act,
                refs,
            })
        },
    )
}

/// The derive verdict on `target` for `actor` doing `capability`, in `txn`.
fn verdict_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    capability: DeriveCapability,
    target: EntityId,
) -> crate::error::Result<PolicyPreflightVerdict> {
    Ok(
        match derive_verdict_in_txn(&vault.store, txn, actor, capability, Some(target))? {
            Ok(allowance) => PolicyPreflightVerdict::Allowed {
                grant: allowance.grant_ref,
            },
            Err(refusal) => PolicyPreflightVerdict::Refused {
                reason: refusal.token().to_owned(),
            },
        },
    )
}
