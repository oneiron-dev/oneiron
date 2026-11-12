//! Caller-readable policy contributors, not the policy in force.

use serde::{Deserialize, Serialize};

use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::gate::policy_manifest_doors::{PolicyManifestView, body_in_txn, view_in_txn};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

const GATE_POLICY_RESOLVE_READ_VERB: &str = "vault.gate.policy.resolve";

/// The policy contributor rows the caller may read, not the policy in force.
/// No resolved values or information about contributors outside the lane is returned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReadablePolicyManifestRows {
    pub manifests: Vec<PolicyManifestView>,
}

/// These are the policy rows the caller may read, not the policy in force.
/// Grant time and body pins are prepared first; the verb Grant, contributor
/// scan, row admission and views then share one serving snapshot. The
/// receipt and producer labels cover only returned rows.
pub fn vault_gate_policy_resolve_embedded(
    memory: &Memory<'_>,
) -> MemoryResult<ScopedReadResult<ReadablePolicyManifestRows>> {
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    let _bodies = lane.prepare_point_read::<MemoryError>()?;
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    let standing = crate::authority::principal_standing_in_txn(
        memory.vault(),
        &txn,
        memory.actor(),
        memory.actor_class(),
        GATE_POLICY_RESOLVE_READ_VERB,
    )?;
    if standing.is_none() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{GATE_POLICY_RESOLVE_READ_VERB} takes a live Grant naming the verb"),
            &["Have the owner grant this caller the verb by name."],
        ));
    }
    let reads: Vec<_> = crate::gate::policy_manifest_contributors(&memory.vault().store, &txn)?
        .into_iter()
        .map(PointRead::id)
        .collect();
    lane.read_projected_opaque_in_txn(
        &txn,
        &reads,
        None,
        |_, _| Ok(true),
        |txn, rows| {
            let mut manifests = Vec::new();
            let mut served = Vec::new();
            for row in rows.into_iter().flatten() {
                let Some(body) = body_in_txn(memory.vault(), txn, row.id)? else {
                    continue;
                };
                manifests.push(view_in_txn(memory.vault(), txn, row.id, &body)?);
                served.push(row.id);
            }
            memory.produced_from(served);
            Ok::<_, MemoryError>(ReadablePolicyManifestRows { manifests })
        },
    )
}
