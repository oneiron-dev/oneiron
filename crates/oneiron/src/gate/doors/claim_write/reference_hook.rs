//! The staged-reference probe's hook into the claim write door (FIX 11304).
//!
//! The batch preflight probes the reader-bound door in a savepoint that is
//! always rolled back, only for the receipt the gate records with a staged
//! reference denial. A staged-only Dreamer precommit failure would shadow
//! that denial there (`hard_denial = precommit.or(reference)`), leaving the
//! denial standing with no receipt. The probe seam here runs the gate
//! reference-only instead, so the gate's own receipt path records the
//! reference verdict; the reference verdict below is the hook the inner
//! executor judges it with.

use crate::claim::{ClaimBody, ScopedRead};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::decision::GateReasonCode;
use crate::gate::resolution::PolicyManifestResolution;
use crate::gate::{ClaimGateWrite, GateWriteMode, RecordedClaimGateDecision};
use crate::store::Store;

/// [`super::check_claim_policy_for_write_with_record_with_reader`] for the
/// rolled-back staged-reference probe only (FIX 11304): the Dreamer
/// precommit is skipped, so `hard_denial` is the reference verdict and the
/// gate's own receipt path records it. A committed write never takes this
/// seam: every other caller of the inner executor passes `false`, so a real
/// write always runs the precommit.
#[expect(
    clippy::too_many_arguments,
    reason = "the record seam's arguments plus the writer's own scoped read"
)]
pub(crate) fn check_claim_policy_for_write_with_record_with_reader_reference_probe(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    reader: &ScopedRead<'_>,
) -> Result<()> {
    super::check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        recorded_decision,
        None,
        false,
        // Only this probe skips the precommit, in its rolled-back savepoint.
        true,
        Some(reader),
    )
}

/// The hard reference verdict over `body` under the writer's own `reader`
/// (OF-063, FIX 1218): a record the body names that does not resolve for it
/// here, in this final snapshot, denies in the same slot as a validity
/// refusal, after it. A synthetic operation body is not a persisted claim
/// and is not judged.
pub(super) fn reference_denial(
    wtxn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    reader: Option<&ScopedRead<'_>>,
    operation_effect_body: bool,
) -> Result<Option<GateReasonCode>> {
    let Some(reader) = reader.filter(|_| !operation_effect_body) else {
        return Ok(None);
    };
    let Some(field) = super::unresolved_claim_reference(reader, wtxn, body)? else {
        return Ok(None);
    };
    tracing::info!(%field, "a claim names a record its writer cannot read; denied");
    Ok(Some(GateReasonCode::DenyUnresolvedRecordReference))
}
