use sha2::{Digest, Sha256};

use crate::authority::{CRITICAL_WRITE_CONFIRM_DOMAIN, CriticalWriteConfirmDisposition};

use crate::batch::{BatchOp, EntityMetadataHeader, apply_session_bundle_claim_puts};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, encode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::{GateDecisionId, PendingGateConsentRecord, Store};
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::ceiling::PolicyCriticality;
use super::decision::GateReasonCode;
use super::input::{GateContentKind, GateEvaluatorInput};

pub const CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS: u64 = 300;
// A public listing uses one expiry pass plus one listing pass: at most 512 rows total.
const CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT: usize = 256;
const CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET: usize = CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT * 2;
pub const GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.allow.critical_confirm_attached";
// The decision receipt uses the allow namespace; the durable pending row must
// remain in store.rs's existing pending namespace.
pub(super) const GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.pending.critical_confirm_attached";
pub const GATE_REASON_CRITICAL_CONFIRM_TIMEOUT: &str = "gate.pending.critical_confirm_timeout";
pub const GATE_REASON_CRITICAL_CONFIRM_DECLINED: &str = "gate.retract.critical_confirm_declined";
pub(crate) const GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE: &str =
    "gate.retract.critical_confirm_replicated_overwrite";

/// A private, single-use authority for a settlement status rewrite.
///
/// Its fields are deliberately not caller supplied at the materialization door:
/// only the verified timeout/sweep and authority-fold paths below can construct it.
#[derive(Clone, Copy)]
pub(super) enum PreauthorizedClaimStatusGrant {
    TimeoutDemotion,
    FoldDecline,
}

#[cfg(test)]
impl PreauthorizedClaimStatusGrant {
    // Test-only access verifies the materialization door's row/header binding.
    pub(super) fn test_timeout_demotion() -> Self {
        Self::TimeoutDemotion
    }
}

pub(super) fn put_preauthorized_claim_status_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    expected: &ClaimBody,
    grant: PreauthorizedClaimStatusGrant,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let current = vault
        .get_claim_in_txn(&*wtxn, id)?
        .ok_or(Error::EntityNotFound)?;
    let raw = vault
        .store
        .entities
        .get(&*wtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM
        || header.occurred_start != occurred.start
        || header.occurred_end != occurred.end
        || header.learned_at != learned_at
        || current != *expected
    {
        return Err(Error::InvariantViolation(
            "preauthorized claim status update does not bind current claim row",
        ));
    }
    let mut updated = current;
    match grant {
        PreauthorizedClaimStatusGrant::TimeoutDemotion => {
            updated.approval = ClaimApprovalStatus::Proposed;
        }
        PreauthorizedClaimStatusGrant::FoldDecline => {
            updated.lifecycle = ClaimLifecycleStatus::Retracted;
        }
    }
    let data = encode_claim_body(&updated)?;
    crate::claim::validate_claim_body_bytes(&data, false)?;
    apply_session_bundle_claim_puts(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
    )
}

impl Vault {
    /// Lists live confirmations in deterministic order within one bounded page.
    /// Calls advance a bounded sweep cursor; this is not a global ordering guarantee.
    /// One expiry pass and one listing pass inspect at most
    /// `CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET` logical pending records combined.
    /// Each logical record separately touches its sequence-index row and primary row.
    pub fn pending_critical_write_confirms(
        &self,
        limit: usize,
    ) -> Result<Vec<CriticalWriteConfirmBinding>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = crate::unix_seconds_now();
        const {
            assert!(
                CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET <= 512,
                "a public list call may inspect no more than 512 logical pending records",
            );
        }
        self.expire_critical_write_confirms()?;
        self.with_write_txn(|wtxn| {
            let (cursor, prior_fence) = self
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?;
            let fence = match prior_fence {
                Some(fence) => Some(fence),
                None => self.store.pending_gate_consents_high_water_in_txn(&*wtxn)?,
            };
            let page = self.store.pending_gate_consents_page_in_txn(
                &*wtxn,
                cursor,
                fence,
                CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT,
            )?;
            let mut bindings = Vec::with_capacity(limit.min(page.len()));
            let mut last_inspected = None;
            for (sequence, pending) in page {
                last_inspected = Some(sequence);
                if let Ok(binding) = critical_write_confirm_binding(&pending)
                    && binding.expires_at > now
                {
                    // Preserve the established public ordering for each
                    // bounded result page; sequence only controls sweep progress.
                    bindings.push((
                        pending.created_at,
                        pending.decision_id,
                        pending.claim_id,
                        binding,
                    ));
                    if bindings.len() == limit {
                        break;
                    }
                }
            }
            bindings.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.as_bytes().cmp(&right.1.as_bytes()))
                    .then_with(|| left.2.cmp(&right.2))
            });
            let bindings = bindings
                .into_iter()
                .map(|(_, _, _, binding)| binding)
                .collect();
            let complete = last_inspected.is_none() || last_inspected == fence;
            self.store.put_critical_confirm_list_sweep_state_in_txn(
                wtxn,
                if complete { None } else { last_inspected },
                if complete { None } else { fence },
            )?;
            Ok(bindings)
        })
    }

    pub fn settle_critical_write_confirm(
        &self,
        confirm_id: [u8; 32],
    ) -> Result<CriticalWriteConfirmResolution> {
        let now = crate::unix_seconds_now();
        self.with_write_txn(|wtxn| {
            let fold = self.authority_fold_readonly_in_txn(&*wtxn)?;
            // Confirm IDs have a dedicated exact index; unrelated calls cannot
            // influence absence detection or turn a live target into terminal state.
            let Some(claim_id) = self
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &confirm_id)?
            else {
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            };
            let Some(pending) = self.store.pending_gate_consent_in_txn(&*wtxn, &claim_id)? else {
                // A stale sidecar is removed transactionally and never causes
                // a scan for a different confirmation.
                self.store
                    .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            };
            let binding = match critical_write_confirm_binding(&pending) {
                Ok(binding) => binding,
                Err(error) => {
                    // A malformed or non-critical primary cannot retain an
                    // exact-confirm alias forever. Remove it, but preserve the
                    // validation error so settlement remains fail-closed.
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    return Ok(Err(error));
                }
            };
            // The sidecar is only an address; re-derive authority from the
            // primary row before reading state or mutating a claim.
            if binding.confirm_id != confirm_id {
                self.store
                    .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            }
            let mut body = self
                .get_claim_in_txn(&*wtxn, &binding.claim_id)?
                .ok_or(Error::EntityNotFound)?;
            let raw = self
                .store
                .entities
                .get(&*wtxn, binding.claim_id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            let expired = binding.expires_at <= now;
            if expired {
                put_preauthorized_claim_status_in_txn(
                    self,
                    wtxn,
                    &binding.claim_id,
                    &body,
                    PreauthorizedClaimStatusGrant::TimeoutDemotion,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                )?;
                // The decline below must bind the transaction's staged Proposed row.
                body.approval = ClaimApprovalStatus::Proposed;
                let mut timed_out = pending;
                timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
                self.store
                    .put_pending_gate_consent_in_txn(wtxn, &timed_out)?;
            }
            let Some(state) = fold.critical_write_confirms.get(&confirm_id) else {
                return Ok(Ok(if expired {
                    CriticalWriteConfirmResolution::DemotedToProposed
                } else {
                    CriticalWriteConfirmResolution::AlreadySettled
                }));
            };
            if fold
                .conflicted_critical_write_confirms
                .contains(&confirm_id)
            {
                return Ok(Ok(if expired {
                    CriticalWriteConfirmResolution::DemotedToProposed
                } else {
                    CriticalWriteConfirmResolution::AlreadySettled
                }));
            }
            if expired && state.action.disposition == CriticalWriteConfirmDisposition::Clear {
                return Ok(Ok(CriticalWriteConfirmResolution::DemotedToProposed));
            }
            if state.action.gate_decision_id != binding.gate_decision_id.as_bytes()
                || state.action.claim_id != binding.claim_id
                || state.action.effect_digest != binding.effect_digest
                || state.action.read_frontier_hash != binding.read_frontier_hash
                || state.action.nonce != binding.nonce
                || state.action.expires_at != binding.expires_at
            {
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            }
            match state.action.disposition {
                CriticalWriteConfirmDisposition::Clear => {
                    self.store
                        .delete_pending_gate_consent_in_txn(wtxn, &binding.claim_id)?;
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    Ok(Ok(CriticalWriteConfirmResolution::Cleared))
                }
                CriticalWriteConfirmDisposition::Decline => {
                    put_preauthorized_claim_status_in_txn(
                        self,
                        wtxn,
                        &binding.claim_id,
                        &body,
                        PreauthorizedClaimStatusGrant::FoldDecline,
                        TimeRange {
                            start: header.occurred_start,
                            end: header.occurred_end,
                        },
                        header.learned_at,
                    )?;
                    self.store.close_pending_gate_consent_in_txn(
                        wtxn,
                        &binding.claim_id,
                        now,
                        "rejected",
                        vec![GATE_REASON_CRITICAL_CONFIRM_DECLINED.to_owned()],
                        None,
                    )?;
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    Ok(Ok(CriticalWriteConfirmResolution::Retracted))
                }
            }
        })?
    }

    pub(crate) fn expire_critical_write_confirms(&self) -> Result<usize> {
        self.expire_critical_write_confirms_impl(crate::unix_seconds_now())
    }

    #[cfg(test)]
    pub(super) fn expire_critical_write_confirms_at(&self, now: u64) -> Result<usize> {
        self.expire_critical_write_confirms_impl(now)
    }

    fn expire_critical_write_confirms_impl(&self, now: u64) -> Result<usize> {
        self.with_write_txn(|wtxn| {
            let (cursor, prior_fence) = self
                .store
                .critical_confirm_expiry_sweep_state_in_txn(&*wtxn)?;
            let fence = match prior_fence {
                Some(fence) => Some(fence),
                None => self.store.pending_gate_consents_high_water_in_txn(&*wtxn)?,
            };
            let pending = self.store.pending_gate_consents_page_in_txn(
                &*wtxn,
                cursor,
                fence,
                CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT,
            )?;
            let last_inspected = pending.last().map(|(sequence, _)| *sequence);
            let complete = last_inspected.is_none() || last_inspected == fence;
            self.store.put_critical_confirm_expiry_sweep_state_in_txn(
                wtxn,
                if complete { None } else { last_inspected },
                if complete { None } else { fence },
            )?;
            let mut demoted = 0;
            for (_, row) in pending {
                let Ok(binding) = critical_write_confirm_binding(&row) else {
                    continue;
                };
                if binding.expires_at > now {
                    continue;
                }
                let Some(body) = self.get_claim_in_txn(&*wtxn, &binding.claim_id)? else {
                    continue;
                };
                if body.approval != ClaimApprovalStatus::Auto {
                    continue;
                }
                let raw = self
                    .store
                    .entities
                    .get(&*wtxn, binding.claim_id.as_bytes())?
                    .ok_or(Error::EntityNotFound)?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                put_preauthorized_claim_status_in_txn(
                    self,
                    wtxn,
                    &binding.claim_id,
                    &body,
                    PreauthorizedClaimStatusGrant::TimeoutDemotion,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                )?;
                let mut timed_out = row;
                timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
                self.store
                    .put_pending_gate_consent_in_txn(wtxn, &timed_out)?;
                demoted += 1;
            }
            Ok(demoted)
        })
    }
}

/// The deterministic authority-log binding for a critical claim attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmBinding {
    pub confirm_id: [u8; 32],
    pub gate_decision_id: GateDecisionId,
    pub claim_id: EntityId,
    pub effect_digest: [u8; 32],
    pub read_frontier_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriticalWriteConfirmResolution {
    Cleared,
    Retracted,
    DemotedToProposed,
    AlreadySettled,
}

/// Reconciles replicated claim input against the claim-scoped critical-confirm
/// lifecycle. The durable invalidation is consulted before classifying ordinary
/// pending rows, so neither deletion nor an unrelated pending row can shadow it.
/// A live attachment is closed only for a changed/missing stored body; an exact
/// replay preserves that attachment.
pub(crate) fn reconcile_critical_write_confirm_on_replicated_overwrite(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    replacement_body: &[u8],
    body_changed_or_missing: bool,
) -> Result<bool> {
    let pending = store.pending_gate_consent_in_txn(wtxn, claim_id)?;
    // Strictly parse a critical-marked row before every marker decision. This
    // keeps malformed attachments fail-closed even when a tombstone also exists.
    let live_binding = pending
        .as_ref()
        .filter(|row| {
            row.reason_codes
                .iter()
                .any(|reason| reason.contains("critical_confirm"))
        })
        .map(critical_write_confirm_binding)
        .transpose()?;

    if store.critical_confirm_invalidation_exists_in_txn(wtxn, claim_id)? {
        return Ok(true);
    }
    let Some(binding) = live_binding else {
        return Ok(false);
    };
    let pending = pending.ok_or(Error::InvariantViolation(
        "critical binding without pending",
    ))?;
    if !body_changed_or_missing {
        return Ok(false);
    }
    store.close_pending_gate_consent_in_txn(
        wtxn,
        claim_id,
        pending.created_at,
        "invalidated",
        vec![GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE.to_owned()],
        None,
    )?;
    store.put_critical_confirm_invalidation_in_txn(
        wtxn,
        claim_id,
        binding.gate_decision_id,
        replacement_body,
    )?;
    Ok(true)
}

pub(crate) fn critical_write_confirm_binding(
    pending: &PendingGateConsentRecord,
) -> Result<CriticalWriteConfirmBinding> {
    if !matches!(
        pending.reason_codes.as_slice(),
        [reason]
            if reason.as_str() == GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED
                || reason.as_str() == GATE_REASON_CRITICAL_CONFIRM_TIMEOUT
    ) {
        return Err(Error::InvalidClaimBody("not a critical-confirm attachment"));
    }
    let claim_id = EntityId::from_bytes(pending.claim_id)
        .map_err(|_| Error::InvalidClaimBody("pending critical-confirm claim id"))?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:critical-confirm:v1");
    digest.update(claim_id.as_bytes());
    digest.update(&pending.decision_id.as_bytes());
    digest.update(&pending.diff_handle);
    digest.update(&pending.read_frontier_hash);
    let effect_digest = *digest.finalize().as_bytes();
    let nonce = pending.decision_id.as_bytes();
    let expires_at = pending
        .created_at
        .saturating_add(CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS);
    let mut confirm = Sha256::new();
    confirm.update(CRITICAL_WRITE_CONFIRM_DOMAIN);
    confirm.update(pending.decision_id.as_bytes());
    confirm.update(claim_id.as_bytes());
    confirm.update(effect_digest);
    confirm.update(pending.read_frontier_hash);
    confirm.update(nonce);
    confirm.update(expires_at.to_be_bytes());
    Ok(CriticalWriteConfirmBinding {
        confirm_id: confirm.finalize().into(),
        gate_decision_id: pending.decision_id,
        claim_id,
        effect_digest,
        read_frontier_hash: pending.read_frontier_hash,
        nonce,
        expires_at,
    })
}

/// Whether a critical claim write may land `Auto` with an attached owner
/// confirmation instead of being floored.
///
/// The ceremony this authorizes is a HUMAN one: the write lands now and an owner
/// closes the attached confirmation afterwards. That trade only makes sense for
/// a claim a person actually authored. `comm.*` standing state is not that — it
/// is DERIVED state a projector folds out of already-recorded comm events
/// (`Auto`, `Observed`, first-party), with no author to confirm anything and no
/// reviewer looking for the attachment. Converting its criticality floor into an
/// `Allow` would let projector output cross a gate that the default policy
/// manifest closes, which is fail-OPEN at the claim door; the floor must stand
/// and the write must be rejected (ONE-1716 sweep-11, oracle ES-03).
///
/// The prefix is matched inline rather than against `comm::COMM_CLAIM_PREDICATES`
/// on purpose: this is a gate-side exclusion of a predicate LAYER, so it must
/// also cover any future `comm.*` predicate without the gate importing the comm
/// module. Every other condition is unchanged, so this is strictly more
/// restrictive than before — it can only remove `Allow`s, never add one.
pub(super) fn critical_claim_can_land_auto_with_confirm(
    input: &GateEvaluatorInput,
    pending: &[GateReasonCode],
    predicate: &str,
) -> bool {
    input.content_kind == GateContentKind::Claim
        && input.criticality == PolicyCriticality::Critical
        && input.consent.is_none()
        && pending == [GateReasonCode::PendingCriticalityFloor]
        && !predicate.starts_with("comm.")
}
