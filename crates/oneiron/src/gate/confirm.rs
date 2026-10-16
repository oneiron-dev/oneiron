use crate::ports::EntityStoreRead;
use sha2::Digest;
use sha2::Sha256;

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
/// The receipt reason of a critical claim its vault's authenticated owner
/// wrote in person: it carries its own confirmation and attaches none.
pub(crate) const GATE_REASON_ALLOW_CRITICAL_OWNER_AUTHORED: &str =
    "gate.allow.critical_owner_authored";
// The decision receipt uses the allow namespace; the durable pending row must
// remain in store.rs's existing pending namespace.
pub(super) const GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.pending.critical_confirm_attached";
pub const GATE_REASON_CRITICAL_CONFIRM_TIMEOUT: &str = "gate.pending.critical_confirm_timeout";
pub const GATE_REASON_CRITICAL_CONFIRM_DECLINED: &str = "gate.retract.critical_confirm_declined";
pub(super) const GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE: &str =
    "gate.retract.critical_confirm_replicated_overwrite";
/// The pending reason of the confirm this device attaches to a critical claim
/// that reached it by sync. The peer's Auto stamp is not this device's Clear.
/// The hold has no deadline here, since a timeout's demotion would rewrite the
/// peer's bytes on this device.
pub(super) const GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM: &str =
    "gate.pending.critical_confirm_replicated";
/// The pending reason of the item a claim's open owner-answer obligation
/// shows its owner after a door removed the one it had without an answer, or a
/// later revision outdated it ([`super::owner_answer`]). Like a replicated
/// hold, it has no deadline.
pub(super) const GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED: &str =
    "gate.pending.critical_confirm_reopened";
/// The change-log reason of a Clear, which changes no claim bytes.
const CHANGE_REASON_CRITICAL_CONFIRM_CLEARED: &str = "critical confirm cleared";

/// Whether `row` is a critical confirm's item: attached here or on sync,
/// timed out, or shown for an open obligation. Each one opens its claim's
/// owner-answer obligation, which is the hold readers ask.
pub(crate) fn pending_row_holds_critical_confirm(row: &PendingGateConsentRecord) -> bool {
    row.reason_codes
        .iter()
        .any(|reason| reason.contains("critical_confirm"))
}

/// Whether `row`'s confirm waits for its owner however long that takes: a hold
/// this device attached on sync, or an item an open obligation shows. Only the
/// claim door's own confirm has the deadline a timeout demotes past.
fn critical_confirm_has_no_deadline(row: &PendingGateConsentRecord) -> bool {
    matches!(
        row.reason_codes.as_slice(),
        [reason] if reason == GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM
            || reason == GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED
    )
}

/// A private, single-use authority for a settlement status rewrite.
///
/// Its fields are deliberately not caller supplied at the materialization door:
/// only the verified timeout/sweep and authority-fold paths below can construct it.
#[derive(Clone, Copy)]
pub(super) enum PreauthorizedClaimStatusGrant {
    TimeoutDemotion,
    FoldDecline,
    FoldClear,
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
        .port_entity_record(&*wtxn, id)?
        .ok_or(Error::EntityNotFound)?;
    if raw.entity_type != ENTITY_TYPE_CLAIM
        || raw.occurred.start != occurred.start
        || raw.occurred.end != occurred.end
        || raw.learned_at != learned_at
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
        PreauthorizedClaimStatusGrant::FoldClear => {
            updated.approval = ClaimApprovalStatus::Auto;
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
        let now = self.store.clock.now_recorded_at();
        const {
            assert!(
                CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET <= 512,
                "a public list call may inspect no more than 512 logical pending records",
            );
        }
        self.expire_critical_write_confirms()?;
        self.with_write_txn_grouped(|wtxn| {
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
                    && (binding.expires_at > now || critical_confirm_has_no_deadline(&pending))
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
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
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
            // An answer to a parked decay or stale mark settles a restriction,
            // so it reads a held machine history; every other answer waits.
            let mut body =
                if self.deferred_claim_is_in_place_demotion_in_txn(&*wtxn, &binding.claim_id)? {
                    self.claim_for_restriction_in_txn(&*wtxn, &binding.claim_id)?
                } else {
                    self.get_claim_in_txn(&*wtxn, &binding.claim_id)?
                }
                .ok_or(Error::EntityNotFound)?;
            let raw = self
                .store
                .port_entity_record(&*wtxn, &binding.claim_id)?
                .map(|row| row.encode())
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            let expired = binding.expires_at <= now && !critical_confirm_has_no_deadline(&pending);
            let answered = pending.diff_handle.clone();
            let deferred = self.has_deferred_claim_in_txn(wtxn, &binding.claim_id)?;
            if expired && !deferred {
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
                return Ok(Ok(if expired && !deferred {
                    CriticalWriteConfirmResolution::DemotedToProposed
                } else {
                    CriticalWriteConfirmResolution::AlreadySettled
                }));
            };
            if fold
                .conflicted_critical_write_confirms
                .contains(&confirm_id)
            {
                return Ok(Ok(if expired && !deferred {
                    CriticalWriteConfirmResolution::DemotedToProposed
                } else {
                    CriticalWriteConfirmResolution::AlreadySettled
                }));
            }
            if expired && state.action.disposition == CriticalWriteConfirmDisposition::Clear {
                return Ok(Ok(if deferred {
                    CriticalWriteConfirmResolution::AlreadySettled
                } else {
                    CriticalWriteConfirmResolution::DemotedToProposed
                }));
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
            // The fact hooks' settlement feed names who answered: the
            // actor the confirm's signing key speaks for, else the owner.
            let settled_by = match fold.actor_bindings.get(&state.signer) {
                Some(binding) => binding.actor_ref,
                None => crate::vault::embedded_owner_actor_id()?,
            };
            let settled = |outcome| crate::runtime_hooks::SettledFact {
                proposal: binding.claim_id,
                outcome,
                settled_by,
                kind: crate::runtime_hooks::SettlementKind::CriticalWriteConfirm,
            };
            match state.action.disposition {
                CriticalWriteConfirmDisposition::Clear => {
                    // The owner's Clear answers the item this confirm bound.
                    let removal = super::owner_answer::close_owner_answer_obligation_in_txn(
                        &self.store,
                        wtxn,
                        &binding.claim_id,
                        &answered,
                        super::owner_answer::OwnerAnswer::authority_log(),
                    )?;
                    if deferred {
                        if self.deferred_claim_is_supersession_in_txn(wtxn, &binding.claim_id)? {
                            put_preauthorized_claim_status_in_txn(
                                self,
                                wtxn,
                                &binding.claim_id,
                                &body,
                                PreauthorizedClaimStatusGrant::FoldClear,
                                TimeRange {
                                    start: header.occurred_start,
                                    end: header.occurred_end,
                                },
                                header.learned_at,
                            )?;
                        }
                        self.complete_deferred_claim_in_txn(wtxn, &binding.claim_id, true, now)?;
                    }
                    self.store.remove_pending_gate_consent_in_txn(
                        wtxn,
                        &binding.claim_id,
                        removal,
                    )?;
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    // A held provenance claim stamped no flags on its edge.
                    if removal == crate::store::TrayRemoval::Answered
                        && body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE
                    {
                        self.restamp_cleared_edge_provenance_in_txn(wtxn, &binding.claim_id)?;
                    }
                    // A Clear changes no claim bytes, so it logs a mutation of
                    // its own: a consumer that skipped the held claim, such as
                    // the Dreamer wake count, meets it again.
                    crate::ports::audit_mutation_in_txn(
                        &self.store,
                        wtxn,
                        crate::ports::MutationAudit {
                            entity: binding.claim_id,
                            op: crate::ports::ChangeOp::Update,
                            actor_principal: None,
                            occurred_at: now,
                            input: &confirm_id,
                            reason: Some(CHANGE_REASON_CRITICAL_CONFIRM_CLEARED),
                        },
                    )?;
                    crate::reaction::release_cleared_reaction_in_txn(
                        self,
                        wtxn,
                        binding.claim_id,
                        &body,
                    )?;
                    crate::runtime_hooks::record_settlement_in_txn(
                        self,
                        wtxn,
                        settled(crate::runtime_hooks::SettledOutcome::Approved),
                    )?;
                    Ok(Ok(CriticalWriteConfirmResolution::Cleared))
                }
                CriticalWriteConfirmDisposition::Decline => {
                    let removal = super::owner_answer::close_owner_answer_obligation_in_txn(
                        &self.store,
                        wtxn,
                        &binding.claim_id,
                        &answered,
                        super::owner_answer::OwnerAnswer::authority_log(),
                    )?;
                    let retract = !deferred
                        || self.deferred_claim_is_supersession_in_txn(wtxn, &binding.claim_id)?;
                    self.cancel_deferred_claim_in_txn(wtxn, &binding.claim_id)?;
                    if retract {
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
                    }
                    self.store.close_pending_gate_consent_as_in_txn(
                        wtxn,
                        &binding.claim_id,
                        now,
                        "rejected",
                        vec![GATE_REASON_CRITICAL_CONFIRM_DECLINED.to_owned()],
                        None,
                        removal,
                    )?;
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    // A retracted write, or a deferred one that never landed
                    // and is cancelled: declined.
                    crate::runtime_hooks::record_settlement_in_txn(
                        self,
                        wtxn,
                        settled(if retract {
                            crate::runtime_hooks::SettledOutcome::Retracted
                        } else {
                            crate::runtime_hooks::SettledOutcome::Declined
                        }),
                    )?;
                    Ok(Ok(if retract {
                        CriticalWriteConfirmResolution::Retracted
                    } else {
                        CriticalWriteConfirmResolution::AlreadySettled
                    }))
                }
            }
        })?
    }

    pub(crate) fn expire_critical_write_confirms(&self) -> Result<usize> {
        Ok(self.expire_critical_write_confirms_page()?.demoted)
    }

    /// One page of the expiry walk, at the vault clock read inside its write
    /// transaction: pages run in clock order, so a walk that began at `t`
    /// judges every confirm it reaches at `t` or later.
    pub(crate) fn expire_critical_write_confirms_page(&self) -> Result<ConfirmExpiryPage> {
        self.expire_critical_write_confirms_impl(None)
    }

    #[cfg(test)]
    pub(crate) fn expire_critical_write_confirms_at(&self, now: u64) -> Result<usize> {
        Ok(self.expire_critical_write_confirms_impl(Some(now))?.demoted)
    }

    fn expire_critical_write_confirms_impl(&self, at: Option<u64>) -> Result<ConfirmExpiryPage> {
        self.with_write_txn_grouped(|wtxn| {
            let now = at.unwrap_or_else(|| self.store.clock.now_recorded_at());
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
                if critical_confirm_has_no_deadline(&row) {
                    continue;
                }
                let Ok(binding) = critical_write_confirm_binding(&row) else {
                    continue;
                };
                if binding.expires_at > now
                    || self.has_deferred_claim_in_txn(wtxn, &binding.claim_id)?
                {
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
                    .port_entity_record(&*wtxn, &binding.claim_id)?
                    .ok_or(Error::EntityNotFound)?;
                put_preauthorized_claim_status_in_txn(
                    self,
                    wtxn,
                    &binding.claim_id,
                    &body,
                    PreauthorizedClaimStatusGrant::TimeoutDemotion,
                    TimeRange {
                        start: raw.occurred.start,
                        end: raw.occurred.end,
                    },
                    raw.learned_at,
                )?;
                let mut timed_out = row;
                timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
                self.store
                    .put_pending_gate_consent_in_txn(wtxn, &timed_out)?;
                demoted += 1;
            }
            Ok(ConfirmExpiryPage {
                demoted,
                began_at: cursor.is_none().then_some(now),
                ended: complete,
            })
        })
    }
}

/// One page of the critical-confirm expiry walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfirmExpiryPage {
    /// Confirms it demoted.
    pub(crate) demoted: usize,
    /// When it began a walk, if it did: the walk judges every confirm at this
    /// time or later.
    pub(crate) began_at: Option<u64>,
    /// Whether it ended the walk it was on.
    pub(crate) ended: bool,
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

/// Reconciles replicated claim input against the claim's owner-answer
/// obligation. A replica overwrite never closes the obligation: the claim stays
/// held, and the put shows its owner an item for the peer's revision. A live
/// confirm binds only the earlier body, so a changed or missing body closes its
/// row; an exact replay keeps it. Returns whether the peer's revision lands
/// demoted: after a peer overwrote a confirm this device attached, as before
/// obligations, until a fresh local confirm. A hold this device attached on
/// sync, or an item it showed its owner, binds only an earlier peer body: the
/// peer's bytes land unchanged.
pub(crate) fn reconcile_critical_write_confirm_on_replicated_overwrite(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body_changed_or_missing: bool,
) -> Result<bool> {
    let pending = store.pending_gate_consent_in_txn(wtxn, claim_id)?;
    // Strictly parse a critical-marked row before every marker decision. This
    // keeps malformed attachments fail-closed.
    let live_binding = pending
        .as_ref()
        .filter(|row| pending_row_holds_critical_confirm(row))
        .map(critical_write_confirm_binding)
        .transpose()?;
    if store
        .owner_answer_obligation_in_txn(wtxn, claim_id)?
        .is_some_and(|obligation| obligation.demotes_peer_revisions)
    {
        return Ok(true);
    }
    let (Some(_), Some(pending)) = (live_binding, pending) else {
        return Ok(false);
    };
    if !body_changed_or_missing {
        return Ok(false);
    }
    // The put shows the item for the new revision; this close shows none.
    store.close_pending_gate_consent_as_in_txn(
        wtxn,
        claim_id,
        pending.created_at,
        "invalidated",
        vec![GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE.to_owned()],
        None,
        crate::store::TrayRemoval::Silent,
    )?;
    if critical_confirm_has_no_deadline(&pending) {
        return Ok(false);
    }
    super::owner_answer::demote_peer_revisions_in_txn(store, wtxn, claim_id)?;
    Ok(true)
}

/// Whether a claim may lend authority beyond being read: its owner-answer
/// obligation is closed (ARCH-0026 §G3, [`super::owner_answer`]).
///
/// A critical write commits `Auto` with an attached confirmation and stays
/// retrieval-visible, but nothing consolidates it or acts on it until its
/// owner answers. The attachment opens the obligation, and only an owner
/// answer closes it: a let-go, a replacement, a timeout, a demotion, a replica
/// overwrite or a deletion leaves it open. A critical-confirm row parked
/// before obligations were recorded holds the claim too; the first door that
/// removes or replaces it records its obligation. Retrieval
/// ([`crate::claim::claim_surfaceable`]) never asks this.
pub(crate) fn claim_critical_confirm_settled_in_txn(
    store: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<bool> {
    if crate::store::owner_answer_obligation_in(store, txn, claim_id)?.is_some() {
        return Ok(false);
    }
    Ok(
        !crate::store::pending_gate_consent_in(store, txn, claim_id)?
            .is_some_and(|row| pending_row_holds_critical_confirm(&row)),
    )
}

pub(crate) fn critical_write_confirm_binding(
    pending: &PendingGateConsentRecord,
) -> Result<CriticalWriteConfirmBinding> {
    if !matches!(
        pending.reason_codes.as_slice(),
        [reason]
            if reason.as_str() == GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED
                || reason.as_str() == GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM
                || reason.as_str() == GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED
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
