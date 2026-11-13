//! The owner's answer to an owner restore's inbox group (RULING 02:26 13 Nov,
//! NOTE ARCHIVE-RESTORE-APPROVE-DESIGN R3-R5).
//!
//! Accept-all and reject-all settle each open member in one write, newest
//! first, on the `vault.claims.settle` path: each member in its own savepoint,
//! with its own owner proof and Settlement receipt. A member the owner opened,
//! one the gate refuses or holds, and, for accept-all, one whose approval
//! would supersede a live head, stays waiting and is named with its reason;
//! the other members land. The act appends one bundle receipt (a proposal
//! outcome) and keeps its settled members in the run journal under
//! `restore:<receipt hex>`, so `vault.runs.revert` takes back all of them or
//! any part (ARCH-0040 REV-2). Review-each settles nothing: it names the open
//! members for `vault.claims.review` and `vault.claims.settle`.
//! `Memory::resolve_restore_inbox_group` is its call surface.

use super::*;
use crate::consent::bundle_projection::GateConsentBundleAction;
use crate::inbox::{
    InboxBulkVerb, InboxGroupResolveRequest, RestoreInboxResolution, RestoreMemberOutcome,
    RestoreMemberVerdict, RestoreMemberWait, RestoredMemberSettle,
};
use crate::ports::EntityStoreRead;

/// Reason code of the bundle receipt an accept-all appends.
const RESTORE_SETTLE_APPROVED: &str = "gate.restore.settle.approved";

/// Reason code of the bundle receipt a reject-all appends.
const RESTORE_SETTLE_REJECTED: &str = "gate.restore.settle.rejected";

/// What one answer's write did: the resolution, the gate metrics and the
/// claims whose VAD consolidates after commit, and the members that landed.
type RestoreAnswer = (
    RestoreInboxResolution,
    Vec<crate::gate::RecordedClaimGateDecision>,
    Vec<EntityId>,
    Vec<EntityId>,
);

/// The bytes a raw-evidence member's undo binds: its stored row and its
/// pending-consent row, as a run review binds a claim, with no author to read.
pub(super) fn restored_binding(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> MemoryResult<Vec<u8>> {
    let raw = vault
        .store
        .port_entity_record(txn, id)?
        .ok_or_else(|| MemoryError::not_found("restored claim is absent"))?
        .encode();
    let pending = vault.store.pending_gate_consent_in_txn(txn, id)?;
    serde_json::to_vec(&(raw, pending))
        .map_err(|_| MemoryError::bad_request("restored claim cannot be encoded"))
}

/// The undo of a landed member: a claim with an author keeps the run
/// review's Authored undo; one with raw evidence names no author, so it gets
/// the Restored undo, which retracts it while its row is unchanged.
fn landed_inverse(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    member: &RunReviewChange,
    id: &EntityId,
) -> MemoryResult<RunInverse> {
    let body = memory
        .vault()
        .get_claim_in_txn(txn, id)?
        .ok_or_else(|| MemoryError::not_found("settled claim is absent"))?;
    Ok(match snapshot::claim_author(&body) {
        Ok(author) => RunInverse::Authored {
            author: author.to_hex(),
            fingerprint: fingerprint(&snapshot::binding(memory, txn, member)?.0),
        },
        Err(_) => RunInverse::Restored {
            fingerprint: fingerprint(&restored_binding(memory.vault(), txn, id)?),
        },
    })
}

/// The open members of the owner restore `group_key` names, newest first,
/// after checking that its receipt is the owner's own restore receipt.
fn restore_group_members(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    group_key: &str,
    actor: WriteActor,
) -> MemoryResult<Vec<EntityId>> {
    let vault = memory.vault();
    let receipt = crate::batch::export::owner_restore_receipt_in_txn(&vault.store, txn, group_key)?
        .filter(|receipt| {
            receipt.actor_ref.as_deref() == Some(actor.entity_ref().to_hex().as_str())
        });
    if receipt.is_none() {
        return Err(MemoryError::not_found(
            "no owner restore group has that key",
        ));
    }
    let mut members = crate::batch::export::owner_restore_members_in_txn(vault, txn, group_key)?;
    members.sort_unstable_by_key(|member| std::cmp::Reverse(*member));
    Ok(members)
}

fn outcome(
    id: EntityId,
    verdict: RestoreMemberVerdict,
    receipt_ref: Option<String>,
) -> RestoreMemberOutcome {
    RestoreMemberOutcome {
        claim_ref: id.to_hex(),
        verdict,
        receipt_ref,
        waiting: None,
        replaces_ref: None,
        detail: None,
    }
}

impl Memory<'_> {
    /// The owner's answer to the restore group `request` names: accept-all,
    /// reject-all or review-each over the claims that restore brought back.
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` for a verb class or a learning target; `FORBIDDEN` when
    /// `owner` is not this handle's own live owner proof; `NOT_FOUND` when no
    /// restore of this owner has that key; a store failure.
    pub(crate) fn resolve_restore_inbox_group(
        &self,
        owner: &AuthenticatedOwner,
        request: &InboxGroupResolveRequest,
    ) -> MemoryResult<RestoreInboxResolution> {
        if request.verb_class.is_some() || request.target.is_some() {
            return Err(MemoryError::bad_request(
                "a restore group has no verb classes and no learning target",
            ));
        }
        let group_key = request.group_key.trim().to_ascii_lowercase();
        let action = match request.verb {
            InboxBulkVerb::ReviewEach => return self.review_restore_group(owner, &group_key),
            InboxBulkVerb::AcceptAll => GateConsentBundleAction::Approve,
            InboxBulkVerb::RejectAll => GateConsentBundleAction::Decline,
        };
        let now = self.vault().store.clock.now_recorded_at();
        let (mut resolution, metrics, vad, landed) = self.with_verified_actor_write_txn(|txn| {
            self.settle_restore_group_in_txn(txn, owner, &group_key, action, now)
        })?;
        for decision in metrics {
            decision.record_metrics(&self.vault().store.diagnostics.gate);
        }
        // An approved curator finding applies now (FIX 6078), and a Dreamer
        // claim's VAD consolidates after the commit; a failure warns and the
        // answer stands (FIX 7600).
        if action == GateConsentBundleAction::Approve {
            crate::dreamer_runner::maintenance::apply_curator_after_consent(
                self.vault(),
                landed.iter().copied(),
                now,
            );
        }
        resolution.warnings = vad
            .iter()
            .filter_map(|claim| self.vault().consolidate_settled_claim_vad(claim, now))
            .collect();
        self.produced_from(
            resolution
                .members
                .iter()
                .filter_map(|member| EntityId::from_hex(&member.claim_ref).ok()),
        );
        Ok(resolution)
    }

    /// Review-each: the open members, each waiting for `vault.claims.review`
    /// and `vault.claims.settle`, with the live head its approval would
    /// supersede. Nothing is written.
    fn review_restore_group(
        &self,
        owner: &AuthenticatedOwner,
        group_key: &str,
    ) -> MemoryResult<RestoreInboxResolution> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let actor = require_owner(self, &txn, owner)?;
        let recorded = restore_group_members(self, &txn, group_key, actor)?;
        let members: Vec<RestoreMemberOutcome> = self
            .vault()
            .open_restored_members_in_txn(&txn, &recorded)?
            .into_iter()
            .map(|member| RestoreMemberOutcome {
                waiting: Some(RestoreMemberWait::ReviewEach),
                replaces_ref: member.replaces.map(|head| head.to_hex()),
                ..outcome(member.id, RestoreMemberVerdict::Waiting, None)
            })
            .collect();
        self.produced_from(
            members
                .iter()
                .filter_map(|member| EntityId::from_hex(&member.claim_ref).ok()),
        );
        Ok(RestoreInboxResolution {
            group_key: group_key.to_owned(),
            receipt_ref: None,
            members,
            revert_handle: None,
            warnings: Vec::new(),
        })
    }

    /// The answer's one write: each open member settled in its own savepoint,
    /// then the bundle receipt and the run journal.
    fn settle_restore_group_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        group_key: &str,
        action: GateConsentBundleAction,
        now: u64,
    ) -> MemoryResult<RestoreAnswer> {
        let actor = require_owner(self, txn, owner)?;
        let approve = action == GateConsentBundleAction::Approve;
        let run = format!("restore:{group_key}");
        let mut members = Vec::new();
        let mut settled = Vec::new();
        let mut stored = Vec::new();
        let mut changes = Vec::new();
        let mut metrics = Vec::new();
        let mut vad = Vec::new();
        for id in restore_group_members(self, txn, group_key, actor)? {
            let mut savepoint = self
                .vault()
                .store
                .env
                .nested_write_txn(txn)
                .map_err(crate::Error::from)?;
            match self.settle_restored_member_in_txn(
                &mut savepoint,
                owner,
                actor,
                id,
                action,
                now,
            )? {
                // Dropping the savepoint aborts it: nothing it read wrote.
                RestoredMemberSettle::Closed => {}
                RestoredMemberSettle::Waiting {
                    wait,
                    replaces,
                    detail,
                } => members.push(RestoreMemberOutcome {
                    waiting: Some(wait),
                    replaces_ref: replaces.map(|head| head.to_hex()),
                    detail,
                    ..outcome(id, RestoreMemberVerdict::Waiting, None)
                }),
                RestoredMemberSettle::Settled {
                    receipt,
                    recorded,
                    dreamer_run,
                } => {
                    let member = RunReviewChange::Claim {
                        claim_ref: id.to_hex(),
                    };
                    let inverse = if approve {
                        Some(landed_inverse(self, &savepoint, &member, &id)?)
                    } else {
                        None
                    };
                    savepoint.commit().map_err(crate::Error::from)?;
                    let receipt_ref = format!("gate:{}", receipt.decision_id.to_hex());
                    let verdict = if approve {
                        RunChangeVerdict::Landed
                    } else {
                        RunChangeVerdict::Rejected
                    };
                    metrics.extend(recorded);
                    if approve && dreamer_run {
                        vad.push(id);
                    }
                    members.push(outcome(
                        id,
                        if approve {
                            RestoreMemberVerdict::Landed
                        } else {
                            RestoreMemberVerdict::Rejected
                        },
                        Some(receipt_ref.clone()),
                    ));
                    changes.push(RunChangeOutcome {
                        change: id.to_hex(),
                        verdict,
                        receipt: Some(receipt_ref),
                    });
                    stored.push(StoredChange {
                        member,
                        verdict,
                        inverse,
                        compensation: None,
                        unrestored: Vec::new(),
                    });
                    settled.push(id);
                }
            }
        }
        let mut resolution = RestoreInboxResolution {
            group_key: group_key.to_owned(),
            receipt_ref: None,
            members,
            revert_handle: None,
            warnings: Vec::new(),
        };
        if settled.is_empty() {
            return Ok((resolution, metrics, vad, Vec::new()));
        }
        // The act's one proposal outcome over its settled members (ARCH-0040
        // `:302`), anchored to them as a run settlement's is (FIX 11002).
        let mut record = crate::memory::authorship::decision(
            actor,
            "proposal_outcome",
            if approve { "approved" } else { "rejected" },
            if approve {
                RESTORE_SETTLE_APPROVED
            } else {
                RESTORE_SETTLE_REJECTED
            },
            None,
            run.as_bytes().to_vec(),
            now,
        );
        crate::gate::append_reviewed_run_decision_in_txn(
            self.vault(),
            txn,
            &mut record,
            &run,
            &settled,
        )?;
        let reference = format!("gate:{}", record.decision_id.to_hex());
        // A later answer to the same restore (reject-all over the members an
        // accept-all left waiting) joins the same journal: each member settles
        // once, so no change repeats.
        let mut journal = SETTLEMENTS.get(&self.vault().store, txn, &run)?;
        let mut journal_changes = journal
            .as_ref()
            .map(|journal| journal.settlement.changes.clone())
            .unwrap_or_default();
        journal_changes.extend(changes);
        let mut stored_changes = journal
            .take()
            .map(|journal| journal.changes)
            .unwrap_or_default();
        stored_changes.extend(stored);
        let settlement = RunSettlement {
            kind: RunSettlementKind::ProposalOutcome,
            run_id: run.clone(),
            receipt: reference.clone(),
            changes: journal_changes,
            verdict: if approve {
                RunChangeVerdict::Landed
            } else {
                RunChangeVerdict::Rejected
            },
            answered_by: RunAnsweredBy::Word {
                word_ref: reference.clone(),
            },
            reason: if approve {
                RunSettlementReason::OwnerApproved
            } else {
                RunSettlementReason::OwnerRejected
            },
            summary: if approve {
                "The owner accepted the restored claims; a member that would replace a live head still waits."
            } else {
                "The owner rejected the restored claims that waited; earlier landings stay."
            }
            .to_owned(),
            revert_handle: format!("run:{run}"),
        };
        resolution.revert_handle = Some(settlement.revert_handle.clone());
        resolution.receipt_ref = Some(reference);
        SETTLEMENTS.put(
            &self.vault().store,
            txn,
            &run,
            &StoredRun {
                settlement,
                changes: stored_changes,
            },
        )?;
        Ok((
            resolution,
            metrics,
            vad,
            if approve { settled } else { Vec::new() },
        ))
    }
}
