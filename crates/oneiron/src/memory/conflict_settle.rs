//! The authorised responder's door to a parked contradiction (OF-023).
//!
//! The vault's root owner, authenticated, settles any open conflict, and so
//! does the vault's own Dreamer, in every vault from birth: its settlement
//! applies at once and the owner reverts it (owner ruling 10-18, "autoapply
//! + revert rather than holdout"). Anyone else needs a named owner-delegated
//! `memory.conflict_review` Grant on the conflict's subject or on the whole
//! vault, the verb the resident dispute door reviews under; a person also
//! authenticates. A decision ladder's answer is never that authority, and no
//! Grant is inferred for any actor but the Dreamer principal. The marker
//! reads and settlement mechanics live beside the markers, in
//! `crate::dreamer_consolidation::settle`. Only the root owner takes the
//! optional ApproveAndKeep, which approves a Keep staged in its import's
//! review and keeps it in one transaction (FIX 6151). A Keep the Gate holds
//! is retried once as the responder's approval of that alternative (FIX
//! 5753).

// The read door to a Dreamer attempt's decided candidates (FIX 11306).
mod candidate_decisions;
mod decision_context;

pub use candidate_decisions::DreamerDecidedCandidateView;

use std::cell::Cell;

use super::authorship::*;
use super::{Memory, MemoryResult};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::dreamer_consolidation::{
    ConflictRevertReceipt, ConflictReviewScope, ConflictSettleOutcome, ConflictSettleReceipt,
    ConflictSettlement, KeepApproval, KeepAs, OpenConflict, SettledAnswer, SettlementApplied,
    apply_settlement_in_txn, open_conflict_in_txn, open_conflicts_in_txn, revert_settlement_in_txn,
    settled_answers_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::run_tree::GateConsentBundleAction;
use crate::{EntityId, Vault, WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

const VERB: &str = "memory.conflict_review";
/// A whole-vault review Grant's one selector, before the vault's root id:
/// no subject's id spells it.
const VAULT_SELECTOR: &str = "vault:";
const KIND: &str = "conflict_settlement";
const REASON: &str = "gate.memory.conflict_settlement";
const REVERT_KIND: &str = "conflict_settlement_revert";
const REVERT_REASON: &str = "gate.memory.conflict_settlement_revert";
/// The provenance a Dreamer settlement names in place of a Grant.
const DREAMER_AUTHORITY: &str = "dreamer.standing_review";
/// The owner's hold on the Dreamer's standing review: a standing Grant on
/// one subject or the whole vault naming the Dreamer, which it leaves to
/// the owner while one is live.
const HOLD_VERB: &str = "memory.conflict_review.hold";
/// FIX 5753 (Engine 10-20 07:4x): a Keep whose retained alternative the Gate
/// holds is the responder's approval of that exact proposal and settlement,
/// in their one commit: no standing permit, no actor-ceiling change.
const KEEP_PENDING_APPROVES_EXACT: bool = true;
/// FIX 5753: the approval retries a held Keep gets, each in a fresh write
/// transaction after the one before aborted whole.
const KEEP_PENDING_APPROVAL_RETRIES: u8 = 1;
/// The Gate receipt naming a responder's approval of the alternative its
/// Keep landed (FIX 5753), with the responder's actor, its Grant and the
/// landing: the settled receipt's `approval_ref`. Every approval mints one;
/// the signed Approve leaves no reference of its own, and the receipt of a
/// tray row it closed keeps the opener's actor.
const APPROVAL_KIND: &str = "conflict_keep_approval";
const APPROVAL_REASON: &str = "gate.memory.conflict_keep_approval";

/// What a held Keep's approval retry answers when one of its own checks
/// fails (Engine 10-21 18:3x).
#[derive(Debug, Clone, Copy)]
enum KeepApprovalCheckError {
    /// The Keep answers as it did before the retry: its first refusal, with
    /// the retained alternative intact.
    PreserveOriginalPath,
}
/// It covers only an error of a retry whose write was discarded. Once the
/// retry has committed, an error from the writer's own post-commit work
/// (the owed stale sweep, for one) is no refusal: the Keep answers with what
/// the retry committed, that failure keeps its own handling, and nothing
/// retries again.
const KEEP_APPROVAL_CHECK_ERROR: KeepApprovalCheckError =
    KeepApprovalCheckError::PreserveOriginalPath;

impl Memory<'_> {
    /// The open conflicts this caller may settle, on `subject` alone when one
    /// is named, oldest marker first, at most `limit`. The owner sees every
    /// one; a delegate sees those its Grant covers.
    pub fn open_conflicts(
        &self,
        reviewer: Option<&AuthenticatedOwner>,
        subject: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<Vec<OpenConflict>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let owner = self.conflict_responder_is_owner(&txn, reviewer)?;
        let dreamer = !owner && self.conflict_responder_is_dreamer()?;
        let mut open = Vec::new();
        for conflict in open_conflicts_in_txn(self.vault, &txn, subject)? {
            if open.len() >= limit {
                break;
            }
            // A settlement the owner reverted, or a scope the owner holds,
            // is the owner's to answer.
            if dreamer {
                if !conflict.reverted && self.dreamer_review_hold(&txn, conflict.subject)?.is_none()
                {
                    open.push(conflict);
                }
            } else if owner
                || self
                    .conflict_review_grant(&txn, conflict.subject)?
                    .is_some()
            {
                open.push(conflict);
            }
        }
        Ok(open)
    }

    /// Settles the open conflict `marker` in ONE transaction: rechecks the
    /// responder's authority and that the marker is still unanswered, applies
    /// `settlement`, and appends the Gate receipt naming the responder and any
    /// Grant it acted under. A person's answer is user-stated and approved; an
    /// agent's is generated and Auto. The Dreamer answers under no Grant; its
    /// receipt names its standing review, and the owner reverts it with
    /// [`Self::revert_conflict_settlement`]. A Keep of a retained
    /// alternative from imported words is staged in its import's review
    /// instead (FIX 5754): nothing is settled, the conflict stays open, and
    /// a pending receipt names the responder's Keep. An ApproveAndKeep is
    /// the root owner's alone: the staged member is approved through the
    /// same owner Gate a claim settlement uses and kept in this transaction,
    /// and its approval consolidates VAD once it commits, as that
    /// settlement's does (FIX 6151).
    ///
    /// A Keep of a retained alternative whose Auto landing the Gate holds on
    /// a typed reason the Keep approves is retried once, after that
    /// transaction aborted whole, in a fresh one (FIX 5753): every check runs
    /// again, the alternative is born Proposed and the responder approves it
    /// as its own act (an Owner, co-Owners included, or a delegate under its
    /// Grant; never the Dreamer), and the settlement commits with it. The
    /// receipt then names that approval. A retry whose write is discarded
    /// answers with the first refusal, the retained alternative intact; one
    /// that committed answers with what it committed, even when the writer's
    /// post-commit work then fails.
    pub fn settle_conflict(
        &self,
        reviewer: Option<&AuthenticatedOwner>,
        marker: EntityId,
        settlement: ConflictSettlement,
        now: u64,
    ) -> MemoryResult<ConflictSettleOutcome> {
        let mut consolidate = None;
        let held = Cell::new(false);
        let first = self.with_verified_actor_write_txn(|txn| {
            self.settle_in_txn(
                txn,
                reviewer,
                (marker, settlement),
                (&held, false),
                &mut consolidate,
                now,
            )
        });
        let outcome = match first {
            Ok(outcome) => outcome,
            Err(refusal) => {
                consolidate = None;
                if !(KEEP_PENDING_APPROVES_EXACT
                    && KEEP_PENDING_APPROVAL_RETRIES > 0
                    && held.get()
                    && matches!(settlement, ConflictSettlement::Keep(_))
                    && matches!(self.conflict_responder_is_dreamer(), Ok(false)))
                {
                    return Err(refusal);
                }
                let mut written = None;
                let retried = self.with_verified_actor_write_txn(|txn| {
                    let outcome = self.settle_in_txn(
                        txn,
                        reviewer,
                        (marker, settlement),
                        (&held, true),
                        &mut consolidate,
                        now,
                    )?;
                    written = Some(outcome.clone());
                    Ok(outcome)
                });
                match (retried, KEEP_APPROVAL_CHECK_ERROR) {
                    (Ok(outcome), _) => outcome,
                    (Err(error), KeepApprovalCheckError::PreserveOriginalPath) => {
                        let committed =
                            written.map(|outcome| (self.keep_retry_committed(&outcome), outcome));
                        match committed {
                            Some((Ok(true), outcome)) => {
                                tracing::warn!(
                                    target: "oneiron::memory",
                                    code = %error.code,
                                    marker = %marker.to_hex(),
                                    "a held Keep's approval committed; its post-commit work failed and keeps its own handling"
                                );
                                outcome
                            }
                            // Whether it committed is unknown: its own error,
                            // never the first refusal.
                            Some((Err(_), _)) => return Err(error),
                            Some((Ok(false), _)) | None => {
                                tracing::warn!(
                                    target: "oneiron::memory",
                                    code = %error.code,
                                    marker = %marker.to_hex(),
                                    "a held Keep's approval did not land; the Keep answers as before"
                                );
                                return Err(refusal);
                            }
                        }
                    }
                }
            }
        };
        // Consent is committed before the consolidator opens its own writer;
        // a VAD failure is returned with the settlement durable.
        if let Some(approved) = consolidate {
            self.vault.consolidate_claim_vad_now(&approved, now)?;
        }
        Ok(outcome)
    }

    /// [`Self::settle_conflict`]'s one transaction. With `approve` (its one
    /// retry, FIX 5753) a kept retained alternative is born Proposed and
    /// approved by this responder, rechecked here; without, it lands Auto and
    /// `held` notes a hold the responder may approve.
    fn settle_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        reviewer: Option<&AuthenticatedOwner>,
        (marker, settlement): (EntityId, ConflictSettlement),
        (held, approve): (&Cell<bool>, bool),
        consolidate: &mut Option<EntityId>,
        now: u64,
    ) -> MemoryResult<ConflictSettleOutcome> {
        let owner = self.conflict_responder_is_owner(txn, reviewer)?;
        let dreamer = !owner && self.conflict_responder_is_dreamer()?;
        let conflict = open_conflict_in_txn(self.vault, txn, marker)?;
        if dreamer && conflict.reverted {
            return Err(authority_denied(
                "the owner reverted the Dreamer's settlement of this conflict",
            )
            .into());
        }
        if dreamer && self.dreamer_review_hold(txn, conflict.subject)?.is_some() {
            return Err(authority_denied("the owner holds the Dreamer's review here").into());
        }
        let grant_ref = if owner || dreamer {
            None
        } else {
            Some(
                self.conflict_review_grant(txn, conflict.subject)?
                    .ok_or_else(|| authority_denied("no named conflict review Grant"))?,
            )
        };
        let actor = WriteActor::new(self.actor, self.actor_class);
        if let ConflictSettlement::ApproveAndKeep(staged) = settlement {
            let dreamer_run = self.approve_staged_keep_in_txn(
                txn,
                reviewer.filter(|_| owner),
                &conflict,
                staged,
                now,
            )?;
            *consolidate = dreamer_run.then_some(staged);
        }
        let approval = if approve {
            Some(self.keep_approval_in_txn(txn, reviewer.filter(|_| owner), dreamer)?)
        } else {
            None
        };
        let keep_as = approval
            .as_ref()
            .map_or(KeepAs::Auto(held), KeepAs::Approved);
        let person = self.actor_class == EdgeActorClass::Human;
        let mut provenance = vec![
            (Value::from("surface"), Value::from(KIND)),
            (
                Value::from("openMarker"),
                Value::Binary(marker.as_bytes().to_vec()),
            ),
        ];
        if let Some(reviewer) = reviewer {
            provenance.push((
                Value::from("ownerAuthentication"),
                Value::from(reviewer.decision_id().to_hex()),
            ));
        }
        if let Some(grant) = &grant_ref {
            provenance.push((Value::from("grant"), Value::from(grant.as_str())));
        }
        if dreamer {
            provenance.push((Value::from("authority"), Value::from(DREAMER_AUTHORITY)));
        }
        let envelope = WriteEnvelope::new(
            actor,
            if person {
                ClaimSource::UserStated
            } else {
                ClaimSource::Generated
            },
            WriteProvenance::new(Value::Map(provenance))?,
            if person {
                ClaimApprovalStatus::Approved
            } else {
                ClaimApprovalStatus::Auto
            },
        );
        let settled = match apply_settlement_in_txn(
            self.vault,
            txn,
            &conflict,
            settlement,
            &envelope,
            (!owner).then_some(actor),
            person,
            keep_as,
            now,
        )? {
            SettlementApplied::Settled(settled) => settled,
            SettlementApplied::ImportReviewPending(_) if approve => {
                return Err(not_approved().into());
            }
            SettlementApplied::ImportReviewPending(staged) => {
                let mut receipt = decision(
                    actor,
                    KIND,
                    "pending",
                    REASON,
                    Some(marker),
                    marker.as_bytes().to_vec(),
                    now,
                );
                receipt.context =
                    decision_context::answering_claim(self.vault, &*txn, marker, None);
                receipt.grant_ref = grant_ref;
                self.vault
                    .store
                    .append_gate_decision_in_txn(txn, &receipt)?;
                return Ok(ConflictSettleOutcome::ImportReviewPending {
                    staged,
                    receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
                });
            }
        };
        // The retry approved exactly the alternative its Keep selected, or
        // it settles nothing. Its ref names the responder's own approval,
        // never a tray row's resolution receipt.
        let approval_ref = match (&approval, settlement) {
            (None, _) => None,
            (Some(approval), ConflictSettlement::Keep(selector)) => {
                let approved = approval.approved().ok_or_else(not_approved)?;
                *consolidate = approved.dreamer_run.then_some(approved.claim);
                let mut record = decision(
                    actor,
                    APPROVAL_KIND,
                    "approved",
                    APPROVAL_REASON,
                    Some(approved.claim),
                    [marker, selector, approved.claim]
                        .iter()
                        .flat_map(|id| *id.as_bytes())
                        .collect(),
                    now,
                );
                record.context =
                    decision_context::answering_claim(self.vault, &*txn, approved.claim, None);
                record.grant_ref.clone_from(&grant_ref);
                self.vault.store.append_gate_decision_in_txn(txn, &record)?;
                Some(format!("gate:{}", record.decision_id.to_hex()))
            }
            (Some(_), _) => return Err(not_approved().into()),
        };
        let mut receipt = decision(
            actor,
            KIND,
            "approved",
            REASON,
            Some(settled.resolved),
            marker.as_bytes().to_vec(),
            now,
        );
        receipt.context = decision_context::answering_claim(self.vault, &*txn, marker, None);
        receipt.grant_ref = grant_ref;
        self.vault
            .store
            .append_gate_decision_in_txn(txn, &receipt)?;
        Ok(ConflictSettleOutcome::Settled(ConflictSettleReceipt {
            marker,
            settlement,
            resolved: settled.resolved,
            superseded: settled.superseded,
            receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
            approval_ref,
        }))
    }

    /// This responder's approval of its held Keep, in the retry's
    /// transaction (FIX 5753): an Owner, co-Owners included, authenticated as
    /// the bound person, approves as his own act, and his proof answers the
    /// claim's owner-answer obligation; a delegate approves with its own
    /// actor under the conflict review Grant the caller rechecked in this
    /// transaction, and answers no owner obligation. The Dreamer, which
    /// opened the alternative, approves nothing: its standing review is no
    /// owner answer.
    fn keep_approval_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: Option<&AuthenticatedOwner>,
        dreamer: bool,
    ) -> Result<KeepApproval, Error> {
        let actor = WriteActor::new(self.actor, self.actor_class);
        if dreamer || actor == dreamer_principal()? {
            return Err(authority_denied(
                "the Dreamer's standing review approves no held Keep",
            ));
        }
        let owner_answer = match owner {
            Some(owner) => owner.owner_answer_in_txn(self.vault, txn)?,
            None => None,
        };
        Ok(KeepApproval::new(actor, owner_answer))
    }

    /// Whether a held Keep's retry, whose write answered `outcome`, committed
    /// it: the answering claim that write minted is stored.
    fn keep_retry_committed(&self, outcome: &ConflictSettleOutcome) -> Result<bool, Error> {
        match outcome {
            ConflictSettleOutcome::Settled(receipt) => self.vault.entity_exists(&receipt.resolved),
            ConflictSettleOutcome::ImportReviewPending { .. } => Ok(false),
        }
    }

    /// The owner's approval of `staged`, a Keep of `conflict` still waiting
    /// in its import's review, in the settlement's transaction (FIX 6151):
    /// through the owner Gate a claim settlement approves by, as `reviewer`,
    /// the authenticated root owner, and nobody else. Returns whether its
    /// approval consolidates VAD once the transaction commits.
    fn approve_staged_keep_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        reviewer: Option<&AuthenticatedOwner>,
        conflict: &OpenConflict,
        staged: EntityId,
        now: u64,
    ) -> Result<bool, Error> {
        let Some(reviewer) = reviewer else {
            return Err(authority_denied(
                "only the vault's owner approves a staged Keep and keeps it",
            ));
        };
        conflict.staged_keep_in_txn(self.vault, txn, staged)?;
        let owner_answer = reviewer.owner_answer_in_txn(self.vault, txn)?;
        let approved = self.vault.settle_proposed_claim_in_txn(
            txn,
            staged,
            GateConsentBundleAction::Approve,
            WriteActor::new(self.actor, self.actor_class),
            owner_answer.as_ref(),
            now,
        )?;
        Ok(approved.dreamer_run)
    }

    /// The standing settlements the owner may revert, on `subject` alone
    /// when one is named, newest first, at most `limit`.
    pub fn settled_conflicts(
        &self,
        owner: &AuthenticatedOwner,
        subject: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<Vec<SettledAnswer>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.conflict_review_owner(&txn, owner)?;
        Ok(settled_answers_in_txn(self.vault, &txn, subject, limit)?)
    }

    /// The owner's revert of the settlement whose answer is `resolved`, any
    /// responder's, the Dreamer's above all (owner ruling 10-18: the Dreamer
    /// applies at once and the owner reverts), in ONE transaction: the
    /// answer is retracted, its marker opens again for the owner alone, and
    /// each member it superseded stands again. The Gate receipt names the
    /// owner and the answer.
    pub fn revert_conflict_settlement(
        &self,
        owner: &AuthenticatedOwner,
        resolved: EntityId,
        now: u64,
    ) -> MemoryResult<ConflictRevertReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            self.conflict_review_owner(txn, owner)?;
            let actor = WriteActor::new(self.actor, self.actor_class);
            let reverted = revert_settlement_in_txn(self.vault, txn, resolved, actor, now)?;
            let mut receipt = decision(
                actor,
                REVERT_KIND,
                "approved",
                REVERT_REASON,
                Some(resolved),
                reverted.marker.as_bytes().to_vec(),
                now,
            );
            receipt.context =
                decision_context::answering_claim(self.vault, &*txn, resolved, Some(KIND));
            self.vault
                .store
                .append_gate_decision_in_txn(txn, &receipt)?;
            Ok(ConflictRevertReceipt {
                resolved,
                reverted,
                receipt_ref: format!("gate:{}", receipt.decision_id.to_hex()),
            })
        })
    }

    /// Whether this caller answers as the vault's root owner. An
    /// authentication must name this bound, live person; without one the
    /// caller is never the owner, and a person must authenticate at all.
    fn conflict_responder_is_owner(
        &self,
        txn: &heed::RoTxn<'_>,
        reviewer: Option<&AuthenticatedOwner>,
    ) -> Result<bool, Error> {
        let Some(reviewer) = reviewer else {
            if self.actor_class == EdgeActorClass::Human {
                return Err(authority_denied(
                    "a person settles a conflict with their authentication",
                ));
            }
            verify_live_actor(
                self.vault,
                txn,
                WriteActor::new(self.actor, self.actor_class),
            )?;
            return Ok(false);
        };
        if self.actor != reviewer.revalidate_person_in_txn(self.vault, txn)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied(
                "review authentication must name the bound human",
            ));
        }
        verify_live_actor(
            self.vault,
            txn,
            WriteActor::new(self.actor, EdgeActorClass::Human),
        )?;
        is_root_owner(self.vault, txn, self.actor)
    }

    /// Whether this caller is the vault's own Dreamer principal, the System
    /// MACHINE whose conflict review stands from birth with no Grant.
    fn conflict_responder_is_dreamer(&self) -> Result<bool, Error> {
        Ok(WriteActor::new(self.actor, self.actor_class) == dreamer_principal()?)
    }

    /// The owner-delegated Grant that lets this caller review conflicts on
    /// `subject`, its own or the whole vault's, if one is live.
    fn conflict_review_grant(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: EntityId,
    ) -> Result<Option<String>, Error> {
        live_review_bound(
            self.vault,
            txn,
            WriteActor::new(self.actor, self.actor_class),
            VERB,
            subject,
        )
    }

    /// The owner's hold on the Dreamer's review of `subject`, its own or the
    /// whole vault's, if one is live.
    fn dreamer_review_hold(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: EntityId,
    ) -> Result<Option<String>, Error> {
        live_review_bound(
            self.vault,
            txn,
            WriteActor::new(self.actor, self.actor_class),
            HOLD_VERB,
            subject,
        )
    }

    /// Lets `delegate` settle the open conflicts `scope` covers: a standing
    /// Grant only the authenticated root owner mints, returned by its ref.
    /// Nothing mints one by default (DEC-0006: a grant is never inferred);
    /// the Dreamer needs none, since its review stands from birth.
    pub fn grant_conflict_review(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        scope: ConflictReviewScope,
    ) -> MemoryResult<String> {
        self.mint_review_bound(owner, delegate, VERB, scope)
    }

    /// Ends the Grant [`Self::grant_conflict_review`] minted for `delegate`
    /// on exactly `scope`; false when none was live. Ending the whole
    /// vault's leaves each subject's own Grant standing.
    pub fn revoke_conflict_review(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        scope: ConflictReviewScope,
    ) -> MemoryResult<bool> {
        self.end_review_bound(owner, delegate, VERB, scope)
    }

    /// The owner's override of the Dreamer's standing review: while this
    /// hold is live, the Dreamer leaves the open conflicts `scope` covers to
    /// the owner. Returned by its ref.
    pub fn hold_dreamer_conflict_review(
        &self,
        owner: &AuthenticatedOwner,
        scope: ConflictReviewScope,
    ) -> MemoryResult<String> {
        self.mint_review_bound(owner, dreamer_principal()?, HOLD_VERB, scope)
    }

    /// Ends the hold [`Self::hold_dreamer_conflict_review`] put on exactly
    /// `scope`; false when none was live. Ending the whole vault's leaves
    /// each subject's own hold standing.
    pub fn release_dreamer_conflict_review(
        &self,
        owner: &AuthenticatedOwner,
        scope: ConflictReviewScope,
    ) -> MemoryResult<bool> {
        self.end_review_bound(owner, dreamer_principal()?, HOLD_VERB, scope)
    }

    fn mint_review_bound(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        verb: &str,
        scope: ConflictReviewScope,
    ) -> MemoryResult<String> {
        self.with_verified_actor_write_txn(|txn| {
            self.conflict_review_owner(txn, owner)?;
            verify_live_actor(self.vault, txn, delegate)?;
            let bound = review_bound(self.vault, txn, delegate, verb, scope)?;
            let grant_ref = bound.digest().to_hex();
            self.vault.create_standing_grant_in_txn(txn, owner, bound)?;
            Ok(grant_ref)
        })
    }

    fn end_review_bound(
        &self,
        owner: &AuthenticatedOwner,
        delegate: WriteActor,
        verb: &str,
        scope: ConflictReviewScope,
    ) -> MemoryResult<bool> {
        self.with_verified_actor_write_txn(|txn| {
            self.conflict_review_owner(txn, owner)?;
            let grant_ref = review_bound(self.vault, txn, delegate, verb, scope)?
                .digest()
                .to_hex();
            Ok(self
                .vault
                .revoke_consent_grant_in_txn(txn, owner, &grant_ref)?
                .is_some())
        })
    }

    /// The owner proof must name this bound person, who owns the vault now.
    fn conflict_review_owner(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<(), Error> {
        if self.actor != verify_owner(self.vault, txn, owner)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied("owner proof must name the bound caller"));
        }
        Ok(())
    }
}

/// A held Keep's retry that did not approve exactly the alternative its Keep
/// selected: it settles nothing.
fn not_approved() -> Error {
    authority_denied("the held Keep's retry approved no alternative it selected")
}

/// The vault's Dreamer principal, the System MACHINE an owner's hold names.
fn dreamer_principal() -> Result<WriteActor, Error> {
    Ok(WriteActor::new(
        crate::dreamer_runner::authority::dreamer_actor_id()?,
        EdgeActorClass::System,
    ))
}

/// The live standing Grant of `verb` naming `actor` on `subject`, its own or
/// the whole vault's, if one is live.
fn live_review_bound(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    verb: &str,
    subject: EntityId,
) -> Result<Option<String>, Error> {
    for scope in [
        ConflictReviewScope::Subject(subject),
        ConflictReviewScope::Vault,
    ] {
        let required = review_bound(vault, txn, actor, verb, scope)?;
        if let Some(grant) = delegated_grant(vault, txn, &required)? {
            return Ok(Some(grant));
        }
    }
    Ok(None)
}

/// The bound a `verb` Grant on `scope` carries, for `actor`: a subject's
/// names that subject, the whole vault's names [`VAULT_SELECTOR`] and its
/// root. Both target the vault root.
fn review_bound(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    verb: &str,
    scope: ConflictReviewScope,
) -> Result<GrantBound, Error> {
    match scope {
        ConflictReviewScope::Subject(subject) => action_bound(vault, txn, actor, verb, subject),
        ConflictReviewScope::Vault => {
            let root = root_id(vault, txn)?;
            GrantBound::action(
                ActorBound::new(actor.entity_ref().to_hex())?
                    .with_actor_class(actor.actor_class().gate_actor_class())?,
                ActionClass::new(verb)?,
                ActionEnvelope::new([format!("{VAULT_SELECTOR}{root}")])?.with_target(root)?,
            )
        }
    }
}
