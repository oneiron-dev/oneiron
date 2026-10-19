//! One proposed claim's review and settlement (DOOR-115, e2e MEMORY-01):
//! `vault.claims.review` reads one proposed claim with a content-bound review
//! handle, and `vault.claims.settle` approves or declines exactly the content
//! that handle names. A server's host door calls these on the caller's own
//! credential handle with the owner's proof from the request; the embedded
//! owner's handle calls them with its own proof.
//!
//! The handle binds the claim's stored row, its pending-consent row when it
//! waits in the tray, and the live policy frontier. A settlement whose handle
//! no longer matches is refused and changes nothing. The handle is no
//! authority: the settlement revalidates the owner's proof in its own writer,
//! and the actor that opened a proposal never settles it (DEC-0006). Each
//! settlement appends one gate ledger row, its durable receipt, and the claim's
//! tray row, when it has one, closes with its own resolution receipt.

use super::commit::claim_envelope_actor;
use super::*;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::run_tree::GateConsentBundleAction;

/// Key-derivation context of the review handle.
const CLAIM_REVIEW_DOMAIN: &str = "oneiron.claim-settle.review.v1";

/// Gate `content_kind` of the one ledger row a settlement appends.
const CLAIM_SETTLEMENT_CONTENT_KIND: &str = "claim_settlement";

/// The typed call an approval's revert handle names: retracting the claim
/// takes the approval back out of recall and keeps its record.
const CLAIM_SETTLEMENT_REVERT_VERB: &str = "vault.claims.retract";

/// `vault.claims.review`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimProposalReviewRequest {
    /// The proposed claim (short-id ref or 32-hex).
    pub claim_ref: String,
}

/// One proposed claim as its review read it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimProposalReview {
    /// The handle a settlement names (64 hex): a digest of what this review
    /// read, never authority.
    pub review_id: String,
    /// The proposal this is (32 hex): a claim proposes itself, one change.
    pub proposal_ref: String,
    /// The claim as the review read it.
    pub claim: crate::memory::ClaimView,
    /// The actor that opened the proposal (32 hex), which never settles it;
    /// absent when the claim records no author.
    pub opener_ref: Option<String>,
    /// The gate decision the claim waits on in the pending-consent tray
    /// (`gate:<hex>`); absent when it waits in no tray row.
    pub pending_ref: Option<String>,
}

/// The settler's answer to one proposed claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSettleDecision {
    /// The reviewed body lands as approved.
    Approve,
    /// The reviewed body is rejected and closed.
    Reject,
}

/// `vault.claims.settle`'s input. It carries no approval, actor or body: the
/// answer is the caller's, and what it settles is what the review read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimSettleRequest {
    /// The proposed claim (short-id ref or 32-hex), as reviewed.
    pub claim_ref: String,
    /// The handle `vault.claims.review` returned for it.
    pub review_id: String,
    /// The answer.
    pub decision: ClaimSettleDecision,
}

/// A settled change's verdict, and the proposal's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSettlementVerdict {
    /// The change landed: the claim reads as approved.
    Landed,
    /// The change was rejected.
    Rejected,
}

/// One change of a settled proposal and its verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimChangeVerdict {
    /// The claim the change is (32 hex).
    pub claim_ref: String,
    /// Its verdict.
    pub verdict: ClaimSettlementVerdict,
}

/// Who answered a settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimSettlementAnswer {
    /// A person's word: the owner whose revalidated proof settled it.
    Word {
        /// The person (32 hex).
        person_ref: String,
    },
}

/// Why a settlement went the way it did; each is the reason code its ledger
/// row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ClaimSettlementReason {
    /// The owner approved the reviewed body.
    #[serde(rename = "gate.claim.settle.approved")]
    OwnerApproved,
    /// The owner rejected the reviewed body.
    #[serde(rename = "gate.claim.settle.declined")]
    OwnerDeclined,
}

impl ClaimSettlementReason {
    /// The reason code, as the ledger row records it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerApproved => "gate.claim.settle.approved",
            Self::OwnerDeclined => "gate.claim.settle.declined",
        }
    }
}

/// The typed call that takes a settlement back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimSettlementRevert {
    /// The verb to call: `vault.claims.retract`.
    pub verb: String,
    /// The claim it names (32 hex).
    pub claim_ref: String,
}

/// One settled proposal: the Settlement receipt `vault.claims.settle`
/// answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimSettlement {
    /// The settlement's durable receipt (`gate:<hex>`), readable through
    /// `vault.receipts`.
    pub receipt_ref: String,
    /// The proposal it settled (32 hex).
    pub proposal_ref: String,
    /// The review it settled.
    pub review_id: String,
    /// One verdict per change.
    pub changes: Vec<ClaimChangeVerdict>,
    /// The proposal's verdict.
    pub verdict: ClaimSettlementVerdict,
    /// Who answered.
    pub answered_by: ClaimSettlementAnswer,
    /// Why, typed.
    pub reason: ClaimSettlementReason,
    /// One human line.
    pub summary: String,
    /// The tray row's resolution receipt (`gate:<hex>`), when the claim
    /// waited in the pending-consent tray.
    pub tray_receipt_ref: Option<String>,
    /// The call that takes an approval back; a rejection is final, and a
    /// new proposal is seeded anew.
    pub revert: Option<ClaimSettlementRevert>,
    /// The claim as it now reads.
    pub claim: crate::memory::ClaimView,
    /// When it settled (Unix seconds).
    pub settled_at: u64,
}

/// What a review reads of one claim, in one snapshot.
struct ReviewedProposal {
    /// The review handle's digest.
    digest: [u8; 32],
    /// The policy frontier it was read under.
    frontier: [u8; 32],
    body: ClaimBody,
    pending: Option<crate::store::PendingGateConsentRecord>,
    /// Whether it changes only through MACHINE signed history, whose
    /// rejection needs its tray row.
    machine: bool,
    /// The actors that opened it: its authenticated author and the actor its
    /// envelope names.
    openers: Vec<EntityId>,
}

impl ReviewedProposal {
    fn read_in_txn(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<Self> {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .ok_or_else(|| MemoryError::not_found("no claim has that ref"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("claim header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(MemoryError::bad_request("the ref names no claim"));
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let pending = vault.store.pending_gate_consent_in_txn(txn, id)?;
        let machine = crate::authority::machine_claim_needs_history(&vault.store, txn, &body)?;
        let frontier =
            crate::gate::resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?;
        let mut hasher = blake3::Hasher::new_derive_key(CLAIM_REVIEW_DOMAIN);
        hasher.update(id.as_bytes());
        hasher.update(&length_prefix(raw.len()));
        hasher.update(&raw);
        match &pending {
            Some(row) => {
                hasher.update(&[1u8]);
                hasher.update(&row.decision_id.as_bytes());
                hasher.update(&length_prefix(row.diff_handle.len()));
                hasher.update(&row.diff_handle);
                hasher.update(&row.read_frontier_hash);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }
        hasher.update(&frontier);
        let mut openers = Vec::new();
        if let Some(author) =
            crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, id, &body)?
        {
            openers.push(author.entity_ref());
        }
        if let Some(actor) = claim_envelope_actor(&body)
            && !openers.contains(&actor)
        {
            openers.push(actor);
        }
        Ok(Self {
            digest: *hasher.finalize().as_bytes(),
            frontier,
            body,
            pending,
            machine,
            openers,
        })
    }

    fn review_id(&self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.digest)
    }

    fn is_open(&self) -> bool {
        self.body.approval == ClaimApprovalStatus::Proposed
            && self.body.lifecycle == ClaimLifecycleStatus::Active
    }

    fn is_vettable(&self) -> bool {
        crate::claim::claim_generated_origin(&self.body)
            && matches!(
                self.body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
            )
            && self.body.lifecycle == ClaimLifecycleStatus::Active
    }

    /// Whether `person` may settle this proposal by `action` on the review
    /// `review_id` names: it is still open and still what that review read,
    /// `person` did not open it, and a MACHINE claim's decline has its
    /// consent row to close. An ordinary proposal in no tray row declines as
    /// the owner's reviewed rejection.
    fn settleable(
        &self,
        review_id: &str,
        person: EntityId,
        action: GateConsentBundleAction,
        vetting: bool,
    ) -> MemoryResult<()> {
        if !(if vetting {
            self.is_vettable()
        } else {
            self.is_open()
        }) {
            return Err(not_open());
        }
        if !self.review_id().eq_ignore_ascii_case(review_id) {
            return Err(stale_review());
        }
        if self.openers.contains(&person) {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the actor that opened a proposal never settles it",
                &["A person outside the lineage that opened the proposal settles it."],
            ));
        }
        if action == GateConsentBundleAction::Decline && self.pending.is_none() && self.machine {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the proposed MACHINE claim waits in no pending-consent row: no consent to decline",
                &["Withdraw it with vault.claims.retract, which keeps its record."],
            ));
        }
        Ok(())
    }
}

/// A variable-width digest field's length, so no two field splits hash alike.
fn length_prefix(len: usize) -> [u8; 8] {
    u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes()
}

fn not_open() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "the claim is no open proposal: it was settled, closed or never proposed",
        &["Read the claim again; only an active proposed claim is settled."],
    )
}

fn stale_review() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "the proposed claim changed since its review",
        &["Review the claim again with vault.claims.review and settle the review_id it returns."],
    )
}

impl Memory<'_> {
    /// Reviews one proposed claim as the vault's owner: the claim as this
    /// handle may read it, and the handle a settlement of exactly this
    /// content names.
    ///
    /// # Errors
    ///
    /// `FORBIDDEN` when `owner` is not this handle's own live owner proof,
    /// `NOT_FOUND` when the claim does not resolve for this handle, and
    /// `INVALID_STATE` when it is no active proposed claim.
    pub fn claim_review_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClaimProposalReviewRequest,
    ) -> MemoryResult<ClaimProposalReview> {
        self.claim_review_for_owner(owner, input, false)
    }

    /// A content-bound review for the owner's vetting of a generated-origin
    /// Auto claim or proposal. The handle grants no authority itself.
    pub fn claim_vetting_review_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClaimProposalReviewRequest,
    ) -> MemoryResult<ClaimProposalReview> {
        self.claim_review_for_owner(owner, input, true)
    }

    fn claim_review_for_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClaimProposalReviewRequest,
        vetting: bool,
    ) -> MemoryResult<ClaimProposalReview> {
        self.require_settling_owner(owner.revalidate(self.vault)?)?;
        let id = self.admitted_claim(&input.claim_ref)?;
        let reviewed = {
            let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
            ReviewedProposal::read_in_txn(self.vault, &rtxn, &id)?
        };
        if !(if vetting {
            reviewed.is_vettable()
        } else {
            reviewed.is_open()
        }) {
            return Err(not_open());
        }
        self.produced_from([id]);
        Ok(ClaimProposalReview {
            review_id: reviewed.review_id(),
            proposal_ref: id.to_hex(),
            claim: self.served_claim_view(&id, &reviewed.body)?,
            opener_ref: reviewed.openers.first().map(EntityId::to_hex),
            pending_ref: reviewed
                .pending
                .as_ref()
                .map(|row| format!("gate:{}", row.decision_id.to_hex())),
        })
    }

    /// Settles one reviewed proposed claim as the vault's owner, in one
    /// writer: the owner's proof is revalidated there, the claim is read
    /// again and must still be what `review_id` names, and the decision
    /// lands through the ordinary gate with its Settlement receipt.
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` for a malformed `review_id`; `FORBIDDEN` when `owner` is
    /// not this handle's own live owner proof, when the owner opened the
    /// proposal, or when the gate refuses or holds the decision; `NOT_FOUND`
    /// when the claim does not resolve for this handle; `INVALID_STATE` when
    /// it is no active proposal, when it changed since its review, or when a
    /// rejection names a MACHINE claim with no pending-consent row. An
    /// ordinary proposal with no row is rejected and retracted.
    pub fn claim_settle_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClaimSettleRequest,
    ) -> MemoryResult<ClaimSettlement> {
        self.claim_settle_for_owner(owner, input, false)
    }

    /// Vet a reviewed generated-origin claim through the same owner Gate,
    /// signed approval and Settlement as a proposed claim. Vetting never
    /// changes its source or makes it admissible corroboration.
    pub fn claim_vet_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClaimSettleRequest,
    ) -> MemoryResult<ClaimSettlement> {
        self.claim_settle_for_owner(owner, input, true)
    }

    fn claim_settle_for_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ClaimSettleRequest,
        vetting: bool,
    ) -> MemoryResult<ClaimSettlement> {
        let review_id = input.review_id.trim();
        if review_id.len() != 64 || !review_id.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(MemoryError::bad_request_with(
                "review_id is the 64-hex handle vault.claims.review returned",
                &["Review the claim with vault.claims.review and pass its review_id."],
            ));
        }
        let id = self.admitted_claim(&input.claim_ref)?;
        let now = self.vault.store.clock.now_recorded_at();
        let (action, verdict, reason) = match input.decision {
            ClaimSettleDecision::Approve => (
                GateConsentBundleAction::Approve,
                ClaimSettlementVerdict::Landed,
                ClaimSettlementReason::OwnerApproved,
            ),
            ClaimSettleDecision::Reject => (
                GateConsentBundleAction::Decline,
                ClaimSettlementVerdict::Rejected,
                ClaimSettlementReason::OwnerDeclined,
            ),
        };
        let written = self
            .vault
            .try_with_write_txn_grouped(|wtxn| -> MemoryResult<_> {
                // The proof is rechecked where the decision commits: an owner
                // whose person, credential or ownership went away while the call
                // waited for the writer decides nothing.
                let person = owner.revalidate_in_txn(self.vault, &*wtxn)?;
                self.require_settling_owner(person)?;
                let owner_answer = owner.owner_answer_in_txn(self.vault, &*wtxn)?;
                let reviewed = ReviewedProposal::read_in_txn(self.vault, &*wtxn, &id)?;
                reviewed.settleable(review_id, person, action, vetting)?;
                let actor = WriteActor::new(person, EdgeActorClass::Human);
                let settled = if vetting {
                    self.vault.vet_generated_claim_in_txn(
                        wtxn,
                        id,
                        action,
                        actor,
                        owner_answer.as_ref(),
                        now,
                    )?
                } else {
                    self.vault.settle_proposed_claim_in_txn(
                        wtxn,
                        id,
                        action,
                        actor,
                        owner_answer.as_ref(),
                        now,
                    )?
                };
                let mut record = crate::memory::authorship::decision(
                    actor,
                    CLAIM_SETTLEMENT_CONTENT_KIND,
                    match action {
                        GateConsentBundleAction::Approve => "approved",
                        GateConsentBundleAction::Decline => "rejected",
                    },
                    reason.as_str(),
                    Some(id),
                    reviewed.digest.to_vec(),
                    now,
                );
                record.read_frontier_hash = reviewed.frontier;
                self.vault
                    .store
                    .append_gate_decision_in_txn(wtxn, &record)?;
                Ok((settled, record, person))
            });
        let (settled, record, person) = written?;
        for decision in &settled.recorded {
            decision.record_metrics(&self.vault.store.diagnostics.gate);
        }
        // Consent is committed before the consolidator opens its own writer;
        // a VAD failure is returned with the settlement durable.
        if action == GateConsentBundleAction::Approve && (settled.dreamer_run || vetting) {
            self.vault.consolidate_claim_vad_now(&id, now)?;
        }
        self.produced_from([id]);
        let claim_ref = id.to_hex();
        let revert = (verdict == ClaimSettlementVerdict::Landed).then(|| ClaimSettlementRevert {
            verb: CLAIM_SETTLEMENT_REVERT_VERB.to_owned(),
            claim_ref: claim_ref.clone(),
        });
        Ok(ClaimSettlement {
            receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
            proposal_ref: claim_ref.clone(),
            review_id: review_id.to_ascii_lowercase(),
            changes: vec![ClaimChangeVerdict { claim_ref, verdict }],
            verdict,
            answered_by: ClaimSettlementAnswer::Word {
                person_ref: person.to_hex(),
            },
            reason,
            summary: match verdict {
                ClaimSettlementVerdict::Landed => {
                    "The owner approved the reviewed claim; it now reads as approved.".to_owned()
                }
                ClaimSettlementVerdict::Rejected => {
                    "The owner rejected the reviewed claim; it no longer waits for consent."
                        .to_owned()
                }
            },
            tray_receipt_ref: settled
                .tray_receipt
                .as_ref()
                .map(|row| format!("gate:{}", row.decision_id.to_hex())),
            revert,
            claim: self.served_claim_view(&id, &settled.body)?,
            settled_at: now,
        })
    }

    /// The owner-only first slice: the proof's person must be this handle's
    /// own human actor. A delegated or non-owner holder settles nothing here.
    fn require_settling_owner(&self, person: EntityId) -> MemoryResult<()> {
        if person != self.actor || self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a proposed claim is settled by the vault's owner, on the owner's own handle",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(())
    }

    /// `claim_ref` as this handle may read it, whatever its status:
    /// `NOT_FOUND` with the read's receipt when it resolves to nothing the
    /// handle admits.
    fn admitted_claim(&self, claim_ref: &str) -> MemoryResult<EntityId> {
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let id = self.resolve_ref_in_lane(&lane, claim_ref)?;
        let rows = lane.read(&[crate::claim::PointRead::id(id)], None)?;
        if rows
            .value
            .into_iter()
            .flatten()
            .any(|row| row.id == id && row.body.is_some())
        {
            return Ok(id);
        }
        Err(self.with_lane_receipt(
            &lane,
            MemoryError::not_found("no claim this caller may read has that ref"),
        )?)
    }
}
