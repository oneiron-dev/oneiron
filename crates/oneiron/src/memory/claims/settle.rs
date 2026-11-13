//! One proposed claim's review and settlement (DOOR-115, e2e MEMORY-01):
//! `vault.claims.review` reads one proposed claim with a content-bound review
//! handle, and `vault.claims.settle` approves or declines exactly the content
//! that handle names. A server's host door calls these on the caller's own
//! credential handle with the owner's proof from the request; the embedded
//! owner's handle calls them with its own proof.
//!
//! The handle binds the claim's stored row, its pending-consent row when it
//! waits in the tray, the head its approval supersedes (or that it supersedes
//! none), and the live policy frontier. A settlement whose handle no longer
//! matches is refused and changes nothing. The handle is no authority: the
//! settlement revalidates the owner's proof or the holder's explicit
//! owner-issued Grant in its own writer. The actor that opened a proposal
//! never settles it (DEC-0006).
//!
//! An approval closes the supersession its proposal proposed (e2e
//! MEMORY-01, ARCH-0040 `mcp:5`): the approved claim supersedes the standing
//! head on its conflict set (`conflict_head`). A proposal whose deferred
//! action names its replaced claim closes that one, through the deferred
//! completion. A rejection closes none. Each settlement appends one gate
//! ledger row, its durable receipt, and the claim's tray row, when it has
//! one, closes with its own resolution receipt.

use super::commit::claim_envelope_actor;
use super::*;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::consent::bundle_projection::GateConsentBundleAction;

mod authority;
use authority::ClaimSettler;
mod conflict_head;
pub(in crate::memory) use conflict_head::ConflictHeadIndex;
use conflict_head::{ConflictHead, conflict_head_in_txn};
mod restored_member;

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
    /// An explicit native consent Grant for this holder and claim (64 hex).
    /// None uses the existing owner proof. A Grant grants no read access.
    pub grant_ref: Option<String>,
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
    /// An explicit native consent Grant for this holder and claim (64 hex).
    /// None uses the existing owner proof, never an inferred Grant.
    pub grant_ref: Option<String>,
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
    /// The actual holder answered under this owner-issued native Grant.
    Grant {
        /// The stored Grant's bound digest (64 hex).
        grant_ref: String,
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
    /// The explicitly granted holder approved the reviewed body.
    #[serde(rename = "gate.claim.settle.holder_approved")]
    HolderApproved,
    /// The explicitly granted holder rejected the reviewed body.
    #[serde(rename = "gate.claim.settle.holder_declined")]
    HolderDeclined,
}

impl ClaimSettlementReason {
    /// The reason code, as the ledger row records it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerApproved => "gate.claim.settle.approved",
            Self::OwnerDeclined => "gate.claim.settle.declined",
            Self::HolderApproved => "gate.claim.settle.holder_approved",
            Self::HolderDeclined => "gate.claim.settle.holder_declined",
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
    /// The work still owed after the settlement committed (FIX 7600); empty
    /// when none is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<SettleWarning>,
}

/// Why a committed settlement warns (FIX 7600).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettleWarningCode {
    /// The approved claim's VAD consolidation failed after the commit: the
    /// settlement stands, and the claim's VAD is pending.
    VadPending,
}

/// A warning a committed settlement carries: a stable code, the claim it is
/// about and one human line (FIX 7600). The settlement it rides on is
/// durable; the warning names work still owed after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleWarning {
    /// Why it warns.
    pub code: SettleWarningCode,
    /// The claim it is about (32 hex).
    pub claim_ref: String,
    /// One human line.
    pub detail: String,
}

/// What a review reads of one claim, in one snapshot.
struct ReviewedProposal {
    /// The review handle's digest.
    digest: [u8; 32],
    /// The policy frontier it was read under.
    frontier: [u8; 32],
    body: ClaimBody,
    pending: Option<crate::store::PendingGateConsentRecord>,
    /// The head an approval of it supersedes, read in the same snapshot.
    prior: Option<ConflictHead>,
    /// Whether it changes only through MACHINE signed history, whose
    /// rejection needs its tray row.
    machine: bool,
    /// The actors that opened it: its authenticated author and the actor its
    /// envelope names, unless the owner's whole-vault restore brought it back.
    openers: Vec<EntityId>,
    /// Whether it is an active claim whose own author's retract waits for
    /// the holder's consent (ARCH-0040 `mcp:5`).
    parked_retract: bool,
}

impl ReviewedProposal {
    fn read_in_txn(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> MemoryResult<Self> {
        Self::read_with_head_in_txn(vault, txn, id, |body| {
            conflict_head_in_txn(vault, txn, id, body)
        })
    }

    /// `read_in_txn`, with the head read from `heads`: one read of each
    /// subject's claims for many reviews in one txn (FIX 23686).
    fn read_indexed_in_txn(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        heads: &mut ConflictHeadIndex,
    ) -> MemoryResult<Self> {
        Self::read_with_head_in_txn(vault, txn, id, |body| heads.head(vault, txn, id, body))
    }

    /// The review of `id`, with `conflict_head` naming the head an approval
    /// of its body would close.
    fn read_with_head_in_txn(
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        conflict_head: impl FnOnce(&ClaimBody) -> crate::Result<Option<ConflictHead>>,
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
        let parked_retract = body.lifecycle == ClaimLifecycleStatus::Active
            && vault.claim_retract_is_parked_in_txn(txn, id)?;
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
        // The head an approval closes, bound by its stored bytes or bound as
        // none: a head that lands, changes or closes after the review makes
        // the review stale. A deferred action names its own target and
        // closes it, so no head is read beside it.
        let prior = if body.approval == ClaimApprovalStatus::Proposed
            && !vault.has_deferred_claim_in_txn(txn, id)?
        {
            conflict_head(&body)?
        } else {
            None
        };
        match &prior {
            Some(prior) => {
                let raw =
                    crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &prior.id)?
                        .ok_or(Error::EntityNotFound)?;
                hasher.update(&[1u8]);
                hasher.update(prior.id.as_bytes());
                hasher.update(&length_prefix(raw.len()));
                hasher.update(&raw);
            }
            None => {
                hasher.update(&[0u8]);
            }
        }
        let mut openers = Vec::new();
        if let Some(author) =
            crate::batch::authenticated_claim_author_in_txn(&vault.store, txn, id, &body)?
        {
            openers.push(author.entity_ref());
        }
        // The owner's whole-vault restore opened a claim it brought back, not
        // the owner its envelope names (D5, RULING 00:08 13 Nov).
        if let Some(actor) = claim_envelope_actor(&body)
            && !openers.contains(&actor)
            && !crate::batch::export::owner_restore_opened_claim_in_txn(
                &vault.store,
                txn,
                &body,
                actor,
            )?
        {
            openers.push(actor);
        }
        Ok(Self {
            digest: *hasher.finalize().as_bytes(),
            frontier,
            body,
            pending,
            prior,
            machine,
            openers,
            parked_retract,
        })
    }

    fn review_id(&self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.digest)
    }

    /// An active proposal, or an active claim whose retract is parked for
    /// the holder.
    fn is_open(&self) -> bool {
        (self.body.approval == ClaimApprovalStatus::Proposed || self.parked_retract)
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
        "the proposed claim, or the head its approval supersedes, changed since its review",
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
        self.review_claim_proposal(input, vetting, None)
    }

    /// Review on an embedded owner handle, or under the explicitly named
    /// Grant on this handle's own credential.
    pub fn claim_review(
        &self,
        input: &ClaimProposalReviewRequest,
    ) -> MemoryResult<ClaimProposalReview> {
        match input.grant_ref.as_deref() {
            Some(_) => self.claim_review_as_grant_holder(input),
            None => self.claim_review_as_owner(&self.embedded_owner("vault.claims.review")?, input),
        }
    }

    /// Reviews a readable proposal under the holder's named, live native
    /// Grant. This action Grant grants no additional read authority.
    pub fn claim_review_as_grant_holder(
        &self,
        input: &ClaimProposalReviewRequest,
    ) -> MemoryResult<ClaimProposalReview> {
        let grant = authority::named_grant(input.grant_ref.as_deref())?;
        self.review_claim_proposal(input, false, Some(ClaimSettler::Grant(&grant)))
    }

    fn review_claim_proposal(
        &self,
        input: &ClaimProposalReviewRequest,
        vetting: bool,
        holder: Option<ClaimSettler<'_>>,
    ) -> MemoryResult<ClaimProposalReview> {
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let id = self.admitted_claim_in_lane(&lane, &input.claim_ref)?;
        let reviewed = {
            let rtxn = self.vault.store.env.read_txn().map_err(Error::from)?;
            if let Some(holder) = holder {
                holder.authorize(self, &rtxn, &lane, id, "vault.claims.review")?;
            }
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
    /// lands through the ordinary gate with its Settlement receipt. An
    /// approval supersedes the head on the proposal's conflict set that the
    /// review read, in the same writer.
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` for a malformed `review_id`; `FORBIDDEN` when `owner` is
    /// not this handle's own live owner proof, when the owner opened the
    /// proposal, or when the gate refuses or holds the decision; `NOT_FOUND`
    /// when the claim does not resolve for this handle; `INVALID_STATE` when
    /// it is no active proposal, when it or the head its approval supersedes
    /// changed since its review, or when a
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
        self.settle_claim_proposal(ClaimSettler::Owner(owner), input, vetting)
    }

    /// Settles on an embedded owner handle, or under the explicitly named
    /// Grant on this handle's own credential.
    pub fn claim_settle(&self, input: &ClaimSettleRequest) -> MemoryResult<ClaimSettlement> {
        match input.grant_ref.as_deref() {
            Some(_) => self.claim_settle_as_grant_holder(input),
            None => self.claim_settle_as_owner(&self.embedded_owner("vault.claims.settle")?, input),
        }
    }

    /// Settles a reviewed readable proposal as the holder named by a live
    /// owner-issued native Grant. It answers no owner-critical obligation.
    pub fn claim_settle_as_grant_holder(
        &self,
        input: &ClaimSettleRequest,
    ) -> MemoryResult<ClaimSettlement> {
        let grant = authority::named_grant(input.grant_ref.as_deref())?;
        self.settle_claim_proposal(ClaimSettler::Grant(&grant), input, false)
    }

    fn settle_claim_proposal(
        &self,
        authority: ClaimSettler<'_>,
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
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let id = self.admitted_claim_in_lane(&lane, &input.claim_ref)?;
        let now = self.vault.store.clock.now_recorded_at();
        let (action, verdict, reason) = match input.decision {
            ClaimSettleDecision::Approve => (
                GateConsentBundleAction::Approve,
                ClaimSettlementVerdict::Landed,
                if authority.is_grant() {
                    ClaimSettlementReason::HolderApproved
                } else {
                    ClaimSettlementReason::OwnerApproved
                },
            ),
            ClaimSettleDecision::Reject => (
                GateConsentBundleAction::Decline,
                ClaimSettlementVerdict::Rejected,
                if authority.is_grant() {
                    ClaimSettlementReason::HolderDeclined
                } else {
                    ClaimSettlementReason::OwnerDeclined
                },
            ),
        };
        let written = self
            .vault
            .try_with_write_txn_grouped(|wtxn| -> MemoryResult<_> {
                // Authority is rechecked where the decision commits, after
                // any wait for the writer. A Grant never supplies owner proof.
                if authority.is_grant() {
                    self.verify_actor_write_in_txn(wtxn)?;
                }
                let authorized =
                    authority.authorize(self, &*wtxn, &lane, id, "vault.claims.settle")?;
                let actor = authorized.actor;
                let owner_answer = authorized.owner_answer;
                let reviewed = ReviewedProposal::read_in_txn(self.vault, &*wtxn, &id)?;
                reviewed.settleable(review_id, actor.entity_ref(), action, vetting)?;
                let settled = if vetting {
                    self.vault.vet_generated_claim_in_txn(
                        wtxn,
                        id,
                        action,
                        actor,
                        owner_answer,
                        now,
                    )?
                } else if authorized.grant_ref.is_some()
                    && action == GateConsentBundleAction::Approve
                {
                    self.vault.approve_proposed_claim_with_caller_in_txn(
                        wtxn,
                        id,
                        self.claim_envelope(
                            reviewed.body.source.unwrap_or(ClaimSource::Inferred),
                            "vault.claims.settle",
                            ClaimApprovalStatus::Approved,
                        )?,
                        now,
                    )?
                } else {
                    self.vault.settle_proposed_claim_in_txn(
                        wtxn,
                        id,
                        action,
                        actor,
                        owner_answer,
                        now,
                    )?
                };
                // MEMORY-01: the approval closes the supersession its proposal
                // proposed, on the head its review bound; a refused close rolls
                // the approval back. The head's read is taken before it closes.
                let closed = match &reviewed.prior {
                    Some(prior) if action == GateConsentBundleAction::Approve && !vetting => {
                        let read =
                            crate::store::GateDecisionReadContext::claim(&prior.id, &prior.body)
                                .map(|read| {
                                    read.with_anchors(crate::conversation::gate_claim_anchors_in(
                                        self.vault,
                                        &*wtxn,
                                        &prior.id,
                                        &prior.body,
                                    ))
                                });
                        self.vault.supersede_claim_in_txn_as(
                            wtxn,
                            &id,
                            &prior.id,
                            now,
                            Some(actor),
                        )?;
                        read
                    }
                    _ => None,
                };
                // The approval's commit carries its consolidation debt (FIX 11858).
                if action == GateConsentBundleAction::Approve && (settled.dreamer_run || vetting) {
                    self.vault.owe_settled_claim_vads_in_txn(wtxn, &[id])?;
                }
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
                record.grant_ref = authorized.grant_ref;
                // FIX 7499, 7500: the reviewed candidate's read context, and
                // the loop links of the pending decision it answers.
                let pending = reviewed.pending.as_ref().and_then(|pending| {
                    let store = &self.vault.store;
                    store
                        .gate_decision_in_txn(&*wtxn, pending.decision_id)
                        .ok()
                        .flatten()
                });
                record.context = crate::store::GateDecisionContext {
                    read: crate::store::GateDecisionReadContext::claim(&id, &reviewed.body)
                        .map(|read| {
                            let anchors = crate::conversation::gate_claim_anchors_in(
                                self.vault,
                                &*wtxn,
                                &id,
                                &reviewed.body,
                            );
                            read.with_anchors(anchors)
                        })
                        .into_iter()
                        .chain(closed)
                        .collect(),
                    ..pending
                        .as_ref()
                        .map(crate::store::GateDecisionContext::answering)
                        .unwrap_or_default()
                };
                self.vault
                    .store
                    .append_gate_decision_in_txn(wtxn, &record)?;
                Ok((settled, record, reviewed.parked_retract))
            });
        let (settled, record, parked_retract) = written?;
        for decision in &settled.recorded {
            decision.record_metrics(&self.vault.store.diagnostics.gate);
        }
        // An approved curator finding applies now, after the approval
        // committed, not at the next nightly pass (FIX 6078); one that cannot
        // waits for that pass, and the settlement stands either way.
        if action == GateConsentBundleAction::Approve && !parked_retract {
            crate::dreamer_runner::maintenance::apply_curator_after_consent(self.vault, [id], now);
        }
        // Consent is committed before the consolidator opens its own writer;
        // a VAD failure warns and the settlement answers success (FIX 7600,
        // Engine 09:24).
        let warnings =
            if action == GateConsentBundleAction::Approve && (settled.dreamer_run || vetting) {
                self.vault
                    .consolidate_settled_claim_vad(&id, now)
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
        self.produced_from([id]);
        let claim_ref = id.to_hex();
        // A retraction is final: an approved parked retract has no revert.
        let revert = (verdict == ClaimSettlementVerdict::Landed && !parked_retract).then(|| {
            ClaimSettlementRevert {
                verb: CLAIM_SETTLEMENT_REVERT_VERB.to_owned(),
                claim_ref: claim_ref.clone(),
            }
        });
        Ok(ClaimSettlement {
            receipt_ref: format!("gate:{}", record.decision_id.to_hex()),
            proposal_ref: claim_ref.clone(),
            review_id: review_id.to_ascii_lowercase(),
            changes: vec![ClaimChangeVerdict { claim_ref, verdict }],
            verdict,
            answered_by: match &record.grant_ref {
                Some(grant_ref) => ClaimSettlementAnswer::Grant {
                    grant_ref: grant_ref.clone(),
                },
                None => ClaimSettlementAnswer::Word {
                    person_ref: self.actor.to_hex(),
                },
            },
            reason,
            summary: match (verdict, authority.is_grant()) {
                (ClaimSettlementVerdict::Landed, _) if parked_retract => {
                    "The parked retract was approved; the claim is retracted.".to_owned()
                }
                (ClaimSettlementVerdict::Rejected, _) if parked_retract => {
                    "The parked retract was declined; the claim stands as it was.".to_owned()
                }
                (ClaimSettlementVerdict::Landed, true) => {
                    "The granted holder approved the reviewed claim; it now reads as approved.".to_owned()
                }
                (ClaimSettlementVerdict::Rejected, true) => {
                    "The granted holder rejected the reviewed claim; it no longer waits for consent."
                        .to_owned()
                }
                (ClaimSettlementVerdict::Landed, false) => {
                    "The owner approved the reviewed claim; it now reads as approved.".to_owned()
                }
                (ClaimSettlementVerdict::Rejected, false) => {
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
            warnings,
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
    fn admitted_claim_in_lane(
        &self,
        lane: &crate::claim::ScopedRead<'_>,
        claim_ref: &str,
    ) -> MemoryResult<EntityId> {
        let id = self.resolve_ref_in_lane(lane, claim_ref)?;
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
            lane,
            MemoryError::not_found("no claim this caller may read has that ref"),
        )?)
    }
}
