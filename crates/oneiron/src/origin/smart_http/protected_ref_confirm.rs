//! The protected ref of a served repository, and the owner's leave for one
//! move of it (L8-51).
//!
//! A push by anyone but the vault's owner may neither delete nor rewrite the
//! branch the repository's HEAD names: force-push or deletion of a protected
//! ref, and history rewrite, are the repo surface's catastrophe class
//! (ARCH-0068 RC4; DEC-0006 names them one-way). Such a push is refused while
//! the hook still blocks the backend, so nothing it carried lands.
//!
//! A rewrite the door would otherwise have let land puts one question to the
//! owner. Its state names the move (the repository, the ref, the old and the
//! new tip, the pusher) and the approve-once digest the engine composed over
//! exactly those. The owner's leave is `vault.consent.approve_once` on that
//! digest (DEC-0006): a plain "yes" to the question mints nothing. The same
//! push sent again then passes the door, and its intent's writer spends the
//! leave with the intent, after every other check, so one leave lands one
//! move. A leave spent on a move git then does not make is gone; the owner's
//! own push is the way left.
//!
//! A deletion is refused with no question: git refuses to delete the branch
//! HEAD names for every pusher, so a leave could never land.

use super::door_window::{DoorWindowRequest, DoorWindowVerdict, printable_ref_name};
use super::retained_reasons::RetainedReasons;
use crate::Vault;
use crate::consent::{
    ComposedEffect, EffectDigest, EffectFacts, UndoFidelity, approve_once_authorization_in_txn,
    spend_approve_once_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::git_wire::GitOid;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};

/// The typed reason a push by anyone but the vault's owner meets when it
/// deletes the repository's protected ref, or moves it to a commit that does
/// not descend from the ref's tip.
const PROTECTED_REF_REWRITE: &str = "protected_ref_rewrite";

/// The operation kind every protected-ref move's consent effect names, the
/// move's own hash appended.
const MOVE_OPERATION_KIND: &str = "origin.protected_ref_rewrite";
const MOVE_DIGEST_DOMAIN: &[u8] = b"oneiron:origin-protected-ref-move:v1";

/// Versioned native queue identity; the host renders the structured question.
const ASK_QUEUE: &str = "origin.protected_ref_rewrite";
const ASK_QUEUE_VERSION: &str = "v1";
const ASK_VERSION: u32 = 1;
const ASK_DOMAIN: &[u8] = b"oneiron:origin-protected-ref-rewrite-ask:v1";

/// The ref a push by anyone but the vault's owner may neither delete nor
/// rewrite, read under the canonical repository's coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtectedRef {
    /// The full name of the branch the repository's HEAD names.
    pub(super) name: String,
    /// The canonical repository's identity (its object store's), which every
    /// move's digest binds: an ingress copy is never the repository.
    pub(super) repo_identity_hex: String,
}

/// One rewrite of the protected ref, as one pusher proposed it.
struct ProtectedRefMove<'a> {
    protected: &'a ProtectedRef,
    old_oid: &'a GitOid,
    new_oid: &'a GitOid,
    pusher: &'a str,
}

impl ProtectedRefMove<'_> {
    /// The approve-once digest of exactly this move: the repository, the ref,
    /// the old and the new tip, and the pusher. The transport's operation id
    /// is not in it, so the same push sent again names the same digest.
    fn approval_digest(&self) -> Result<EffectDigest> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MOVE_DIGEST_DOMAIN);
        for part in [
            self.protected.repo_identity_hex.as_str(),
            self.protected.name.as_str(),
            self.old_oid.as_str(),
            self.new_oid.as_str(),
            self.pusher,
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        let mut facts = EffectFacts::new(format!(
            "{MOVE_OPERATION_KIND}.{}",
            hasher.finalize().to_hex()
        ))?;
        // The commits the rewrite drops stay in the object store only until
        // it is pruned.
        facts.undo_fidelity = UndoFidelity::Partial;
        Ok(ComposedEffect::new(facts).digest())
    }

    /// The state the owner's question carries: native identifiers only, and
    /// the digest the owner's leave names.
    fn ask_state(&self, digest: &EffectDigest) -> serde_json::Value {
        serde_json::json!({
            "repo_identity": self.protected.repo_identity_hex,
            "ref": self.protected.name,
            "old_oid": self.old_oid.as_str(),
            "new_oid": self.new_oid.as_str(),
            "pusher": self.pusher,
            "approval_digest": digest.to_hex(),
        })
    }
}

/// The one question a move's digest is asked as, found by exact lookup.
struct MoveAsk {
    question: DecisionQuestion,
    principal: EntityId,
    evidence: [EntityId; 1],
    to: AskTo,
    correlation: EntityId,
}

impl MoveAsk {
    /// `None` when the pusher names no principal: a bare admission invents
    /// none, and its rewrite is refused unasked.
    fn of(digest: &EffectDigest, pusher: &str) -> Result<Option<Self>> {
        let Ok(principal) = EntityId::from_hex(pusher) else {
            return Ok(None);
        };
        let correlation = EntityId::derive(ASK_DOMAIN, &[digest.as_bytes()])?;
        Ok(Some(Self {
            question: DecisionQuestion {
                id: correlation,
                version: ASK_VERSION,
                text: String::new(),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Noul,
                accept_type: false,
            },
            principal,
            evidence: [correlation],
            to: AskTo::owner(),
            correlation,
        }))
    }

    fn find_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<u64>> {
        Ok(vault
            .decision_ask_for_in_txn(
                txn,
                &self.question,
                self.principal,
                &self.evidence,
                &self.to,
                Some(self.correlation),
            )?
            .map(|ask| ask.seq))
    }
}

/// What the door decided about the protected ref, before the push's scan.
#[derive(Default)]
pub(super) struct ProtectedRefDecision {
    /// Each refused deletion or rewrite, as its reason.
    refused: RetainedReasons,
    /// The refused rewrites the owner is asked about if nothing else refuses
    /// the push, each with its digest.
    unasked: Vec<(EffectDigest, serde_json::Value, String)>,
    /// The digests of the rewrites the owner left once, still unspent: the
    /// intent's writer spends each.
    approved: Vec<EffectDigest>,
}

impl ProtectedRefDecision {
    /// Reads, for each move of `protected` in `request`, whether it may land:
    /// a creation and a fast-forward pass; a deletion is refused; a rewrite
    /// passes only on the owner's unspent leave for exactly it. `pusher` is
    /// the principal the push was admitted for.
    pub(super) fn read(
        vault: &Vault,
        protected: &ProtectedRef,
        request: &DoorWindowRequest,
        pusher: Option<&str>,
    ) -> Result<Self> {
        let mut decision = Self::default();
        for update in (request.ref_updates.iter()).filter(|update| update.name == protected.name) {
            let refuse = |decision: &mut Self, why: &str| {
                decision.refused.push_with(|| {
                    format!(
                        "{}: {PROTECTED_REF_REWRITE}: {why}",
                        printable_ref_name(&update.name)
                    )
                });
            };
            let (Some(old_oid), Some(new_oid)) = (&update.old_oid, &update.new_oid) else {
                if update.old_oid.is_some() {
                    refuse(
                        &mut decision,
                        "only the vault's owner may delete this repository's default branch",
                    );
                }
                continue;
            };
            if !request.rewritten_refs.contains(&protected.name) {
                continue;
            }
            let Some(pusher) = pusher else {
                refuse(
                    &mut decision,
                    "only the vault's owner may rewrite this repository's default branch",
                );
                continue;
            };
            let rewrite = ProtectedRefMove {
                protected,
                old_oid,
                new_oid,
                pusher,
            };
            let digest = rewrite.approval_digest()?;
            let rtxn = vault.store.env.read_txn()?;
            match approve_once_authorization_in_txn(&vault.store, &rtxn, &digest) {
                Ok(Some(_)) => decision.approved.push(digest),
                Ok(None) => {
                    refuse(
                        &mut decision,
                        "only the vault's owner may rewrite this repository's default branch, \
                         or allow this exact move once",
                    );
                    decision
                        .unasked
                        .push((digest, rewrite.ask_state(&digest), pusher.to_owned()));
                }
                Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) => refuse(
                    &mut decision,
                    "the owner's leave for this exact move was already spent",
                ),
                Err(error) => return Err(error),
            }
        }
        Ok(decision)
    }

    /// The window's verdict with this decision applied, and the digests of
    /// the owner's leaves the intent's writer must spend. A refusal here
    /// refuses the push. When nothing else refused it, the owner is asked
    /// about each refused rewrite, once per digest: a push the door would
    /// refuse anyway costs the owner no question.
    pub(super) fn apply(
        self,
        vault: &Vault,
        scanned: DoorWindowVerdict,
    ) -> (DoorWindowVerdict, Vec<EffectDigest>) {
        if self.refused.is_empty() {
            return (scanned, self.approved);
        }
        let mut reasons = self.refused;
        match scanned {
            DoorWindowVerdict::Rejected { reasons: others } => {
                for other in others {
                    reasons.push_with(|| other);
                }
            }
            DoorWindowVerdict::Clean | DoorWindowVerdict::AdmitMarked { .. } => {
                for (digest, state, pusher) in &self.unasked {
                    if vault
                        .ask_owner_for_protected_ref_move(digest, state, pusher)
                        .is_err()
                    {
                        reasons.push_with(|| {
                            format!("{PROTECTED_REF_REWRITE}: the owner could not be asked")
                        });
                    }
                }
            }
            DoorWindowVerdict::NotInvoked => {}
        }
        let refused = DoorWindowVerdict::Rejected {
            reasons: reasons.into_reasons(),
        };
        (refused, Vec::new())
    }
}

impl Vault {
    /// Puts the owner the one question for the move `digest` names, in a
    /// write of its own. A question already asked for it, open or answered,
    /// is never asked again; nothing is asked for a pusher that names no
    /// principal.
    fn ask_owner_for_protected_ref_move(
        &self,
        digest: &EffectDigest,
        state: &serde_json::Value,
        pusher: &str,
    ) -> Result<Option<u64>> {
        let Some(ask) = MoveAsk::of(digest, pusher)? else {
            return Ok(None);
        };
        self.with_write_txn_grouped(|txn| {
            if let Some(seq) = ask.find_in_txn(self, txn)? {
                return Ok(Some(seq));
            }
            let mut question = ask.question;
            question.text = state.to_string();
            Ok(Some(self.queue_decision_ask_in_txn(
                txn,
                &HumanDecisionRequest {
                    question,
                    principal: ask.principal,
                    evidence: ask.evidence.to_vec(),
                    reason: HumanAskReason::OwnerSelected,
                    prior: None,
                    prior_provider: None,
                    queue_pin: ProviderPin {
                        rung: DecisionRung::Human,
                        model: ASK_QUEUE.to_owned(),
                        version: ASK_QUEUE_VERSION.to_owned(),
                    },
                    to: ask.to,
                    correlation: Some(ask.correlation),
                },
                Some(state),
            )?))
        })
    }

    /// Spends, in the intent's writer, the owner's leave for each rewrite of
    /// the protected ref the door let pass (`approved`), and withdraws the
    /// question each was asked as. A leave spent since the door read it
    /// refuses the intent. Returns the withdrawn questions' numbers, whose
    /// waiters wake once the write commits.
    pub(super) fn spend_protected_ref_leaves_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        pusher: &str,
        approved: &[EffectDigest],
    ) -> Result<Vec<u64>> {
        let mut withdrawn = Vec::new();
        for digest in approved {
            let authorization = approve_once_authorization_in_txn(&self.store, wtxn, digest)?
                .ok_or(Error::Gate(GateError::ConsentApproveOnceSpent(
                    "the owner's leave for this protected-ref move is gone",
                )))?;
            spend_approve_once_in_txn(&self.store, wtxn, &authorization)?;
            let Some(ask) = MoveAsk::of(digest, pusher)? else {
                continue;
            };
            if let Some(seq) = ask.find_in_txn(self, wtxn)?
                && self.withdraw_decision_ask_in_txn(wtxn, seq)?
            {
                withdrawn.push(seq);
            }
        }
        Ok(withdrawn)
    }
}
