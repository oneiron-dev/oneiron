//! The protected ref of a served repository, and the owner's leave for one
//! move of it (L8-51).
//!
//! A push by anyone but the vault's owner may neither delete nor rewrite the
//! branch the repository's HEAD names: force-push or deletion of a protected
//! ref, and history rewrite, are the repo surface's catastrophe class
//! (ARCH-0068 RC4; DEC-0006 names them one-way). Such a push is refused while
//! the hook still blocks the backend, so nothing it carried lands. A push to a
//! symbolic ref whose referent is the protected ref is the same move, since git
//! moves or deletes the referent in its place; the hook names each such
//! referent, and the move is judged as the protected ref's.
//!
//! A deletion or rewrite the door would otherwise have let land puts one
//! question to the owner. Its state names the move (the repository, the ref,
//! the old tip, the new tip or none for a deletion, the pusher) and the
//! approve-once digest the engine composed over exactly those. The owner's
//! leave is `vault.consent.approve_once` on that digest (DEC-0006): a plain
//! "yes" to the question mints nothing. The same push sent again then passes
//! the door, and its intent's writer spends the leave with the intent, after
//! every other check, so one leave lands one move. A leave spent on a move
//! git then does not make is gone; the owner's own push is the way left.
//! Git refuses a deletion that names the branch HEAD names, for every pusher,
//! so a leave for that deletion meets git's own refusal, which the pusher
//! reads as git's.
//!
//! Inside its scope, the owner's live bypass grant replaces the question
//! (DEC-0006 invariant 7; the floor's `protected_ref_rewrite_or_delete`): a
//! bypass scoped to the repository's PROJECT whose bound names the pusher and
//! the ref lets the move pass unasked. The intent's writer reads it again and
//! receipts the act as bypassed, with the intent or not at all.

use super::door_window::{DoorWindowRequest, DoorWindowVerdict, printable_ref_name};
use super::retained_reasons::RetainedReasons;
use crate::Vault;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, CatastropheClass, ComposedEffect, EffectDigest,
    EffectFacts, EffectPlace, GrantBound, UndoFidelity, approve_once_authorization_in_txn,
    covering_bypass_ref_in_txn, spend_approve_once_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::federation::GitPushRepo;
use crate::git_wire::GitOid;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};

/// The typed reason a push by anyone but the vault's owner meets when it
/// deletes the repository's protected ref, or moves it to a commit that does
/// not descend from the ref's tip.
const PROTECTED_REF_REWRITE_OR_DELETE: &str = "protected_ref_rewrite_or_delete";

/// The operation kind every protected-ref move's consent effect names, the
/// move's own hash appended.
const MOVE_OPERATION_KIND: &str = "origin.protected_ref_rewrite_or_delete";
const MOVE_DIGEST_DOMAIN: &[u8] = b"oneiron:origin-protected-ref-move:v1";

/// Versioned native queue identity; the host renders the structured question.
const ASK_QUEUE: &str = "origin.protected_ref_rewrite_or_delete";
const ASK_QUEUE_VERSION: &str = "v1";
const ASK_VERSION: u32 = 1;
const ASK_DOMAIN: &[u8] = b"oneiron:origin-protected-ref-move-ask:v1";

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

/// One deletion or rewrite of the protected ref, as one pusher proposed it.
struct ProtectedRefMove<'a> {
    protected: &'a ProtectedRef,
    old_oid: &'a GitOid,
    /// `None` for a deletion.
    new_oid: Option<&'a GitOid>,
    pusher: &'a str,
}

impl ProtectedRefMove<'_> {
    /// The facts of exactly this move: one operation kind that binds the
    /// repository, the ref, the old tip, the new tip (empty for a deletion),
    /// and the pusher. Each part is length-prefixed, so a deletion never
    /// shares a rewrite's kind. The transport's operation id is not in it, so
    /// the same push sent again names the same move.
    fn facts(&self) -> Result<EffectFacts> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MOVE_DIGEST_DOMAIN);
        for part in [
            self.protected.repo_identity_hex.as_str(),
            self.protected.name.as_str(),
            self.old_oid.as_str(),
            self.new_oid.map_or("", GitOid::as_str),
            self.pusher,
        ] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        let mut facts = EffectFacts::new(format!(
            "{MOVE_OPERATION_KIND}.{}",
            hasher.finalize().to_hex()
        ))?;
        // The commits the deletion or rewrite drops stay in the object store
        // only until it is pruned.
        facts.undo_fidelity = UndoFidelity::Partial;
        Ok(facts)
    }

    /// The approve-once digest of exactly this move, over its facts alone.
    fn approval_digest(&self) -> Result<EffectDigest> {
        Ok(ComposedEffect::new(self.facts()?).digest())
    }

    /// The effect a live bypass grant is matched against (DEC-0006 invariant
    /// 7): this move's facts on the catastrophe floor, the pusher acting on
    /// the ref (`ref:<name>`) of the repository's CODE anchor, inside the
    /// anchor's PROJECT. It is composed apart from the approve-once digest,
    /// whose key it never is; its digest goes on the Bypassed receipt.
    fn coverage_effect(&self, repo: &GitPushRepo) -> Result<ComposedEffect> {
        let class = CatastropheClass::ProtectedRefRewriteOrDelete;
        let action = GrantBound::action(
            ActorBound::new(self.pusher)?,
            ActionClass::new(class.as_str())?,
            ActionEnvelope::new([format!("ref:{}", self.protected.name)])?
                .with_target(repo.repo.to_hex())?,
        )?;
        Ok(ComposedEffect::new(self.facts()?.with_catastrophe(class))
            .with_action_requirement(action)?
            .in_place(EffectPlace {
                project: Some(repo.project),
                thread: None,
            }))
    }

    /// The state the owner's question carries: native identifiers only (a
    /// deletion's `new_oid` is null), and the digest the owner's leave names.
    fn ask_state(&self, digest: &EffectDigest) -> serde_json::Value {
        serde_json::json!({
            "repo_identity": self.protected.repo_identity_hex,
            "ref": self.protected.name,
            "old_oid": self.old_oid.as_str(),
            "new_oid": self.new_oid.map(GitOid::as_str),
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
    /// The refused deletions and rewrites the owner is asked about if
    /// nothing else refuses the push, each with its digest.
    unasked: Vec<(EffectDigest, serde_json::Value, String)>,
    /// The deletions and rewrites that pass, and on what.
    passes: ProtectedRefPasses,
}

/// The deletions and rewrites of the protected ref the door let pass, and on
/// what. The intent's writer spends each leave and reads each bypass again,
/// with the intent or not at all.
#[derive(Default)]
pub(super) struct ProtectedRefPasses {
    /// The digests of the moves the owner left once, still unspent.
    approved: Vec<EffectDigest>,
    /// The coverage effects of the moves a live bypass of the owner's
    /// covered.
    bypassed: Vec<ComposedEffect>,
}

impl ProtectedRefDecision {
    /// Reads, for each move of `protected` in `request`, whether it may land:
    /// a creation and a fast-forward pass; a deletion or a rewrite passes on
    /// a live bypass of the owner's that covers it, or else only on the
    /// owner's unspent leave for exactly it. An update naming a symbolic ref
    /// whose referent is `protected` is such a move, since git moves the
    /// referent: it is judged, covered, asked and left as that move. `pusher`
    /// is the principal the push was admitted for, and `repo` the CODE anchor
    /// and PROJECT its authority names; with no `repo`, no bypass covers the
    /// move.
    pub(super) fn read(
        vault: &Vault,
        protected: &ProtectedRef,
        request: &DoorWindowRequest,
        pusher: Option<&str>,
        repo: Option<&GitPushRepo>,
    ) -> Result<Self> {
        let mut decision = Self::default();
        for update in (request.ref_updates.iter())
            .filter(|update| request.moved_ref(&update.name) == protected.name)
        {
            let refuse = |decision: &mut Self, why: &str| {
                decision.refused.push_with(|| {
                    format!(
                        "{}: {PROTECTED_REF_REWRITE_OR_DELETE}: {why}",
                        printable_ref_name(&update.name)
                    )
                });
            };
            // A creation moves no tip anyone had.
            let Some(old_oid) = &update.old_oid else {
                continue;
            };
            let new_oid = update.new_oid.as_ref();
            if new_oid.is_some() && !request.rewritten_refs.contains(&update.name) {
                continue;
            }
            let act = if new_oid.is_some() {
                "rewrite"
            } else {
                "delete"
            };
            let Some(pusher) = pusher else {
                refuse(
                    &mut decision,
                    format!("only the vault's owner may {act} this repository's default branch")
                        .as_str(),
                );
                continue;
            };
            let protected_move = ProtectedRefMove {
                protected,
                old_oid,
                new_oid,
                pusher,
            };
            let rtxn = vault.store.env.read_txn()?;
            // Inside its scope, the owner's live bypass replaces the
            // question: the move passes unasked, and the intent's writer
            // receipts it as bypassed.
            if let Some(repo) = repo {
                let coverage = protected_move.coverage_effect(repo)?;
                if covering_bypass_ref_in_txn(&vault.store, &rtxn, &coverage)?.is_some() {
                    // One move named twice, through a symbolic ref and its
                    // referent, is receipted once.
                    if !decision.passes.bypassed.contains(&coverage) {
                        decision.passes.bypassed.push(coverage);
                    }
                    continue;
                }
            }
            let digest = protected_move.approval_digest()?;
            match approve_once_authorization_in_txn(&vault.store, &rtxn, &digest) {
                // A symbolic ref and its referent named together for one move
                // are one move: its leave is spent once.
                Ok(Some(_)) if decision.passes.approved.contains(&digest) => {}
                Ok(Some(_)) => decision.passes.approved.push(digest),
                Ok(None) => {
                    refuse(
                        &mut decision,
                        format!(
                            "only the vault's owner may {act} this repository's default branch, \
                             or allow this exact move once"
                        )
                        .as_str(),
                    );
                    decision.unasked.push((
                        digest,
                        protected_move.ask_state(&digest),
                        pusher.to_owned(),
                    ));
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

    /// The window's verdict with this decision applied, and the passes the
    /// intent's writer must settle. A refusal here refuses the push. When
    /// nothing else refused it, the owner is asked about each refused move,
    /// once per digest: a push the door would refuse anyway costs the owner
    /// no question.
    pub(super) fn apply(
        self,
        vault: &Vault,
        scanned: DoorWindowVerdict,
    ) -> (DoorWindowVerdict, ProtectedRefPasses) {
        if self.refused.is_empty() {
            return (scanned, self.passes);
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
                            format!(
                                "{PROTECTED_REF_REWRITE_OR_DELETE}: the owner could not be asked"
                            )
                        });
                    }
                }
            }
            DoorWindowVerdict::NotInvoked => {}
        }
        let refused = DoorWindowVerdict::Rejected {
            reasons: reasons.into_reasons(),
        };
        (refused, ProtectedRefPasses::default())
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

    /// Settles, in the intent's writer, each deletion or rewrite of the
    /// protected ref the door let pass. A bypassed move's bypass is read
    /// again on this write and the act receipted as bypassed; a bypass
    /// revoked since the door read it refuses the intent. Each leave is spent
    /// and the question it was asked as withdrawn; a leave spent since the
    /// door read it refuses the intent. Returns the withdrawn questions'
    /// numbers, whose waiters wake once the write commits.
    pub(super) fn settle_protected_ref_passes_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        pusher: &str,
        passes: &ProtectedRefPasses,
    ) -> Result<Vec<u64>> {
        for coverage in &passes.bypassed {
            if !self.record_covering_bypass_in_txn(wtxn, coverage)? {
                return Err(Error::Gate(GateError::ConsentGrantRevoked));
            }
        }
        let mut withdrawn = Vec::new();
        for digest in &passes.approved {
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
