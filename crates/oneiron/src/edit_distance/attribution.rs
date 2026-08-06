//! ED-03 (ONE-1759, ARCH-0056 §5): the amendment JUDGE, and the `*.edit_cost`
//! claim rows a judged amendment earns.
//!
//! ```text
//! Δ RECEIPT (ED-01/02)  +  routing facts (recorded at the amendment door)
//!   └─ judge_amendment ──> AmendmentJudgment
//!        ├─ skill_defect     → skill.edit_cost   (SKILL entity)
//!        ├─ execution_lapse  → actor.edit_cost   (ACTOR entity)
//!        ├─ discovery        → nothing here; SK-04 already owns its consequence
//!        ├─ environment      → nothing at all — the judgment row IS the record
//!        └─ preference_shift → a PREFERENCE proposal for ED-04's miner
//! ```
//!
//! # The judge extends SK-04, it does not fork it
//!
//! [`crate::skill_attribution`] landed the attempt lane: a FAILED attempt, two
//! routing facts, one of three verdicts. An amendment differs in exactly one
//! respect — the proposal was APPROVED, so "something was wrong" is no longer
//! given. A decider may amend a perfectly good proposal because the world moved
//! ([`AmendmentClass::Environment`]) or because they wanted it otherwise
//! ([`AmendmentClass::PreferenceShift`]).
//!
//! So this module adds ONE fact ([`AmendmentCause`]) and pre-filters on it.
//! The `ProposalWrong` arm is then handed VERBATIM to
//! [`AttributionJudge`] — SK-04's own trait, SK-04's own rule table, SK-04's
//! own [`crate::skill_attribution::attribution_call_purpose`] for an LLM tier.
//! There is no second classifier here and no LLM client: the import direction
//! is the proof, and a host that wants a model tier implements SK-04's trait
//! rather than a new one.
//!
//! # Cost is an AGGREGATE, never a raw Δ
//!
//! [`project_edit_cost_claims`] takes JUDGMENTS, not deltas — that signature is
//! the guard. A `d_norm` reaches a claim only after a class named who owns it,
//! and the value written is the mean over every persisted judgment sharing the
//! row's `(subject, scope)` pair. Recomputed from the judgment ledger on every
//! pass, so an interrupted pass leaves a stale row the next pass corrects,
//! never a double-counted one (the [`crate::skill_reliability`] posture).
//!
//! # The Blind Curator guard
//!
//! A judge biased toward "nothing was wrong" would quietly suppress every
//! contribution-based retirement downstream, and each individual verdict would
//! look defensible. [`run_judge_audit`] therefore runs the judge over a
//! held-out fixture set whose answers are already known — including one whose
//! honest answer is ABSTENTION — and persists the pass-rate as an aggregate.
//! The bias shows up as a number that moved, which is the only form in which it
//! is visible at all.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::actor_claims::{
    ActorClaimEvidence, ActorClaimRow, edit_cost_scope, edit_cost_scope_name, require_actor_entity,
    write_actor_claim,
};
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST,
};
use crate::edit_distance::delta::amendment_delta;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::skill_attribution::{
    AttemptOutcome, AttributionAuditReport, AttributionJudge, AttributionVerdict, OutcomeEvidence,
    RuleAttributionJudge,
};
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// Keyspace + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` prefix of the recorded routing facts, keyed by receipt id —
/// the same join key ED-01's Δ side-ledger uses, so evidence and measurement
/// are read with one lookup each and cannot drift apart.
const EVIDENCE_KEY_PREFIX: &[u8] = b"edit_distance/amendment_evidence/v1\0";

/// `vault_meta` prefix of the routed judgments, keyed by receipt id.
const JUDGMENT_KEY_PREFIX: &[u8] = b"edit_distance/amendment_judgment/v1\0";

/// `vault_meta` prefix of minted preference proposals, keyed by receipt id.
const PREFERENCE_KEY_PREFIX: &[u8] = b"edit_distance/preference_proposal/v1\0";

/// `vault_meta` prefix of the `(predicate, subject, scope)` tuples this
/// projector holds a live cost head for — the retraction ledger. Without it a
/// re-judged receipt's OLD tuple is unreachable: no judgment names it any more,
/// and nothing else knows a row was ever landed there.
const TARGET_KEY_PREFIX: &[u8] = b"edit_distance/edit_cost_target/v1\0";

/// `vault_meta` prefix of persisted audit reports: prefix ‖ at (8 BE) ‖
/// sequence (8 BE), so reports read back oldest-first and two runs in one
/// second stay two rows.
const AUDIT_KEY_PREFIX: &[u8] = b"edit_distance/judge_audit/v1\0";

/// Monotonic counter behind the audit key's sequence half.
const AUDIT_SEQUENCE_KEY: &[u8] = b"edit_distance/judge_audit_sequence/v1";

/// Only accepted schema version for any row this module stores.
const ROW_VERSION: u8 = 1;

const EVIDENCE_ROW_LABEL: &str = "amendment evidence row";
const JUDGMENT_ROW_LABEL: &str = "amendment judgment row";
const PREFERENCE_ROW_LABEL: &str = "preference proposal row";
const TARGET_ROW_LABEL: &str = "edit cost target row";
const AUDIT_ROW_LABEL: &str = "amendment judge audit row";

/// Longest accepted amendment scope — the ED lane's scope bound, shared with
/// `edit_distance::escalation` and the `actor.edit_cost` row it feeds.
const MAX_AMENDMENT_SCOPE_LEN: usize = crate::consent::MAX_CONSENT_REF_LEN;

/// Upper bound on the receipts one cost row cites, matching the `actor.*`
/// ledger's own bound so a skill row and an actor row cite alike.
const MAX_CITED_RECEIPTS: usize = crate::actor_claims::ACTOR_CLAIM_MAX_CITED_EVIDENCE;

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

/// The ARCH-0056 §5 amendment classes.
///
/// Deliberately an ALIAS of [`AttributionVerdict`] rather than a parallel enum:
/// the two lanes classify the same question about different evidence, and one
/// taxonomy is what keeps a downstream reader from having to learn two.
pub type AmendmentClass = AttributionVerdict;

/// Why the decider amended — the one fact the attempt lane never has to ask.
///
/// An attempt that FAILED is wrong by construction. An amendment rode an
/// APPROVAL, so wrongness is a question, and these three answers are what the
/// pre-filter in [`classify_amendment`] reasons over. `None` on the evidence
/// means the question is unsettled, and the judge abstains rather than guessing
/// — the false-pass bias [`run_judge_audit`] exists to expose starts exactly
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AmendmentCause {
    /// The proposal was wrong on its own terms. Routes down SK-04's ladder.
    ProposalWrong,
    /// The proposal was right when made; an external fact moved under it.
    ExternalChange,
    /// The proposal was not wrong; the decider wanted it otherwise.
    DeciderPreference,
}

impl AmendmentCause {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposalWrong => "proposal_wrong",
            Self::ExternalChange => "external_change",
            Self::DeciderPreference => "decider_preference",
        }
    }

    /// Parses a pinned on-disk token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proposal_wrong" => Some(Self::ProposalWrong),
            "external_change" => Some(Self::ExternalChange),
            "decider_preference" => Some(Self::DeciderPreference),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// One amendment, as the judge sees it: whose proposal was edited, in what
/// scope, and the facts that settle the class.
///
/// The `Option` facts are unsettled-by-default on purpose. A door that observed
/// an amendment but cannot say WHY records what it knows and lets the judge
/// abstain; inventing a cause to fill the slot is the failure this whole module
/// is instrumented against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendmentEvidence {
    /// The receipt ED-01 measured this amendment's Δ against.
    pub receipt_id: String,
    /// The actor whose proposal was amended.
    pub actor: EntityId,
    /// The SKILL the proposal rode, when it rode one.
    pub skill: Option<EntityId>,
    /// The `(subject, scope)` axis the resulting cost row is keyed on.
    pub scope: String,
    /// Why the decider amended (see [`AmendmentCause`]).
    pub cause: Option<AmendmentCause>,
    /// Did the actor actually follow what the skill said?
    pub followed_skill: Option<bool>,
    /// Did the skill contain content covering what the decider changed?
    pub skill_covered_step: Option<bool>,
    /// Unix seconds the amendment was observed.
    pub at: u64,
}

impl AmendmentEvidence {
    /// Builds evidence for one observed amendment, with every routing fact
    /// unsettled.
    #[must_use]
    pub fn new(receipt_id: impl Into<String>, actor: EntityId, scope: impl Into<String>) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            actor,
            skill: None,
            scope: scope.into(),
            cause: None,
            followed_skill: None,
            skill_covered_step: None,
            at: 0,
        }
    }

    /// Stamps when the amendment was observed.
    #[must_use]
    pub const fn at(mut self, at: u64) -> Self {
        self.at = at;
        self
    }

    /// Names the SKILL the amended proposal rode.
    #[must_use]
    pub const fn with_skill(mut self, skill: EntityId) -> Self {
        self.skill = Some(skill);
        self
    }

    /// Settles why the decider amended.
    #[must_use]
    pub const fn with_cause(mut self, cause: AmendmentCause) -> Self {
        self.cause = Some(cause);
        self
    }

    /// Settles the two facts SK-04's ladder reasons over.
    #[must_use]
    pub const fn with_routing_facts(
        mut self,
        followed_skill: bool,
        skill_covered_step: bool,
    ) -> Self {
        self.followed_skill = Some(followed_skill);
        self.skill_covered_step = Some(skill_covered_step);
        self
    }

    /// The attempt-lane shape of this evidence, for the delegated arm.
    ///
    /// [`AttemptOutcome::Failed`] is the honest stamp and not a convenience:
    /// this projection is only ever built for
    /// [`AmendmentCause::ProposalWrong`], and a proposal that had to be
    /// corrected did not succeed on its own terms.
    fn as_outcome_evidence(&self) -> OutcomeEvidence {
        let mut probe = OutcomeEvidence::new(
            self.receipt_id.as_str(),
            self.actor,
            AttemptOutcome::Failed,
            self.at,
        );
        probe.skill = self.skill;
        probe.followed_skill = self.followed_skill;
        probe.skill_covered_step = self.skill_covered_step;
        probe
    }
}

/// One routed amendment: the class, who owns it, and the Δ behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentJudgment {
    /// The receipt this judgment routed.
    pub receipt_id: String,
    pub class: AmendmentClass,
    /// SKILL for a defect or a discovery, ACTOR for a lapse, `None` for the
    /// two classes that name no owner.
    pub subject: Option<EntityId>,
    /// The `(subject, scope)` axis the cost row is keyed on.
    pub scope: String,
    /// Receipt ids this verdict rests on (trace-or-derivation).
    pub evidence_receipts: Vec<String>,
    /// ED-01's measured edit mass for this amendment.
    pub d_norm: f32,
    pub at: u64,
}

/// One minted PREFERENCE proposal: the durable consequence of a
/// [`AmendmentClass::PreferenceShift`], and ED-04's inlet.
///
/// It names no subject deliberately. A preference shift says the proposal was
/// not wrong — so there is nobody to charge, and the thing worth mining is the
/// Δ itself, which the cited receipt resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferenceProposal {
    /// The amendment receipt whose Δ carries the preference.
    pub receipt_id: String,
    /// The scope the preference was expressed in.
    pub scope: String,
    /// Receipt ids the originating judgment rested on.
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classifies one amendment, or ABSTAINS (`Ok(None)`) when the facts do not
/// settle it.
///
/// | cause | followed skill | skill covered it | class |
/// |---|---|---|---|
/// | external change | — | — | `Environment` |
/// | decider preference | — | — | `PreferenceShift` |
/// | proposal wrong | | | *delegated to `judge`* |
/// | unsettled | | | abstain |
///
/// The delegated arm is SK-04's table verbatim (lapse / defect / discovery),
/// reached by handing it the same evidence in its own shape. `judge` is the
/// tier seam: [`RuleAttributionJudge`] for the deterministic pass, a
/// host-supplied implementation for the model tier.
///
/// # Errors
///
/// Whatever `judge` returns.
pub fn classify_amendment(
    evidence: &AmendmentEvidence,
    judge: &dyn AttributionJudge,
) -> Result<Option<AmendmentClass>> {
    match evidence.cause {
        None => Ok(None),
        Some(AmendmentCause::ExternalChange) => Ok(Some(AmendmentClass::Environment)),
        Some(AmendmentCause::DeciderPreference) => Ok(Some(AmendmentClass::PreferenceShift)),
        Some(AmendmentCause::ProposalWrong) => judge.judge(&evidence.as_outcome_evidence()),
    }
}

/// The entity a class charges, or `None` when it charges nobody.
fn class_subject(class: AmendmentClass, evidence: &AmendmentEvidence) -> Option<EntityId> {
    match class {
        AmendmentClass::ExecutionLapse => Some(evidence.actor),
        AmendmentClass::SkillDefect | AmendmentClass::Discovery => evidence.skill,
        AmendmentClass::Environment | AmendmentClass::PreferenceShift => None,
    }
}

/// Which `*.edit_cost` row a class earns, or `None` when it earns none.
///
/// `Discovery` earns nothing HERE: missing content is SK-04's edit-proposal
/// case, and charging the skill for content it never claimed to have would
/// double-book a signal that already has a consequence.
const fn cost_predicate(class: AmendmentClass) -> Option<&'static str> {
    match class {
        AmendmentClass::ExecutionLapse => Some(PREDICATE_ACTOR_EDIT_COST),
        AmendmentClass::SkillDefect => Some(PREDICATE_SKILL_EDIT_COST),
        AmendmentClass::Discovery
        | AmendmentClass::Environment
        | AmendmentClass::PreferenceShift => None,
    }
}

// ---------------------------------------------------------------------------
// Evidence door
// ---------------------------------------------------------------------------

/// Records the routing facts behind one amendment, for a later judging pass.
///
/// Recording never classifies — the same split SK-04 keeps, and for the same
/// reason: facts can be captured where they are observed, and a fixed judge can
/// re-route them afterwards.
///
/// Everything the row asserts is RESOLVED here, at the door: the receipt must
/// carry a Δ this engine measured, any skill must exist, the scope must be a
/// usable key, and the actor must be an entity that can ACT. A judgment is only
/// as good as its inputs, and the classes it feeds author reserved truth.
///
/// The actor check is the DOWNSTREAM door's own ([`require_actor_entity`], the
/// D13 matrix), asked here rather than three passes later: an
/// [`AmendmentClass::ExecutionLapse`] on a TURN would be recorded, judged and
/// persisted before [`project_edit_cost_claims`] hit the refusal, wedging every
/// later pass on durable state the engine had already accepted.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when a reference does not resolve, names an
/// entity that cannot act, or the scope is unusable; storage errors.
pub fn record_amendment_evidence(vault: &Vault, evidence: &AmendmentEvidence) -> Result<()> {
    let scope = normalized_scope(&evidence.scope)?.to_owned();
    if amendment_delta(vault, &evidence.receipt_id)?.is_none() {
        return Err(invalid("amendment evidence cites an unmeasured receipt"));
    }
    require_actor_entity(vault, &evidence.actor)?;
    if let Some(skill) = evidence.skill
        && vault.get_skill_record(&skill)?.is_none()
    {
        return Err(invalid("amendment evidence names an unknown skill"));
    }
    let row = StoredEvidence {
        v: ROW_VERSION,
        actor: evidence.actor.to_hex(),
        skill: evidence.skill.map(|id| id.to_hex()),
        scope,
        cause: evidence.cause.map(|cause| cause.as_str().to_owned()),
        followed_skill: evidence.followed_skill,
        skill_covered_step: evidence.skill_covered_step,
        at: evidence.at,
    };
    let encoded = encode_row(&row, EVIDENCE_ROW_LABEL)?;
    let key = meta_key(EVIDENCE_KEY_PREFIX, evidence.receipt_id.as_bytes());
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

/// The routing facts recorded for `receipt_id`, if any.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an undecodable row; storage errors.
pub fn amendment_evidence(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentEvidence>> {
    let rtxn = vault.store.env.read_txn()?;
    amendment_evidence_in_txn(vault, &rtxn, receipt_id)
}

fn amendment_evidence_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_id: &str,
) -> Result<Option<AmendmentEvidence>> {
    let key = meta_key(EVIDENCE_KEY_PREFIX, receipt_id.as_bytes());
    let Some(raw) = vault.store.vault_meta.get(rtxn, &key)? else {
        return Ok(None);
    };
    let row: StoredEvidence = decode_row(&raw, EVIDENCE_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(EVIDENCE_ROW_LABEL));
    }
    Ok(Some(AmendmentEvidence {
        receipt_id: receipt_id.to_owned(),
        actor: hex_entity(&row.actor, EVIDENCE_ROW_LABEL)?,
        skill: row
            .skill
            .as_deref()
            .map(|hex| hex_entity(hex, EVIDENCE_ROW_LABEL))
            .transpose()?,
        scope: row.scope,
        cause: row
            .cause
            .as_deref()
            .map(|token| {
                AmendmentCause::parse(token).ok_or(Error::CorruptedIndex(EVIDENCE_ROW_LABEL))
            })
            .transpose()?,
        followed_skill: row.followed_skill,
        skill_covered_step: row.skill_covered_step,
        at: row.at,
    }))
}

// ---------------------------------------------------------------------------
// The judging pass
// ---------------------------------------------------------------------------

/// Judges the amendment recorded against `receipt_id` with the deterministic
/// tier, persisting and returning the judgment — or `None` when the judge
/// abstains, no facts were recorded, or no Δ was measured.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn judge_amendment(vault: &Vault, receipt_id: &str) -> Result<Option<AmendmentJudgment>> {
    judge_amendment_with(vault, receipt_id, &RuleAttributionJudge)
}

/// [`judge_amendment`] with an explicit tier — the seam the model judge and the
/// audit harness both use.
///
/// Re-judging OVERWRITES the receipt's judgment row rather than freezing the
/// first answer. A deterministic judge re-derives the same row, so the pass is
/// idempotent; a judge that has since been FIXED is exactly what the audit
/// exists to provoke, and a ledger that refused its correction would keep the
/// wrong verdict forever. The claim rows follow on the next
/// [`project_edit_cost_claims`] pass, which recomputes from this ledger.
///
/// ABSTENTION is a correction like any other. A re-judging pass whose honest
/// answer is silence WITHDRAWS whatever the previous pass persisted rather than
/// leaving it queryable: this ledger is what the projector recomputes from, so
/// a row nobody now stands behind would keep charging by itself.
///
/// # Errors
///
/// Storage errors, and whatever `judge` returns.
pub fn judge_amendment_with(
    vault: &Vault,
    receipt_id: &str,
    judge: &dyn AttributionJudge,
) -> Result<Option<AmendmentJudgment>> {
    let Some(evidence) = amendment_evidence(vault, receipt_id)? else {
        return Ok(None);
    };
    // No measurement, no judgment: a cost with nothing behind it is the number
    // this module refuses to invent.
    let Some(delta) = amendment_delta(vault, receipt_id)? else {
        return withdraw_judgment(vault, receipt_id).map(|()| None);
    };
    let Some(class) = classify_amendment(&evidence, judge)? else {
        return withdraw_judgment(vault, receipt_id).map(|()| None);
    };
    let judgment = AmendmentJudgment {
        receipt_id: receipt_id.to_owned(),
        class,
        subject: class_subject(class, &evidence),
        scope: normalized_scope(&evidence.scope)?.to_owned(),
        evidence_receipts: vec![receipt_id.to_owned()],
        d_norm: delta.d_norm,
        at: evidence.at,
    };
    // A class that charges somebody but names nobody is not a judgment, it is a
    // routing bug wearing one. Recorded as an abstention rather than landed.
    if cost_predicate(class).is_some() && judgment.subject.is_none() {
        return withdraw_judgment(vault, receipt_id).map(|()| None);
    }

    let row = StoredJudgment {
        v: ROW_VERSION,
        class: class.as_str().to_owned(),
        subject: judgment.subject.map(|id| id.to_hex()),
        scope: judgment.scope.clone(),
        evidence_receipts: judgment.evidence_receipts.clone(),
        d_norm: judgment.d_norm,
        at: judgment.at,
    };
    let encoded = encode_row(&row, JUDGMENT_ROW_LABEL)?;
    let judgment_key = meta_key(JUDGMENT_KEY_PREFIX, receipt_id.as_bytes());
    let preference_row = (class == AmendmentClass::PreferenceShift)
        .then(|| {
            encode_row(
                &StoredPreference {
                    v: ROW_VERSION,
                    scope: judgment.scope.clone(),
                    evidence_receipts: judgment.evidence_receipts.clone(),
                    at: judgment.at,
                },
                PREFERENCE_ROW_LABEL,
            )
        })
        .transpose()?;

    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &judgment_key, &encoded)?;
        let key = meta_key(PREFERENCE_KEY_PREFIX, receipt_id.as_bytes());
        match preference_row.as_ref() {
            // A proposal and the judgment that demanded it land together, and a
            // re-judgment that moved OFF preference_shift withdraws the
            // proposal it no longer stands behind.
            Some(row) => vault.store.vault_meta.put(wtxn, &key, row)?,
            None => {
                vault.store.vault_meta.delete(wtxn, &key)?;
            }
        }
        Ok(())
    })?;
    Ok(Some(judgment))
}

/// Deletes whatever a previous pass persisted for `receipt_id` — its judgment
/// and, with it, any preference proposal that judgment minted.
///
/// The withdrawal is the whole correction on this side: the cost head the row
/// was holding up loses its ledger support, and the next
/// [`project_edit_cost_claims`] pass retracts it.
fn withdraw_judgment(vault: &Vault, receipt_id: &str) -> Result<()> {
    let judgment_key = meta_key(JUDGMENT_KEY_PREFIX, receipt_id.as_bytes());
    let preference_key = meta_key(PREFERENCE_KEY_PREFIX, receipt_id.as_bytes());
    {
        // A receipt that never landed an answer has none to withdraw, and an
        // abstention is the common case — it must not cost a write transaction.
        let rtxn = vault.store.env.read_txn()?;
        if vault.store.vault_meta.get(&rtxn, &judgment_key)?.is_none()
            && vault
                .store
                .vault_meta
                .get(&rtxn, &preference_key)?
                .is_none()
        {
            return Ok(());
        }
    }
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.delete(wtxn, &judgment_key)?;
        vault.store.vault_meta.delete(wtxn, &preference_key)?;
        Ok(())
    })
}

/// Every persisted amendment judgment, in receipt-id order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn amendment_judgments(vault: &Vault) -> Result<Vec<AmendmentJudgment>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, JUDGMENT_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let receipt_id = key_tail(&key, JUDGMENT_KEY_PREFIX, JUDGMENT_ROW_LABEL)?;
        let row: StoredJudgment = decode_row(&raw, JUDGMENT_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(JUDGMENT_ROW_LABEL));
        }
        out.push(AmendmentJudgment {
            receipt_id,
            class: AmendmentClass::parse(&row.class)
                .ok_or(Error::CorruptedIndex(JUDGMENT_ROW_LABEL))?,
            subject: row
                .subject
                .as_deref()
                .map(|hex| hex_entity(hex, JUDGMENT_ROW_LABEL))
                .transpose()?,
            scope: row.scope,
            evidence_receipts: row.evidence_receipts,
            d_norm: row.d_norm,
            at: row.at,
        });
    }
    Ok(out)
}

/// Every preference proposal awaiting ED-04's miner, in receipt-id order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn pending_preference_proposals(vault: &Vault) -> Result<Vec<PreferenceProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PREFERENCE_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let receipt_id = key_tail(&key, PREFERENCE_KEY_PREFIX, PREFERENCE_ROW_LABEL)?;
        let row: StoredPreference = decode_row(&raw, PREFERENCE_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(PREFERENCE_ROW_LABEL));
        }
        out.push(PreferenceProposal {
            receipt_id,
            scope: row.scope,
            evidence_receipts: row.evidence_receipts,
            at: row.at,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The claim write door
// ---------------------------------------------------------------------------

/// Projects judged amendments into `*.edit_cost` rows, returning the claim ids
/// this pass landed.
///
/// **Judgments, never deltas.** The argument type is the guard the ticket asks
/// for: there is no path from a raw `d_norm` to a claim that does not pass a
/// class first.
///
/// **Every judgment is re-grounded, not trusted.** [`AmendmentJudgment`] is a
/// public type with public fields and this function authors reserved truth, so
/// a row counts only if it IS the row this module persisted for that receipt
/// (the ONE-1738/ONE-1739 posture). Ungrounded rows are SKIPPED rather than
/// fatal — one forged row must not deny a whole pass.
///
/// The value written is RECOMPUTED from the whole judgment ledger for the row's
/// `(subject, scope)` pair, so the pass is idempotent and an interrupted one
/// leaves a stale row rather than a double-counted one. A pass that would write
/// the row already standing writes nothing and re-returns it.
///
/// **Every pass reconciles before it writes.** The judgment ledger is
/// overwrite-by-receipt, so a re-judgment can move a receipt off the tuple it
/// used to charge — and nothing in the new judgment names the old one. The
/// tuples this projector has landed are therefore kept as their own ledger, and
/// one that has lost every supporting judgment is RETRACTED here rather than
/// left charging a verdict no judge stands behind.
///
/// # Errors
///
/// Storage errors, and whatever the `actor.*` write door rejects.
pub fn project_edit_cost_claims(
    vault: &Vault,
    judgments: &[AmendmentJudgment],
) -> Result<Vec<EntityId>> {
    let persisted = amendment_judgments(vault)?;
    retract_unsupported_targets(vault, &persisted)?;
    let mut targets: Vec<(&'static str, EntityId, String)> = Vec::new();
    for judgment in judgments {
        let Some(predicate) = cost_predicate(judgment.class) else {
            continue;
        };
        let Some(subject) = judgment.subject else {
            continue;
        };
        // Grounded is not authorization: this row must also BE the row this
        // module routed for that receipt.
        if !persisted
            .iter()
            .any(|row| row.receipt_id == judgment.receipt_id && row == judgment)
        {
            continue;
        }
        let target = (predicate, subject, judgment.scope.clone());
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    let mut written = Vec::with_capacity(targets.len());
    for (predicate, subject, scope) in targets {
        let Some(aggregate) = aggregate_for(&persisted, predicate, subject, &scope) else {
            continue;
        };
        // Recorded BEFORE the head it describes: the write door owns its own
        // transaction, so the two cannot land atomically, and a tuple recorded
        // without a head is reconciled away harmlessly while a head landed
        // without its tuple would be unreachable for the rest of time.
        record_target(vault, predicate, &subject, &scope)?;
        written.push(write_cost_head(
            vault, predicate, subject, &scope, &aggregate,
        )?);
    }
    Ok(written)
}

/// Lands one tuple's cost head — or re-returns the head that already says
/// exactly this.
///
/// The no-op arm is what makes a replay a replay. Both writers mint
/// `EntityId::now()` and supersede whatever head they find, so an unchanged
/// pass without this check forks a fresh claim entity every run: unbounded
/// phantom supersession history, sync traffic for a number that did not move,
/// and a different id back from a function whose contract is idempotence.
///
/// ONE head, and only one: two active heads for a tuple is a post-sync fork
/// that must collapse even when the surviving value is unchanged, so that case
/// falls through to the writers on purpose.
fn write_cost_head(
    vault: &Vault,
    predicate: &'static str,
    subject: EntityId,
    scope: &str,
    aggregate: &CostAggregate,
) -> Result<EntityId> {
    let evidence = ActorClaimEvidence::amendment(aggregate.receipts.clone(), aggregate.at)?;
    let value = rmpv::Value::F32(aggregate.cost);
    let cited = if predicate == PREDICATE_ACTOR_EDIT_COST {
        evidence.to_value()
    } else {
        skill_cost_evidence(aggregate)
    };
    {
        let rtxn = vault.store.env.read_txn()?;
        let heads = active_cost_heads_in_txn(vault, &rtxn, predicate, &subject, scope)?;
        if let [(head_id, head)] = heads.as_slice()
            && head.value == value
            && head.valid_from == Some(aggregate.at)
            && head.evidence.as_ref() == Some(&cited)
        {
            return Ok(*head_id);
        }
    }
    if predicate == PREDICATE_ACTOR_EDIT_COST {
        write_actor_claim(
            vault,
            ActorClaimRow::EditCost {
                actor: subject,
                scope: scope.to_owned(),
                cost: aggregate.cost,
            },
            &evidence,
        )
    } else {
        write_skill_edit_cost(vault, &subject, scope, aggregate)
    }
}

// ---------------------------------------------------------------------------
// The landed-target ledger (retraction)
// ---------------------------------------------------------------------------

/// Records that this projector holds a live head for `(predicate, subject,
/// scope)`, so a later pass can find it again after the judgments that earned
/// it have moved elsewhere.
fn record_target(
    vault: &Vault,
    predicate: &'static str,
    subject: &EntityId,
    scope: &str,
) -> Result<()> {
    let encoded = encode_row(
        &StoredTarget {
            v: ROW_VERSION,
            predicate: predicate.to_owned(),
            subject: subject.to_hex(),
            scope: scope.to_owned(),
        },
        TARGET_ROW_LABEL,
    )?;
    let key = target_key(predicate, subject, scope);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

/// Every tuple this projector has landed a head for.
fn recorded_targets(vault: &Vault) -> Result<Vec<(&'static str, EntityId, String)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, TARGET_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        let row: StoredTarget = decode_row(&raw, TARGET_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(TARGET_ROW_LABEL));
        }
        let predicate =
            known_cost_predicate(&row.predicate).ok_or(Error::CorruptedIndex(TARGET_ROW_LABEL))?;
        out.push((
            predicate,
            hex_entity(&row.subject, TARGET_ROW_LABEL)?,
            row.scope,
        ));
    }
    Ok(out)
}

/// Closes every landed head the judgment ledger no longer supports.
///
/// A receipt re-judged onto another class, subject or scope orphans the head
/// its old tuple was holding up: the aggregate is only ever recomputed for
/// tuples some judgment still points at, so without this the old charge would
/// stand forever and [`edit_cost_for`] would keep reporting it. Retraction —
/// not deletion — is the withdrawal: the row stays readable as history.
fn retract_unsupported_targets(vault: &Vault, persisted: &[AmendmentJudgment]) -> Result<()> {
    for (predicate, subject, scope) in recorded_targets(vault)? {
        if aggregate_for(persisted, predicate, subject, &scope).is_some() {
            continue;
        }
        retract_target(vault, predicate, &subject, &scope)?;
    }
    Ok(())
}

/// Retracts one tuple's active heads and forgets the tuple, in one transaction.
///
/// The `skill.*`/`actor.*` namespaces own their own lifecycle mechanics — the
/// generic [`crate::Vault::retract_claim`] refuses a reserved predicate by
/// design — so the closed body is re-put through the same engine-owned door
/// that wrote it, exactly as the reserved supersession path does.
fn retract_target(
    vault: &Vault,
    predicate: &'static str,
    subject: &EntityId,
    scope: &str,
) -> Result<()> {
    let now = crate::unix_seconds_now();
    let key = target_key(predicate, subject, scope);
    vault.with_write_txn(|wtxn| {
        for (id, mut body) in active_cost_heads_in_txn(vault, wtxn, predicate, subject, scope)? {
            let header = {
                let Some(raw) = vault.store.entities.get(&*wtxn, id.as_bytes())? else {
                    continue;
                };
                EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("edit cost claim entity"))?
            };
            // The clamp mirrors the supersession path: a withdrawal stamped
            // BEFORE the row it closes would make the re-Put range invalid and
            // roll the whole transaction back.
            let at = now.max(header.occurred_start);
            body.lifecycle = ClaimLifecycleStatus::Retracted;
            body.valid_to = Some(at);
            vault.put_reserved_claim_in_txn(
                wtxn,
                &id,
                &body,
                TimeRange {
                    start: header.occurred_start,
                    end: at,
                },
                header.learned_at,
            )?;
        }
        vault.store.vault_meta.delete(wtxn, &key)?;
        Ok(())
    })
}

/// The `vault_meta` key of one landed tuple. The scope goes LAST: it is the
/// only field a caller supplies, so nothing it can contain shifts another.
fn target_key(predicate: &str, subject: &EntityId, scope: &str) -> Vec<u8> {
    let mut handle = Vec::with_capacity(predicate.len() + scope.len() + 2 * ENTITY_ID_LEN + 2);
    handle.extend_from_slice(predicate.as_bytes());
    handle.push(0);
    handle.extend_from_slice(subject.to_hex().as_bytes());
    handle.push(0);
    handle.extend_from_slice(scope.as_bytes());
    meta_key(TARGET_KEY_PREFIX, &handle)
}

/// The `'static` predicate a stored token names, if it names one of the two.
fn known_cost_predicate(token: &str) -> Option<&'static str> {
    [PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST]
        .into_iter()
        .find(|predicate| *predicate == token)
}

/// One `(subject, scope)` pair's folded cost.
struct CostAggregate {
    cost: f32,
    /// The newest cited receipts, oldest-first, bounded.
    receipts: Vec<String>,
    /// The newest judged amendment's stamp — the row's event time.
    at: u64,
}

/// Folds every persisted judgment charging `(predicate, subject, scope)`.
///
/// The mean is the aggregate, and it is taken over the CLASS that earns this
/// predicate only: a `discovery` names the same SKILL a `skill_defect` does,
/// and folding both would charge a skill for content it never claimed to have.
fn aggregate_for(
    persisted: &[AmendmentJudgment],
    predicate: &'static str,
    subject: EntityId,
    scope: &str,
) -> Option<CostAggregate> {
    let mut rows: Vec<&AmendmentJudgment> = persisted
        .iter()
        .filter(|row| {
            row.subject == Some(subject)
                && row.scope == scope
                && cost_predicate(row.class) == Some(predicate)
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    rows.sort_by(|left, right| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    let total: f64 = rows.iter().map(|row| f64::from(row.d_norm)).sum();
    // Precision loss is intended: this is a reported estimate over a bounded
    // unit-interval fold, not an accumulator.
    #[expect(
        clippy::cast_precision_loss,
        reason = "reported aggregate over unit-interval judgments"
    )]
    let mean = (total / rows.len() as f64).clamp(0.0, 1.0) as f32;
    let at = rows.last().map_or(0, |row| row.at);
    // The NEWEST citations survive the bound: a row's trace should point at the
    // evidence nearest the estimate it carries.
    let first = rows.len().saturating_sub(MAX_CITED_RECEIPTS);
    let receipts = rows[first..]
        .iter()
        .flat_map(|row| row.evidence_receipts.iter().cloned())
        .take(MAX_CITED_RECEIPTS)
        .collect();
    Some(CostAggregate {
        cost: mean,
        receipts,
        at,
    })
}

/// Writes the `skill.edit_cost` head for one `(skill, scope)` pair, superseding
/// every active head that shares it.
///
/// The `skill.*` mirror of [`write_actor_claim`]: the body is built HERE, never
/// by a caller, and rides `put_reserved_claim_in_txn` — the same engine-owned
/// door `skill.reliability` and the scan verdicts author through.
fn write_skill_edit_cost(
    vault: &Vault,
    skill: &EntityId,
    scope: &str,
    aggregate: &CostAggregate,
) -> Result<EntityId> {
    if vault.get_skill_record(skill)?.is_none() {
        return Err(Error::EntityNotFound);
    }
    let scope = normalized_scope(scope)?.to_owned();
    let at = aggregate.at;
    let value = rmpv::Value::F32(aggregate.cost);
    let evidence = skill_cost_evidence(aggregate);
    vault.with_write_txn(|wtxn| {
        let heads =
            active_cost_heads_in_txn(vault, wtxn, PREDICATE_SKILL_EDIT_COST, skill, &scope)?;
        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_SKILL_EDIT_COST,
            ClaimSubject::Entity(*skill),
            value.clone(),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(evidence.clone());
        body.scope = Some(edit_cost_scope(&scope));
        body.valid_from = Some(at);
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange { start: at, end: at },
            at,
        )?;
        // EVERY active head closes, not just the first found: `EntityId::now()`
        // is per-replica unique, so two replicas that both projected this pair
        // hold two distinct claims, and closing one would leave the other live
        // forever. The `max` mirrors the sibling clamp — an out-of-order event
        // time makes the re-Put range invalid and rolls the transaction back.
        for (head_id, head) in &heads {
            let head_start = head.valid_from.unwrap_or(0);
            vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, head_id, at.max(head_start))?;
        }
        Ok(claim_id)
    })
}

/// The citation array a `skill.edit_cost` row carries — the `skill.*` shape,
/// beside the lane envelope its `actor.*` sibling's own ledger builds.
fn skill_cost_evidence(aggregate: &CostAggregate) -> rmpv::Value {
    rmpv::Value::Array(
        aggregate
            .receipts
            .iter()
            .map(|receipt| rmpv::Value::from(receipt.as_str()))
            .collect(),
    )
}

/// The active heads of one `(predicate, subject, scope)` tuple.
///
/// One scan for both predicates: an entity is an ACTOR or a SKILL, never both,
/// so the tuple already says which ledger is being read.
fn active_cost_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    predicate: &str,
    subject: &EntityId,
    scope: &str,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut heads = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, subject)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != predicate
            || body.lifecycle != ClaimLifecycleStatus::Active
            || edit_cost_scope_name(body.scope.as_ref()) != Some(scope)
        {
            continue;
        }
        heads.push((id, body));
    }
    Ok(heads)
}

/// The live `*.edit_cost` estimate for `(subject, scope)`, or `None`.
///
/// One read for both predicates: an entity is an ACTOR or a SKILL, never both,
/// so the subject already says which row is being asked about. Two active heads
/// for one pair is a legitimate post-sync convergence state, so the newest wins
/// deterministically — by event time, then claim id — rather than bricking the
/// read.
///
/// # Errors
///
/// Storage errors.
pub fn edit_cost_for(vault: &Vault, subject: &EntityId, scope: &str) -> Result<Option<f32>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(u64, EntityId, f32)> = None;
    for id in vault.claims_for_subject_in_txn(&rtxn, subject)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if !matches!(
            body.predicate.as_str(),
            PREDICATE_SKILL_EDIT_COST | PREDICATE_ACTOR_EDIT_COST
        ) || body.lifecycle != ClaimLifecycleStatus::Active
            || edit_cost_scope_name(body.scope.as_ref()) != Some(scope)
        {
            continue;
        }
        let rmpv::Value::F32(cost) = body.value else {
            return Err(invalid("edit_cost value must be a cost in 0..=1"));
        };
        let valid_from = body.valid_from.unwrap_or(0);
        let newer = match &best {
            None => true,
            Some((best_from, best_id, _)) => {
                valid_from > *best_from || (valid_from == *best_from && id > *best_id)
            }
        };
        if newer {
            best = Some((valid_from, id, cost));
        }
    }
    Ok(best.map(|(_, _, cost)| cost))
}

// ---------------------------------------------------------------------------
// Defect-injection audit (Blind Curator guard)
// ---------------------------------------------------------------------------

/// One held-out audit case: an amendment whose correct class is already known.
///
/// `expected: None` means ABSTENTION is the honest answer — a judge that names
/// a class anyway is WRONG, not unlucky. Without that arm the audit could only
/// reward labelling, which is the bias it exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendmentAuditFixture {
    pub evidence: AmendmentEvidence,
    pub expected: Option<AmendmentClass>,
}

/// Runs the built-in held-out audit against the deterministic tier, persists
/// the report, and returns the pass-rate.
///
/// # Errors
///
/// Storage errors.
pub fn run_judge_audit(vault: &Vault) -> Result<f32> {
    let fixtures = held_out_amendment_fixtures();
    let report = run_judge_audit_with_judge(
        vault,
        &fixtures,
        &RuleAttributionJudge,
        crate::unix_seconds_now(),
    )?;
    Ok(report.pass_rate())
}

/// The audit harness: any fixture set, any tier.
///
/// Reuses [`AttributionAuditReport`] rather than minting a second metric shape —
/// two evidence classes, one number ops reads. The rows land in this module's
/// own keyspace so the two ledgers stay tellable apart.
///
/// # Errors
///
/// Storage errors, and whatever `judge` returns.
pub fn run_judge_audit_with_judge(
    vault: &Vault,
    fixtures: &[AmendmentAuditFixture],
    judge: &dyn AttributionJudge,
    at: u64,
) -> Result<AttributionAuditReport> {
    let mut passed = 0;
    let mut abstained = 0;
    for fixture in fixtures {
        let answer = classify_amendment(&fixture.evidence, judge)?;
        if answer.is_none() {
            abstained += 1;
        }
        if answer == fixture.expected {
            passed += 1;
        }
    }
    let report = AttributionAuditReport {
        total: fixtures.len(),
        passed,
        abstained,
        at,
    };
    let encoded = encode_row(
        &StoredAudit {
            v: ROW_VERSION,
            total: report.total as u64,
            passed: report.passed as u64,
            abstained: report.abstained as u64,
            at,
        },
        AUDIT_ROW_LABEL,
    )?;
    vault.with_write_txn(|wtxn| {
        let sequence = next_audit_sequence_in_txn(vault, wtxn)?;
        let mut handle = Vec::with_capacity(16);
        handle.extend_from_slice(&at.to_be_bytes());
        handle.extend_from_slice(&sequence.to_be_bytes());
        let key = meta_key(AUDIT_KEY_PREFIX, &handle);
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })?;
    Ok(report)
}

/// Every persisted audit report, oldest first.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn judge_audit_reports(vault: &Vault) -> Result<Vec<AttributionAuditReport>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, AUDIT_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        let row: StoredAudit = decode_row(&raw, AUDIT_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(AUDIT_ROW_LABEL));
        }
        let count = |value: u64| -> Result<usize> {
            usize::try_from(value).map_err(|_| Error::CorruptedIndex(AUDIT_ROW_LABEL))
        };
        out.push(AttributionAuditReport {
            total: count(row.total)?,
            passed: count(row.passed)?,
            abstained: count(row.abstained)?,
            at: row.at,
        });
    }
    Ok(out)
}

/// The held-out set: one case per class the judge can reach, plus one whose
/// honest answer is ABSTENTION.
///
/// The case ids are OPAQUE and carry no class token. A fixture named
/// `audit:environment` would let a judge score full marks by reading the label
/// instead of the facts — precisely the bias this audit exists to expose, so
/// the answer key must not leak into its own inputs.
///
/// These ids are never resolved against any ledger: fixtures go straight to
/// [`classify_amendment`], never through [`record_amendment_evidence`]. Subject
/// ids are minted fresh per call and never written — the table reasons over the
/// cause and the two routing facts, so a fixed seed would only risk aliasing a
/// real entity.
#[must_use]
pub fn held_out_amendment_fixtures() -> Vec<AmendmentAuditFixture> {
    let actor = EntityId::now();
    let skill = EntityId::now();
    let base = |case: &str| {
        AmendmentEvidence::new(case, actor, "audit")
            .at(1)
            .with_skill(skill)
    };
    let wrong = |case: &str, followed: bool, covered: bool| {
        base(case)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(followed, covered)
    };
    vec![
        AmendmentAuditFixture {
            evidence: wrong("audit:amendment:1", true, true),
            expected: Some(AmendmentClass::SkillDefect),
        },
        AmendmentAuditFixture {
            evidence: wrong("audit:amendment:2", false, true),
            expected: Some(AmendmentClass::ExecutionLapse),
        },
        AmendmentAuditFixture {
            evidence: wrong("audit:amendment:3", true, false),
            expected: Some(AmendmentClass::Discovery),
        },
        AmendmentAuditFixture {
            evidence: base("audit:amendment:4").with_cause(AmendmentCause::ExternalChange),
            expected: Some(AmendmentClass::Environment),
        },
        AmendmentAuditFixture {
            evidence: base("audit:amendment:5").with_cause(AmendmentCause::DeciderPreference),
            expected: Some(AmendmentClass::PreferenceShift),
        },
        // The cause is unsettled, so the honest answer is to abstain. A judge
        // that names a class here is wrong, not unlucky.
        AmendmentAuditFixture {
            evidence: base("audit:amendment:6").with_routing_facts(true, true),
            expected: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEvidence {
    v: u8,
    actor: String,
    skill: Option<String>,
    scope: String,
    cause: Option<String>,
    followed_skill: Option<bool>,
    skill_covered_step: Option<bool>,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredJudgment {
    v: u8,
    class: String,
    subject: Option<String>,
    scope: String,
    evidence_receipts: Vec<String>,
    d_norm: f32,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPreference {
    v: u8,
    scope: String,
    evidence_receipts: Vec<String>,
    at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTarget {
    v: u8,
    predicate: String,
    subject: String,
    scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAudit {
    v: u8,
    total: u64,
    passed: u64,
    abstained: u64,
    at: u64,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}

fn decode_row<T: serde::de::DeserializeOwned>(raw: &[u8], label: &'static str) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

fn meta_key(prefix: &[u8], handle: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

/// The receipt id a keyed row was stored under.
fn key_tail(key: &[u8], prefix: &[u8], label: &'static str) -> Result<String> {
    let tail = key
        .get(prefix.len()..)
        .ok_or(Error::CorruptedIndex(label))?;
    String::from_utf8(tail.to_vec()).map_err(|_| Error::CorruptedIndex(label))
}

fn hex_entity(hex: &str, label: &'static str) -> Result<EntityId> {
    EntityId::from_hex(hex).map_err(|_| Error::CorruptedIndex(label))
}

/// The trimmed scope, or the reason it is not one — `escalation`'s rule, so one
/// scope string means one thing lane-wide.
fn normalized_scope(scope: &str) -> Result<&str> {
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_AMENDMENT_SCOPE_LEN {
        return Err(invalid(
            "an amendment scope must be non-empty and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}

fn next_audit_sequence_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let current = match vault.store.vault_meta.get(&*wtxn, AUDIT_SEQUENCE_KEY)? {
        Some(raw) => {
            let bytes: [u8; 8] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex(AUDIT_ROW_LABEL))?;
            u64::from_be_bytes(bytes)
        }
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("judge audit sequence"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, AUDIT_SEQUENCE_KEY, &next.to_be_bytes())?;
    Ok(next)
}

#[cfg(test)]
mod tests;
