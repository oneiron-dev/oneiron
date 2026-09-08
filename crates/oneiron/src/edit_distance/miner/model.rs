//! ED-04 miner domain and stored-row types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::config::{ROW_VERSION, SKILL_EDIT_VERDICT_ACCEPTED, SKILL_EDIT_VERDICT_REJECTED};
use crate::edit_distance::FinalizedProposalText;
use crate::edit_distance::attribution::AmendmentJudgment;
use crate::edit_distance::delta::{AmendmentDelta, DeltaSource};
use crate::entity_id::EntityId;
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One bucket of identical normalized substitutions inside one scope.
///
/// `receipt_refs` are ED-01 receipt ids — STRINGS, because that is what a
/// receipt id is in this engine (`gate:<hex>`, `proposal_outcome:<hex>`); the
/// Δ side-ledger and ED-03's judgment ledger key on the same type.
///
/// `actor` is part of the bucket's KEY, not derived from it. ARCH-0056 §5 pins
/// the scope as the `op × target class × skill/agent` cross, so a scope already
/// names one actor — keying on it explicitly is what lets the preference arm
/// name a SUBJECT without ever guessing between two candidates. `skill` IS
/// derived: it is the skill every citing amendment named, and `None` when they
/// disagree or none did, so a content arm never edits a skill on a split vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionCluster {
    /// The `(op × target class × skill/agent)` axis this bucket lives on.
    pub scope: String,
    /// Normalized text the decider removed.
    pub from: String,
    /// Normalized text the decider wrote instead.
    pub to: String,
    /// The actor whose output kept earning this correction.
    pub actor: EntityId,
    /// The skill every citing amendment rode, when they agree on one.
    pub skill: Option<EntityId>,
    /// Distinct amendment receipts showing this substitution, in receipt-id
    /// order so two passes over one ledger cite the same list in the same order.
    pub receipt_refs: Vec<String>,
    /// `receipt_refs.len()` — the recurrence count K is compared against.
    pub count: u32,
    /// The newest citing amendment's stamp; the emitted proposal's event time.
    pub at: u64,
}

/// What one cluster earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinedOutcome {
    /// A `preference.phrasing` claim landed in the Proposed lane.
    PreferenceClaim(EntityId),
    /// A gated skill-edit proposal was minted (never applied).
    SkillEditProposal(EntityId),
    /// Fewer than K distinct receipts — nothing was emitted.
    BelowThreshold,
}

/// Which lane a substitution routes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstitutionClass {
    /// Every token on both sides is tone/stop lexicon: a phrasing swap.
    Lexical,
    /// At least one token is content: a factual or structural correction.
    Content,
}

impl SubstitutionClass {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lexical => "lexical",
            Self::Content => "content",
        }
    }

    /// The receipted rationale for this routing — pinned text, so two readers
    /// quoting a proposal quote the same sentence.
    #[must_use]
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::Lexical => "every token on both sides is in the tone lexicon",
            Self::Content => "at least one token on one side is outside the tone lexicon",
        }
    }
}

/// One minted skill-edit proposal: the durable consequence of a recurring
/// CONTENT correction, and ONE-1448's rejected-edit-buffer source.
///
/// Minting is not applying (the ONE-1737 posture): this row is a proposal the
/// gated apply door picks up, and nothing here touches the skill's content or
/// its prior version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinedSkillEditProposal {
    /// This proposal's own handle.
    pub proposal_id: EntityId,
    /// The SKILL whose content kept being corrected.
    pub skill: EntityId,
    /// The scope the correction recurred in.
    pub scope: String,
    /// Normalized text to replace.
    pub from: String,
    /// Normalized text to replace it with.
    pub to: String,
    /// Receipt ids the cluster rested on.
    pub evidence_receipts: Vec<String>,
    /// Why the chooser routed here.
    pub rationale: String,
    pub at: u64,
    /// The decider's answer, once there is one — the hysteresis seam.
    ///
    /// `None` is an OPEN proposal. It is a recorded field rather than an
    /// inference from the row's absence because a deletion cannot tell an
    /// acceptance from a refusal, and the cooldown needs to tell them apart.
    pub decision: Option<MinedSkillEditDecision>,
}

/// What a decider said about a mined skill-edit proposal, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinedSkillEditDecision {
    pub verdict: MinedSkillEditVerdict,
    /// The verdict's own clock — where the rejection cooldown runs from.
    pub at: u64,
}

/// The two answers a mined skill-edit proposal can receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinedSkillEditVerdict {
    /// The edit was applied through the gated apply door.
    Accepted,
    /// The decider refused it. The cluster goes quiet for
    /// [`MINER_REJECTION_COOLDOWN_SECS`].
    Rejected,
}

impl MinedSkillEditVerdict {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => SKILL_EDIT_VERDICT_ACCEPTED,
            Self::Rejected => SKILL_EDIT_VERDICT_REJECTED,
        }
    }

    pub(super) fn from_token(token: &str) -> Option<Self> {
        match token {
            SKILL_EDIT_VERDICT_ACCEPTED => Some(Self::Accepted),
            SKILL_EDIT_VERDICT_REJECTED => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// A normalized substitution pair extracted from one edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Substitution {
    pub(super) from: String,
    pub(super) to: String,
}

/// What one miner pass is, as the caller supplies it.
///
/// The sitting alone is not enough to WRITE with, for two reasons the engine
/// enforces rather than documents:
///
/// * The D13 matrix ([`crate::provenance::validate_actor_class`]) binds actor
///   class to entity kind — a SESSION is not an actor entity at all — so the
///   pass cannot mint its own write actor, and the `dreamer_runner`
///   milestone-envelope rule says in as many words that WHICH actor a
///   deployment trusts is policy the engine does not hold.
/// * `gate.rs` derives a Proposed claim's INBOX GROUP KEY only from an
///   `Agent`-class `Generated` write whose provenance names the dreamer surface
///   AND a run id. Get that wrong and the proposal lands in a tray with no
///   group — Proposed forever, reviewable by nobody. So the run id is a
///   required field, not decoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerRun {
    /// The sitting whose close ran this pass: the provenance stamp and the
    /// review-bundle session tag, so one pass's proposals surface together.
    pub session: EntityId,
    /// The Dreamer run this pass belongs to — the inbox group key.
    pub run_id: String,
    /// The DREAMER agent actor every emitted proposal is written as.
    pub agent: WriteActor,
}

/// The `(scope, actor, from, to)` identity of one bucket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ClusterKey {
    pub(super) scope: String,
    pub(super) actor: EntityId,
    pub(super) from: String,
    pub(super) to: String,
}

/// One bucket under construction.
#[derive(Debug, Default)]
pub(super) struct Bucket {
    pub(super) receipts: Vec<String>,
    /// The skill every fold so far has named — `None` until the first fold,
    /// `Some(None)` when the folds agree that no skill was named.
    pub(super) skill: Option<Option<EntityId>>,
    /// Set once two folds disagree.
    pub(super) skill_conflict: bool,
    pub(super) at: u64,
}

impl Bucket {
    /// Folds one citing amendment in. Receipts are counted DISTINCTLY: one
    /// receipt whose window shows a substitution three times is one occurrence
    /// of a habit, not three.
    pub(super) fn observe(&mut self, receipt_id: &str, skill: Option<EntityId>, at: u64) {
        if !self.receipts.iter().any(|seen| seen == receipt_id) {
            self.receipts.push(receipt_id.to_owned());
        }
        match self.skill {
            None => self.skill = Some(skill),
            Some(held) if held == skill => {}
            Some(_) => self.skill_conflict = true,
        }
        self.at = self.at.max(at);
    }

    pub(super) fn into_cluster(mut self, key: ClusterKey) -> SubstitutionCluster {
        self.receipts.sort();
        SubstitutionCluster {
            scope: key.scope,
            from: key.from,
            to: key.to,
            actor: key.actor,
            skill: if self.skill_conflict {
                None
            } else {
                self.skill.flatten()
            },
            count: u32::try_from(self.receipts.len()).unwrap_or(u32::MAX),
            receipt_refs: self.receipts,
            at: self.at,
        }
    }
}

/// What one judged amendment contributes: the routing facts and the text pair.
pub(super) struct AmendmentSource<'a> {
    pub(super) actor: EntityId,
    pub(super) skill: Option<EntityId>,
    pub(super) delta_source: DeltaSource,
    pub(super) artifact: &'a FinalizedProposalText,
}

/// Every persisted proposal artifact, addressable by either ref pair a Δ can
/// name it with.
pub(super) struct ArtifactIndex {
    pub(super) records: Vec<FinalizedProposalText>,
    pub(super) by_refs: BTreeMap<(String, String), usize>,
}

impl ArtifactIndex {
    /// The artifact a Δ's `(proposed_ref, final_ref)` pair names.
    pub(super) fn resolve(&self, delta: &AmendmentDelta) -> Option<&FinalizedProposalText> {
        let key = (delta.proposed_ref.clone(), delta.final_ref.clone());
        self.records.get(*self.by_refs.get(&key)?)
    }
}

/// The changed region of both texts, widened to whole-token boundaries.
pub(super) struct Region {
    /// Shared start — the two texts agree left of the changed run.
    pub(super) start: usize,
    pub(super) before_end: usize,
    pub(super) after_end: usize,
}

/// The GLOBAL miner work gate: the newest judged amendment a pass has seen, and
/// how many judgments shared that exact second.
///
/// The count is what makes the gate EXACT. Judgment stamps are second-granular
/// while the corrections that earn them are not, so a stamp alone cannot tell a
/// fourth receipt landing in the boundary second from the three already folded
/// in: a strict `>` bound would strand it, and a `>=` bound would re-cluster the
/// whole ledger on every pass forever. Counting the boundary second answers the
/// only question the gate asks — "is there evidence I have not seen?" — without
/// either failure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MinerWatermark {
    /// The newest judgment stamp seen.
    pub at: u64,
    /// Judgments stamped exactly `at` when this watermark was written.
    pub boundary: u64,
}

impl MinerWatermark {
    /// The watermark `judgments` currently support, or `None` when the ledger
    /// is empty.
    pub(super) fn observed(judgments: &[AmendmentJudgment]) -> Option<Self> {
        let at = judgments.iter().map(|judgment| judgment.at).max()?;
        Some(Self {
            at,
            boundary: judgments
                .iter()
                .filter(|judgment| judgment.at == at)
                .count() as u64,
        })
    }

    /// Whether this watermark holds evidence `previous` did not.
    pub(super) const fn advances(self, previous: Self) -> bool {
        self.at > previous.at || (self.at == previous.at && self.boundary > previous.boundary)
    }
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

/// A dedup POINTER, not a content record: what was proposed already lives in
/// the claim body or the skill-edit row the reference names, so the mark stores
/// nothing but where to look.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredMintMark {
    pub(super) v: u8,
    pub(super) kind: String,
    /// Hex of the claim or proposal this cluster minted.
    pub(super) reference: String,
}

impl StoredMintMark {
    pub(super) fn new(kind: &str, reference: &EntityId) -> Self {
        Self {
            v: ROW_VERSION,
            kind: kind.to_owned(),
            reference: reference.to_hex(),
        }
    }
}

/// The at-threshold cluster, persisted as the mined claim's evidence.
///
/// Everything the miner actually observed and nothing it did not: the scope the
/// correction recurred in, both normalized sides, the chooser's routing, the
/// ordered distinct receipts, their count, and the newest citing stamp. It is
/// the SAME material `MinedSkillEditProposal` records for the content lane —
/// stored here as an entity, because an entity is what a resolver can follow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredMinedEvidence {
    pub(super) v: u8,
    pub(super) scope: String,
    pub(super) from: String,
    pub(super) to: String,
    pub(super) class: String,
    pub(super) receipt_refs: Vec<String>,
    pub(super) count: u32,
    pub(super) at: u64,
}

impl StoredMinedEvidence {
    pub(super) fn new(cluster: &SubstitutionCluster, class: SubstitutionClass) -> Self {
        Self {
            v: ROW_VERSION,
            scope: cluster.scope.clone(),
            from: cluster.from.clone(),
            to: cluster.to.clone(),
            class: class.as_str().to_owned(),
            receipt_refs: cluster.receipt_refs.clone(),
            count: cluster.count,
            at: cluster.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredSkillEdit {
    pub(super) v: u8,
    pub(super) skill: String,
    pub(super) scope: String,
    pub(super) from: String,
    pub(super) to: String,
    pub(super) evidence_receipts: Vec<String>,
    pub(super) rationale: String,
    pub(super) at: u64,
    pub(super) decision: Option<StoredSkillEditDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredSkillEditDecision {
    pub(super) outcome: String,
    pub(super) at: u64,
}
