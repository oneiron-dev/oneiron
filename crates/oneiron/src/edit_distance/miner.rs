//! ED-04 (ONE-1760, ARCH-0056 §4): the recurring-substitution miner — the
//! Dreamer session-end pass that turns a REPEATED correction into a proposal.
//!
//! ```text
//! judged amendments (ED-03)  ──> Δ (ED-01) ──> proposal artifact (ED-00)
//!    └─ substitution runs ──> normalized token pairs ──> per-scope clusters
//!         └─ >=K distinct receipts ──> chooser
//!              ├─ lexical  ──> preference.phrasing claim (Proposed, gated)
//!              └─ content  ──> gated skill-edit proposal (ONE-1448's source)
//! ```
//!
//! # Recurrence, not weighting (§4, ruling r3)
//!
//! One changed word is not a signal; the SAME changed word across K distinct
//! amendments is. So nothing here scores a substitution — the mining is
//! mechanical (exact normalized pairs, bucketed) and the semantics come from
//! the count. There are no embeddings, no stemming and no similarity: two
//! substitutions cluster when their normalized text is EQUAL, which is the one
//! rule a reader can check by eye.
//!
//! # Where the pass runs
//!
//! It rides the LANDED SessionEnd wake as a consolidation-scope job —
//! `dreamer_consolidation`'s executor dispatches
//! [`DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE`](crate::dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE)
//! exactly as it dispatches the reflection gap scan: a payload discriminator on
//! the existing queue, never a second wake mechanism.
//!
//! The registration is
//! [`register_substitution_mine_in_txn`](crate::dreamer_consolidation), inside
//! `Vault::end_session_with_wake`'s own close transaction and dedupe-keyed on
//! the sitting — so the pass is a durable fact of the close rather than
//! something the closing process meant to do, session close never blocks on it,
//! and a pass that dies is simply re-admitted by the queue. Concurrency is not
//! assumed away: the emission's dedup check runs INSIDE its write transaction,
//! so two passes running at once still mint one proposal per cluster.
//!
//! # Two ledgers, one law
//!
//! * **Counts are never stored.** [`mine_substitution_clusters`] recomputes
//!   every cluster from the judgment ledger on every pass (doc-13 r1, the
//!   `skill.reliability` posterior posture). The watermark is a WORK GATE —
//!   "did anything new arrive?" — never a counting boundary; a cluster's
//!   recurrence accumulates across sittings because nothing ever consumes it.
//! * **Emissions are marked.** A cluster that emitted records a MINT-MARK in
//!   the SAME transaction as its proposal, and the dedup check that gates that
//!   emission READS the marks inside that same transaction. Both halves land or
//!   neither does, and nothing can slip between the check and the write, so one
//!   cluster mints one proposal even when two callers race.
//! * **The watermark advances ONCE, at the end of a pass.** It is a pass-wide
//!   work gate, and folding it into a cluster's transaction would make the
//!   first emission speak for clusters it never reached: a pass that died
//!   between two eligible clusters would leave the second one behind a bound it
//!   never earned, and the replay that should have emitted it would find
//!   nothing new to do. The mint-marks are what make the replay emit ONCE; the
//!   watermark only decides whether a replay does any work at all.
//!
//! # Hysteresis is a dial, not a wall
//!
//! A cluster whose proposal is OPEN, or which already landed, never
//! re-proposes. A cluster whose proposal the decider REJECTED goes quiet for
//! [`MINER_REJECTION_COOLDOWN_SECS`] and may then speak again — the sibling of
//! `DREAMER_GAP_DECAY_MS`'s escalate-or-let-go rule. Nagging is the failure
//! mode; permanent silence after one "no" is the other one.
//!
//! Both emission classes answer that question the same way, because both have
//! to: the preference arm reads the tray row and the gate ledger the inbox door
//! writes, and the skill-edit arm reads the DECISION its own proposal row
//! carries ([`resolve_mined_skill_edit`] is the door ONE-1448's gated apply
//! answers through). Row-existence alone cannot say "rejected, recently" — it
//! collapses a no into either permanent silence or instant re-proposal — so the
//! verdict is recorded rather than inferred from a deletion.
//!
//! # A proposal nobody can answer is not a proposal
//!
//! Both emissions are PROPOSALS, never applications, so both are worthless
//! unless a decider can reach them. That makes two things load-bearing rather
//! than cosmetic: the preference claim's envelope must carry the `Agent`-class
//! Generated dreamer provenance `gate.rs` derives an INBOX GROUP KEY from, and
//! it must NOT carry a session tag (see `miner_envelope`). [`MinerRun`] is
//! shaped by that requirement, and the pass refuses rather than landing a
//! proposal into a tray with no group.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{FinalizedProposalText, PROPOSAL_ARTIFACT_KEY_PREFIX, decode_finalized_proposal_text};
use crate::Vault;
use crate::actor_claims::edit_cost_scope;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::edit_distance::attribution::{
    AmendmentJudgment, amendment_evidence, amendment_judgments,
};
use crate::edit_distance::delta::{AmendmentDelta, DeltaSource, amendment_delta};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

// ---------------------------------------------------------------------------
// Dials + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` key holding K, the distinct-receipt threshold.
///
/// The key lives HERE, not in `settings.rs`: that module is UI customization,
/// and this is a per-feature engine dial over `vault_meta` — the
/// `INBOX_REVIEW_DIAL_KEY` house pattern.
pub const MINER_K_SETTINGS_KEY: &[u8] = b"settings:edit_distance:v1:miner_k";

/// K when the dial has never been set.
///
/// Three is the smallest count that distinguishes a habit from a coincidence:
/// two identical corrections are a pair, and a pair is what a decider produces
/// by fixing the same draft twice.
pub const MINER_K_DEFAULT: u32 = 3;

/// How long a REJECTED proposal keeps its cluster quiet.
///
/// The seconds-flavoured sibling of `DREAMER_GAP_DECAY_MS` (14 days): long
/// enough that a "no" is respected, short enough that a preference which really
/// did change can be re-observed rather than lost for good.
pub const MINER_REJECTION_COOLDOWN_SECS: u64 = 14 * 24 * 60 * 60;

/// The predicate a mined LEXICAL substitution claims.
///
/// `preference.*` is an existing public claim family (`serialize.rs` already
/// treats it as manifest-critical), so a mined phrasing preference is readable
/// by the same prompt-assembly path that reads a stated one — which is the
/// whole point of §4's "the edits stop happening". Defined in the owning module
/// rather than `claim.rs` for the `identity_topology::PREDICATE_ENTITY_DISTINCT_FROM`
/// reason: `CLAIM_PREDICATE_REGISTRY` is a documented well-known list whose
/// arity is coordinated across lanes, and a predicate does not need to join it
/// to be written through the public gate.
pub const PREDICATE_PREFERENCE_PHRASING: &str = "preference.phrasing";

/// Domain for cluster handles, so a handle can never be confused with another
/// unit's hash (the `DREAMER_BUCKET_HASH_DOMAIN` pattern).
const MINER_CLUSTER_HASH_DOMAIN: &[u8] = b"oneiron:edit-distance-substitution-cluster:v1";

/// Domain for the mined-evidence record's entity id, derived FROM the cluster
/// handle: one more separation so a record id can never be read as a handle,
/// a mint-mark key, or another unit's entity.
const MINER_EVIDENCE_RECORD_ID_DOMAIN: &[u8] = b"oneiron:edit-distance-mined-evidence:v1";

/// `vault_meta` key of the GLOBAL work-gate watermark.
const MINER_WATERMARK_KEY: &[u8] = b"edit_distance/miner_watermark/v1";

/// `vault_meta` prefix of the mint-marks, keyed by cluster handle.
const MINT_MARK_KEY_PREFIX: &[u8] = b"edit_distance/miner_mint_mark/v1\0";

/// `vault_meta` prefix of the mined skill-edit proposals, keyed by proposal id.
const SKILL_EDIT_KEY_PREFIX: &[u8] = b"edit_distance/miner_skill_edit/v1\0";

/// Only accepted schema version for any row this module stores.
const ROW_VERSION: u8 = 1;

const MINT_MARK_ROW_LABEL: &str = "substitution mint mark row";
const MINED_EVIDENCE_ROW_LABEL: &str = "mined substitution evidence record";
const SKILL_EDIT_ROW_LABEL: &str = "mined skill edit proposal row";

/// Reader-facing key under which the ordered receipt citations ride ALONGSIDE
/// the consolidation envelope in a mined claim's candidate evidence.
const MINED_EVIDENCE_RECEIPTS_KEY: &str = "receipt_refs";
const WATERMARK_ROW_LABEL: &str = "substitution miner watermark";
const MINER_K_ROW_LABEL: &str = "substitution miner k dial";

/// Longest substitution side the miner will cluster, in whitespace tokens.
///
/// Past it the edit is a REWRITE, not a recurring correction: a nine-token
/// replacement is essentially never produced twice verbatim, so admitting it
/// buys buckets that can only ever hold one member while widening the key space
/// the mint-marks hash over.
const MAX_SUBSTITUTION_TOKENS: usize = 8;

/// Bound on the artifact rows one pass reads.
///
/// A bound on WORK, matching the receipt family's own scan cap: the pass runs
/// at session close, and a vault with a very long artifact history must not
/// turn a close into an unbounded walk. Past it the pass mines the oldest rows
/// it can reach, which is the same direction ED-01's projection pass degrades
/// in — less evidence, never wrong evidence.
const MAX_ARTIFACT_SCAN: usize = 100_000;

/// Confidence stamped on a mined preference claim.
///
/// Deliberately NOT derived from the recurrence count. The miner has no
/// probability to report — it observed that a threshold was crossed, which is a
/// boolean fact — and a count dressed up as a confidence would be exactly the
/// fake precision the `d_norm` metric was pinned to avoid. A reader who wants
/// the strength reads the citation array, which names every receipt.
const MINER_PREFERENCE_CONFIDENCE: f32 = 0.5;

/// Value-map keys of a mined preference claim.
const PREFERENCE_VALUE_KEY_FROM: &str = "from";
const PREFERENCE_VALUE_KEY_TO: &str = "to";
const PREFERENCE_VALUE_KEY_CLASS: &str = "class";
const PREFERENCE_VALUE_KEY_RATIONALE: &str = "rationale";

/// Provenance-map keys of the miner's write envelope. `surface` and `run` are
/// the two `gate.rs` parses for the inbox group key; the other two are this
/// module's own trace.
const PROVENANCE_KEY_SURFACE: &str = "surface";
const PROVENANCE_KEY_RUN: &str = "run";
const PROVENANCE_KEY_SESSION: &str = "session";
const PROVENANCE_KEY_CLUSTER: &str = "cluster";

/// The only key of the dreamer attempt payload this job rides.
///
/// A miner attempt names the SITTING and nothing else, because the sitting is
/// all the session-close transaction that registers it knows. The write actor
/// is the deployment's (`ConsolidationExecutor::actor` — the D13 rule that a
/// SESSION is not an actor entity, and the `dreamer_runner` milestone-envelope
/// ruling that WHICH actor a deployment trusts is policy the engine does not
/// hold), and the inbox group is the queue row's own run id.
const PAYLOAD_KEY_SESSION: &str = "session";

/// The gate-decision outcome token the inbox reject door writes.
///
/// Mirrored rather than shared: the token is a pinned LEDGER string and the door
/// that writes it lives in another module's write path. A reader of that ledger
/// is entitled to name what it is looking for.
const GATE_OUTCOME_REJECTED: &str = "rejected";

/// Pinned mint-mark kinds.
const MARK_KIND_PREFERENCE: &str = "preference_claim";
const MARK_KIND_SKILL_EDIT: &str = "skill_edit_proposal";

/// Pinned on-disk tokens of a skill-edit proposal's verdict.
const SKILL_EDIT_VERDICT_ACCEPTED: &str = "accepted";
const SKILL_EDIT_VERDICT_REJECTED: &str = "rejected";

/// The tone/stop lexicon the chooser reasons over — SORTED, so membership is a
/// binary search and a careless insertion is a test failure rather than a slow
/// path.
///
/// Closed and small on purpose. It holds the words a phrasing preference is
/// made of (greetings, sign-offs, politeness, hedges) plus the function words
/// that ride along with them. Anything NOT here is content, which is the safe
/// direction: an unlisted word routes a substitution to the skill-edit lane,
/// where a human reads it, rather than to a preference claim that quietly
/// rewrites future drafts.
const TONE_LEXICON: [&str; 74] = [
    "a",
    "actually",
    "all",
    "an",
    "and",
    "any",
    "as",
    "at",
    "be",
    "best",
    "but",
    "by",
    "cheers",
    "dear",
    "do",
    "for",
    "from",
    "greetings",
    "hello",
    "hey",
    "hi",
    "i",
    "if",
    "in",
    "is",
    "it",
    "just",
    "kind",
    "kindly",
    "madam",
    "many",
    "maybe",
    "me",
    "my",
    "of",
    "on",
    "only",
    "or",
    "our",
    "perhaps",
    "please",
    "possibly",
    "quite",
    "rather",
    "really",
    "regards",
    "respectfully",
    "sincerely",
    "sir",
    "so",
    "some",
    "somewhat",
    "thank",
    "thanks",
    "that",
    "the",
    "their",
    "them",
    "then",
    "this",
    "to",
    "truly",
    "us",
    "very",
    "warm",
    "warmly",
    "was",
    "we",
    "were",
    "with",
    "yes",
    "you",
    "your",
    "yours",
];

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

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

    fn from_token(token: &str) -> Option<Self> {
        match token {
            SKILL_EDIT_VERDICT_ACCEPTED => Some(Self::Accepted),
            SKILL_EDIT_VERDICT_REJECTED => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// A normalized substitution pair extracted from one edit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Substitution {
    from: String,
    to: String,
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

// ---------------------------------------------------------------------------
// The K dial
// ---------------------------------------------------------------------------

/// Reads K, the distinct-receipt threshold (default [`MINER_K_DEFAULT`]).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] when the stored dial is not a
/// positive decimal count.
pub fn miner_k(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, MINER_K_SETTINGS_KEY)? else {
        return Ok(MINER_K_DEFAULT);
    };
    std::str::from_utf8(&raw)
        .ok()
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|k| *k > 0)
        .ok_or(Error::CorruptedIndex(MINER_K_ROW_LABEL))
}

/// Persists K.
///
/// Stored as decimal ASCII so the dial is readable in a `vault_meta` dump —
/// the `InboxReviewDial` token convention, applied to a count.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when `k` is zero: a threshold of zero emits on
/// the FIRST correction, which is the opposite of recurrence. Storage errors.
pub fn set_miner_k(vault: &Vault, k: u32) -> Result<()> {
    if k == 0 {
        return Err(invalid("the substitution miner's K must be at least 1"));
    }
    let encoded = k.to_string();
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, MINER_K_SETTINGS_KEY, encoded.as_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------------

/// Session-end pass: scan Δ receipts since the GLOBAL miner watermark, cluster,
/// emit at >=K.
///
/// The mint-mark and its DEDUP CHECK ride the same transaction as the proposal,
/// so a crash between emit and mark is unreachable and a racing caller cannot
/// double-propose. The pass-wide watermark advances once, at the END of the
/// pass, so a pass that dies partway leaves every unreached cluster still
/// reachable by the replay.
///
/// `run` names the sitting whose close triggered the pass and the actor its
/// proposals are written as (see [`MinerRun`]).
///
/// The returned vector holds one entry per cluster the pass RULED on. A cluster
/// the pass declined to rule on is ABSENT rather than reported as
/// below-threshold: an already-open proposal, a cooling rejection and a content
/// correction with no skill to edit are three different silences, and none of
/// them is "this did not recur".
///
/// # Errors
///
/// Storage errors; whatever the claim write gate rejects for a single cluster
/// rolls that cluster's transaction back and fails the pass.
pub fn run_substitution_miner(vault: &Vault, run: &MinerRun) -> Result<Vec<MinedOutcome>> {
    // Checked HERE, before any evidence is read, because the consequence is
    // invisible at the write: a mined preference under the wrong actor class or
    // with no run id lands Proposed in a tray that has no group, so no surface
    // can ever show it and no decider can ever answer it. Refusing the pass is
    // the only outcome a caller can notice.
    if run.agent.actor_class() != EdgeActorClass::Agent || run.run_id.trim().is_empty() {
        return Err(invalid(
            "a miner pass needs an Agent-class actor and a run id, or its proposals are unreviewable",
        ));
    }
    let judgments = amendment_judgments(vault)?;
    // The watermark is a WORK GATE: no evidence the last pass did not already
    // see means there is nothing a re-cluster could conclude that it did not.
    let Some(observed) = MinerWatermark::observed(&judgments) else {
        return Ok(Vec::new());
    };
    if !observed.advances(miner_watermark(vault)?) {
        return Ok(Vec::new());
    }

    let now = crate::unix_seconds_now();
    let k = miner_k(vault)?;
    let clusters = clusters_from(vault, &judgments)?;
    let mut outcomes = Vec::with_capacity(clusters.len());
    for cluster in &clusters {
        if cluster.count < k {
            outcomes.push(MinedOutcome::BelowThreshold);
            continue;
        }
        if let Some(outcome) = emit_cluster(vault, run, cluster, now)? {
            outcomes.push(outcome);
        }
    }
    // ONCE, and only now that every cluster has been ruled on. An error above
    // returns before this line, so the failed pass's unreached clusters are
    // still new evidence to its replay.
    vault.with_write_txn(|wtxn| advance_watermark_in_txn(vault, wtxn, observed))?;
    Ok(outcomes)
}

/// The `DreamerAttemptPayload.input` a substitution-mine attempt carries: the
/// sitting whose close registered it, and nothing else.
///
/// The shape is owned HERE rather than by the queue, so the module that defines
/// the job also defines its payload and `dreamer_consolidation` stays a
/// dispatcher. The entity ref rides as 16 MessagePack-binary bytes — the house
/// convention (`TURN_BODY_WORLD_REF_KEY`).
///
/// It carries no write actor on purpose. The registration runs inside the
/// session-close transaction, which knows a sitting ended and nothing about
/// which agent a deployment trusts to author claims; that is the executor's
/// configured actor, and a payload that pretended otherwise would be a policy
/// decision smuggled into a lifecycle door.
#[must_use]
pub fn miner_attempt_input(session: &EntityId) -> Value {
    Value::Map(vec![(
        Value::from(PAYLOAD_KEY_SESSION),
        Value::Binary(session.as_bytes().to_vec()),
    )])
}

/// Inverse of [`miner_attempt_input`].
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the payload does not name a sitting. Every
/// proposal a pass lands is stamped with it, and inventing one would put an
/// untraceable claim in front of the decider.
pub fn miner_session_from_input(input: &Value) -> Result<EntityId> {
    let Value::Map(entries) = input else {
        return Err(malformed_payload());
    };
    let Some((_, Value::Binary(bytes))) = entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(PAYLOAD_KEY_SESSION))
    else {
        return Err(malformed_payload());
    };
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| malformed_payload())?;
    EntityId::from_bytes(bytes).map_err(|_| malformed_payload())
}

/// The inbox GROUP KEY a pass falls back to when its queue row carries no run
/// id — which is the ordinary case, because a session close enqueues without
/// one.
///
/// Per sitting, so one close's proposals arrive in the decider's tray as one
/// group. Any non-empty string would satisfy `gate.rs`; this one also says
/// which sitting earned the group, which is what a reader of a stale tray
/// needs.
#[must_use]
pub fn miner_run_id(session: &EntityId) -> String {
    format!("edit_distance.substitution_mine:{}", session.to_hex())
}

fn malformed_payload() -> Error {
    invalid("a substitution-mine payload must name a SESSION")
}

/// Every substitution cluster the judgment ledger currently supports, in
/// `(scope, actor, from, to)` order.
///
/// Recomputed from the ledger on every call — never a stored counter (doc-13
/// r1). ED-08's signature emission (ONE-1764) reads clusters through here.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable artifact row.
pub fn mine_substitution_clusters(vault: &Vault) -> Result<Vec<SubstitutionCluster>> {
    let judgments = amendment_judgments(vault)?;
    clusters_from(vault, &judgments)
}

/// Buckets every judged amendment's substitutions by `(scope, actor, from,
/// to)`.
fn clusters_from(
    vault: &Vault,
    judgments: &[AmendmentJudgment],
) -> Result<Vec<SubstitutionCluster>> {
    let artifacts = artifact_index(vault)?;
    let mut buckets: BTreeMap<ClusterKey, Bucket> = BTreeMap::new();
    for judgment in judgments {
        let Some(source) = amendment_source(vault, judgment, &artifacts)? else {
            continue;
        };
        for substitution in substitutions(source.delta_source, source.artifact) {
            let key = ClusterKey {
                scope: judgment.scope.clone(),
                actor: source.actor,
                from: substitution.from,
                to: substitution.to,
            };
            buckets.entry(key).or_default().observe(
                &judgment.receipt_id,
                source.skill,
                judgment.at,
            );
        }
    }
    Ok(buckets
        .into_iter()
        .map(|(key, bucket)| bucket.into_cluster(key))
        .collect())
}

/// The `(scope, actor, from, to)` identity of one bucket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClusterKey {
    scope: String,
    actor: EntityId,
    from: String,
    to: String,
}

/// One bucket under construction.
#[derive(Debug, Default)]
struct Bucket {
    receipts: Vec<String>,
    /// The skill every fold so far has named — `None` until the first fold,
    /// `Some(None)` when the folds agree that no skill was named.
    skill: Option<Option<EntityId>>,
    /// Set once two folds disagree.
    skill_conflict: bool,
    at: u64,
}

impl Bucket {
    /// Folds one citing amendment in. Receipts are counted DISTINCTLY: one
    /// receipt whose window shows a substitution three times is one occurrence
    /// of a habit, not three.
    fn observe(&mut self, receipt_id: &str, skill: Option<EntityId>, at: u64) {
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

    fn into_cluster(mut self, key: ClusterKey) -> SubstitutionCluster {
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

// ---------------------------------------------------------------------------
// Receipt -> artifact resolution
// ---------------------------------------------------------------------------

/// What one judged amendment contributes: the routing facts and the text pair.
struct AmendmentSource<'a> {
    actor: EntityId,
    skill: Option<EntityId>,
    delta_source: DeltaSource,
    artifact: &'a FinalizedProposalText,
}

/// Resolves one judged amendment to its routing facts and its persisted
/// proposal artifact, or `None` when it carries no minable pair.
///
/// Three ways to carry none, all of them silent by design:
///
/// * no recorded routing facts — the amendment has no scope axis and no actor,
///   and inventing either is the failure ED-03 is instrumented against;
/// * no Δ — nothing measured this window, so there is nothing to read;
/// * a Δ whose refs name no persisted artifact — the field-diff lane hashes
///   two MessagePack BODIES, which are not retained, so it resolves to no text
///   pair at all. The recorded-ops and reconstructed lanes both do resolve,
///   which is exactly what their refs are for (ED-01 pins them as "directly
///   replayable" and "directly verifiable").
fn amendment_source<'a>(
    vault: &Vault,
    judgment: &AmendmentJudgment,
    artifacts: &'a ArtifactIndex,
) -> Result<Option<AmendmentSource<'a>>> {
    let Some(evidence) = amendment_evidence(vault, &judgment.receipt_id)? else {
        return Ok(None);
    };
    let Some(delta) = amendment_delta(vault, &judgment.receipt_id)? else {
        return Ok(None);
    };
    Ok(artifacts.resolve(&delta).map(|artifact| AmendmentSource {
        actor: evidence.actor,
        skill: evidence.skill,
        delta_source: delta.source,
        artifact,
    }))
}

/// Every persisted proposal artifact, addressable by either ref pair a Δ can
/// name it with.
struct ArtifactIndex {
    records: Vec<FinalizedProposalText>,
    by_refs: BTreeMap<(String, String), usize>,
}

impl ArtifactIndex {
    /// The artifact a Δ's `(proposed_ref, final_ref)` pair names.
    fn resolve(&self, delta: &AmendmentDelta) -> Option<&FinalizedProposalText> {
        let key = (delta.proposed_ref.clone(), delta.final_ref.clone());
        self.records.get(*self.by_refs.get(&key)?)
    }
}

/// Reads the artifact rows once per pass and indexes them under BOTH ref
/// families ED-01 can hand back.
///
/// The op-window pair addresses a [`DeltaSource::RecordedOps`] Δ (hex of the
/// encoded Loro frontiers, which is what that lane writes); the text-hash pair
/// addresses a [`DeltaSource::Reconstructed`] one (blake3 of each endpoint
/// text). One map holds both: the tokens are opaque hex, so the two families
/// cannot collide in any way a reader would have to reason about.
fn artifact_index(vault: &Vault) -> Result<ArtifactIndex> {
    let rtxn = vault.store.env.read_txn()?;
    let mut index = ArtifactIndex {
        records: Vec::new(),
        by_refs: BTreeMap::new(),
    };
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, PROPOSAL_ARTIFACT_KEY_PREFIX)?
        .take(MAX_ARTIFACT_SCAN)
    {
        let (_, raw) = entry?;
        let record = decode_finalized_proposal_text(&raw)?;
        let position = index.records.len();
        index.by_refs.insert(
            (
                bytes_to_hex_lower(record.proposed_ref.as_bytes()),
                bytes_to_hex_lower(record.final_ref.as_bytes()),
            ),
            position,
        );
        index.by_refs.insert(
            (
                text_ref(&record.proposed_text),
                text_ref(&record.final_text),
            ),
            position,
        );
        index.records.push(record);
    }
    Ok(index)
}

/// The ref ED-01's reconstructed lane writes for one endpoint text.
fn text_ref(text: &str) -> String {
    bytes_to_hex_lower(blake3::hash(text.as_bytes()).as_bytes())
}

// ---------------------------------------------------------------------------
// Substitution extraction
// ---------------------------------------------------------------------------

/// Extracts every substitution one artifact shows, through the lane its Δ was
/// measured on.
///
/// * [`DeltaSource::RecordedOps`] — one pair per recorded CHANGE, from the
///   change's own before/after text. Op runs are what this lane retains and
///   they see churn: a word typed, replaced, and typed again yields the
///   substitution the decider actually performed.
/// * [`DeltaSource::Reconstructed`] — the stored text pair is re-diffed here
///   for line pairs. ED-02's `myers_line_diff` counts lines rather than naming
///   them, so the pairing is done locally instead of widening that lane's API
///   for one consumer.
/// * [`DeltaSource::FieldDiff`] — unreachable: that lane resolves to no
///   artifact (see [`amendment_source`]). Answered rather than asserted, so a
///   future body-retaining producer degrades to silence instead of a panic.
fn substitutions(source: DeltaSource, artifact: &FinalizedProposalText) -> Vec<Substitution> {
    match source {
        DeltaSource::RecordedOps => artifact
            .ops_by_actor
            .iter()
            .filter_map(|(_, span)| substitution_pair(&span.before_text, &span.after_text))
            .collect(),
        DeltaSource::Reconstructed => {
            line_substitutions(&artifact.proposed_text, &artifact.final_text)
        }
        DeltaSource::FieldDiff => Vec::new(),
    }
}

/// Pairs the lines a line-for-line rewrite replaced.
///
/// Deliberately narrow: after the common leading and trailing lines are
/// trimmed, the two middles must have the SAME length. A substitution IS a
/// one-for-one replacement, and when the counts differ there is no pairing that
/// is not a guess — pairing by position across a length change would cluster
/// two lines that have nothing to do with each other, and a wrong cluster is
/// worse than a missing one because it can reach K.
fn line_substitutions(before: &str, after: &str) -> Vec<Substitution> {
    let before: Vec<&str> = before.lines().collect();
    let after: Vec<&str> = after.lines().collect();
    let (prefix, suffix) = common_affix(&before, &after);
    let left = &before[prefix..before.len() - suffix];
    let right = &after[prefix..after.len() - suffix];
    if left.len() != right.len() {
        return Vec::new();
    }
    left.iter()
        .zip(right)
        .filter_map(|(removed, added)| substitution_pair(removed, added))
        .collect()
}

/// The normalized substitution between two texts, or `None` when the change is
/// not one.
///
/// The pair is the CHANGED RUN — what sits between the common prefix and the
/// common suffix — widened to whole TOKENS, so the substitution recurs across
/// artifacts that share nothing but the correction. A run empty on either side
/// is a pure insertion or deletion, which is an edit but not a substitution, and
/// a run past [`MAX_SUBSTITUTION_TOKENS`] is a rewrite.
///
/// Emptiness is judged on the RAW region, before widening. Widening first would
/// dress an insertion up as a replacement: `hello` -> `hello there` has an
/// empty removed run, and pulling `hello` in on both sides would report the
/// substitution `hello` -> `hello there`, which nobody performed.
fn substitution_pair(before: &str, after: &str) -> Option<Substitution> {
    let before: Vec<char> = before.chars().collect();
    let after: Vec<char> = after.chars().collect();
    let (prefix, suffix) = common_affix(&before, &after);
    if prefix == before.len() - suffix || prefix == after.len() - suffix {
        return None;
    }
    let region = token_aligned(&before, &after, prefix, suffix);
    let from = normalize_run(&before[region.start..region.before_end]);
    let to = normalize_run(&after[region.start..region.after_end]);
    if from.is_empty() || to.is_empty() || from == to {
        return None;
    }
    if token_count(&from) > MAX_SUBSTITUTION_TOKENS || token_count(&to) > MAX_SUBSTITUTION_TOKENS {
        return None;
    }
    Some(Substitution { from, to })
}

/// The changed region of both texts, widened to whole-token boundaries.
struct Region {
    /// Shared start — the two texts agree left of the changed run.
    start: usize,
    before_end: usize,
    after_end: usize,
}

/// Widens the changed region out to the whitespace on either side of it.
///
/// Without this the affix trim cuts INSIDE words: `regards` -> `cheers` shares a
/// trailing `s`, so the raw region is `regard` -> `cheer` and the chooser is
/// handed two words that are in no lexicon. §4 says the miner clusters TOKEN
/// pairs, and this is what makes the extracted pair one.
///
/// Both ends move in lockstep, which is exactly what the affixes guarantee:
/// `before[..prefix] == after[..prefix]`, so testing the left character on
/// either text gives the same answer, and the two suffixes are equal, so
/// advancing the right end by one advances both by the same character.
fn token_aligned(before: &[char], after: &[char], prefix: usize, suffix: usize) -> Region {
    let mut start = prefix;
    while start > 0 && !before[start - 1].is_whitespace() {
        start -= 1;
    }
    let mut before_end = before.len() - suffix;
    let mut after_end = after.len() - suffix;
    while before_end < before.len() && !before[before_end].is_whitespace() {
        before_end += 1;
        after_end += 1;
    }
    Region {
        start,
        before_end,
        after_end,
    }
}

/// Token normalization: lowercase, trim, collapse whitespace. Nothing else — no
/// stemming and no embeddings, because the signal is recurrence of the LITERAL
/// correction (blueprint note; §4's "mechanical distance, semantic recurrence").
fn normalize_run(run: &[char]) -> String {
    run.iter()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn token_count(normalized: &str) -> usize {
    normalized.split_whitespace().count()
}

/// The shared leading and trailing run of two slices, as `(prefix, suffix)`.
///
/// The two must not overlap on the shorter side, or a repeated run (`a a a` ->
/// `a a a a a`) would count the same element twice and report a negative
/// middle. ED-01's `CharAffix` and ED-02's line trim keep the same rule for the
/// same reason; those are counting helpers, this is a text extractor, so the
/// rule is restated rather than shared through a widened API.
fn common_affix<T: PartialEq>(before: &[T], after: &[T]) -> (usize, usize) {
    let prefix = before
        .iter()
        .zip(after)
        .take_while(|(left, right)| left == right)
        .count();
    let budget = before.len().min(after.len()) - prefix;
    let suffix = before
        .iter()
        .rev()
        .zip(after.iter().rev())
        .take(budget)
        .take_while(|(left, right)| left == right)
        .count();
    (prefix, suffix)
}

// ---------------------------------------------------------------------------
// The chooser
// ---------------------------------------------------------------------------

/// Routes one substitution: tone/stop lexicon on BOTH sides is a phrasing swap,
/// anything else is content.
///
/// A deterministic rule table over a closed lexicon, and the asymmetry is the
/// point: an unrecognized word makes the substitution CONTENT, which routes it
/// to a proposal a human reads, rather than to a preference claim that silently
/// shapes every later draft.
#[must_use]
pub fn classify_substitution(from: &str, to: &str) -> SubstitutionClass {
    let lexical = from
        .split_whitespace()
        .chain(to.split_whitespace())
        .all(|token| TONE_LEXICON.binary_search(&trim_token(token)).is_ok());
    if lexical {
        SubstitutionClass::Lexical
    } else {
        SubstitutionClass::Content
    }
}

/// A token stripped of the punctuation that rides on prose, so `"regards,"` is
/// the sign-off it plainly is. Normalization already lowercased it.
fn trim_token(token: &str) -> &str {
    token.trim_matches(|character: char| !character.is_alphanumeric())
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Rules on one at-threshold cluster, or declines.
fn emit_cluster(
    vault: &Vault,
    run: &MinerRun,
    cluster: &SubstitutionCluster,
    now: u64,
) -> Result<Option<MinedOutcome>> {
    let handle = cluster_handle(cluster);
    match classify_substitution(&cluster.from, &cluster.to) {
        SubstitutionClass::Lexical => Ok(emit_preference_claim(vault, run, cluster, &handle, now)?
            .map(MinedOutcome::PreferenceClaim)),
        // A content correction with no skill to edit has no proposal to make.
        // No mint-mark is written, so the cluster is still eligible in a pass
        // where its amendments do name a skill.
        SubstitutionClass::Content => match cluster.skill {
            None => Ok(None),
            Some(skill) => Ok(emit_skill_edit(vault, cluster, skill, &handle, now)?
                .map(MinedOutcome::SkillEditProposal)),
        },
    }
}

/// Whether a cluster may propose: no mark, a mark whose proposal no longer
/// stands, or a rejection past its cooldown.
///
/// Takes the CALLER's transaction, and the caller is the emission's own write
/// transaction. Reading the marks in a transaction of its own would leave a
/// window between the answer and the write in which a second pass could get the
/// same answer, and two live proposals for one cluster is the exact state the
/// mint-marks exist to make impossible.
fn cluster_is_eligible(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handle: &[u8; 32],
    now: u64,
) -> Result<bool> {
    let Some(mark) = mint_mark_in_txn(vault, txn, handle)? else {
        return Ok(true);
    };
    let reference = EntityId::from_hex(&mark.reference)
        .map_err(|_| Error::CorruptedIndex(MINT_MARK_ROW_LABEL))?;
    match mark.kind.as_str() {
        MARK_KIND_SKILL_EDIT => skill_edit_is_stale(vault, txn, &reference, now),
        MARK_KIND_PREFERENCE => preference_is_stale(vault, txn, &reference, now),
        _ => Err(Error::CorruptedIndex(MINT_MARK_ROW_LABEL)),
    }
}

/// Whether the skill-edit proposal a mark points at has stopped standing for
/// its cluster — the content arm's half of the hysteresis.
///
/// Deliberately the same three-way shape as [`preference_is_stale`], because it
/// is the same question. What differs is where the answer lives: a preference
/// claim is answered at the inbox door, which writes a tray row and a gate
/// decision, while a mined skill edit is answered at [`resolve_mined_skill_edit`],
/// which writes the verdict onto the proposal. A proposal that was ERASED
/// rather than answered frees its cluster: nothing stands, so there is nothing
/// left for the mark to speak for.
fn skill_edit_is_stale(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal_id: &EntityId,
    now: u64,
) -> Result<bool> {
    let Some(proposal) = mined_skill_edit_in_txn(vault, txn, proposal_id)? else {
        return Ok(true);
    };
    let Some(decision) = proposal.decision else {
        // Open in front of the decider: the cluster has already spoken.
        return Ok(false);
    };
    match decision.verdict {
        // Applied. Re-proposing an edit the skill already carries is nagging.
        MinedSkillEditVerdict::Accepted => Ok(false),
        MinedSkillEditVerdict::Rejected => {
            Ok(now >= decision.at.saturating_add(MINER_REJECTION_COOLDOWN_SECS))
        }
    }
}

/// Whether the preference claim a mark points at has stopped standing for its
/// cluster.
///
/// The state does NOT live in the claim's `approval` field, and reading it there
/// would make the cooldown dead code: the inbox reject door closes the tray row
/// and appends a `rejected` gate decision, leaving the body exactly as Proposed
/// as it was. So the answer is assembled from the three places it actually is:
///
/// * gone — the claim was erased; nothing stands and the cluster is free;
/// * a PENDING gate consent — the question is still open in front of the
///   decider, and asking again is the nagging this exists to stop;
/// * `Approved`/`Auto` — the preference landed and is standing truth;
/// * otherwise the row was CLOSED without accepting, so the newest `rejected`
///   decision's own clock runs the cooldown.
///
/// A claim with no tray row, no acceptance and no rejection stays quiet. Its row
/// was consumed by something this module cannot read as an answer, and "no
/// answer I understand" is not a licence to re-propose.
fn preference_is_stale(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    now: u64,
) -> Result<bool> {
    let Some(body) = vault.get_claim_in_txn(txn, claim_id)? else {
        return Ok(true);
    };
    if vault
        .store
        .pending_gate_consent_in_txn(txn, claim_id)?
        .is_some()
        || matches!(
            body.approval,
            ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
        )
    {
        return Ok(false);
    }
    let rejected_at = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim_id.as_bytes())?
        .iter()
        .filter(|decision| decision.outcome == GATE_OUTCOME_REJECTED)
        .map(|decision| decision.created_at)
        .max();
    Ok(rejected_at.is_some_and(|at| now >= at.saturating_add(MINER_REJECTION_COOLDOWN_SECS)))
}

/// Lands a mined preference claim through the write gate, with its mint-mark,
/// in ONE transaction — or declines, when that transaction finds the cluster
/// has already spoken.
///
/// `Proposed`, never `Auto`: a phrasing preference inferred from three
/// corrections is a reading of the decider's habit, and the decider is the one
/// who confirms it. The gate can only narrow a Proposed request, so the lane is
/// structural rather than a convention.
///
/// # The cluster is the evidence, so the cluster is persisted
///
/// A mined claim is Dreamer-authored, so the write door asks it to cite at
/// least one ref that RESOLVES. The miner's truthful evidence is the
/// at-threshold cluster itself — and its receipt ids are side-ledger strings
/// (`gate:<hex>`), never entities, so no resolver can ever follow one. The
/// cluster is therefore written as a typed record entity, in the SAME
/// transaction and BEFORE the candidate is gated, and the claim cites THAT.
/// The receipt ids stay in the record and beside the envelope for readers;
/// they are simply not what the floor resolves.
fn emit_preference_claim(
    vault: &Vault,
    run: &MinerRun,
    cluster: &SubstitutionCluster,
    handle: &[u8; 32],
    now: u64,
) -> Result<Option<EntityId>> {
    let claim_id = EntityId::now();
    let class = SubstitutionClass::Lexical;
    let envelope = miner_envelope(run, handle)?;
    let evidence_id = mined_evidence_record_id(handle)?;
    let evidence_record = encode_row(
        &StoredMinedEvidence::new(cluster, class),
        MINED_EVIDENCE_ROW_LABEL,
    )?;
    let candidate = ClaimCandidate::new(
        PREDICATE_PREFERENCE_PHRASING,
        ClaimSubject::Entity(cluster.actor),
        preference_value(cluster, class),
        MINER_PREFERENCE_CONFIDENCE,
    )
    .with_evidence(mined_evidence_candidate(cluster, evidence_id))
    .with_scope(edit_cost_scope(&cluster.scope))
    .with_validity(Some(cluster.at), None);
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_PREFERENCE, &claim_id),
        MINT_MARK_ROW_LABEL,
    )?;
    let mark_key = mint_mark_key(handle);
    let occurred = TimeRange {
        start: cluster.at,
        end: cluster.at,
    };
    vault.with_write_txn(|wtxn| {
        if !cluster_is_eligible(vault, wtxn, handle, now)? {
            return Ok(None);
        }
        // FIRST, and in this transaction: the door validates the candidate
        // below against this very `wtxn`, so a record written after it — or in
        // a transaction of its own — is a ref the resolver cannot see.
        vault
            .batch_in()
            .put(
                &evidence_id,
                ENTITY_TYPE_ASSET,
                occurred,
                cluster.at,
                &evidence_record,
            )
            .apply(wtxn)?;
        vault
            .batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, cluster.at)
            .apply_recording_gate_decisions(wtxn)?;
        vault.store.vault_meta.put(wtxn, &mark_key, &mark)?;
        Ok(Some(claim_id))
    })
}

/// The mined-evidence record's entity id, derived from the cluster's own
/// already domain-separated handle.
///
/// Deterministic, so one cluster has one record however many passes read it —
/// the mint-mark still decides whether a proposal is minted at all. A digest
/// landing on a reserved sentinel is re-salted rather than forced.
fn mined_evidence_record_id(handle: &[u8; 32]) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MINER_EVIDENCE_RECORD_ID_DOMAIN);
        hasher.update(&[salt]);
        hasher.update(handle);
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "mined evidence record id derivation failed",
    ))
}

/// A mined claim's candidate evidence: the persisted cluster record in the ONE
/// envelope the GATE-12 floor decodes, with the citation array riding beside it
/// for readers.
///
/// `Inferred` is the lattice-truthful meet — a mined preference is derived from
/// repeated corrections, never stated. The floor reads `refs`/`chain`/
/// `source_meet` and ignores every other key, so the citations add no second
/// schema to it.
fn mined_evidence_candidate(cluster: &SubstitutionCluster, record_id: EntityId) -> Value {
    let mut entries = match encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: vec![record_id],
        chain: Vec::new(),
        source_meet: ClaimSource::Inferred,
    }) {
        Value::Map(entries) => entries,
        // The encoder's contract is a map; anything else would carry no
        // admissible evidence, and the door would refuse the write.
        other => return other,
    };
    entries.push((
        Value::from(MINED_EVIDENCE_RECEIPTS_KEY),
        receipt_citations(cluster),
    ));
    Value::Map(entries)
}

/// Mints a gated skill-edit proposal with its mint-mark in ONE transaction — or
/// declines, on the same in-transaction dedup check the preference arm makes.
///
/// The proposal is a ROW, not an edit: the skill's content and every prior
/// version are untouched, exactly as `skill_attribution`'s discovery proposals
/// leave them. ONE-1448 consumes this class, and the apply door it goes through
/// is the gate.
fn emit_skill_edit(
    vault: &Vault,
    cluster: &SubstitutionCluster,
    skill: EntityId,
    handle: &[u8; 32],
    now: u64,
) -> Result<Option<EntityId>> {
    let proposal_id = EntityId::now();
    let class = SubstitutionClass::Content;
    let row = encode_row(
        &StoredSkillEdit {
            v: ROW_VERSION,
            skill: skill.to_hex(),
            scope: cluster.scope.clone(),
            from: cluster.from.clone(),
            to: cluster.to.clone(),
            evidence_receipts: cluster.receipt_refs.clone(),
            rationale: class.rationale().to_owned(),
            at: cluster.at,
            decision: None,
        },
        SKILL_EDIT_ROW_LABEL,
    )?;
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_SKILL_EDIT, &proposal_id),
        MINT_MARK_ROW_LABEL,
    )?;
    let row_key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    let mark_key = mint_mark_key(handle);
    vault.with_write_txn(|wtxn| {
        if !cluster_is_eligible(vault, wtxn, handle, now)? {
            return Ok(None);
        }
        // Inside the transaction with the row it proposes to edit: a proposal
        // naming a skill that is not there is one ONE-1448 could only fail on.
        vault.read_skill_record_in_txn(&*wtxn, &skill)?;
        vault.store.vault_meta.put(wtxn, &row_key, &row)?;
        vault.store.vault_meta.put(wtxn, &mark_key, &mark)?;
        Ok(Some(proposal_id))
    })
}

/// The miner's write envelope: the caller's Agent actor, `Generated` source,
/// `Proposed` ceiling.
///
/// `Generated` because a mined preference is derived, never stated — which is
/// also what makes GATE-007 refuse to let it supersede anything the owner said.
/// The provenance is the shape `gate.rs::dreamer_run_id_from_provenance` parses
/// (`dreamer_promotion`'s precedent, verbatim on the two keys that matter), so
/// the pending row lands in the run's INBOX GROUP and the decider can answer it.
/// The extra `session` and `cluster` keys are this module's trace: a landed
/// claim resolves back to the exact bucket that earned it.
///
/// **No `session_tag`.** It looks like free review bundling and is in fact a
/// trap: a `sess`-carrying body may only be written by the envelope actor that
/// PRODUCED the session (`batch.rs`'s bound-producer rule), and the inbox accept
/// door re-puts the reviewed body RAW — so the tag would make the mined claim
/// impossible to accept. The run group already bundles the pass's proposals,
/// which is the job the tag would have done.
fn miner_envelope(run: &MinerRun, handle: &[u8; 32]) -> Result<WriteEnvelope> {
    let provenance = WriteProvenance::new(Value::Map(vec![
        (
            Value::from(PROVENANCE_KEY_SURFACE),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (
            Value::from(PROVENANCE_KEY_RUN),
            Value::from(run.run_id.as_str()),
        ),
        (
            Value::from(PROVENANCE_KEY_SESSION),
            Value::from(run.session.to_hex()),
        ),
        (
            Value::from(PROVENANCE_KEY_CLUSTER),
            Value::from(bytes_to_hex_lower(handle)),
        ),
    ]))?;
    Ok(WriteEnvelope::new(
        run.agent,
        ClaimSource::Generated,
        provenance,
        ClaimApprovalStatus::Proposed,
    ))
}

/// The claim value: the pair, the class, and the chooser's receipted rationale.
///
/// The rationale rides the BODY rather than a receipt of its own: the miner
/// mints no receipt kind (a projector, not a door), and a claim a reader can
/// quote is a better record than a receipt nothing projects.
fn preference_value(cluster: &SubstitutionCluster, class: SubstitutionClass) -> Value {
    Value::Map(vec![
        (
            Value::from(PREFERENCE_VALUE_KEY_FROM),
            Value::from(cluster.from.as_str()),
        ),
        (
            Value::from(PREFERENCE_VALUE_KEY_TO),
            Value::from(cluster.to.as_str()),
        ),
        (
            Value::from(PREFERENCE_VALUE_KEY_CLASS),
            Value::from(class.as_str()),
        ),
        (
            Value::from(PREFERENCE_VALUE_KEY_RATIONALE),
            Value::from(class.rationale()),
        ),
    ])
}

/// The citation array — trace-or-derivation, in the `skill.edit_cost` shape.
fn receipt_citations(cluster: &SubstitutionCluster) -> Value {
    Value::Array(
        cluster
            .receipt_refs
            .iter()
            .map(|receipt| Value::from(receipt.as_str()))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Mint-marks, proposals, watermark
// ---------------------------------------------------------------------------

/// The cluster's durable handle: a domain-separated hash of its whole identity.
///
/// Hashed rather than concatenated because the scope and both substitution
/// sides are text of unbounded length, and an LMDB key is not. The domain keeps
/// the digest from ever being read as another unit's.
fn cluster_handle(cluster: &SubstitutionCluster) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MINER_CLUSTER_HASH_DOMAIN);
    for part in [
        cluster.scope.as_bytes(),
        cluster.actor.as_bytes(),
        cluster.from.as_bytes(),
        cluster.to.as_bytes(),
    ] {
        hasher.update(&[0]);
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn mint_mark_key(handle: &[u8; 32]) -> Vec<u8> {
    meta_key(MINT_MARK_KEY_PREFIX, handle)
}

fn mint_mark_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handle: &[u8; 32],
) -> Result<Option<StoredMintMark>> {
    let Some(raw) = vault.store.vault_meta.get(txn, &mint_mark_key(handle))? else {
        return Ok(None);
    };
    let row: StoredMintMark = decode_row(&raw, MINT_MARK_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(MINT_MARK_ROW_LABEL));
    }
    Ok(Some(row))
}

/// Every mined skill-edit proposal still awaiting an answer, in proposal-id
/// order — ONE-1448's inbox.
///
/// Answered proposals are excluded: they are still readable by id (the cooldown
/// reads them there), but a decided proposal is not work.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn pending_substitution_skill_edits(vault: &Vault) -> Result<Vec<MinedSkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, SKILL_EDIT_KEY_PREFIX)?
    {
        let (key, raw) = entry?;
        let handle = key
            .get(SKILL_EDIT_KEY_PREFIX.len()..)
            .ok_or(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?;
        let proposal = decode_skill_edit(handle, &raw)?;
        if proposal.decision.is_none() {
            out.push(proposal);
        }
    }
    Ok(out)
}

/// One mined skill-edit proposal, answered or not, or `None`.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn mined_skill_edit(
    vault: &Vault,
    proposal_id: &EntityId,
) -> Result<Option<MinedSkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    mined_skill_edit_in_txn(vault, &rtxn, proposal_id)
}

fn mined_skill_edit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proposal_id: &EntityId,
) -> Result<Option<MinedSkillEditProposal>> {
    let key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    let Some(raw) = vault.store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    decode_skill_edit(proposal_id.as_bytes(), &raw).map(Some)
}

/// Records the decider's answer to a mined skill-edit proposal — the seam
/// ONE-1448's gated apply closes, and the only thing that lets the miner tell a
/// refusal from an acceptance.
///
/// Re-answering is allowed and the latest verdict stands: a decider is
/// permitted to change their mind, and a rejection's cooldown then runs from
/// the answer that is actually current.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when no such proposal exists — an answer to a
/// question nobody asked is a caller bug, not a row to invent. Storage errors.
pub fn resolve_mined_skill_edit(
    vault: &Vault,
    proposal_id: &EntityId,
    verdict: MinedSkillEditVerdict,
    at: u64,
) -> Result<()> {
    let key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    vault.with_write_txn(|wtxn| {
        let Some(raw) = vault.store.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::EntityNotFound);
        };
        let mut row: StoredSkillEdit = decode_row(&raw, SKILL_EDIT_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL));
        }
        row.decision = Some(StoredSkillEditDecision {
            outcome: verdict.as_str().to_owned(),
            at,
        });
        let encoded = encode_row(&row, SKILL_EDIT_ROW_LABEL)?;
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })
}

fn decode_skill_edit(handle: &[u8], raw: &[u8]) -> Result<MinedSkillEditProposal> {
    let row: StoredSkillEdit = decode_row(raw, SKILL_EDIT_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL));
    }
    let bytes: [u8; 16] = handle
        .try_into()
        .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?;
    let decision = row
        .decision
        .map(|decision| -> Result<MinedSkillEditDecision> {
            Ok(MinedSkillEditDecision {
                verdict: MinedSkillEditVerdict::from_token(&decision.outcome)
                    .ok_or(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?,
                at: decision.at,
            })
        })
        .transpose()?;
    Ok(MinedSkillEditProposal {
        proposal_id: EntityId::from_bytes(bytes)
            .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?,
        skill: EntityId::from_hex(&row.skill)
            .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?,
        scope: row.scope,
        from: row.from,
        to: row.to,
        evidence_receipts: row.evidence_receipts,
        rationale: row.rationale,
        at: row.at,
        decision,
    })
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
    fn observed(judgments: &[AmendmentJudgment]) -> Option<Self> {
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
    const fn advances(self, previous: Self) -> bool {
        self.at > previous.at || (self.at == previous.at && self.boundary > previous.boundary)
    }
}

/// Reads the work gate.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a malformed row.
pub fn miner_watermark(vault: &Vault) -> Result<MinerWatermark> {
    let rtxn = vault.store.env.read_txn()?;
    watermark_in_txn(vault, &rtxn)
}

fn watermark_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<MinerWatermark> {
    let Some(raw) = vault.store.vault_meta.get(rtxn, MINER_WATERMARK_KEY)? else {
        return Ok(MinerWatermark::default());
    };
    let bytes: [u8; 16] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(WATERMARK_ROW_LABEL))?;
    let (at, boundary) = bytes.split_at(8);
    Ok(MinerWatermark {
        at: u64::from_be_bytes(at.try_into().expect("an 8-byte half of 16 bytes")),
        boundary: u64::from_be_bytes(boundary.try_into().expect("an 8-byte half of 16 bytes")),
    })
}

/// Advances the work gate, never rewinds it.
///
/// Monotone because a pass that saw LESS than the last one saw is a pass over a
/// ledger that lost rows, and the last pass's bound is still the honest one. A
/// re-scanned amendment costs one bucket fold and is stopped from re-proposing
/// by its mint-mark, which is the guard that actually matters.
fn advance_watermark_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    observed: MinerWatermark,
) -> Result<()> {
    if observed.advances(watermark_in_txn(vault, &*wtxn)?) {
        let mut row = [0_u8; 16];
        row[..8].copy_from_slice(&observed.at.to_be_bytes());
        row[8..].copy_from_slice(&observed.boundary.to_be_bytes());
        vault
            .store
            .vault_meta
            .put(wtxn, MINER_WATERMARK_KEY, &row)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

/// A dedup POINTER, not a content record: what was proposed already lives in
/// the claim body or the skill-edit row the reference names, so the mark stores
/// nothing but where to look.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMintMark {
    v: u8,
    kind: String,
    /// Hex of the claim or proposal this cluster minted.
    reference: String,
}

impl StoredMintMark {
    fn new(kind: &str, reference: &EntityId) -> Self {
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
struct StoredMinedEvidence {
    v: u8,
    scope: String,
    from: String,
    to: String,
    class: String,
    receipt_refs: Vec<String>,
    count: u32,
    at: u64,
}

impl StoredMinedEvidence {
    fn new(cluster: &SubstitutionCluster, class: SubstitutionClass) -> Self {
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
struct StoredSkillEdit {
    v: u8,
    skill: String,
    scope: String,
    from: String,
    to: String,
    evidence_receipts: Vec<String>,
    rationale: String,
    at: u64,
    decision: Option<StoredSkillEditDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSkillEditDecision {
    outcome: String,
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

#[cfg(test)]
mod tests;
