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
//! the existing queue, never a second wake mechanism. Session close therefore
//! never blocks on this pass, and a pass that dies is re-admitted by the
//! attempt queue, whose claim mechanics also give the single-flight the
//! watermark assumes.
//!
//! # Two ledgers, one law
//!
//! * **Counts are never stored.** [`mine_substitution_clusters`] recomputes
//!   every cluster from the judgment ledger on every pass (doc-13 r1, the
//!   `skill.reliability` posterior posture). The watermark is a WORK GATE —
//!   "did anything new arrive?" — never a counting boundary; a cluster's
//!   recurrence accumulates across sittings because nothing ever consumes it.
//! * **Emissions are marked.** A cluster that emitted records a MINT-MARK, and
//!   the mark lands in the SAME transaction as the proposal. A crash between
//!   the two is therefore not a state: either both are there or neither is, so
//!   a re-run cannot double-propose. The dedup check reads the mark inside that
//!   same transaction's read view.
//!
//! # Hysteresis is a dial, not a wall
//!
//! A cluster whose proposal is OPEN, or which already landed, never
//! re-proposes. A cluster whose proposal the decider REJECTED goes quiet for
//! [`MINER_REJECTION_COOLDOWN_SECS`] and may then speak again — the sibling of
//! `DREAMER_GAP_DECAY_MS`'s escalate-or-let-go rule. Nagging is the failure
//! mode; permanent silence after one "no" is the other one.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{FinalizedProposalText, PROPOSAL_ARTIFACT_KEY_PREFIX, decode_finalized_proposal_text};
use crate::Vault;
use crate::actor_claims::edit_cost_scope;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::edit_distance::attribution::{
    AmendmentJudgment, amendment_evidence, amendment_judgments,
};
use crate::edit_distance::delta::{AmendmentDelta, DeltaSource, amendment_delta};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
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

/// `vault_meta` key of the GLOBAL work-gate watermark.
const MINER_WATERMARK_KEY: &[u8] = b"edit_distance/miner_watermark/v1";

/// `vault_meta` prefix of the mint-marks, keyed by cluster handle.
const MINT_MARK_KEY_PREFIX: &[u8] = b"edit_distance/miner_mint_mark/v1\0";

/// `vault_meta` prefix of the mined skill-edit proposals, keyed by proposal id.
const SKILL_EDIT_KEY_PREFIX: &[u8] = b"edit_distance/miner_skill_edit/v1\0";

/// Only accepted schema version for any row this module stores.
const ROW_VERSION: u8 = 1;

const MINT_MARK_ROW_LABEL: &str = "substitution mint mark row";
const SKILL_EDIT_ROW_LABEL: &str = "mined skill edit proposal row";
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

/// Provenance-map keys of the miner's write envelope.
const PROVENANCE_KEY_SURFACE: &str = "surface";
const PROVENANCE_KEY_SESSION: &str = "session";
const PROVENANCE_KEY_CLUSTER: &str = "cluster";

/// The surface token the miner's provenance stamps.
const MINER_SURFACE: &str = "edit_distance.substitution_miner";

/// Pinned mint-mark kinds.
const MARK_KIND_PREFERENCE: &str = "preference_claim";
const MARK_KIND_SKILL_EDIT: &str = "skill_edit_proposal";

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
/// `actor` and `skill` are part of the bucket rather than derived from it. ARCH-0056
/// §5 pins the scope as the `op × target class × skill/agent` cross, so a scope
/// already names one actor — making that explicit is what lets the preference
/// arm name a SUBJECT without ever guessing between two candidates. `skill` is
/// the skill every citing amendment named, or `None` when they disagree or none
/// did.
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
    /// Distinct amendment receipts showing this substitution, oldest first.
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
}

/// A normalized substitution pair extracted from one edit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Substitution {
    from: String,
    to: String,
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
/// Watermark + mint-marks advance IN THE SAME TXN as proposal emission (crash
/// between emit and mark cannot double-propose; dedup check is also in-txn).
/// Dreamer job admission serializes miner runs (single-flight per vault — the
/// attempt-queue claim mechanics already give this; do not run two miner
/// attempts concurrently).
///
/// `session` is the sitting whose close triggered the pass. It is the write
/// actor's entity ref and the review-bundle session tag, so one pass's Proposed
/// claims surface together rather than one at a time.
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
pub fn run_substitution_miner(vault: &Vault, session: &EntityId) -> Result<Vec<MinedOutcome>> {
    let judgments = amendment_judgments(vault)?;
    let watermark = miner_watermark(vault)?;
    // The watermark is a WORK GATE: no judgment newer than the last pass means
    // no new evidence, so there is nothing a re-cluster could conclude that the
    // last pass did not.
    let Some(high) = judgments
        .iter()
        .map(|judgment| judgment.at)
        .filter(|at| *at >= watermark)
        .max()
    else {
        return Ok(Vec::new());
    };

    let now = crate::unix_seconds_now();
    let k = miner_k(vault)?;
    let clusters = clusters_from(vault, &judgments)?;
    let mut outcomes = Vec::with_capacity(clusters.len());
    for cluster in &clusters {
        if cluster.count < k {
            outcomes.push(MinedOutcome::BelowThreshold);
            continue;
        }
        if let Some(outcome) = emit_cluster(vault, session, cluster, high, now)? {
            outcomes.push(outcome);
        }
    }
    // Every emission already advanced the watermark inside its own transaction;
    // this closes the case where nothing emitted, so a pass over evidence that
    // is all below threshold does not re-cluster the same ledger forever.
    vault.with_write_txn(|wtxn| advance_watermark_in_txn(vault, wtxn, high))?;
    Ok(outcomes)
}

/// The `DreamerAttemptPayload.input` a substitution-mine attempt carries: the
/// ended sitting, as 16 MessagePack-binary bytes.
///
/// The shape is owned HERE rather than by the queue, so the module that defines
/// the job also defines its payload and `dreamer_consolidation` stays a
/// dispatcher. Binary, not hex, is the house entity-ref-in-a-payload convention
/// (`TURN_BODY_WORLD_REF_KEY`).
#[must_use]
pub fn miner_attempt_input(session: &EntityId) -> Value {
    Value::Binary(session.as_bytes().to_vec())
}

/// Inverse of [`miner_attempt_input`].
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the payload does not name a sitting — a
/// miner attempt with no session has no provenance to stamp, and inventing one
/// would put an unattributable claim in front of the decider.
pub fn session_from_miner_input(input: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = input else {
        return Err(invalid("a substitution-mine payload must name a SESSION"));
    };
    let bytes: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("a substitution-mine payload must name a SESSION"))?;
    EntityId::from_bytes(bytes)
        .map_err(|_| invalid("a substitution-mine payload must name a SESSION"))
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
/// common suffix — so the substitution recurs across artifacts that share
/// nothing but the correction. A run empty on either side is a pure insertion
/// or deletion, which is an edit but not a substitution, and a run past
/// [`MAX_SUBSTITUTION_TOKENS`] is a rewrite.
fn substitution_pair(before: &str, after: &str) -> Option<Substitution> {
    let before: Vec<char> = before.chars().collect();
    let after: Vec<char> = after.chars().collect();
    let (prefix, suffix) = common_affix(&before, &after);
    let from = normalize_run(&before[prefix..before.len() - suffix]);
    let to = normalize_run(&after[prefix..after.len() - suffix]);
    if from.is_empty() || to.is_empty() || from == to {
        return None;
    }
    if token_count(&from) > MAX_SUBSTITUTION_TOKENS || token_count(&to) > MAX_SUBSTITUTION_TOKENS {
        return None;
    }
    Some(Substitution { from, to })
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
    session: &EntityId,
    cluster: &SubstitutionCluster,
    watermark: u64,
    now: u64,
) -> Result<Option<MinedOutcome>> {
    let handle = cluster_handle(cluster);
    if !cluster_is_eligible(vault, &handle, now)? {
        return Ok(None);
    }
    let class = classify_substitution(&cluster.from, &cluster.to);
    match class {
        SubstitutionClass::Lexical => Ok(Some(MinedOutcome::PreferenceClaim(
            emit_preference_claim(vault, session, cluster, &handle, watermark)?,
        ))),
        // A content correction with no skill to edit has no proposal to make.
        // No mint-mark is written, so the cluster is still eligible in a pass
        // where its amendments do name a skill.
        SubstitutionClass::Content => match cluster.skill {
            None => Ok(None),
            Some(skill) => Ok(Some(MinedOutcome::SkillEditProposal(emit_skill_edit(
                vault, cluster, skill, &handle, watermark,
            )?))),
        },
    }
}

/// Whether a cluster may propose: no mark, a mark whose proposal no longer
/// stands, or a rejection past its cooldown.
fn cluster_is_eligible(vault: &Vault, handle: &[u8; 32], now: u64) -> Result<bool> {
    let Some(mark) = mint_mark(vault, handle)? else {
        return Ok(true);
    };
    let reference = EntityId::from_hex(&mark.reference)
        .map_err(|_| Error::CorruptedIndex(MINT_MARK_ROW_LABEL))?;
    match mark.kind.as_str() {
        // The proposal row IS the open proposal; ONE-1448's gated apply is what
        // consumes it, and until then there is nothing more to say.
        MARK_KIND_SKILL_EDIT => Ok(mined_skill_edit(vault, &reference)?.is_none()),
        MARK_KIND_PREFERENCE => preference_is_stale(vault, &reference, now),
        _ => Err(Error::CorruptedIndex(MINT_MARK_ROW_LABEL)),
    }
}

/// Whether the preference claim a mark points at has stopped standing for its
/// cluster.
///
/// * open (`Proposed`) or landed (`Approved`/`Auto`) — the cluster has said its
///   piece; re-proposing would be the nagging the hysteresis exists to stop;
/// * `Rejected` — quiet until the cooldown elapses, then speak again;
/// * gone — the claim was erased, so nothing stands and the cluster is free.
fn preference_is_stale(vault: &Vault, claim_id: &EntityId, now: u64) -> Result<bool> {
    let Some(body) = vault.get_claim(claim_id)? else {
        return Ok(true);
    };
    match body.approval {
        ClaimApprovalStatus::Rejected => {
            let rejected_at = body.valid_to.unwrap_or(0);
            Ok(now >= rejected_at.saturating_add(MINER_REJECTION_COOLDOWN_SECS))
        }
        ClaimApprovalStatus::Proposed
        | ClaimApprovalStatus::Approved
        | ClaimApprovalStatus::Auto => Ok(false),
    }
}

/// Lands a mined preference claim through the write gate, with its mint-mark
/// and the watermark, in ONE transaction.
///
/// `Proposed`, never `Auto`: a phrasing preference inferred from three
/// corrections is a reading of the decider's habit, and the decider is the one
/// who confirms it. The gate can only narrow a Proposed request, so the lane is
/// structural rather than a convention.
fn emit_preference_claim(
    vault: &Vault,
    session: &EntityId,
    cluster: &SubstitutionCluster,
    handle: &[u8; 32],
    watermark: u64,
) -> Result<EntityId> {
    let claim_id = EntityId::now();
    let class = SubstitutionClass::Lexical;
    let envelope = miner_envelope(session, handle)?;
    let candidate = ClaimCandidate::new(
        PREDICATE_PREFERENCE_PHRASING,
        ClaimSubject::Entity(cluster.actor),
        preference_value(cluster, class),
        MINER_PREFERENCE_CONFIDENCE,
    )
    .with_evidence(receipt_citations(cluster))
    .with_scope(edit_cost_scope(&cluster.scope))
    .with_validity(Some(cluster.at), None);
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_PREFERENCE, &claim_id, cluster),
        MINT_MARK_ROW_LABEL,
    )?;
    let mark_key = mint_mark_key(handle);
    let occurred = TimeRange {
        start: cluster.at,
        end: cluster.at,
    };
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, cluster.at)
            .apply_recording_gate_decisions(wtxn)?;
        vault.store.vault_meta.put(wtxn, &mark_key, &mark)?;
        advance_watermark_in_txn(vault, wtxn, watermark)
    })?;
    Ok(claim_id)
}

/// Mints a gated skill-edit proposal, with its mint-mark and the watermark, in
/// ONE transaction.
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
    watermark: u64,
) -> Result<EntityId> {
    if vault.get_skill_record(&skill)?.is_none() {
        return Err(Error::EntityNotFound);
    }
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
        },
        SKILL_EDIT_ROW_LABEL,
    )?;
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_SKILL_EDIT, &proposal_id, cluster),
        MINT_MARK_ROW_LABEL,
    )?;
    let row_key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    let mark_key = mint_mark_key(handle);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &row_key, &row)?;
        vault.store.vault_meta.put(wtxn, &mark_key, &mark)?;
        advance_watermark_in_txn(vault, wtxn, watermark)
    })?;
    Ok(proposal_id)
}

/// The miner's write envelope: a SYSTEM actor, `Generated` source, `Proposed`
/// ceiling, and the sitting as the review-bundle tag.
///
/// `System` because no model chose anything — the pass is a projector over a
/// count, and stamping it `Agent` would claim a judgment it did not make. The
/// actor's entity ref is the SITTING whose close ran the pass, which is the one
/// durable handle the pass has for "where this came from"; the provenance map
/// carries the rest.
fn miner_envelope(session: &EntityId, handle: &[u8; 32]) -> Result<WriteEnvelope> {
    let provenance = WriteProvenance::new(Value::Map(vec![
        (
            Value::from(PROVENANCE_KEY_SURFACE),
            Value::from(MINER_SURFACE),
        ),
        (
            Value::from(PROVENANCE_KEY_SESSION),
            Value::from(session.to_hex()),
        ),
        (
            Value::from(PROVENANCE_KEY_CLUSTER),
            Value::from(bytes_to_hex_lower(handle)),
        ),
    ]))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(*session, EdgeActorClass::System),
        ClaimSource::Generated,
        provenance,
        ClaimApprovalStatus::Proposed,
    )
    .with_session_tag(session.to_hex()))
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

fn mint_mark(vault: &Vault, handle: &[u8; 32]) -> Result<Option<StoredMintMark>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &mint_mark_key(handle))? else {
        return Ok(None);
    };
    let row: StoredMintMark = decode_row(&raw, MINT_MARK_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(MINT_MARK_ROW_LABEL));
    }
    Ok(Some(row))
}

/// Every mined skill-edit proposal awaiting a gated apply, in proposal-id order.
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
        out.push(decode_skill_edit(handle, &raw)?);
    }
    Ok(out)
}

/// One mined skill-edit proposal, or `None`.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn mined_skill_edit(
    vault: &Vault,
    proposal_id: &EntityId,
) -> Result<Option<MinedSkillEditProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes());
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    decode_skill_edit(proposal_id.as_bytes(), &raw).map(Some)
}

fn decode_skill_edit(handle: &[u8], raw: &[u8]) -> Result<MinedSkillEditProposal> {
    let row: StoredSkillEdit = decode_row(raw, SKILL_EDIT_ROW_LABEL)?;
    if row.v != ROW_VERSION {
        return Err(Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL));
    }
    let bytes: [u8; 16] = handle
        .try_into()
        .map_err(|_| Error::CorruptedIndex(SKILL_EDIT_ROW_LABEL))?;
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
    })
}

/// The GLOBAL miner watermark — the newest judged amendment a pass has seen.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a malformed row.
pub fn miner_watermark(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    watermark_in_txn(vault, &rtxn)
}

fn watermark_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<u64> {
    let Some(raw) = vault.store.vault_meta.get(rtxn, MINER_WATERMARK_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(WATERMARK_ROW_LABEL))?;
    Ok(u64::from_be_bytes(bytes))
}

/// Advances the watermark, never rewinds it.
///
/// Monotone because a pass reads a `>=` window: the newest stamp SEEN is the
/// next pass's lower bound, and the bound is inclusive on purpose. Valid time
/// is second-granular while amendments are not, so an exclusive bound would
/// silently drop every judgment that shared its second with the boundary. A
/// re-scanned amendment costs one bucket fold and is stopped from re-proposing
/// by its mint-mark, which is the guard that actually matters.
fn advance_watermark_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, at: u64) -> Result<()> {
    if at > watermark_in_txn(vault, &*wtxn)? {
        vault
            .store
            .vault_meta
            .put(wtxn, MINER_WATERMARK_KEY, &at.to_be_bytes())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stored rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMintMark {
    v: u8,
    kind: String,
    /// Hex of the claim or proposal this cluster minted.
    reference: String,
    scope: String,
    from: String,
    to: String,
    at: u64,
}

impl StoredMintMark {
    fn new(kind: &str, reference: &EntityId, cluster: &SubstitutionCluster) -> Self {
        Self {
            v: ROW_VERSION,
            kind: kind.to_owned(),
            reference: reference.to_hex(),
            scope: cluster.scope.clone(),
            from: cluster.from.clone(),
            to: cluster.to.clone(),
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
