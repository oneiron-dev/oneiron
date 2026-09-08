//! ED-04 miner dials, pinned keys, labels and the tone lexicon.

use crate::error::Error;

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
pub(super) const MINER_CLUSTER_HASH_DOMAIN: &[u8] =
    b"oneiron:edit-distance-substitution-cluster:v1";

/// Domain for the mined-evidence record's entity id, derived FROM the cluster
/// handle: one more separation so a record id can never be read as a handle,
/// a mint-mark key, or another unit's entity.
pub(super) const MINER_EVIDENCE_RECORD_ID_DOMAIN: &[u8] =
    b"oneiron:edit-distance-mined-evidence:v1";

/// `vault_meta` key of the GLOBAL work-gate watermark.
pub(super) const MINER_WATERMARK_KEY: &[u8] = b"edit_distance/miner_watermark/v1";

/// `vault_meta` prefix of the mint-marks, keyed by cluster handle.
pub(super) const MINT_MARK_KEY_PREFIX: &[u8] = b"edit_distance/miner_mint_mark/v1\0";

/// `vault_meta` prefix of the mined skill-edit proposals, keyed by proposal id.
pub(super) const SKILL_EDIT_KEY_PREFIX: &[u8] = b"edit_distance/miner_skill_edit/v1\0";

/// Only accepted schema version for any row this module stores.
pub(super) const ROW_VERSION: u8 = 1;

pub(super) const MINT_MARK_ROW_LABEL: &str = "substitution mint mark row";

pub(super) const MINED_EVIDENCE_ROW_LABEL: &str = "mined substitution evidence record";

pub(super) const SKILL_EDIT_ROW_LABEL: &str = "mined skill edit proposal row";

/// Reader-facing key under which the ordered receipt citations ride ALONGSIDE
/// the consolidation envelope in a mined claim's candidate evidence.
pub(super) const MINED_EVIDENCE_RECEIPTS_KEY: &str = "receipt_refs";

pub(super) const WATERMARK_ROW_LABEL: &str = "substitution miner watermark";

pub(super) const MINER_K_ROW_LABEL: &str = "substitution miner k dial";

/// Longest substitution side the miner will cluster, in whitespace tokens.
///
/// Past it the edit is a REWRITE, not a recurring correction: a nine-token
/// replacement is essentially never produced twice verbatim, so admitting it
/// buys buckets that can only ever hold one member while widening the key space
/// the mint-marks hash over.
pub(super) const MAX_SUBSTITUTION_TOKENS: usize = 8;

/// Bound on the artifact rows one pass reads.
///
/// A bound on WORK, matching the receipt family's own scan cap: the pass runs
/// at session close, and a vault with a very long artifact history must not
/// turn a close into an unbounded walk. Past it the pass mines the oldest rows
/// it can reach, which is the same direction ED-01's projection pass degrades
/// in — less evidence, never wrong evidence.
pub(super) const MAX_ARTIFACT_SCAN: usize = 100_000;

/// Confidence stamped on a mined preference claim.
///
/// Deliberately NOT derived from the recurrence count. The miner has no
/// probability to report — it observed that a threshold was crossed, which is a
/// boolean fact — and a count dressed up as a confidence would be exactly the
/// fake precision the `d_norm` metric was pinned to avoid. A reader who wants
/// the strength reads the citation array, which names every receipt.
pub(super) const MINER_PREFERENCE_CONFIDENCE: f32 = 0.5;

/// Value-map keys of a mined preference claim.
pub(super) const PREFERENCE_VALUE_KEY_FROM: &str = "from";

pub(super) const PREFERENCE_VALUE_KEY_TO: &str = "to";

pub(super) const PREFERENCE_VALUE_KEY_CLASS: &str = "class";

pub(super) const PREFERENCE_VALUE_KEY_RATIONALE: &str = "rationale";

/// Provenance-map keys of the miner's write envelope. `surface` and `run` are
/// the two `gate.rs` parses for the inbox group key; the other two are this
/// module's own trace.
pub(super) const PROVENANCE_KEY_SURFACE: &str = "surface";

pub(super) const PROVENANCE_KEY_RUN: &str = "run";

pub(super) const PROVENANCE_KEY_SESSION: &str = "session";

pub(super) const PROVENANCE_KEY_CLUSTER: &str = "cluster";

/// The only key of the dreamer attempt payload this job rides.
///
/// A miner attempt names the SITTING and nothing else, because the sitting is
/// all the session-close transaction that registers it knows. The write actor
/// is the deployment's (`ConsolidationExecutor::actor` — the D13 rule that a
/// SESSION is not an actor entity, and the `dreamer_runner` milestone-envelope
/// ruling that WHICH actor a deployment trusts is policy the engine does not
/// hold), and the inbox group is the queue row's own run id.
pub(super) const PAYLOAD_KEY_SESSION: &str = "session";

/// The gate-decision outcome token the inbox reject door writes.
///
/// Mirrored rather than shared: the token is a pinned LEDGER string and the door
/// that writes it lives in another module's write path. A reader of that ledger
/// is entitled to name what it is looking for.
pub(super) const GATE_OUTCOME_REJECTED: &str = "rejected";

/// Pinned mint-mark kinds.
pub(super) const MARK_KIND_PREFERENCE: &str = "preference_claim";

pub(super) const MARK_KIND_SKILL_EDIT: &str = "skill_edit_proposal";

/// Pinned on-disk tokens of a skill-edit proposal's verdict.
pub(super) const SKILL_EDIT_VERDICT_ACCEPTED: &str = "accepted";

pub(super) const SKILL_EDIT_VERDICT_REJECTED: &str = "rejected";

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
pub(super) const TONE_LEXICON: [&str; 74] = [
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

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}
