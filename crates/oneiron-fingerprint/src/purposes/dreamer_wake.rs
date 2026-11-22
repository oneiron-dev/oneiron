//! Legacy identities of Dreamer wake sessions, queued work and sieve readings.
//!
//! Follower session rows and prepared suffixes retain their identities; queued
//! projection and rung work retain their dedupe keys; durable program steps retain
//! their response digests. Sieve span, reading and audit rows retain the source,
//! policy, envelope, span and member identities that readers compare with current
//! evidence. Arc success material retains the statements the gate compares.
//! Deterministic topic grouping, audit draws and read-phase retry keys also retain
//! their comparisons. Each recipe therefore keeps its bytes (K, PLAN-UC-04 stage 7).
//! The individual entries name each write and the row or comparison that needs it.

purposes! {}

legacy_purposes! {
    /// Audit rank: the tag, the 16-byte attempt seed, then the 32-byte span id,
    /// without lengths. Its first eight bytes are a u64-BE draw; all 32 bytes
    /// sort the retained-span sample before the policy's audit limit.
    AUDIT_SAMPLE = (Blake3, HashedFirst, "oneiron:sieve:audit-sample:v1");

    /// Window audit rank: the tag, the raw domain (`turn` or `window`), the
    /// 16-byte attempt seed, then the raw id, without lengths. The rank sorts
    /// turns and its first eight bytes are compared with the audit percentage.
    AUDIT_WINDOW_SAMPLE = (Blake3, HashedFirst, "oneiron:sieve:audit-window-sample:v1");

    /// Follower prefix: the tag, then the instruction followed by each part,
    /// each as a u64-BE byte length and its UTF-8 bytes. Stored in
    /// `PreparedSuffix.base_prefix` and retained in follower result rows.
    FOLLOWER_PREFIX = (Blake3, HashedFirst, "oneiron:dreamer-follower:prefix:v1");

    /// Follower question: the tag, then the question's UTF-8 bytes, without a
    /// length. Stored in `PreparedSuffix.question` and compared on reuse.
    FOLLOWER_QUESTION = (Blake3, HashedFirst, "oneiron:dreamer-follower:question:v1");

    /// Follower session: the tag, the authority id's raw bytes, then the read
    /// scope's fixed bytes, without lengths. Its hex names queued attempts
    /// and is compared with their input; it keys the persisted session rows.
    FOLLOWER_SESSION = (Blake3, HashedFirst, "oneiron:dreamer-follower:session:v1");

    /// Nightly topic: the tag, then whitespace-split, lowercased words joined
    /// with one space as UTF-8, without a length. Empty folded words name no
    /// topic. Compared as the deterministic grouping key of unbound Name spans.
    NIGHTLY_TOPIC = (Blake3, HashedFirst, "oneiron:dreamer-nightly-topic:v1");

    /// Sieve policy: the tag, then `serde_json::to_vec(policy)` bytes, without
    /// a length. Stored in `SieveSpan.policy_digest` in the span queue rows.
    POLICY_DIGEST = (Blake3, HashedFirst, "oneiron:dreamer-sieve:policy:v1");

    /// Read-phase trigger: only the attempt input string's UTF-8 bytes, without
    /// a tag or length. The tag is a registry name only. Compared as the key
    /// of the in-memory `ReadPhases` deferral map across retries.
    READ_PHASE_TRIGGER = (Blake3, NotHashed, "oneiron.dreamer_wake.read_phase_trigger.v1");

    /// Rung input: only the serialized `RungInput` JSON string's UTF-8 bytes,
    /// without a tag or length. The tag is a registry name only. Lowercase
    /// hex after `sieve:rungs:` is stored as the attempt queue dedupe key.
    RUNG_DEDUPE_KEY = (Blake3, NotHashed, "oneiron.dreamer_wake.rung_dedupe_key.v1");

    /// Sieve chunk: the tag, then the text's UTF-8 bytes, without a length.
    /// Stored in `SieveSpan.source_digest` and chunk references; compared by
    /// chunk reads, follower evidence, rung evidence and window audits.
    SIEVE_CHUNK = (Blake3, HashedFirst, "oneiron:dreamer-sieve:chunk:v1");

    /// Sieve reading: the tag, the chunk count as a u64-BE, then for each chunk
    /// in reading order its raw source id and 32-byte digest, without lengths.
    /// Stored in the READ cursor row and compared to the current reading.
    SIEVE_READING = (Blake3, HashedFirst, "oneiron:dreamer-sieve:reading:v1");

    /// Sieve span id: the tag, raw turn id, raw source id, start and end each as
    /// a u64-BE, then the 32-byte chunk digest. Rule origin writes bytes
    /// `[0, kind, class]` then rules as a u32-BE. Saved-tag origin writes
    /// `[1, kind]`, the 32-byte envelope digest, then index as a u64-BE.
    /// Stored as `SieveSpan.id` and in SPANS and QUEUE keys.
    SPAN_ID = (Blake3, HashedFirst, "oneiron:dreamer-sieve:span:v2");

    /// Statement material: the tag, the evidence class string's u64-BE byte
    /// length, its UTF-8 bytes (empty for no class), then normalized tokens
    /// joined with one space as UTF-8, without a length. Empty tokens make no
    /// digest. Stored in Arc projection success material and compared by the
    /// Arc gate and projector when deciding whether material is new.
    STATEMENT = (Blake3, HashedFirst, "oneiron:dreamer-projector:statement:v3");

    /// Tag envelope: the tag, then content_hash, model_id, version and
    /// params_hash, each as a u64-BE byte length then UTF-8 bytes. Some(stack)
    /// writes `[1]`, its u64-BE byte length and UTF-8 bytes; None writes `[0]`.
    /// Stored in `SievedTurn.names.envelope` and compared to detect a new read.
    TAG_ENVELOPE_DIGEST = (Blake3, HashedFirst, "oneiron:dreamer-sieve:tag-envelope:v1");

    /// Turn program response: the tag, then `serde_json::to_vec(response)`
    /// bytes, without a length. Encoding failure makes no digest. Stored in
    /// `TurnProgramStep.result_digest` for durable model step replay.
    TURN_PROGRAM_RESPONSE = (Blake3, HashedFirst, "oneiron:dreamer:turn-program-response:v1");

    /// Turn projection: the tag, the turn ordinal as a u64-BE, then the 32-byte
    /// projection digest. Some caller key appends its u64-BE byte length and
    /// UTF-8 bytes; None appends nothing. Lowercase hex after `turn-projection:`
    /// is stored as the attempt queue dedupe key.
    TURN_PROJECTION = (Blake3, HashedFirst, "dreamer:turn-projection:v1");

    /// Typing member: the tag, the 16-byte carrier attempt id, then the 32-byte
    /// span id, without lengths. The first 16 output bytes form the AttemptId
    /// under which the member's reading is stored in the AUDIT table.
    TYPING_MEMBER_KEY = (Blake3, HashedFirst, "oneiron:dreamer-sieve:typing-member:v1");
}
