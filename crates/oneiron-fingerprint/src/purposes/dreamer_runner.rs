//! Legacy dreamer-runner digests stored or compared by existing records.
//!
//! Queue deduplication, review receipts, grant terms, work and step keys,
//! maintenance evidence and replay bindings retain their exact bytes through
//! the K door (K, PLAN-UC-04 stage 7).

purposes! {}

legacy_purposes! {
    /// Review state: the tag, raw 16-byte subject, one-byte signal (its index
    /// in AgentHealthSignal::all()) and 16-byte task (zeros when absent, as
    /// card_key encodes them); reviewer's u64-LE UTF-8 length and
    /// bytes; diagnostics then evidence, each sorted by EntityId with a u64-LE
    /// count and raw 16-byte ids; then absent brief `[0]`, or `[1]`, its raw
    /// 16-byte task, u32-LE revision and digest UTF-8 (64 hex at the site),
    /// without a length. Lowercase hex after HEALTH_REVIEW_RECEIPT_PREFIX keys
    /// review_state rows and card outcomes; brief observed_at is excluded.
    AGENT_HEALTH_REVIEW_STATE = (Blake3, HashedFirst, "oneiron.coach.agent_health.review_state.v1");

    /// Coach ask: raw handle UTF-8 then at as u64-LE, without lengths or a
    /// hashed tag (the tag is a registry name only). Lowercase hex after
    /// COACH_AGENT_HEALTH_ASK_FACET is stored in the queued ask's dedupe key.
    COACH_ASK_DEDUPE = (Blake3, NotHashed, "oneiron.dreamer_runner.coach_ask_dedupe.v1");

    /// Blocked work: the tag including one final NUL, then the raw 16-byte
    /// receipt EntityId, without a length. The first 16 digest bytes become
    /// the EntityId that stores and finds CodeFixWork in WORK; run reports
    /// check it.
    CODE_FIX_BLOCKED_WORK = (Blake3, HashedFirst, "oneiron.code-fix.blocked.v1\0");

    /// Harm basis: the tag, candidate JSON's u64-BE byte length and JSON bytes,
    /// then raw question UTF-8 without a length. Its hex keys the digest assess
    /// queue; basis bytes also enter witnesses and STATE's answered_assessments.
    DIGEST_HARM_BASIS = (Blake3, HashedFirst, "oneiron:digest-harm:v1");

    /// Host witness: the tag, assessment JSON's u64-BE byte length and JSON
    /// bytes. Lowercase hex after DIGEST_URGENT_FACET plus `:host:` is stored
    /// as the queued host-built assessment witness's dedupe key.
    DIGEST_HARM_HOST_WITNESS = (Blake3, HashedFirst, "oneiron:digest-harm-host:v1");

    /// Grant terms: raw encode_access_grant_body canonical MessagePack bytes,
    /// no length or hashed tag (the tag is a registry name only). Stored as
    /// proposal terms_digest hex and compared with rebuilt grant terms before
    /// landing, to reject target_moved.
    ENVIRONMENT_GRANT_TERMS = (Blake3, NotHashed, "oneiron.dreamer_runner.environment_grant_terms.v1");

    /// Fold defaults: the tag and raw 16-byte definition, then each suggestion
    /// in input order: kind UTF-8, one NUL, keep_last_steps as u64-BE (u64::MAX
    /// for None), median_span_steps as u64-BE. No list count or string length.
    /// Stored in SUGGESTED and compared before emitting proposed findings.
    FOLD_SUGGESTION_STATE = (Blake3, HashedFirst, "oneiron:coach-fold-suggestions:v1");

    /// Wake key: raw key UTF-8, no length or hashed tag (the tag is a registry
    /// name only). Lowercase hex after the caller's facet and colon is stored
    /// as the policy-author, honesty-audit or stewardship queue dedupe key.
    MAINTENANCE_WAKE_KEY = (Blake3, NotHashed, "oneiron.dreamer_runner.maintenance_wake_key.v1");

    /// Upkeep evidence: the tag including one final NUL; settled teams only,
    /// in BTreeMap team-ref order (last duplicate wins). Each writes team-ref
    /// and node-id UTF-8, each a u64-BE byte length then bytes; u64-BE tree
    /// version; pattern UTF-8 with u64-BE byte length; u64-BE model count then
    /// each model UTF-8 with u64-BE byte length; success byte; u64-BE at; then
    /// absent task `[0]` or `[1]` and task UTF-8 with u64-BE byte length.
    /// Stored with project as the JOURNAL key; pass time and live tree excluded.
    PROJECT_TREE_UPKEEP_EVIDENCE = (Blake3, HashedFirst, "oneiron:project-tree-upkeep:evidence:v1\0");

    /// Room source: the tag, raw 16-byte room, then raw 16-byte turns in input
    /// order, without lengths or count. Stored in DECLARED and compared before
    /// declaring the room summary over exactly those turns.
    ROOM_UPKEEP_SOURCE_STATE = (Blake3, HashedFirst, "oneiron:coach-room-upkeep-summary:v1");

    /// Route prompt: raw JSON bytes of Option<&str> (None is null, Some is a
    /// JSON string), no length or hashed tag (the tag is a registry name only).
    /// Stored in replay capsule StoredRungBinding.prompt_digest and compared
    /// against the route pin before the stored prompt is used.
    ROUTE_PROMPT = (Blake3, NotHashed, "oneiron.dreamer_runner.route_prompt.v1");

    /// Turn steps share one tag and two existing layouts. Step id: the tag,
    /// then each part's u64-BE byte length and raw bytes, with no part count;
    /// first 16 digest bytes form the EntityId used as STEP's row key. Outbound
    /// result: the tag, raw 32-byte payload_hash, then body's bytes read to the
    /// end when present, with no presence byte or length (None equals empty).
    /// All 32 result bytes are stored in StepState::Settled.result_digest.
    TURN_PROGRAM_STEP = (Blake3, HashedFirst, "oneiron:dreamer:turn-program-step:v1");
}
