//! The side tables `dreamer_wake` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// FIX 8531: the first frame after a follower session's keyframe that holds one chunk, and
    /// the chunk's place in it, written with the frame. Key: hash32(session) + id16(turn) +
    /// id16(source) + hash32(chunk words); value: (frame ordinal, chunk index).
    DREAMER_FOLLOWER_CHUNK: VaultMeta b"dreamer:follower:chunk:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 7510: one admitted source observation of a follower session, its exact rendered bytes
    /// and source pins. Key: hash32(session) + u64be(frame ordinal).
    DREAMER_FOLLOWER_FRAME: VaultMeta b"dreamer:follower:frame:v1:" Named Admitted
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 7510: one follower model result: a suffix's batch readings with its cache evidence, or
    /// a keyframe's folded text. Key: id16(attempt) + u64be(session sequence).
    DREAMER_FOLLOWER_RESULT: VaultMeta b"dreamer:follower:result:v1:" Named Authored [accepts: crate::dreamer_wake::dreamer_follower_result_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 7510: one follower session's cursors, prefix digest, epoch, keyframe ref, writer fence
    /// and prepared suffix. Key: hash32(session).
    DREAMER_FOLLOWER_STATE: VaultMeta b"dreamer:follower:state:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// The projector rounds one TURN gave words to, for erasure. Key: id16(turn).
    DREAMER_PROJECTION_GIVEN: VaultMeta b"dreamer:projection:given:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The latest TURN the projector queued, vault-wide, its round, and whether it holds. Key: ().
    DREAMER_PROJECTION_LATEST: VaultMeta b"dreamer:projection:latest:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A TURN consumed as a repeat of the held TURN: the round it rode and the TURN it repeated.
    /// Key: u64be + id16.
    DREAMER_PROJECTION_RIDER: VaultMeta b"dreamer:projection:rider:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A rider by the TURN it repeated. Key: id16(repeated) + u64be + id16(rider).
    DREAMER_PROJECTION_RIDER_OF: VaultMeta b"dreamer:projection:rider_of:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The temporal key one riding TURN rides under. Key: id16(turn).
    DREAMER_PROJECTION_RIDES: VaultMeta b"dreamer:projection:rides:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One projector round: its turns and riders, and whether it applied. Key: hash32(round).
    DREAMER_PROJECTION_ROUND: VaultMeta b"dreamer:projection:round:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The refusal dial an agent last woke under (OF-533), so its next wake notes a change in its
    /// own diary. Key: id16(agent).
    DREAMER_REFUSAL_DIAL_SEEN: VaultMeta b"dreamer:refusal-dial:seen:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Sample audit grade per durable rung attempt. Key: id16.
    DREAMER_SIEVE_AUDIT: VaultMeta b"dreamer:sieve:audit:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One span the nightly spending consumed, by the attempt that spent it.
    /// Key: id16(attempt) + hash32(span).
    DREAMER_SIEVE_CONSUMED: VaultMeta b"dreamer:sieve:consumed:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A TURN whose sieve read the pass's text bound stopped, with the chunks it reads on in.
    /// Key: id16(turn).
    DREAMER_SIEVE_CONTINUE: VaultMeta b"dreamer:sieve:continue:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Where the continuous sieve stands on the TURN timeline. Key: ().
    DREAMER_SIEVE_CURSOR: VaultMeta b"dreamer:sieve:cursor:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Retained original cheap span readings, for sampled expensive-path audits. Key: turn id16 + span hash32.
    DREAMER_SIEVE_HISTORY: VaultMeta b"dreamer:sieve:history:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A TURN owed a new sieve read (new, changed words or saved tags). Key: id16(turn).
    DREAMER_SIEVE_OWED: VaultMeta b"dreamer:sieve:owed:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The sieve's interest queue, one span per row. Key: u32be(inverted score) + hash32(span).
    DREAMER_SIEVE_QUEUE: VaultMeta b"dreamer:sieve:queue:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The sieve's grant epoch and its sweep over the withheld turns. Key: ().
    DREAMER_SIEVE_RETRY: VaultMeta b"dreamer:sieve:retry:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One queued span of a TURN. Key: id16(turn) + u32be(inverted score) + hash32(span).
    DREAMER_SIEVE_SPANS: VaultMeta b"dreamer:sieve:spans:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// What the sieve last read of one TURN. Key: id16(turn).
    DREAMER_SIEVE_TURN: VaultMeta b"dreamer:sieve:turn:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A TURN the sieve read with a MESSAGE the Dreamer may not read, and the grant epoch it was
    /// read at (u64be). Key: id16(turn).
    DREAMER_SIEVE_WITHHELD: VaultMeta b"dreamer:sieve:withheld:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Coalesced recipe input for one wake recipe. Key: u8(recipe).
    DREAMER_WAKE_RECIPE_INPUT: VaultMeta b"dreamer:wake-policy:recipe-input:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Wake cursor and pending state. Key: ().
    DREAMER_WAKE_STATE: VaultMeta b"dreamer:wake-policy:state:v1" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Node-local wake-pass observation (DOOR-144): a pass's header, admitted generations, calls
    /// and Checkpoint cuts. Key: u8(row kind) + ids (`dreamer_wake::observation`).
    DREAMER_WAKE_OBSERVATION: VaultMeta b"dreamer:wake:observation:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// Digest (32 bytes) of the last queued wake projector image. Key: ().
    DREAMER_WAKE_PROJECTION: VaultMeta b"dreamer:wake:projection:v1" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-authored wake recipe budgets and rung instructions. Key: ().
    DREAMER_WAKE_RECIPE_POLICY: VaultMeta b"dreamer:wake:recipe_policy:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// A paid wake call not yet settled, keyed by attempt id16 + step hash32 (FIX 11450).
    DREAMER_WAKE_OWED_CALL: VaultMeta b"dreamer:wake_owed_call:" Raw
        // Restore class: FIX 11450: a paid wake call not yet settled works on the wake budget
        // ledger, which stands as the live vault holds it; so does what it still owes.
        [restore: live] [family: unclassified] [tier: canonical];
    /// Committed weave-recipe result bound to its pin, evidence and claim. Key: id16(attempt).
    DREAMER_WEAVE_RECIPE_RESULT: VaultMeta b"dreamer:weave:result:v1:" LegacyJson
        [restore: content] [family: unclassified] [tier: canonical];
    /// Owner-set projector surprise policy. Key: ().
    DREAMER_PROJECTOR_POLICY: VaultMeta b"settings:dreamer:projector-policy:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-set continuous sieve policy. Key: ().
    DREAMER_SIEVE_POLICY: VaultMeta b"settings:dreamer:sieve-policy:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner-controlled wake thresholds. Key: ().
    DREAMER_WAKE_POLICY: VaultMeta b"settings:dreamer:wake-policy:v1" LegacyJson
        [restore: live] [family: unclassified] [tier: canonical];
}
