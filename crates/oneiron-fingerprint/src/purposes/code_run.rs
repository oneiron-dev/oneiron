//! Legacy code-run digests that existing rows, ids and keys hold.
//!
//! Replay-generation pending-step digests, live-fork offer digests, code
//! consent request and run-origin digests, fork execution pins, emission
//! record and team review ids, leader spawn slip ids, program write call and
//! answer digests, repo request params hashes, live-run credential digests and
//! action keys, and step capsule messages digests retain their exact bytes
//! through the K door (K, PLAN-UC-04 stage 7).

purposes! {}

legacy_purposes! {
    /// Capsule messages: a request's messages as JSON (`serde_json::to_vec`),
    /// no length or hashed tag (the tag is a registry name only). Stored as a
    /// step replay capsule's messages digest, and compared with the call a
    /// ladder sends for it.
    CAPSULE_MESSAGES = (Blake3, NotHashed, "oneiron.code_run.capsule_messages.v1");

    /// Code consent request: an agent verb call's identity bytes (the verb's
    /// UTF-8, NUL, then its sorted input JSON, or that JSON's BLAKE3 for a
    /// custody verb), no length or hashed tag (the tag is a registry name
    /// only). Stored as a code consent binding's request digest, and part of
    /// its wait id.
    CONSENT_REQUEST = (Blake3, NotHashed, "oneiron.code_run.consent_request.v1");

    /// Code consent run origin: the domain `oneiron:code-consent-run-origin:v1`,
    /// then every origin field, each after its u64-LE byte length; no hashed
    /// tag (the tag is a registry name only). Mixed into a code consent
    /// binding's sealed digest.
    CONSENT_RUN_ORIGIN = (Blake3, NotHashed, "oneiron.code_run.consent_run_origin.v1");

    /// Code emission record id: the tag with no length before it, the salt
    /// byte, then the tier, source trust, Dreamer run id and run ref, each after
    /// its u64-LE byte length; the id is the first 16 bytes. Names the stored
    /// emission record entity.
    EMISSION_RECORD = (Sha256, HashedFirst, "oneiron:self-code-emission-record:v1");

    /// Fork execution pin: the sandbox WIT world name, NUL, the shadow protocol
    /// version as u32-BE, the 32-byte start digest, the bridge window's ends as
    /// u64-BE, a context flag byte and the 32-byte context digest when present,
    /// the frozen clock as u64-BE, the 32-byte RNG seed and the 32-byte runtime
    /// pin. Stored in an executed fork's evidence mode.
    FORK_EXECUTION_PIN = (Blake3, DeriveKeyContext, "oneiron contribution fork execution pin");

    /// Leader spawn slip id: the child's 16-byte id, then a fresh 16-byte id;
    /// no length or hashed tag (the tag is a registry name only). The slip id a
    /// leader's spawn signs into the authority log.
    LEADER_SPAWN_SLIP = (Blake3, NotHashed, "oneiron.code_run.leader_spawn_slip.v1");

    /// Live fork offer: an offer binding's JSON (`serde_json::to_vec`), no
    /// length or hashed tag (the tag is a registry name only); written as 64
    /// lowercase hex digits. Stored as a chat breakpoint rung's offer digest.
    LIVE_FORK_OFFER = (Blake3, NotHashed, "oneiron.code_run.live_fork_offer.v1");

    /// Live-run action key: the issued handle, the credential digest and the
    /// caller's key, each after its u64-BE byte length; written as
    /// `live-run:` and 64 lowercase hex digits. The idempotency key an action
    /// sent through a live-run attachment runs under.
    LIVE_RUN_ACTION_KEY = (Blake3, DeriveKeyContext, "oneiron live-run action key v1");

    /// Live-run credential: the principal's UTF-8, no length. Kept in a run
    /// replay row's live-run binding and compared at each attach and action.
    LIVE_RUN_CREDENTIAL = (Blake3, DeriveKeyContext, "oneiron live-run credential v1");

    /// Pending step: the tag with no length before it, then the pending step's
    /// MessagePack. Carried in a code run replay generation, which a guarded
    /// write compares.
    PENDING_STEP = (Blake3, HashedFirst, "oneiron:code-run-pending-step:v1");

    /// Program write call and answer: the tag with no length before it, then
    /// either the verb's UTF-8 and the call input's JSON (a write's call
    /// digest) or the receipt's first outcome as MessagePack (its answer
    /// digest). Stored in a turn program step, issued and settled.
    PROGRAM_CALL = (Blake3, HashedFirst, "oneiron:dreamer:turn-program-write-call:v1");

    /// Repo request params: the JSON of a request's sampling params and
    /// provider options (`serde_json::to_vec` of the pair), no length or hashed
    /// tag (the tag is a registry name only); written as 64 lowercase hex
    /// digits. Stored in a repo provenance claim's derivation envelope.
    REPO_REQUEST_PARAMS = (Blake3, NotHashed, "oneiron.code_run.repo_request_params.v1");

    /// Team submit review id: the tag with no length before it, the salt byte,
    /// then the leader's 16-byte attempt id, the team ref and the output
    /// revision, each after its u64-LE byte length; the id is the first 16
    /// bytes. Names the stored review claim.
    TEAM_SUBMIT_REVIEW = (Sha256, HashedFirst, "oneiron:self-team-submit-review:v1");
}
