//! Legacy self-heal digests that existing rows, keys and findings hold.
//!
//! Blocked-report and consent-depth replay hashes, graded-window keys, minted
//! T2 revisions, retrieval-window and run replay hashes, tier-1 source pins,
//! healer run keys, detector wording parts, finding recipes and window
//! contexts retain their exact bytes through the K door (K, PLAN-UC-04
//! stage 7).

purposes! {}

legacy_purposes! {
    /// Blocked report content: the blocked receipt's content (its record
    /// prefix, then its JSON) as UTF-8, no length or hashed tag (the tag is a
    /// registry name only). Stored as the blocked-report diagnostic's replay
    /// content hash.
    BLOCKED_REPORT_CONTENT = (Blake3, NotHashed, "oneiron.self_heal.blocked_report_content.v1");

    /// Centroid window key: the T2a tier token's UTF-8 (`t2a`) without a
    /// length, the 32-byte T2b window key, then the 32-byte corpus revision; no
    /// hashed tag (the tag is a registry name only). Keys the graded-window
    /// table.
    CENTROID_WINDOW = (Blake3, NotHashed, "oneiron.self_heal.centroid_window.v1");

    /// Consent queue depth: per queued consent in tray order, its 32-byte
    /// payload digest; then the snapshot time and the threshold, each as
    /// u64-BE; no hashed tag (the tag is a registry name only). Stored as a
    /// consent-depth finding's replay content hash.
    CONSENT_DEPTH = (Blake3, NotHashed, "oneiron.self_heal.consent_depth.v1");

    /// Detector window key: the tier token, family, event class, prompt and
    /// rubric, each after its u64-BE byte length; the consecutive count as
    /// u64-BE; per run oldest first, its 16-byte run id; no hashed tag (the tag
    /// is a registry name only). Keys the graded-window table.
    DETECTOR_WINDOW = (Blake3, NotHashed, "oneiron.self_heal.detector_window.v1");

    /// Detector wording: the prompt, then the rubric, each after its u64-BE
    /// byte length; no hashed tag (the tag is a registry name only). A question
    /// part of a detector whose wording rides in the state, so it names the
    /// question a finding pins.
    DETECTOR_WORDING = (Blake3, NotHashed, "oneiron.self_heal.detector_wording.v1");

    /// Finding recipe: the tag, NUL-terminated and with no length before it;
    /// the tier token, family, event class, prompt and rubric, each after its
    /// u64-BE byte length; the consecutive count as u64-BE; the positive, then
    /// the negative, example ids, each list as its u64-BE count then its
    /// 16-byte ids; then 1 and the 32-byte corpus revision, or 0. Stored as a
    /// finding basis's recipe revision in the issue row, which keys the Coach
    /// issue.
    FINDING_RECIPE = (Blake3, HashedFirst, "oneiron.self_heal.finding_recipe.v1\0");

    /// Healer run key: the run name's UTF-8, no length or hashed tag (the tag
    /// is a registry name only). The second half of a per-actor healer run
    /// receipt's key.
    HEALER_RUN = (Blake3, NotHashed, "oneiron.self_heal.healer_run.v1");

    /// Minted T2 revision: the tag, NUL-terminated and with no length before
    /// it; the seed's family, event class, prompt and rubric, each after its
    /// u64-BE byte length; the consecutive count as u64-BE; the positive, then
    /// the negative, event ids, each list as its u64-BE count then its 16-byte
    /// ids. Stored in the minted registration and keys its graded windows.
    MINTED_T2_REVISION = (Blake3, HashedFirst, "oneiron.self_heal.minted_t2.v1\0");

    /// Minted window key: the 32-byte T2b detector window key, then the
    /// 32-byte registration revision; no hashed tag (the tag is a registry
    /// name only). Keys the graded-window table.
    MINTED_WINDOW = (Blake3, NotHashed, "oneiron.self_heal.minted_window.v1");

    /// Observed run replay: one retrieval run record's named MessagePack, no
    /// length or hashed tag (the tag is a registry name only). Stored as an
    /// observed run's replay in the issue's judgment.
    OBSERVED_RUN_REPLAY = (Blake3, NotHashed, "oneiron.self_heal.observed_run_replay.v1");

    /// Retrieval window: per run oldest first, its record's named MessagePack
    /// after its u64-BE byte length; no hashed tag (the tag is a registry name
    /// only). Stored as a model finding's replay content hash and an observed
    /// window's coordinate, and compared when a minted T2's example window is
    /// read back.
    RETRIEVAL_WINDOW = (Blake3, NotHashed, "oneiron.self_heal.retrieval_window.v1");

    /// Tier-1 source: the source row's named MessagePack, no length or hashed
    /// tag (the tag is a registry name only). Pinned in a tier-1 source proof,
    /// carried in the failure-signal witness, and compared with the row's
    /// current bytes before capture.
    TIER1_SOURCE = (Blake3, NotHashed, "oneiron.self_heal.tier1_source.v1");

    /// Window context: each asked state's JSON bytes in asking order, each
    /// after its u64-BE byte length; no hashed tag (the tag is a registry name
    /// only). Stored as a finding basis's context digest in the issue row.
    WINDOW_CONTEXT = (Blake3, NotHashed, "oneiron.self_heal.window_context.v1");
}
