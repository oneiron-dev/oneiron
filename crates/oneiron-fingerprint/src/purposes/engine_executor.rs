//! Purposes of the engine executor (`crates/oneiron/src/engine_executor`).
//!
//! Both executor digests are plain BLAKE3 with no tag: the domain is their first field.
//! Each field is a u64 big-endian length and its bytes; a field marked (u64) is a number
//! written as its 8 big-endian bytes, with no length.

purposes! {}

legacy_purposes! {
    /// A run's replay identity (`engine_executor::record`, `executor_config_hash`). The
    /// domain `oneiron:engine-executor-config:v1`; the storage binding
    /// (`storage:canonical`, or `storage:off-record-session` and the session ref); the
    /// route target when the storage has one (`route:overlay`, `route:base` or `discard`);
    /// the run id's hex; the task; the model; the model locality; `seat_effort:<effort>`
    /// when the seat pins an effort; the global tier; the frozen time (u64); the RNG seed;
    /// for a continuation, `continuation` and its digest. Its hex is the config marker's
    /// `config_hash`, stored with each CodeRun replay record and compared on every resume.
    CONFIG = (Blake3, NotHashed, "oneiron:engine-executor-config:v1");

    /// A REPL step's checkpoint hash (`engine_executor::record`,
    /// `prepared_step_state_hash`). The domain `oneiron:engine-executor-repl-step:v1`; the
    /// previous step's hash; the step number (u64); the request hash; the program's
    /// content hash; for a prepared program,
    /// `oneiron:engine-executor-repl-step:prepared-source:v1` and its identity; the
    /// observation digest; one byte for `done`; one byte for whether the step spoke
    /// implicitly, then the spoken text's content hash when it did; the output count (u64),
    /// then each output's path and digest; the binding count (u64), then each binding's name
    /// and handle; the bridge call count (u64), then each call's number (u64), effect,
    /// encoded request, encoded outcome and, when it has one, encoded rewritten request; the
    /// bridge end (u64); the replay context digest. Stored as the checkpoint's `state_hash`
    /// in the replay record, and chained into the next step's hash.
    STEP_CHECKPOINT = (Blake3, NotHashed, "oneiron:engine-executor-repl-step:v1");
}
