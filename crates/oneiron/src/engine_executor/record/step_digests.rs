//! What a step's checkpoint hashes beside its state: where its calls end
//! and its replay context's digest (FIX 6354, FIX 6351), and its result's
//! body digests. Moved out of `record.rs` (ratchet).

/// Where a step's calls end and what its guest read beside them, which its
/// checkpoint binds (FIX 6354, FIX 6351): the run-global bridge position
/// the step's calls end at, exclusive, and the BLAKE3 of the step's replay
/// context as captured.
#[derive(Debug, Clone, Copy)]
pub(in crate::engine_executor) struct StepEnd {
    pub(in crate::engine_executor) bridge_end: u64,
    pub(in crate::engine_executor) context: [u8; 32],
}

/// What a step's checkpoint hashes of its result: each body's BLAKE3
/// digest, which its stored manifest already carries, never the body.
pub(in crate::engine_executor) struct StepResultDigests {
    pub(in crate::engine_executor) observation: [u8; 32],
    pub(in crate::engine_executor) done: bool,
    /// Each file the step wrote, by the guest path it named.
    pub(in crate::engine_executor) outputs: Vec<(String, [u8; 32])>,
    /// Each result name the step bound, with the handle it names, in the
    /// order the step bound them.
    pub(in crate::engine_executor) bindings: Vec<(String, String)>,
}

impl StepResultDigests {
    /// The digests of a result held whole in memory.
    pub(in crate::engine_executor) fn of(observation: &str, done: bool) -> Self {
        Self {
            observation: *blake3::hash(observation.as_bytes()).as_bytes(),
            done,
            outputs: Vec::new(),
            bindings: Vec::new(),
        }
    }
}
