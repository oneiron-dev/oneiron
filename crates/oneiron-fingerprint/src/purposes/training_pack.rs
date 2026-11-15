//! Purposes of training runs (`crates/oneiron/src/training_pack`; OF-382).
//!
//! A run pins its corpus rows, plan, compute binding, probes, question definition,
//! evaluation and checkpoints by the BLAKE3 of each one's sorted JSON. Runs, corpus splits
//! and role swaps store the pins; dispatch, completion and promotion compare them; and the
//! Python training worker (`scripts/training_pack/worker.py`) takes the definition,
//! load-set and probe pins again. So they keep their bytes (K, PLAN-UC-04 stage 6.4a).

purposes! {}

legacy_purposes! {
    /// A training pin (`training_pack::pin::pin_digest`): plain BLAKE3 of the value's
    /// sorted JSON (`llm::canonical_json_bytes`), with no tag or length; kept as 32 raw
    /// bytes. A value holding a non-finite float has no pin.
    PIN = (Blake3, NotHashed, "oneiron.training_pack.pin.v1");
}
