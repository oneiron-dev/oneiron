//! Purposes of training runs (`crates/oneiron/src/training_pack`; OF-382).
//!
//! A training swap ask (`crates/oneiron/src/task_verb/training_swap_ask`) freezes a digest
//! of what the swap binds against and the run's export checks. The ask's route and its key
//! store the digest, the owner's view and the ask's intent key carry it, and a renewal
//! compares it afresh. So it keeps its bytes (K, PLAN-UC-04 stage 6.4e).

purposes! {}

legacy_purposes! {
    /// A training swap question's digest (`training_swap_ask::question`,
    /// `swap_question_digest`): plain BLAKE3 of the sorted JSON (`llm::canonical_json_bytes`)
    /// of the pair (`SwapExpectation`, `ExportCheck`), with no tag or length; lowercase hex.
    SWAP_QUESTION = (Blake3, NotHashed, "oneiron.training_pack.swap_question.v1");
}
