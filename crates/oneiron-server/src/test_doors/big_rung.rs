//! Doors for `tests/big_rung_written_reply.rs` (FIX 22368): the decision the
//! Big rung stores from a written reply.

use oneiron::llm::decision::{AnswerContract, DecisionAnswer};

use crate::config::models::BigReply;

/// The answer and probability the Big rung stores from the written reply
/// `text` in the `reply` format over `contract`, by the same function its
/// model call uses; `None` when the rung abstains.
pub fn written_decision(
    reply: BigReply,
    contract: &AnswerContract,
    text: &str,
) -> Option<(DecisionAnswer, f64)> {
    crate::big_rung::written_decision(reply, contract, text)
}
