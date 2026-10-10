//! A host's shadow output, once it clears parity, saved as its turn's tags
//! the way the tagging slot saves an answer: derived, local, unconfirmed.
use super::types::*;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::tagging::TurnTags;
use crate::{EntityId, Error};
impl Memory<'_> {
    /// Saves a parity-checked shadow output as its turn's tag set, under the
    /// vault's tagging label table. The source must still read as the model
    /// read it. It writes no edge, no claim and no merge; any refusal writes
    /// nothing, and saving the same envelope again leaves the tags as they
    /// are.
    pub fn persist_extraction(
        &self,
        trace: &ShadowTrace,
        parity: &EncoderParity,
        now: u64,
    ) -> MemoryResult<TurnTags> {
        if parity.model != trace.model {
            return Err(
                Error::InvalidConfig("encoder has no matching parity receipt".into()).into(),
            );
        }
        let output = trace
            .output
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("shadow did not produce a valid output".into()))?;
        let turn = EntityId::from_hex(&trace.input.turn)?;
        self.with_verified_actor_write_txn(|txn| {
            crate::tagging::save_shadow_output_in_txn(
                self.vault,
                txn,
                turn,
                &trace.input,
                output,
                &trace.model,
                now,
            )?
            .ok_or_else(|| MemoryError::bad_request("source changed after shadow inference"))
        })
    }
}
