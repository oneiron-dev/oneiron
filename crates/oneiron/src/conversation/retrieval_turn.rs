//! The retrieval turn a chat host stamps on the recall it runs for one TURN
//! of a conversation: the convention on [`RetrievalTurn`] the engine's
//! natural outcome producer reads (UNBUILT-03-TURN-LINK = A; FIX
//! RETRIEVAL-TURN-CONVENTION-HOST-STAMP).

use crate::error::Result;
use crate::store::RetrievalTurn;
use crate::{EntityId, Vault};

impl Vault {
    /// The [`RetrievalTurn`] a host stamps on the recall it runs for `turn`,
    /// a TURN of `conversation` that is already witnessed or is witnessed
    /// once the recall has read: `episode_id` holds the conversation's id
    /// and `turn_id` the TURN's, so the engine can label the run from what
    /// the user says later in that conversation. `turn_idx` is the TURN's
    /// place among the conversation's live TURNs by learned time, or their
    /// count when it is not written yet.
    ///
    /// `None` while retrieval telemetry capture is off: such a recall writes
    /// no run, so the conversation is not read.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn conversation_retrieval_turn(
        &self,
        conversation: &EntityId,
        turn: &EntityId,
    ) -> Result<Option<RetrievalTurn>> {
        if !self.store.retrieval_telemetry_capture_enabled() {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        let mut turns = self.childof_turns_in(&txn, conversation)?;
        turns.sort_unstable();
        let place = turns
            .iter()
            .position(|(_, id)| id == turn)
            .unwrap_or(turns.len());
        Ok(Some(RetrievalTurn {
            turn_id: *turn.as_bytes(),
            episode_id: *conversation.as_bytes(),
            turn_idx: u64::try_from(place).unwrap_or(u64::MAX),
        }))
    }
}
