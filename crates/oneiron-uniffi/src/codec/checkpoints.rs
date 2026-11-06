//! Owned checkpoint output lifts for stored reply JSON (FIX 12936).

use oneiron::engine_executor::checkpoint_read as engine;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<engine::CheckpointResumeView> for crate::CheckpointResumeView {
    fn lift(resumed: engine::CheckpointResumeView) -> Result<Self, OneironError> {
        let engine::CheckpointResumeView {
            step,
            wait_ref,
            effect,
            output_handle,
            reply,
        } = resumed;
        // Optional JSON null reads as absent in the existing record codec.
        let reply = match reply {
            None | Some(Value::Null) => None,
            Some(reply) => Some(WireJson::lift(reply)?),
        };
        Ok(Self {
            step,
            wait_ref,
            effect,
            output_handle,
            reply,
        })
    }
}

impl Lift<engine::CheckpointView> for crate::CheckpointView {
    fn lift(view: engine::CheckpointView) -> Result<Self, OneironError> {
        let engine::CheckpointView {
            run_ref,
            completed_steps,
            steps,
            resumed,
            next_step,
        } = view;
        // Consume every opaque reply before propagating any conversion error.
        let resumed: Vec<_> = resumed
            .into_iter()
            .map(crate::CheckpointResumeView::lift)
            .collect();
        let resumed = resumed.into_iter().collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            run_ref,
            completed_steps,
            steps: lift_record("vault.runs.checkpoint", &steps)?,
            resumed,
            next_step,
        })
    }
}
