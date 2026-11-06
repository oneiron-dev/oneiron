//! Owned lens-frame event output conversion (FIX 12936).

use oneiron_remote::LensFrameEventReply as EngineReply;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<EngineReply> for crate::LensFrameEventReply {
    fn lift(reply: EngineReply) -> Result<Self, OneironError> {
        match reply {
            EngineReply::Local { state, refinement } => {
                let refinement = match refinement {
                    None | Some(Value::Null) => None,
                    Some(refinement) => Some(WireJson::lift(refinement)?),
                };
                Ok(Self::Local {
                    state: lift_record("lens_frame_event:Local.state", &state)?,
                    refinement,
                })
            }
            EngineReply::Tool {
                outcome,
                read_receipt,
            } => {
                let outcome = WireJson::lift(outcome)?;
                Ok(Self::Tool {
                    outcome,
                    read_receipt: lift_record("lens_frame_event:Tool.readReceipt", &read_receipt)?,
                })
            }
            callback @ EngineReply::Callback { .. } => lift_record("lens_frame_event", &callback),
        }
    }
}
