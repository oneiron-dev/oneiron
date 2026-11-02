//! What a press a browser act waited on came to (FIX 10423), as the answer
//! a code run's parked call resumes with carries it.
//!
//! A code run's click, click at a point or batch whose grant gave an act no
//! press parks on a code consent wait, and resumes with the answer its verb
//! declares: the act's own answer once it ran, else the answer the call had
//! when the press held it (the page the act began on, or a batch's answer
//! at its stop). [`PressAnswer`] beside it names the wait and what the
//! owner's answer came to.

use crate::{EffectReceipt, ObservationPage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What the owner's answer to the press an act waited on came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PressOutcome {
    /// The act ran under the owner's press.
    Delivered,
    /// Nothing ran.
    Refused,
    /// The act's input was sent and what it came to is not known; it never
    /// runs again.
    DeliveryUnknown,
}

/// The press an act of the call waited on, as the call's resumed answer
/// names it.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PressAnswer {
    /// The code consent wait the act waited on, by its id.
    pub wait: String,
    pub outcome: PressOutcome,
    /// Why it came to that, when the act did not run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// A held batch step's own answer once it ran: the page it left. The
    /// batch's own fields stay as the batch stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<ObservationPage>,
    /// The act's receipt, for an act whose input was sent and whose page did
    /// not read after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<EffectReceipt>,
}
