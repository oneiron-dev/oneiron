//! What a terminal attempt left behind (FIX 9578): its durable outputs and
//! the checkpoint frontier it recorded, written with the row that settles.

use serde::{Deserialize, Serialize};

use super::AttemptResultRef;
use crate::attempt_queue::AttemptResumePoint;

/// A terminal try's durable exhaust: the output references it attached
/// before it settled, explicitly empty when it attached none, and the resume
/// point it recorded, when it recorded one. Nothing here is made up: an
/// empty list is the record that no output exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptTerminalExhaust {
    /// The output references the try attached, in attach order; empty when
    /// it attached none.
    pub outputs: Vec<AttemptResultRef>,
    /// The resume point the try recorded, when it recorded one.
    #[serde(default)]
    pub frontier: Option<AttemptResumePoint>,
}
