//! OF-336 component discriminators and the action descriptor every card
//! advertises. Rendering belongs to clients, never to the engine (RD-18).

use super::consent_eval::ConsentActionKind;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::genui::protocol::{Of336ActionDescriptor, Of336ComponentKind};
