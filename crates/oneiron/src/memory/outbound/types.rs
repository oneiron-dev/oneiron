//! Outbound schedule DTOs: context, draft input, and intent receipt.

pub use crate::delivery_window::OutboundScheduleContext;

#[doc(hidden)]
pub use oneiron_records::memory::outbound::types::OutboundDraftInput;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::outbound::types::OutboundIntentReceipt;
