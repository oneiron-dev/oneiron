//! Outbound schedule/dispatch and the calendar read/search/freebusy/invite
//! surface. Split from the flat `facade.rs`; surface re-exported by [`super`].

mod calendar;
mod dedupe;
mod errors;
mod invite;
mod schedule;
mod types;

pub use self::calendar::{CalendarFreebusyDto, CalendarFreebusyIntervalDto};
pub use self::invite::{
    CALENDAR_INVITE_OUTBOUND_CHANNEL, CALENDAR_INVITE_OUTBOUND_VERB, CalendarInviteSurfaceInput,
    CalendarInviteSurfaceMethod,
};
pub use self::schedule::BRIDGE_OUTBOUND_ATTEMPT_KIND;
pub use self::types::{OutboundDraftInput, OutboundIntentReceipt, OutboundScheduleContext};

pub(crate) use self::errors::facade_error_from_outbound_dispatch;

pub(super) use self::dedupe::parse_job_ref;
