//! Engine-generic booking module.
//!
//! Declarations and re-exports only: every seam type is defined in
//! [`constraint`], which is the single home later booking layers import from.
//! This file defines no type and allocates no entity byte.

pub mod agent_front;
pub mod constraint;
pub mod disclosure_rung;
#[cfg(test)]
mod tests;

pub use constraint::{
    BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotMask, SlotOracle, SolveRequest,
    SolveResult,
};
pub use disclosure_rung::{
    BusyBlockRow, CalendarDisclosureDefault, DisclosureRung, EventDetailsRow, EventRow,
    RungProjection, SurfaceClass, TitledEventRow, default_disclosure_rung, project_at_rung,
    project_calendar_grant,
};
