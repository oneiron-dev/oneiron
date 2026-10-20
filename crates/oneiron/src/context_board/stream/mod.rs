//! Board streaming frames, routing and the pending-wake queue.

mod events;
mod frames;
mod provenance;
mod publish;
mod registry;
mod review;
mod wake;

#[cfg(test)]
mod routing_tests;
#[cfg(test)]
mod tests;

pub use self::events::{
    BoardEvent, DeliveryClass, DeliveryPolicy, RouteObservation, SubscriptionError,
    SubscriptionReceipt, SubscriptionScope,
};
pub use self::frames::{
    AppliedStreamState, BoardRenderMode, BoardSnapshot, BoardStreamFrame, CarrierCoalesceBuffer,
    CoalesceOutcome, DeltaRow, FrameApplyOutcome, FrameEnqueueOutcome, FrameKind,
    StreamConnectionId,
};
pub use self::publish::CommittedTaskBoardState;
pub use self::registry::{BoardStreamRegistry, StreamConnectionState};
pub use self::review::PendingDiaryReview;
pub use self::wake::WakeEnvelope;

use super::one_line_token;

// The flat stream.rs module used to provide these names to the inline test
// module through `use super::*`: every stream-internal item the tests name
// bare, plus the std names from its private import header. After the
// directory split the seam re-imports both so the test children resolve
// exactly as they did before.
#[cfg(test)]
use self::provenance::*;
#[cfg(test)]
use std::collections::BTreeSet;
