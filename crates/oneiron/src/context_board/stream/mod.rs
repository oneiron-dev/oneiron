//! Board streaming frames and harness wake dispatch.

mod events;
mod frames;
mod provenance;
mod registry;
mod wake;
mod wake_dispatch;

#[cfg(test)]
mod routing_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wake_adapter_tests;
#[cfg(test)]
mod wake_tests;

pub use self::events::{
    BoardEvent, DeliveryClass, DeliveryPolicy, RouteObservation, SubscriptionError,
    SubscriptionReceipt, SubscriptionScope,
};
pub use self::frames::{
    AppliedStreamState, BoardRenderMode, BoardSnapshot, BoardStreamFrame, CarrierCoalesceBuffer,
    CoalesceOutcome, DeltaRow, FrameApplyOutcome, FrameEnqueueOutcome, FrameKind,
    StreamConnectionId,
};
pub use self::registry::{BoardStreamRegistry, StreamConnectionState};
pub use self::wake::{
    BindInstanceError, HarnessInstanceKey, InstanceBindingReceipt, WakeAdapterKind,
    WakeDeliveryOutcome, WakeDeliveryReportError, WakeDispatch, WakeDispatchObservations,
    WakeEnvelope, WakeReportDisposition,
};

use super::one_line_token;

// The flat stream.rs module used to provide these names to the inline test
// module through `use super::*`: every stream-internal item the tests name
// bare, plus the std names from its private import header. After the
// directory split the seam re-imports both so the test children resolve
// exactly as they did before.
#[cfg(test)]
use self::provenance::*;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
