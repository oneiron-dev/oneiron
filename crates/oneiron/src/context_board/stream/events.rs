//! Board events and their subscription/delivery classification.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::frames::{DeltaRow, StreamConnectionId};
use super::provenance::{ChildEvent, VerifiedOwnTaskEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SubscriptionScope {
    MyTasks,
    MyChildren,
    ConsultsToMe,
    Memories,
    Worlds,
    Presence,
    Counts,
}

impl SubscriptionScope {
    pub const ALL: [Self; 7] = [
        Self::MyTasks,
        Self::MyChildren,
        Self::ConsultsToMe,
        Self::Memories,
        Self::Worlds,
        Self::Presence,
        Self::Counts,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryClass {
    Wake,
    Carrier,
    OnDemand,
}

impl DeliveryClass {
    pub const fn is_pushable(self) -> bool {
        matches!(self, Self::Wake | Self::Carrier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPolicy<A> {
    pub audience: A,
    pub class: DeliveryClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardEvent {
    ConsultArrived {
        event: VerifiedOwnTaskEvent,
        line: String,
    },
    OwnTaskFailed {
        event: VerifiedOwnTaskEvent,
        line: String,
    },
    OwnTaskDone {
        event: VerifiedOwnTaskEvent,
        delta: DeltaRow,
    },
    ChildDone {
        event: ChildEvent,
        delta: DeltaRow,
    },
    MemoriesChanged {
        event_ref: String,
    },
    PresenceChanged {
        event_ref: String,
    },
    WorldsChanged {
        event_ref: String,
    },
    CountsChanged {
        event_ref: String,
    },
}

impl BoardEvent {
    pub const fn class(&self) -> DeliveryClass {
        match self {
            Self::ConsultArrived { .. } | Self::OwnTaskFailed { .. } => DeliveryClass::Wake,
            Self::OwnTaskDone { .. } | Self::ChildDone { .. } => DeliveryClass::Carrier,
            _ => DeliveryClass::OnDemand,
        }
    }
    pub const fn subscription_scope(&self) -> SubscriptionScope {
        match self {
            Self::ConsultArrived { .. } => SubscriptionScope::ConsultsToMe,
            Self::OwnTaskFailed { .. } | Self::OwnTaskDone { .. } => SubscriptionScope::MyTasks,
            Self::ChildDone { .. } => SubscriptionScope::MyChildren,
            Self::MemoriesChanged { .. } => SubscriptionScope::Memories,
            Self::PresenceChanged { .. } => SubscriptionScope::Presence,
            Self::WorldsChanged { .. } => SubscriptionScope::Worlds,
            Self::CountsChanged { .. } => SubscriptionScope::Counts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    ConnectionMissing(StreamConnectionId),
    OutsideAllowedSet {
        requested: BTreeSet<SubscriptionScope>,
        allowed: BTreeSet<SubscriptionScope>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionReceipt {
    pub connection: StreamConnectionId,
    pub active: BTreeSet<SubscriptionScope>,
}

#[derive(Debug, Default)]
pub struct RouteObservation {
    pub wake_enqueued: usize,
    pub carrier_enqueued: usize,
    pub on_demand_ignored: usize,
}
