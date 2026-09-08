//! Wake envelopes, harness instance keys and the adapter dispatch ladder.

use std::collections::BTreeSet;

use super::frames::StreamConnectionId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeEnvelope {
    pub event_ref: String,
    pub task_ref: String,
    pub actor_ref: String,
    pub line: String,
}

/// Opaque per-instance wake-delivery key: harness kind plus canonicalized
/// harness config directory, derived host-side and stored verbatim.
///
/// This is an ephemeral delivery key, never an entity identifier. The engine
/// never parses a path, harness, vendor, or actor id out of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HarnessInstanceKey(String);

impl HarnessInstanceKey {
    #[must_use]
    pub fn new(opaque: impl Into<String>) -> Self {
        Self(opaque.into())
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed wake-adapter family. Layer 2 is harness-native, layer 3 is the hard
/// fallback; durable TASK/consult transport is the layer-1 correctness floor
/// and is deliberately not a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WakeAdapterKind {
    ClaudeCodeMonitor,
    CodexStopHook,
    TmuxSendKeys,
    BootPromptSpawn,
}

impl WakeAdapterKind {
    /// Delivery layer; numerically smaller is the stronger layer.
    #[must_use]
    pub const fn layer(self) -> u8 {
        match self {
            Self::ClaudeCodeMonitor | Self::CodexStopHook => 2,
            Self::TmuxSendKeys | Self::BootPromptSpawn => 3,
        }
    }
    /// Deterministic tie-break for over-complete same-layer capability sets.
    const fn same_layer_order(self) -> u8 {
        match self {
            Self::ClaudeCodeMonitor => 0,
            Self::CodexStopHook => 1,
            Self::TmuxSendKeys => 0,
            Self::BootPromptSpawn => 1,
        }
    }
}

/// Total preference order over one complete install snapshot.
pub(super) fn ordered_candidates(installed: &BTreeSet<WakeAdapterKind>) -> Vec<WakeAdapterKind> {
    let mut candidates: Vec<_> = installed.iter().copied().collect();
    candidates.sort_by_key(|kind| (kind.layer(), kind.same_layer_order()));
    candidates
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeDeliveryOutcome {
    Delivered,
    Failed,
}

/// One coalesced, reportable wake-delivery unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeDispatch {
    pub instance: HarnessInstanceKey,
    pub dispatch_seq: u64,
    pub chosen: Option<WakeAdapterKind>,
    pub envelopes: Vec<WakeEnvelope>,
    /// Total envelopes folded into this one dispatch unit.
    pub coalesced: usize,
}

/// Cumulative in-memory diagnostics. Never a receipt, synced fact, metrics
/// entity, or retry row; connection teardown never decrements them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeDispatchObservations {
    pub dispatch_units_created: usize,
    pub envelopes_coalesced: usize,
    pub delivery_failures: usize,
    pub delivered_dispatches: usize,
    pub exhausted_dispatches: usize,
    pub exhausted_envelopes: usize,
    pub transport_only_dispatches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindInstanceError {
    ConnectionMissing(StreamConnectionId),
    AlreadyBound {
        connection: StreamConnectionId,
        existing: HarnessInstanceKey,
        requested: HarnessInstanceKey,
    },
    InstallSetMismatch {
        connection: StreamConnectionId,
        instance: HarnessInstanceKey,
        existing: BTreeSet<WakeAdapterKind>,
        requested: BTreeSet<WakeAdapterKind>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceBindingReceipt {
    pub connection: StreamConnectionId,
    pub instance: HarnessInstanceKey,
    pub installed: BTreeSet<WakeAdapterKind>,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeReportDisposition {
    Delivered {
        envelopes: usize,
    },
    Reoffered {
        failed: WakeAdapterKind,
        next: WakeAdapterKind,
        envelopes: usize,
    },
    Exhausted {
        envelopes: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeDeliveryReportError {
    ConnectionMissing(StreamConnectionId),
    NoActiveDispatch(StreamConnectionId),
    StaleDispatch {
        expected: u64,
        reported: u64,
    },
    KindMismatch {
        expected: WakeAdapterKind,
        reported: WakeAdapterKind,
    },
}

/// Ephemeral per-instance adapter state. The connection set is the private
/// ref-count: the entry lives while at least one attached connection binds it.
#[derive(Debug, Clone)]
pub(super) struct InstanceAdapterState {
    pub(super) installed: BTreeSet<WakeAdapterKind>,
    pub(super) connections: BTreeSet<StreamConnectionId>,
}

/// One in-flight bundle, retained until a report resolves it. Its candidate
/// list is frozen at creation, so a later snapshot replacement cannot rewrite
/// an offer already in flight.
#[derive(Debug, Clone)]
pub(super) struct PendingWakeDispatch {
    pub(super) instance: HarnessInstanceKey,
    pub(super) dispatch_seq: u64,
    pub(super) candidates: Vec<WakeAdapterKind>,
    pub(super) candidate_index: usize,
    pub(super) envelopes: Vec<WakeEnvelope>,
}

impl PendingWakeDispatch {
    pub(super) fn chosen(&self) -> Option<WakeAdapterKind> {
        self.candidates.get(self.candidate_index).copied()
    }
    pub(super) fn as_public(&self) -> WakeDispatch {
        WakeDispatch {
            instance: self.instance.clone(),
            dispatch_seq: self.dispatch_seq,
            chosen: self.chosen(),
            envelopes: self.envelopes.clone(),
            coalesced: self.envelopes.len(),
        }
    }
}
