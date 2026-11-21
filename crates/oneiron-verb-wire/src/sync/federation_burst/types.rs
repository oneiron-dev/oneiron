//! Moved from `crates/oneiron/src/sync/federation_burst/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationBurstWorld {
    All,
    Base,
    World { world_ref: EntityId },
}

/// A named normal rate and normal completed structural-failure streak.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstBaseline {
    pub name: String,
    pub writes_per_sec: f64,
    pub structural_streak: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum FederationBurstOutcome {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "isolate-and-propose")]
    IsolateAndPropose,
    #[serde(rename = "defer")]
    Defer,
}

/// Ordinary work is allowed. These outcomes route an unusual rate, then an
/// unusual rate with an unusual structural-failure streak. No model is used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstPolicy {
    /// None uses the peer's observed, completed-tick baseline.
    pub baseline: Option<FederationBurstBaseline>,
    pub unusual_rate: FederationBurstOutcome,
    pub unusual_streak: FederationBurstOutcome,
}

impl Default for FederationBurstPolicy {
    fn default() -> Self {
        Self {
            baseline: None,
            unusual_rate: FederationBurstOutcome::Defer,
            unusual_streak: FederationBurstOutcome::IsolateAndPropose,
        }
    }
}

impl FederationBurstPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.baseline.as_ref().is_some_and(|row| {
            row.name.trim().is_empty()
                || !row.writes_per_sec.is_finite()
                || row.writes_per_sec <= 0.0
                || !row.structural_streak.is_finite()
                || row.structural_streak <= 0.0
        }) {
            return Err(Error::InvalidConfig(
                "burst baseline needs a name and positive finite rates".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstBaselineState {
    pub baseline: FederationBurstBaseline,
    pub learned: bool,
    pub vault_size: u64,
    pub recent_writes: u64,
    pub rate_ratio: f32,
    pub streak: u32,
    pub streak_ratio: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FederationBurstWorkState {
    Pending,
    Imported,
    Rejected,
    /// Its wait ended before its turn came; nothing was imported (FIX 7997).
    Expired,
    /// It was held under a grant or pact scope that has changed since. Its
    /// bytes were never imported, and it counts as no structural failure
    /// (FIX 7999).
    StaleAuthority,
    /// An erase took a row its bytes carried; only this receipt is kept
    /// (FIX 7998).
    Erased,
}

impl FederationBurstWorkState {
    /// Whether the batch's delivery is settled for good, so a resend of the
    /// same bytes answers with this receipt. A batch that ended any other
    /// way may be sent again, and that delivery starts afresh.
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Imported | Self::Rejected)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome")]
pub enum FederationBurstDisposition {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "isolate-and-propose")]
    IsolateAndPropose {
        bundle_ref: String,
        replay_ref: String,
    },
    #[serde(rename = "defer")]
    Defer { replay_ref: String },
}

/// Whose batch a receipt names: a federated peer under its grant, or one of
/// the vault's own devices writing at its home, as its connection proved it
/// (L7-41). The in-memory view of a receipt's naming fields
/// ([`FederationBurstReceipt::peer`]); never stored or sent itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FederationBurstPeerRef {
    /// A federated peer: its authenticated principal and the grant it writes under.
    Federated {
        principal: EntityId,
        grant: EntityId,
    },
    /// An own device, by the machine its connection proved.
    Machine { machine: EntityId },
    /// An own device, by the hex id of the paired app's slip that bound its
    /// Write credential.
    Slip { slip: String },
    /// Own-device connections that proved neither.
    Unproven,
}

/// The own device a receipt names (L7-41), as its connection proved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FederationBurstDeviceRef {
    /// By the machine its connection proved.
    Machine { machine: EntityId },
    /// By the hex id of the paired app's slip that bound its Write credential.
    Slip { slip: String },
    /// Own-device connections that proved neither.
    Unproven,
}

impl From<FederationBurstDeviceRef> for FederationBurstPeerRef {
    fn from(device: FederationBurstDeviceRef) -> Self {
        match device {
            FederationBurstDeviceRef::Machine { machine } => Self::Machine { machine },
            FederationBurstDeviceRef::Slip { slip } => Self::Slip { slip },
            FederationBurstDeviceRef::Unproven => Self::Unproven,
        }
    }
}

impl FederationBurstPeerRef {
    /// The principal a federated peer's receipt names; `None` for a device.
    pub fn principal(&self) -> Option<EntityId> {
        match self {
            Self::Federated { principal, .. } => Some(*principal),
            Self::Machine { .. } | Self::Slip { .. } | Self::Unproven => None,
        }
    }

    /// The grant a federated peer's receipt names; `None` for a device.
    pub fn grant(&self) -> Option<EntityId> {
        match self {
            Self::Federated { grant, .. } => Some(*grant),
            Self::Machine { .. } | Self::Slip { .. } | Self::Unproven => None,
        }
    }

    /// The device an own device's receipt names; `None` for a federated peer.
    pub fn device(&self) -> Option<FederationBurstDeviceRef> {
        match self {
            Self::Federated { .. } => None,
            Self::Machine { machine } => {
                Some(FederationBurstDeviceRef::Machine { machine: *machine })
            }
            Self::Slip { slip } => Some(FederationBurstDeviceRef::Slip { slip: slip.clone() }),
            Self::Unproven => Some(FederationBurstDeviceRef::Unproven),
        }
    }
}

/// A stable batch identity, its original routed outcome, and its current
/// completion state. Replay does not erase the original disposition.
///
/// The burst ledger stores this row by field name (L7-41 keep path, the
/// lead's M-1 STORED-CHANGE-RULE): a federated peer's receipt names
/// `principal` and `grant`, as every receipt stored before own devices did,
/// and its bytes are unchanged; an own device's receipt names `device`
/// instead. A field that is `None` is neither stored nor sent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstReceipt {
    pub batch_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<FederationBurstDeviceRef>,
    pub window_key: String,
    pub disposition: FederationBurstDisposition,
    pub state: FederationBurstWorkState,
    pub baseline: FederationBurstBaselineState,
}

impl FederationBurstReceipt {
    /// Whose batch this receipt names: a federated peer when it names a
    /// principal and a grant, an own device when it names a device. A row
    /// that names both or neither names no peer.
    pub fn peer(&self) -> Option<FederationBurstPeerRef> {
        match (self.principal, self.grant, &self.device) {
            (Some(principal), Some(grant), None) => {
                Some(FederationBurstPeerRef::Federated { principal, grant })
            }
            (None, None, Some(device)) => Some(device.clone().into()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FederationBurstReviewRequest {
    pub bundle_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstReviewReceipt {
    pub bundle_ref: String,
    pub batches: Vec<FederationBurstReceipt>,
}
