//! Moved from `crates/oneiron/src/memory/usage_repair.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::ActSurface;
use serde::Deserialize;
use serde::Serialize;

/// `vault.usage.events.undecodable`'s input: none. The server lists its own
/// metering scope, never one a caller names.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageRepairListRequest {}

/// Why a stored usage row is listed. Pending settlements also use redelivery's
/// scope and validation checks. It names no part of the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UndecodableUsageReason {
    StoredEventDecodeFailed,
    StoredPendingDecodeFailed,
}

/// One stored usage row of the metering scope that does not decode, as its
/// reviewer sees it before removing it: where it is and what it hashes to,
/// none of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UndecodableUsageRow {
    /// The row's opaque locator: its event or pending kind and key parts,
    /// within the host-bound scope, as unpadded base64url.
    pub row_ref: String,
    /// How many bytes the row holds.
    pub byte_length: u64,
    /// BLAKE3 of the row's exact bytes, 64 lowercase hex digits.
    pub hash: String,
    pub decode_reason: UndecodableUsageReason,
}

/// `vault.usage.events.undecodable`'s answer: every stored usage event or pending
/// settlement of the metering scope that does not decode, in key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndecodableUsageList {
    pub events: Vec<UndecodableUsageRow>,
}

/// `vault.usage.events.remove_undecodable`'s input: one listed row, and the
/// hash its review read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageRepairRemoveRequest {
    /// The row's `rowRef` as the list gave it.
    pub row_ref: String,
    /// The row's `hash` as the list gave it: the removal changes nothing
    /// unless the row still holds exactly those bytes.
    pub expected_hash: String,
}

/// Why a repair removed a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageRepairReason {
    UndecodableEventRemoved,
    UndecodablePendingRemoved,
}

/// The authority a repair ran under: a live owner's own proof, by the
/// authentication it was bound to, or an agent's own Grant, each by its 32
/// hex id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "ref", rename_all = "snake_case")]
pub enum UsageRepairAuthority {
    Owner(String),
    Grant(String),
}

/// Where the call reached this install, for the receipt alone: no admission
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UsageRepairSurface {
    ThisInstall,
    /// A linked machine of the vault, by its 32 hex id.
    LinkedDevice {
        machine: String,
    },
    HostedConsole,
}

impl From<ActSurface> for UsageRepairSurface {
    fn from(surface: ActSurface) -> Self {
        match surface {
            ActSurface::ThisInstall => Self::ThisInstall,
            ActSurface::LinkedDevice { machine } => Self::LinkedDevice {
                machine: machine.to_hex(),
            },
            ActSurface::HostedConsole => Self::HostedConsole,
        }
    }
}

/// `vault.usage.events.remove_undecodable`'s answer, kept in the same write
/// that removed the row: what was removed, from which scope, by whom, under
/// which authority, where and when. It holds none of the row's bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageRepairReceipt {
    /// 32 hex.
    pub receipt_id: String,
    /// The billing owner of the metering scope, as the host bound it.
    pub owner: String,
    pub vault_id: String,
    pub row_ref: String,
    /// BLAKE3 of the removed bytes, 64 lowercase hex digits.
    pub hash: String,
    pub byte_length: u64,
    pub reason: UsageRepairReason,
    /// The caller, 32 hex.
    pub actor_ref: String,
    /// `human`, `agent` or `system`.
    pub actor_class: String,
    pub authority: UsageRepairAuthority,
    pub surface: UsageRepairSurface,
    /// The engine's time of the removal, in seconds.
    pub recorded_at: u64,
}

/// `vault.usage.repair.receipts`'s input: none. The server lists the
/// receipts of its own metering scope, never one a caller names (FIX 7036).
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageRepairReceiptsRequest {}

/// `vault.usage.repair.receipts`'s answer (FIX 7036): every receipt a
/// removal kept for the metering scope, in key order, as its write kept it;
/// none is capped or dropped. A kept receipt row that no longer decodes is
/// counted in `undecodable`, never read as a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageRepairReceiptList {
    pub receipts: Vec<UsageRepairReceipt>,
    pub undecodable: u64,
}
