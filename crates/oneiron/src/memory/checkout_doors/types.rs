//! Typed checkout custody calls. Holder identity and time come from the credential and vault.
use serde::{Deserialize, Serialize};
use crate::EntityId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutClass { Edit, Build, Verify, Effect }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutState { Active, Settling, Settled, Retained }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutAction { Select, Apply, Release, Discard }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutClaimInput {
    /// Caller-chosen nonzero 32 lower-hex checkout id.
    pub checkout: String,
    /// Existing CODE_ARTIFACT, whose stored pointer supplies the repository and commit.
    pub repo: EntityId,
    pub task: EntityId,
    pub task_class: CheckoutClass,
    pub ttl_seconds: u64,
    /// Build and verify may be reclaimed on expiry only when declared idempotent.
    pub declared_idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutGetInput { pub checkout: String }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRenewInput {
    pub checkout: String,
    pub epoch: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutReclaimInput {
    pub checkout: String,
    /// The epoch being replaced. A concurrent reclaim is never silently retried.
    pub expired_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutTakeoverInput {
    pub checkout: String,
    pub expected_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckoutLeaseView {
    pub checkout: String,
    pub task: EntityId,
    /// The stored repository pointer, not a caller-selected path.
    pub repo_ref: String,
    pub holder: EntityId,
    pub epoch: u64,
    pub task_class: CheckoutClass,
    pub state: CheckoutState,
    pub claimed_at: u64,
    pub expires_at: Option<u64>,
    pub expired: bool,
    /// Redemption right only; every Git request also authenticates the holder.
    pub ticket: String,
    pub receipt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutPublishInput {
    pub checkout: String,
    pub epoch: u64,
    pub observed_ref: String,
    /// A stored result artifact. Publication offers it for consume-once settlement;
    /// it does not move a Git ref (vault.code.export is the Git export door).
    pub candidate: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckoutPublished {
    pub checkout: String,
    pub epoch: u64,
    pub observed_ref: String,
    pub candidate: EntityId,
    pub result_identity: String,
    pub receipt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutSettleInput {
    pub checkout: String,
    pub epoch: u64,
    pub observed_ref: String,
    pub candidate: EntityId,
    pub action: CheckoutAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckoutSettled {
    pub checkout: String,
    pub epoch: u64,
    pub observed_ref: String,
    pub candidate: EntityId,
    pub action: CheckoutAction,
    pub result_identity: String,
    pub receipt: String,
    pub settled_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckoutTeardownInput {
    pub checkout: String,
    pub epoch: u64,
    /// A durable Published origin publication by this holder, on this repository,
    /// since this epoch was issued. No client-authored pushed-head receipt is accepted.
    pub pushed_head_receipt: Option<EntityId>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutRetention {
    MissingPushedHeadReceipt, ReceiptMismatch, LiveOccupant, DirtyOrUncertain,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckoutTornDown {
    Collected { checkout: String, epoch: u64 },
    Retained { checkout: String, epoch: u64, reason: CheckoutRetention },
}
