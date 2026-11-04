//! Checkout identifiers, lease requests, settlement receipts and teardown values.

use crate::entity_id::EntityId;
use crate::error::Error;
use crate::side_table::{FixedSideKey, SideKey};
use crate::store::code_snapshot::RepoRef;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Closed materialization ladder. There is deliberately no copy-on-write, lazy
/// mount, overlay, filesystem-clone, or `Other(String)` rung: a rung that the
/// executor cannot honour must not be representable.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationSpec {
    FullClone = 1,
    #[default]
    Blobless = 2,
}

pub const CHECKOUT_LEASE_SCHEMA_VERSION: u8 = 1;
pub const CHECKOUT_LEASE_KEY_PREFIX: &[u8] = b"checkout:lease:v1:";
pub const CHECKOUT_SETTLEMENT_KEY_PREFIX: &[u8] = b"checkout:settlement:v1:";
/// Advisory, monotone-only row: the highest epoch that ever existed in a live
/// lease row for a `CheckoutId`. It is written inside the teardown delete txn,
/// so a freed namespace can never hand a later lifecycle an epoch that an
/// earlier lifecycle already used.
pub const CHECKOUT_TOMBSTONE_KEY_PREFIX: &[u8] = b"checkout:tombstone:v1:";
pub const CHECKOUT_RESULT_ID_DOMAIN: &[u8] = b"oneiron:checkout-result:v1";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckoutId([u8; 16]);
impl CheckoutId {
    pub fn from_bytes(bytes: [u8; 16]) -> CheckoutResult<Self> {
        if bytes == [0; 16] {
            return Err(CheckoutError::Invalid("checkout id zero"));
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl fmt::Display for CheckoutId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
/// The side tables' key spelling: the same lower-hex text [`fmt::Display`] writes, 32 bytes.
impl SideKey for CheckoutId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        for byte in self.0 {
            out.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        if text.len() != 32 {
            return None;
        }
        let mut out = [0_u8; 16];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
        }
        Self::from_bytes(out).ok()
    }
}
impl FixedSideKey for CheckoutId {
    const WIDTH: usize = 32;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitOid([u8; 20]);
impl GitOid {
    pub fn parse(value: &str) -> CheckoutResult<Self> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(CheckoutError::Invalid(
                "git oid must be 40 lower-hex characters",
            ));
        }
        let mut bytes = [0; 20];
        for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| CheckoutError::Invalid("git oid"))?,
                16,
            )
            .map_err(|_| CheckoutError::Invalid("git oid"))?;
        }
        if bytes == [0; 20] {
            return Err(CheckoutError::Invalid("git oid zero"));
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}
impl fmt::Display for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
pub use crate::store::checkout_task::CheckoutTaskClass;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutLeaseState {
    Active,
    Settling,
    Settled,
    Retained,
}
pub type CheckoutHolder = String;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckoutFactMutation {
    Claimed {
        task_ref: EntityId,
        assignee_ref: String,
        started_at: u64,
        epoch: u64,
    },
    Reclaimed {
        task_ref: EntityId,
        assignee_ref: String,
        epoch: u64,
    },
    Settled {
        task_ref: EntityId,
        epoch: u64,
        result_ref: String,
    },
    Released {
        task_ref: EntityId,
        epoch: u64,
    },
}
pub trait CheckoutFactSink {
    fn apply_checkout_fact(&mut self, mutation: CheckoutFactMutation) -> CheckoutResult<()>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLivenessPulse {
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub holder_ref: String,
    pub observed_at: u64,
}
pub trait CheckoutLiveness {
    fn publish(&mut self, pulse: CheckoutLivenessPulse) -> CheckoutResult<()>;
    fn current(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>>;
    fn clear(&mut self, id: CheckoutId, epoch: u64) -> CheckoutResult<()>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutClaimRequest {
    pub checkout_id: CheckoutId,
    pub task_ref: EntityId,
    pub repo_ref: RepoRef,
    pub holder_ref: String,
    pub task_class: CheckoutTaskClass,
    pub ttl_secs: Option<u64>,
    pub now: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLeaseGrant {
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub holder_ref: String,
    pub lease_expires_at: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLeaseFence {
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub holder_ref: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutSettlementDisposition {
    Select,
    Apply,
    Release,
    Discard,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSettlementRequest {
    pub fence: CheckoutLeaseFence,
    pub disposition: CheckoutSettlementDisposition,
    pub observed_ref: String,
    pub result_ref: String,
    pub now: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutSettlementReceipt {
    pub receipt_id: [u8; 32],
    pub checkout_id: CheckoutId,
    pub epoch: u64,
    pub result_identity: [u8; 32],
    pub disposition: CheckoutSettlementDisposition,
    pub observed_ref: String,
    pub result_ref: String,
    pub settled_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedHeadReceipt {
    pub receipt_ref: String,
    pub observed_ref: String,
    pub pushed_head: String,
    pub checkout_id: CheckoutId,
    pub epoch: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckoutTeardownOutcome {
    Collected {
        checkout_id: CheckoutId,
        epoch: u64,
    },
    Retained {
        checkout_id: CheckoutId,
        epoch: u64,
        reason: CheckoutRetainReason,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckoutRetainReason {
    MissingPushedHeadReceipt,
    ReceiptMismatch,
    LiveOccupant,
    DirtyOrUncertain,
}
#[derive(Debug)]
pub enum CheckoutError {
    StaleEpoch { held: u64, presented: u64 },
    LivenessOccupied { occupant: CheckoutHolder },
    ReceiptMismatch,
    SettlementAlreadyWon,
    RepoOps(String),
    Store(Error),
    Invalid(&'static str),
}
impl From<Error> for CheckoutError {
    fn from(e: Error) -> Self {
        Self::Store(e)
    }
}
pub type CheckoutResult<T> = Result<T, CheckoutError>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutTeardownInspection {
    pub observed_head: Option<GitOid>,
    pub dirty: bool,
    pub receipt_match: TeardownReceiptMatch,
    pub occupant: Option<CheckoutHolder>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReceiptMatch {
    Match,
    Mismatch,
    Uncertain,
}
// ONE-1907 (CSTDY-07) additive extension. Nothing above this line changes: the
// `CheckoutRepoOps::materialize(&CheckoutLeaseAct)` port, every claim/grant
// shape, and every persisted row keep their established bytes.
/// Standalone data carried by `CheckoutEnvPlan`. `None` means "use the exact
/// ONE-1901 path". This type is never persisted and is not attached as a field
/// to `CheckoutLeaseAct` or any existing public request or grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckoutMaterializationOptions {
    pub spec: Option<MaterializationSpec>,
}
impl CheckoutMaterializationOptions {
    pub const fn legacy() -> Self {
        Self { spec: None }
    }

    pub const fn resolved(spec: MaterializationSpec) -> Self {
        Self { spec: Some(spec) }
    }
}
