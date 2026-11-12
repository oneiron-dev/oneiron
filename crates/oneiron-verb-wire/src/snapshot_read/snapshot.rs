//! Moved from `crates/oneiron/src/snapshot_read/snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::ScopedReadResult;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::registry::ENTITY_TYPE_MESSAGE;
use oneiron_base::registry::ENTITY_TYPE_NOTE;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MEMORY_CODE_NOT_FOUND;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::vault::entity_view::EntityView;
use serde::Deserialize;
use serde::Serialize;

/// One kind of row a snapshot pages, by the vault's type index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// CLAIM rows.
    Claim,
    /// TURN rows, each served with its projected text.
    Turn,
    /// MESSAGE rows.
    Message,
    /// NOTE rows.
    Note,
    /// The rows of one other entity type code.
    Entity {
        /// The entity type code.
        entity_type: u8,
    },
}

impl SnapshotKind {
    fn entity_type(self) -> u8 {
        match self {
            Self::Claim => ENTITY_TYPE_CLAIM,
            Self::Turn => ENTITY_TYPE_TURN,
            Self::Message => ENTITY_TYPE_MESSAGE,
            Self::Note => ENTITY_TYPE_NOTE,
            Self::Entity { entity_type } => entity_type,
        }
    }
}

/// One `vault.snapshot.open` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotOpenRequest {
    /// The kinds the handle pages, in this order.
    pub kinds: Vec<SnapshotKind>,
    /// A read filter that narrows every page (it never widens the caller's
    /// read).
    #[serde(default)]
    pub filter: Option<oneiron_contracts::gate::ReadFilterInput>,
    /// The handle's lifetime in seconds: the owner's default when absent,
    /// and never above the owner's most lifetime or past the caller's
    /// credential's end.
    #[serde(default)]
    pub lifetime_secs: Option<u64>,
}

/// One open snapshot handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotHandle {
    /// The handle, for `vault.snapshot.page`.
    pub handle: EntityId,
    /// When it opened, on the vault's clock.
    pub opened_at: u64,
    /// When it ends, on the vault's clock.
    pub expires_at: u64,
    /// The kinds it pages, in order.
    pub kinds: Vec<SnapshotKind>,
}

/// One `vault.snapshot.page` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPageRequest {
    /// The handle `vault.snapshot.open` returned to this caller.
    pub handle: EntityId,
    /// The `next` of the page before; absent for the first page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// The most rows this page serves, at most the owner's rows per page.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A row a page does not serve because it is larger than the owner's bytes
/// per page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotOversizedRow {
    /// The row.
    pub entity: EntityId,
    /// Its size as a page row would encode it, in bytes.
    pub bytes: u64,
}
