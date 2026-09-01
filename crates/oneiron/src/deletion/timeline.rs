use uuid::Uuid;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::claim::ClaimLifecycleStatus;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::tombstone::{
    decode_tombstone_value, pending_tombstone_key, window_label_from_timestamp,
};

/// Stable deletion reason surfaced by short-id hydrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

/// Where hydrate found deletion evidence for a short-id row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Deletion metadata returned when a short-id row resolves to deleted state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HydratedShortIdDeletion {
    pub source: HydratedShortIdDeletionSource,
    pub reason: Option<HydratedShortIdDeletionReason>,
    pub deleted_at: Option<u64>,
    pub request_id: Option<String>,
    pub hard: bool,
}

/// Renderer-facing lifecycle state for one record in a memory timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTimelineRecordState {
    /// The record exists and is not closed by the supersession graph.
    Live,
    /// The record exists and has been superseded by at least one newer record.
    Superseded,
    /// The record exists as explicitly retracted claim history.
    Retracted,
    /// The record exists only as a deletion shell with tombstone metadata.
    Deleted,
    /// The graph still references an entity id whose record is absent locally.
    Missing,
}

/// One node in a bitemporal supersession timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimelineRecord {
    pub id: EntityId,
    pub state: MemoryTimelineRecordState,
    pub entity_type: Option<u8>,
    pub occurred_start: Option<u64>,
    pub occurred_end: Option<u64>,
    pub learned_at: Option<u64>,
    pub body_bytes: Option<usize>,
    pub deletion: Option<HydratedShortIdDeletion>,
    pub supersedes: Vec<EntityId>,
    pub superseded_by: Vec<EntityId>,
}

/// Stable, ordered supersession-chain data for one anchor entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimeline {
    pub anchor: EntityId,
    pub records: Vec<MemoryTimelineRecord>,
}

/// Human-readable memory verbs exposed by API surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedMemoryVerb {
    Remember,
    Supersede,
    Retract,
    Delete,
    HardDelete,
}

impl NamedMemoryVerb {
    /// Parses a public route verb, accepting stable aliases while resolving to
    /// one canonical typed operation family.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "remember" | "put" | "put_entity" => Some(Self::Remember),
            "supersede" | "replace" | "revise" | "supersede_claim" => Some(Self::Supersede),
            "retract" | "withdraw" | "retract_claim" => Some(Self::Retract),
            "delete" | "forget" | "soft_delete" | "user_delete" => Some(Self::Delete),
            "hard_delete" | "erase" | "purge" | "user_hard_delete" => Some(Self::HardDelete),
            _ => None,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Remember => "remember",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Delete => "delete",
            Self::HardDelete => "hard_delete",
        }
    }

    pub const fn operation_kind(self) -> MemoryOperationKind {
        match self {
            Self::Remember => MemoryOperationKind::PutEntity,
            Self::Supersede => MemoryOperationKind::SupersedeClaim,
            Self::Retract => MemoryOperationKind::RetractClaim,
            Self::Delete | Self::HardDelete => MemoryOperationKind::DeleteEntity,
        }
    }
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

/// Cap for renderer timeline expansion across supersession edges.
const MAX_MEMORY_TIMELINE_RECORDS: usize = 10_000;

fn memory_timeline_record_cmp(
    left: &MemoryTimelineRecord,
    right: &MemoryTimelineRecord,
) -> std::cmp::Ordering {
    left.occurred_start
        .unwrap_or(u64::MAX)
        .cmp(&right.occurred_start.unwrap_or(u64::MAX))
        .then_with(|| {
            left.learned_at
                .unwrap_or(u64::MAX)
                .cmp(&right.learned_at.unwrap_or(u64::MAX))
        })
        .then_with(|| {
            left.occurred_end
                .unwrap_or(u64::MAX)
                .cmp(&right.occurred_end.unwrap_or(u64::MAX))
        })
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}

impl Vault {
    /// Returns stable, renderer-facing data for the supersession chain that
    /// contains `anchor`.
    pub fn memory_timeline(&self, anchor: &EntityId) -> Result<MemoryTimeline> {
        let mut ids = std::collections::BTreeSet::new();
        let mut edges = std::collections::BTreeMap::new();
        let mut stack = vec![*anchor];
        ids.insert(*anchor);

        while let Some(id) = stack.pop() {
            let older = self.targets(&id, EdgeKind::Supersedes, None)?;
            let newer = self.sources(&id, EdgeKind::Supersedes, None)?;
            edges.insert(id, (older.clone(), newer.clone()));
            for next in older.into_iter().chain(newer) {
                if ids.insert(next) {
                    if ids.len() > MAX_MEMORY_TIMELINE_RECORDS {
                        return Err(Error::IndexOverflow("memory_timeline"));
                    }
                    stack.push(next);
                }
            }
        }

        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let (supersedes, superseded_by) = edges.remove(&id).unwrap_or_default();
            records.push(self.memory_timeline_record(&id, supersedes, superseded_by)?);
        }
        records.sort_unstable_by(memory_timeline_record_cmp);

        Ok(MemoryTimeline {
            anchor: *anchor,
            records,
        })
    }

    fn memory_timeline_record(
        &self,
        id: &EntityId,
        mut supersedes: Vec<EntityId>,
        mut superseded_by: Vec<EntityId>,
    ) -> Result<MemoryTimelineRecord> {
        supersedes.sort_unstable();
        superseded_by.sort_unstable();

        let Some(raw) = self.get_raw(id)? else {
            return Ok(MemoryTimelineRecord {
                id: *id,
                state: MemoryTimelineRecordState::Missing,
                entity_type: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body_bytes: None,
                deletion: None,
                supersedes,
                superseded_by,
            });
        };

        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let body_bytes = raw.len().saturating_sub(ENTITY_METADATA_HEADER_LEN);
        let deletion = if body_bytes == 0 {
            self.entity_deletion_metadata(id, header.learned_at)?
        } else {
            None
        };
        let lifecycle =
            if deletion.is_none() && header.entity_type == ENTITY_TYPE_CLAIM && body_bytes > 0 {
                self.get_claim(id)?.map(|claim| claim.lifecycle)
            } else {
                None
            };
        let state = if deletion.is_some() {
            MemoryTimelineRecordState::Deleted
        } else if lifecycle == Some(ClaimLifecycleStatus::Retracted) {
            MemoryTimelineRecordState::Retracted
        } else if lifecycle == Some(ClaimLifecycleStatus::Superseded) || !superseded_by.is_empty() {
            MemoryTimelineRecordState::Superseded
        } else {
            MemoryTimelineRecordState::Live
        };

        Ok(MemoryTimelineRecord {
            id: *id,
            state,
            entity_type: Some(header.entity_type),
            occurred_start: Some(header.occurred_start),
            occurred_end: Some(header.occurred_end),
            learned_at: Some(header.learned_at),
            body_bytes: Some(body_bytes),
            deletion,
            supersedes,
            superseded_by,
        })
    }

    pub(crate) fn entity_deletion_metadata(
        &self,
        id: &EntityId,
        learned_at: u64,
    ) -> Result<Option<HydratedShortIdDeletion>> {
        let window_label = window_label_from_timestamp(learned_at);
        let pending_key = pending_tombstone_key(&window_label, id);
        let rtxn = self.store.env.read_txn()?;
        if let Some(value) = self.store.sync_state.get(&rtxn, pending_key.as_str())? {
            return Ok(Some(Self::deletion_metadata_from_tombstone_value(
                HydratedShortIdDeletionSource::PendingTombstone,
                &value,
            )));
        }
        drop(rtxn);

        #[cfg(feature = "sync")]
        {
            use crate::sync::loro_support::tombstone_values_for_id;
            use crate::sync::types::WindowKey;

            let window_key = WindowKey::from_timestamp(learned_at);
            match crate::sync::window::load_window_from_state(self, "local", &window_key) {
                Ok(doc) => Ok(
                    Self::select_tombstone_metadata_value(&tombstone_values_for_id(
                        &doc.get_map("tombstones"),
                        id,
                    ))
                    .map(|value| {
                        Self::deletion_metadata_from_tombstone_value(
                            HydratedShortIdDeletionSource::Tombstone,
                            value,
                        )
                    }),
                ),
                Err(Error::WindowNotFound { .. }) => Ok(None),
                Err(error) => Err(error),
            }
        }

        #[cfg(not(feature = "sync"))]
        {
            Ok(None)
        }
    }

    fn deletion_metadata_from_tombstone_value(
        source: HydratedShortIdDeletionSource,
        value: &[u8],
    ) -> HydratedShortIdDeletion {
        let decoded = decode_tombstone_value(value);
        HydratedShortIdDeletion {
            source,
            reason: decoded.reason.map(Self::hydrate_deletion_reason),
            deleted_at: (decoded.deleted_at != 0).then_some(decoded.deleted_at),
            request_id: decoded
                .request_id
                .map(|request_id| Uuid::from_bytes(request_id).to_string()),
            hard: decoded.is_hard(),
        }
    }

    fn hydrate_deletion_reason(
        reason: crate::deletion::TombstoneReason,
    ) -> HydratedShortIdDeletionReason {
        match reason {
            crate::deletion::TombstoneReason::UserDelete => {
                HydratedShortIdDeletionReason::UserDelete
            }
            crate::deletion::TombstoneReason::UserHardDelete => {
                HydratedShortIdDeletionReason::UserHardDelete
            }
            crate::deletion::TombstoneReason::GdprDelete => {
                HydratedShortIdDeletionReason::GdprDelete
            }
            crate::deletion::TombstoneReason::PolicyDelete => {
                HydratedShortIdDeletionReason::PolicyDelete
            }
        }
    }

    #[cfg(feature = "sync")]
    fn select_tombstone_metadata_value(values: &[Vec<u8>]) -> Option<&[u8]> {
        values
            .iter()
            .find(|value| decode_tombstone_value(value).is_hard())
            .or_else(|| values.first())
            .map(Vec::as_slice)
    }
}

impl Store {
    /// Whether deletion metadata exists for `id`, read through the CALLER'S
    /// transaction.
    ///
    /// In-transaction counterpart of [`Vault::entity_deletion_metadata`],
    /// which opens read transactions of its own and therefore cannot answer
    /// for a caller mid-write: `deletion/delete.rs` commits the `pt:` pending
    /// marker in the SAME transaction as the shell scrub, and a fresh reader
    /// sees neither until that transaction commits. Same two sources in the
    /// same order — the `pt:` pending marker, then the published window
    /// tombstone — and the same "no `d:w:` snapshot means no published
    /// tombstone" answer the non-txn reader's `WindowNotFound` arm gives.
    ///
    /// PRESENCE only: liveness never needs the tombstone's reason, timestamp
    /// or request id, so no tombstone value is decoded here.
    pub(crate) fn entity_deletion_present_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        learned_at: u64,
    ) -> Result<bool> {
        let window_label = window_label_from_timestamp(learned_at);
        let pending_key = pending_tombstone_key(&window_label, id);
        if self.sync_state.get(txn, pending_key.as_str())?.is_some() {
            return Ok(true);
        }

        #[cfg(feature = "sync")]
        {
            use crate::sync::loro_support::{
                doc_from_snapshot, import_doc, tombstone_map_contains_id,
            };

            // The window doc is rebuilt from the rows THIS transaction sees
            // (`d:w:` snapshot plus the pending `u:w:` updates applied on top,
            // exactly as `sync::window::load_window_from_state` composes it),
            // so the read stays inside the caller's transaction.
            let snapshot_key = format!("d:w:{window_label}");
            let Some(snapshot) = self.sync_state.get(txn, snapshot_key.as_str())? else {
                return Ok(false);
            };
            let doc = doc_from_snapshot(&snapshot)?;
            let update_prefix = format!("u:w:{window_label}:");
            for entry in self.sync_state.prefix_iter(txn, update_prefix.as_str())? {
                let (_key, update) = entry?;
                import_doc(&doc, &update)?;
            }
            Ok(tombstone_map_contains_id(&doc.get_map("tombstones"), id))
        }

        #[cfg(not(feature = "sync"))]
        {
            Ok(false)
        }
    }
}
