//! Durable, request-bound interlock between tombstone publication and purge.
//!
//! This is local transaction state, not an event or a CRDT carrier. The
//! tombstone request UUID names its owner. No clock/TTL can release a delete
//! whose committed tombstone may still be replayed.

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::identity_topology::IdentityTopologyRejection;
use crate::store::Store;

use super::tombstone::{TombstoneReason, TombstoneValueV2};

const PREFIX: &str = "topology-delete-intent:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopologyDeletePhase {
    /// Reserved before an attempted publication, no destructive act yet.
    Prepared,
    /// The matching CRDT tombstone was durably published.
    Published,
    /// The first destructive transaction committed, possibly awaiting replay.
    Committed,
}

impl TopologyDeletePhase {
    fn byte(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::Published => 1,
            Self::Committed => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TopologyDeleteIntent {
    pub(crate) phase: TopologyDeletePhase,
    pub(crate) request_id: [u8; 16],
    pub(crate) reason: TombstoneReason,
    pub(crate) deleted_at: u64,
    pub(crate) window_ts: u64,
}

fn key(entity: &EntityId) -> String {
    format!("{PREFIX}{}", entity.to_hex())
}

fn conflict(entity: &EntityId) -> Error {
    Error::Sync(SyncError::IdentityTopologyRejected(
        IdentityTopologyRejection::ActiveMergeParticipantDeletion { entity: *entity },
    ))
}

/// Read the reservation in the caller's snapshot. A topology/batch writer
/// must call this under its own write transaction before admitting the entity.
pub(crate) fn topology_delete_reservation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<TopologyDeleteIntent>> {
    let Some(raw) = store.sync_state.get(txn, &key(entity))? else {
        return Ok(None);
    };
    if raw.len() != 34 {
        return Err(Error::CorruptedIndex("topology delete intent"));
    }
    let phase = match raw[0] {
        0 => TopologyDeletePhase::Prepared,
        1 => TopologyDeletePhase::Published,
        2 => TopologyDeletePhase::Committed,
        _ => return Err(Error::CorruptedIndex("topology delete intent")),
    };
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&raw[1..17]);
    let reason = TombstoneReason::from_wire_byte(raw[17])
        .ok_or(Error::CorruptedIndex("topology delete intent reason"))?;
    let deleted_at = u64::from_le_bytes(
        raw[18..26]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("topology delete intent time"))?,
    );
    let window_ts = u64::from_le_bytes(
        raw[26..34]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("topology delete intent window"))?,
    );
    Ok(Some(TopologyDeleteIntent {
        phase,
        request_id,
        reason,
        deleted_at,
        window_ts,
    }))
}

/// Source eligibility must be checked BEFORE calling this under the same
/// writer. A retry can advance its own phase, but cannot replace a different
/// request's reservation or move a committed request backwards.
pub(super) fn reserve_topology_delete_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    value: &TombstoneValueV2,
    window_ts: u64,
    phase: TopologyDeletePhase,
) -> Result<()> {
    if let Some(existing) = topology_delete_reservation_in_txn(store, txn, entity)? {
        if existing.request_id != value.request_id
            || existing.reason != value.reason
            || existing.deleted_at != value.deleted_at
            || existing.window_ts != window_ts
        {
            return Err(conflict(entity));
        }
        if existing.phase.byte() >= phase.byte() {
            return Ok(());
        }
    }
    let mut raw = [0; 34];
    raw[0] = phase.byte();
    raw[1..17].copy_from_slice(&value.request_id);
    raw[17] = value.reason.wire_byte();
    raw[18..26].copy_from_slice(&value.deleted_at.to_le_bytes());
    raw[26..34].copy_from_slice(&window_ts.to_le_bytes());
    store.sync_state.put(txn, &key(entity), &raw)?;
    Ok(())
}

#[cfg(feature = "sync")]
pub(super) fn owns_topology_delete_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    request_id: &[u8; 16],
) -> Result<bool> {
    Ok(topology_delete_reservation_in_txn(store, txn, entity)?
        .is_some_and(|intent| intent.request_id == *request_id))
}

/// Only an already published (or destructively committed) matching request
/// may skip a later source-role redecision. A merely Prepared request has not
/// crossed a linearization point.
pub(super) fn settled_topology_delete_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    request_id: &[u8; 16],
) -> Result<bool> {
    Ok(
        crate::deletion::topology_delete_reservation_in_txn(store, txn, entity)?.is_some_and(
            |intent| {
                intent.request_id == *request_id && intent.phase != TopologyDeletePhase::Prepared
            },
        ),
    )
}

pub(super) fn guard_topology_delete_request_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    request_id: Option<&[u8; 16]>,
) -> Result<()> {
    if let Some(intent) = topology_delete_reservation_in_txn(store, txn, entity)?
        && request_id.is_none_or(|id| *id != intent.request_id)
    {
        return Err(conflict(entity));
    }
    Ok(())
}

/// Clear only THIS request and, optionally, only its still-uncommitted
/// preparation. Pre-publication errors must never withdraw a settled intent.
pub(super) fn clear_own_topology_delete_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    request_id: &[u8; 16],
    prepared_only: bool,
) -> Result<bool> {
    if let Some(intent) = topology_delete_reservation_in_txn(store, txn, entity)?
        && intent.request_id == *request_id
        && (!prepared_only || intent.phase == TopologyDeletePhase::Prepared)
    {
        return store.sync_state.delete(txn, &key(entity));
    }
    Ok(false)
}

/// Called while retiring a replayed `pt:` row in the SAME window-persistence
/// transaction. Hard erasure may still be between publication/soft scrub and
/// purge: only a matching permanent `dt:` marker proves local completion.
/// No other request or a merely Prepared reservation can be released here.
#[cfg(any(feature = "sync", test))]
pub(crate) fn complete_replayed_topology_delete_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    request_id: &[u8; 16],
    is_hard: bool,
) -> Result<bool> {
    let Some(intent) = topology_delete_reservation_in_txn(store, txn, entity)? else {
        return Ok(false);
    };
    if intent.request_id != *request_id || intent.phase == TopologyDeletePhase::Prepared {
        return Ok(false);
    }
    if is_hard {
        let Some(marker) = store
            .sync_state
            .get(txn, &super::tombstone::local_hard_delete_key(entity))?
        else {
            return Ok(false);
        };
        if super::tombstone::decode_tombstone_value(&marker).request_id != Some(*request_id) {
            return Ok(false);
        }
    }
    store.sync_state.delete(txn, &key(entity))
}

/// Recover an interrupted deletion before a Vault handle becomes observable.
/// Prepared with no published/propagation witness can be withdrawn. A
/// persisted matching tombstone (or committed `pt:` intent) is completed under
/// the caller's LMDB writer using the same reason-aware replay eraser. No
/// timeout or guessed-owner cleanup is allowed; ambiguous evidence fails
/// open rather than releasing an interlock a peer might already obey.
pub(crate) fn recover_topology_delete_intents_on_open(vault: &crate::Vault) -> Result<()> {
    let mut intents = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault.store.sync_state.prefix_iter(&rtxn, PREFIX)? {
            let (name, _) = row?;
            let hex = name
                .strip_prefix(PREFIX)
                .ok_or(Error::CorruptedIndex("topology delete intent key"))?;
            let entity = EntityId::from_hex(hex)
                .map_err(|_| Error::CorruptedIndex("topology delete intent key"))?;
            let intent = topology_delete_reservation_in_txn(&vault.store, &rtxn, &entity)?
                .ok_or(Error::CorruptedIndex("topology delete intent index"))?;
            intents.push((entity, intent));
        }
    }
    for (entity, intent) in intents {
        let candidate = {
            let txn = vault.store.env.read_txn()?;
            matching_recovery_tombstone_in_txn(&vault.store, &txn, &entity, intent)?
        };
        let Some(raw) = candidate else {
            if intent.phase != TopologyDeletePhase::Prepared {
                // Published/Committed without recoverable bytes is a failed
                // recovery, not permission to accept a fresh topology write.
                return Err(Error::CorruptedIndex("topology delete recovery witness"));
            }
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.discard_pending_deletion_gate_decision_in_txn(
                &mut wtxn,
                crate::store::GateDecisionId::from_bytes(intent.request_id),
                entity.as_bytes(),
                intent.reason.wire_byte(),
            )?;
            clear_own_topology_delete_in_txn(
                &vault.store,
                &mut wtxn,
                &entity,
                &intent.request_id,
                true,
            )?;
            wtxn.commit()?;
            continue;
        };
        let mut wtxn = vault.store.env.write_txn()?;
        // A crash after d:w: persistence cannot ordinarily leave Prepared,
        // because phase advances in the same publish commit. Handle it
        // defensively without re-deciding already published eligibility.
        if intent.phase == TopologyDeletePhase::Prepared {
            reserve_topology_delete_in_txn(
                &vault.store,
                &mut wtxn,
                &entity,
                &TombstoneValueV2 {
                    reason: intent.reason,
                    deleted_at: intent.deleted_at,
                    request_id: intent.request_id,
                },
                intent.window_ts,
                TopologyDeletePhase::Published,
            )?;
        }
        vault.apply_replayed_tombstone_in_txn(&mut wtxn, &entity, &raw)?;
        wtxn.commit()?;
    }
    Ok(())
}

fn matching_recovery_tombstone_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    intent: TopologyDeleteIntent,
) -> Result<Option<Vec<u8>>> {
    let mut matched = None;
    let mut observe = |raw: &[u8]| -> Result<()> {
        let decoded = super::tombstone::decode_tombstone_value(raw);
        if decoded.request_id != Some(intent.request_id) {
            return Ok(());
        }
        if decoded.reason != Some(intent.reason) || decoded.deleted_at != intent.deleted_at {
            return Err(Error::CorruptedIndex("topology delete recovery request"));
        }
        if matched.as_deref().is_some_and(|old| old != raw) {
            return Err(Error::CorruptedIndex("topology delete recovery conflict"));
        }
        matched = Some(raw.to_vec());
        Ok(())
    };
    // cfg-off first destructive commit carries a pt: marker until sync can
    // publish it. This is a REAL deletion witness, unlike Prepared alone.
    for row in store
        .sync_state
        .prefix_iter(txn, super::tombstone::PENDING_TOMBSTONE_PREFIX)?
    {
        let (name, raw) = row?;
        if name.ends_with(&format!(":{}", entity.to_hex())) {
            observe(&raw)?;
        }
    }
    #[cfg(feature = "sync")]
    {
        use crate::sync::loro_support::{doc_from_snapshot, import_doc, tombstone_values_for_id};
        for row in store.sync_state.prefix_iter(txn, "d:w:")? {
            let (name, snapshot) = row?;
            let Some(label) = name.strip_prefix("d:w:") else {
                continue;
            };
            let doc = doc_from_snapshot(&snapshot)?;
            for update in store
                .sync_state
                .prefix_iter(txn, &format!("u:w:{label}:"))?
            {
                let (_, bytes) = update?;
                import_doc(&doc, &bytes)?;
            }
            for value in tombstone_values_for_id(&doc.get_map("tombstones"), entity) {
                observe(&value)?;
            }
        }
    }
    // A completed hard purge may have retired pt:, yet a crash before the
    // reservation clear left the permanent dt: witness for the same request.
    if intent.reason.is_hard()
        && let Some(raw) = store
            .sync_state
            .get(txn, &super::tombstone::local_hard_delete_key(entity))?
    {
        observe(&raw)?;
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vault, VaultConfig};
    fn tombstone(request_id: [u8; 16]) -> TombstoneValueV2 {
        TombstoneValueV2 {
            reason: TombstoneReason::UserHardDelete,
            deleted_at: 1_772_000_000,
            request_id,
        }
    }

    #[test]
    fn reservation_is_request_bound_and_visible_to_store_only_writer() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let entity = EntityId::from_hex("11111111111111111111111111111111").unwrap();
        let first = [1; 16];
        let other = [2; 16];
        {
            let mut txn = vault.store.env.write_txn().unwrap();
            reserve_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &tombstone(first),
                1_772_000_000,
                TopologyDeletePhase::Prepared,
            )
            .unwrap();
            txn.commit().unwrap();
        }
        let read = vault.store.env.read_txn().unwrap();
        assert_eq!(
            topology_delete_reservation_in_txn(&vault.store, &read, &entity).unwrap(),
            Some(TopologyDeleteIntent {
                phase: TopologyDeletePhase::Prepared,
                request_id: first,
                reason: TombstoneReason::UserHardDelete,
                deleted_at: 1_772_000_000,
                window_ts: 1_772_000_000,
            }),
        );
        drop(read);
        {
            let mut txn = vault.store.env.write_txn().unwrap();
            assert!(
                reserve_topology_delete_in_txn(
                    &vault.store,
                    &mut txn,
                    &entity,
                    &tombstone(other),
                    1_772_000_000,
                    TopologyDeletePhase::Published,
                )
                .is_err()
            );
            assert!(
                !clear_own_topology_delete_in_txn(&vault.store, &mut txn, &entity, &other, false,)
                    .unwrap()
            );
            assert!(!settled_topology_delete_in_txn(&vault.store, &txn, &entity, &first).unwrap());
            reserve_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &tombstone(first),
                1_772_000_000,
                TopologyDeletePhase::Published,
            )
            .unwrap();
            txn.commit().unwrap();
        }
        {
            let mut txn = vault.store.env.write_txn().unwrap();
            assert!(
                !clear_own_topology_delete_in_txn(&vault.store, &mut txn, &entity, &first, true,)
                    .unwrap()
            );
            assert!(settled_topology_delete_in_txn(&vault.store, &txn, &entity, &first).unwrap());
            assert!(!settled_topology_delete_in_txn(&vault.store, &txn, &entity, &other).unwrap());
            assert!(
                clear_own_topology_delete_in_txn(&vault.store, &mut txn, &entity, &first, false,)
                    .unwrap()
            );
            txn.commit().unwrap();
        }
        let read = vault.store.env.read_txn().unwrap();
        assert_eq!(
            topology_delete_reservation_in_txn(&vault.store, &read, &entity).unwrap(),
            None
        );
    }
    #[test]
    fn pending_replay_only_retires_matching_completed_hard_delete() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let entity = EntityId::from_hex("44444444444444444444444444444444").unwrap();
        let request = [4; 16];
        let other = [5; 16];
        let mut txn = vault.store.env.write_txn().unwrap();
        reserve_topology_delete_in_txn(
            &vault.store,
            &mut txn,
            &entity,
            &tombstone(request),
            1_772_000_000,
            TopologyDeletePhase::Published,
        )
        .unwrap();
        assert!(
            !complete_replayed_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &request,
                true
            )
            .unwrap()
        );
        let marker = super::super::tombstone::TombstoneValueV2 {
            reason: super::super::tombstone::TombstoneReason::UserHardDelete,
            deleted_at: 1_772_000_000,
            request_id: other,
        };
        vault
            .store
            .sync_state
            .put(
                &mut txn,
                &super::super::tombstone::local_hard_delete_key(&entity),
                &marker.encode(),
            )
            .unwrap();
        assert!(
            !complete_replayed_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &request,
                true
            )
            .unwrap()
        );
        let matching = super::super::tombstone::TombstoneValueV2 {
            request_id: request,
            ..marker
        };
        vault
            .store
            .sync_state
            .put(
                &mut txn,
                &super::super::tombstone::local_hard_delete_key(&entity),
                &matching.encode(),
            )
            .unwrap();
        assert!(
            !complete_replayed_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &other,
                true
            )
            .unwrap()
        );
        assert!(
            complete_replayed_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &request,
                true
            )
            .unwrap()
        );
        txn.commit().unwrap();
    }

    /// A crash with only Prepared state has not published or erased. Open
    /// withdraws just that request instead of stranding topology forever.
    #[test]
    fn reopen_with_unpublished_preparation_releases_only_its_intent() {
        let dir = tempfile::tempdir().unwrap();
        let entity = EntityId::from_hex("77777777777777777777777777777777").unwrap();
        let value = tombstone([7; 16]);
        {
            let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
            vault
                .put_entity(
                    &entity,
                    crate::registry::ENTITY_TYPE_PERSON,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"still present",
                )
                .unwrap();
            let mut txn = vault.store.env.write_txn().unwrap();
            reserve_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &value,
                1_772_000_000,
                TopologyDeletePhase::Prepared,
            )
            .unwrap();
            txn.commit().unwrap();
        }
        let reopened = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        assert!(reopened.get_raw(&entity).unwrap().is_some());
        let txn = reopened.store.env.read_txn().unwrap();
        assert!(
            topology_delete_reservation_in_txn(&reopened.store, &txn, &entity)
                .unwrap()
                .is_none()
        );
    }

    /// Publication and reservation commit together. If the process stops
    /// before purge, reopen applies exactly that persisted CRDT request and
    /// completes the local dt:/receipt rather than re-deciding eligibility.
    #[cfg(feature = "sync")]
    #[test]
    fn reopen_finishes_published_hard_tombstone_before_issuing_handle() {
        use crate::sync::loro_support::export_snapshot;
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::apply_tombstone_to_window_doc;

        let dir = tempfile::tempdir().unwrap();
        let entity = EntityId::from_hex("78787878787878787878787878787878").unwrap();
        let window_ts = 1_772_000_000;
        let value = tombstone([8; 16]);
        {
            let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
            vault
                .put_entity(
                    &entity,
                    crate::registry::ENTITY_TYPE_PERSON,
                    crate::temporal::TimeRange {
                        start: window_ts,
                        end: window_ts,
                    },
                    window_ts,
                    b"must be erased",
                )
                .unwrap();
            let key = WindowKey::from_timestamp(window_ts);
            let doc = create_window_doc("local", &key);
            apply_tombstone_to_window_doc(&doc, &entity, &value.encode()).unwrap();
            doc.commit();
            let snapshot = export_snapshot(&doc).unwrap();
            let mut txn = vault.store.env.write_txn().unwrap();
            reserve_topology_delete_in_txn(
                &vault.store,
                &mut txn,
                &entity,
                &value,
                window_ts,
                TopologyDeletePhase::Published,
            )
            .unwrap();
            vault
                .store
                .sync_state
                .put(&mut txn, &format!("d:w:{key}"), &snapshot)
                .unwrap();
            txn.commit().unwrap();
        }
        let reopened = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        assert!(reopened.get_raw(&entity).unwrap().is_none());
        let txn = reopened.store.env.read_txn().unwrap();
        let marker = reopened
            .store
            .sync_state
            .get(
                &txn,
                &super::super::tombstone::local_hard_delete_key(&entity),
            )
            .unwrap()
            .expect("completed dt marker");
        assert_eq!(
            super::super::tombstone::decode_tombstone_value(&marker).request_id,
            Some(value.request_id)
        );
        assert!(
            topology_delete_reservation_in_txn(&reopened.store, &txn, &entity)
                .unwrap()
                .is_none()
        );
    }

    /// A real tombstone commit must leave a request-specific reservation in
    /// the gap where another writer could otherwise install topology.
    #[cfg(feature = "sync")]
    #[test]
    fn published_delete_reserves_until_its_purge_completes() {
        use std::sync::Arc;
        use std::sync::mpsc::sync_channel;

        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        let entity = EntityId::from_hex("22222222222222222222222222222222").unwrap();
        vault
            .put_entity(
                &entity,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::temporal::TimeRange {
                    start: 1_772_000_000,
                    end: 1_772_000_000,
                },
                1_772_000_000,
                b"delete me",
            )
            .unwrap();
        let (arrived_tx, arrived_rx) = sync_channel(0);
        let (resume_tx, resume_rx) = sync_channel(0);
        vault.test_hooks().install_delete_rendezvous(
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            entity,
            arrived_tx,
            resume_rx,
        );
        std::thread::scope(|scope| {
            let deleter = scope.spawn(|| {
                vault.delete_entity_with_reason(
                    &entity,
                    crate::deletion::DeleteReason::UserHardDelete,
                )
            });
            arrived_rx.recv().unwrap();
            let txn = vault.store.env.read_txn().unwrap();
            let intent = topology_delete_reservation_in_txn(&vault.store, &txn, &entity)
                .unwrap()
                .expect("published delete must reserve the target");
            assert_eq!(intent.phase, TopologyDeletePhase::Published);
            assert!(
                settled_topology_delete_in_txn(&vault.store, &txn, &entity, &intent.request_id,)
                    .unwrap()
            );
            drop(txn);
            // The caller's own writer snapshot sees exactly the same lock.
            let txn = vault.store.env.write_txn().unwrap();
            assert!(
                topology_delete_reservation_in_txn(&vault.store, &txn, &entity)
                    .unwrap()
                    .is_some()
            );
            drop(txn);
            resume_tx.send(()).unwrap();
            assert!(deleter.join().unwrap().unwrap().existed);
            let txn = vault.store.env.read_txn().unwrap();
            assert!(
                topology_delete_reservation_in_txn(&vault.store, &txn, &entity)
                    .unwrap()
                    .is_none()
            );
        });
    }
    #[cfg(not(feature = "sync"))]
    #[test]
    fn failed_first_destructive_commit_rolls_back_reservation_with_scrub() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        let entity = EntityId::from_hex("33333333333333333333333333333333").unwrap();
        vault
            .put_entity(
                &entity,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::temporal::TimeRange {
                    start: 1_772_000_000,
                    end: 1_772_000_000,
                },
                1_772_000_000,
                b"keep me",
            )
            .unwrap();
        crate::deletion::arm_fail_first_txn_pending_tombstone();
        assert!(
            vault
                .delete_entity_with_reason(&entity, crate::deletion::DeleteReason::GdprDelete)
                .is_err()
        );
        let txn = vault.store.env.read_txn().unwrap();
        assert!(
            topology_delete_reservation_in_txn(&vault.store, &txn, &entity)
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .store
                .entities
                .get(&txn, entity.as_bytes())
                .unwrap()
                .is_some_and(|row| row.len() > crate::batch::ENTITY_METADATA_HEADER_LEN)
        );
    }
}
