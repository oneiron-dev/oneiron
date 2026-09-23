use super::*;
use crate::sync::transport::decode_document;
use crate::{TimeRange, VaultConfig};

fn seed(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"ledger pointer",
        )
        .unwrap();
}

#[test]
fn document_crash_child() {
    let Some(path) = std::env::var_os("ONEIRON_DOCUMENT_CRASH_PATH") else {
        return;
    };
    let vault = Arc::new(Vault::open(path, VaultConfig::device()).unwrap());
    let id = EntityId::from_bytes([3; 16]).unwrap();
    seed(&vault, id);
    let registry = DocumentRegistry::new(vault);
    let doc = registry.open(id).unwrap();
    doc.edit_text(0, 0, "snapshot").unwrap();
    drop(doc);
    // Reopening checkpoints the snapshot, then one more durable update remains.
    let doc = registry.open(id).unwrap();
    doc.edit_text(8, 0, "+update").unwrap();
    std::process::abort();
}

#[test]
fn recovery_replays_snapshot_then_updates_after_kill_and_evicts_idle_docs() {
    let dir = tempfile::tempdir().unwrap();
    let exit = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sync::documents::tests::document_crash_child",
            "--nocapture",
        ])
        .env("ONEIRON_DOCUMENT_CRASH_PATH", dir.path())
        .status()
        .unwrap();
    assert!(!exit.success());
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let registry = DocumentRegistry::new(vault.clone());
    assert_eq!(registry.resident_count(), 0);
    let id = EntityId::from_bytes([3; 16]).unwrap();
    let doc = registry.open(id).unwrap();
    assert_eq!(doc.text().unwrap(), "snapshot+update");
    let same = registry.open(id).unwrap();
    same.edit_text(15, 0, "!").unwrap();
    assert_eq!(doc.text().unwrap(), "snapshot+update!");
    assert_eq!(registry.resident_count(), 1);
    drop(same);
    drop(doc);
    assert_eq!(registry.resident_count(), 0);
    assert_eq!(
        registry.open(id).unwrap().text().unwrap(),
        "snapshot+update!"
    );
    assert_eq!(vault.get(&id).unwrap().unwrap(), b"ledger pointer");
}

#[test]
fn admission_and_behind_shallow_peer_get_state_never_delta_and_future_edits_converge() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let registry = DocumentRegistry::new(vault.clone());
    let doc = registry.open(id).unwrap();
    doc.edit_text(0, 0, "secret past").unwrap();
    doc.edit_text(0, 11, "visible").unwrap();
    let admission = doc
        .export(
            b"selector-a",
            &VersionVector::default().encode(),
            crate::FederationGrantScope::vault(7),
        )
        .unwrap();
    let frame = decode_document(&admission[1..]).unwrap();
    assert_eq!(frame.kind, document_sub_tags::STATE);
    let peer = LoroDoc::new();
    storage::import_complete(&peer, frame.payload).unwrap();
    assert_eq!(peer.get_text("body").to_string(), "visible");
    let behind = peer.oplog_vv().encode();
    doc.edit_text(7, 0, " after purge").unwrap();
    drop(doc);
    compact(&vault, id, false).unwrap();
    let doc = registry.open(id).unwrap();
    doc.edit_text(19, 0, "!").unwrap();
    // Pin the Loro 1.13.9 trap: an unchecked stale delta returns Ok with pending ops.
    let raw = doc
        .lock()
        .unwrap()
        .export(ExportMode::updates(&storage::decode_vv(&behind).unwrap()))
        .unwrap();
    let status = peer.import(&raw).unwrap();
    assert!(status.pending.is_some());
    assert_ne!(peer.get_text("body").to_string(), doc.text().unwrap());
    let response = doc
        .export(
            b"selector-a",
            &behind,
            crate::FederationGrantScope::vault(7),
        )
        .unwrap();
    let frame = decode_document(&response[1..]).unwrap();
    assert_eq!(frame.kind, document_sub_tags::STATE);
    let peer = LoroDoc::new();
    storage::import_complete(&peer, frame.payload).unwrap();
    assert_eq!(peer.get_text("body").to_string(), doc.text().unwrap());
    let vv = peer.oplog_vv().encode();
    doc.edit_text(20, 0, " next").unwrap();
    let delta = doc
        .export(b"selector-a", &vv, crate::FederationGrantScope::vault(7))
        .unwrap();
    let frame = decode_document(&delta[1..]).unwrap();
    assert_eq!(frame.kind, document_sub_tags::UPDATE);
    storage::import_complete(&peer, frame.payload).unwrap();
    assert_eq!(peer.get_text("body").to_string(), doc.text().unwrap());
}

#[test]
fn offline_document_journal_survives_eviction_and_clears_only_on_covering_ack() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let registry = DocumentRegistry::new(vault);
    let doc = registry.open(id).unwrap();
    doc.edit_text(0, 0, "offline").unwrap();
    drop(doc);
    let doc = registry.open(id).unwrap();
    assert_eq!(doc.pending_frames().unwrap().len(), 1);
    doc.acknowledge(&VersionVector::default().encode()).unwrap();
    assert_eq!(doc.pending_frames().unwrap().len(), 1);
    let peer = LoroDoc::new();
    for frame in doc.pending_frames().unwrap() {
        storage::import_complete(&peer, decode_document(&frame[1..]).unwrap().payload).unwrap();
    }
    doc.acknowledge(&peer.oplog_vv().encode()).unwrap();
    assert!(doc.pending_frames().unwrap().is_empty());
    assert_eq!(peer.get_text("body").to_string(), "offline");
}

#[test]
fn document_sweep_defers_live_editor_then_erases_snapshot_updates_and_journal() {
    use crate::sync::{WindowManager, bridge::Materializer};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let manager = Arc::new(WindowManager::new(
        vault.clone(),
        Arc::new(Materializer::new()),
        "sweep",
    ));
    let doc = manager.documents().open(id).unwrap();
    doc.edit_text(0, 0, "erase-this").unwrap();
    assert!(!vault.compact_document_for_sweep(id, true).unwrap());
    drop(doc);
    assert!(vault.compact_document_for_sweep(id, true).unwrap());
    let doc = manager.documents().open(id).unwrap();
    assert_eq!(doc.text().unwrap(), "");
    assert!(doc.pending_frames().unwrap().is_empty());
}

fn document_grant(vault: &Vault, id: EntityId, grant: crate::federation::FederationGrant) {
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::federation::encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
}

fn turn_band() -> crate::federation::SelectorRange {
    crate::federation::selector_range_of(crate::registry::ENTITY_TYPE_TURN).unwrap()
}

fn peer_update(text: &str) -> Vec<u8> {
    let doc = LoroDoc::new();
    doc.get_text("body").insert(0, text).unwrap();
    doc.commit();
    doc.export(ExportMode::all_updates()).unwrap()
}

fn assert_document_denied(error: Error) {
    assert!(matches!(
        error,
        Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: SyncProtocolValidation::DocumentAdmissionDenied,
        })
    ));
}

#[test]
fn peer_import_rechecks_role_selector_and_grant_in_the_committing_writer() {
    use crate::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
    use crate::sync::{SyncSelector, SyncSelectorWorld};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    seed(&vault, id);
    let facet = EntityId::now();
    vault
        .put_entity(
            &facet,
            crate::registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .unwrap();
    vault
        .put_edge(&id, crate::EdgeKind::FacetOf, &facet, 1.0)
        .unwrap();
    let grant_id = EntityId::now();
    let member = EntityId::now();
    let scope = crate::FederationGrantScope::vault(7);
    let grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    document_grant(&vault, grant_id, grant.clone());
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![turn_band()],
    );
    let registry = DocumentRegistry::new(vault.clone());
    let doc = registry.open(id).unwrap();
    let update = peer_update("accepted");
    doc.import_from_peer(document_sub_tags::UPDATE, &update, scope, &selector)
        .unwrap();
    let before = doc.version_vector().unwrap();
    let next = peer_update("forbidden");
    let mut readonly = grant.clone();
    readonly.role = FederationGrantRole::Viewer;
    document_grant(&vault, grant_id, readonly.clone());
    assert_document_denied(
        doc.import_from_peer(document_sub_tags::UPDATE, &next, scope, &selector)
            .unwrap_err(),
    );
    assert_eq!(doc.version_vector().unwrap(), before);
    document_grant(&vault, grant_id, grant);
    // Stage the downgrade INSIDE the import's committing writer. A nested
    // readonly authorization snapshot would still see Member and wrongly pass.
    let raw = vault.get_raw(&grant_id).unwrap().unwrap();
    let mut downgraded = raw[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
    downgraded.extend(crate::federation::encode_federation_grant_body(&readonly).unwrap());
    assert_document_denied(
        doc.import_admitted(document_sub_tags::UPDATE, &next, |txn| {
            vault
                .store
                .entities
                .put(txn, grant_id.as_bytes(), &downgraded)?;
            crate::sync::selector::admit_document_write_in_txn(&vault, txn, id, scope, &selector)
        })
        .unwrap_err(),
    );
    assert_eq!(vault.get_raw(&grant_id).unwrap().unwrap(), raw);
    assert_eq!(doc.version_vector().unwrap(), before);
    let mut wrong_member = selector.clone();
    wrong_member.member_ref = EntityId::now();
    let error = doc
        .import_from_peer(document_sub_tags::UPDATE, &next, scope, &wrong_member)
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: crate::error::SyncSelectorValidation::MemberNotGranted
            },
        })
    ));
    let error = doc
        .import_from_peer(
            document_sub_tags::UPDATE,
            &next,
            crate::FederationGrantScope::vault(8),
            &selector,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: crate::error::SyncSelectorValidation::GrantScopeMismatch
            },
        })
    ));
    let mut narrowed = selector.clone();
    narrowed.bands = vec![crate::federation::SelectorRange::Maintenance];
    assert_document_denied(
        doc.import_from_peer(document_sub_tags::UPDATE, &next, scope, &narrowed)
            .unwrap_err(),
    );
    assert_document_denied(
        doc.import_from_peer(document_sub_tags::STATE, &next, scope, &selector)
            .unwrap_err(),
    );
    vault.delete_entity(&grant_id).unwrap();
    let error = doc
        .import_from_peer(document_sub_tags::UPDATE, &next, scope, &selector)
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: crate::error::SyncSelectorValidation::GrantNotFound
            },
        })
    ));
    assert_eq!(doc.text().unwrap(), "accepted");
    assert_eq!(doc.version_vector().unwrap(), before);
    // Trusted embedding/authority import remains a separate, privileged door.
    doc.import(document_sub_tags::UPDATE, &next).unwrap();
    assert!(doc.text().unwrap().contains("forbidden"));
}

#[test]
fn peer_import_live_facet_scope_cannot_be_preserved_by_an_old_subscription() {
    use crate::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
    use crate::sync::{SyncSelector, SyncSelectorWorld};
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let id = EntityId::now();
    let neighbor = EntityId::now();
    seed(&vault, id);
    seed(&vault, neighbor);
    let facet = EntityId::now();
    let other = EntityId::now();
    for f in [facet, other] {
        vault
            .put_entity(
                &f,
                crate::registry::ENTITY_TYPE_FACET,
                TimeRange { start: 1, end: 1 },
                1,
                b"facet",
            )
            .unwrap();
    }
    vault
        .put_edge(&neighbor, crate::EdgeKind::FacetOf, &facet, 1.0)
        .unwrap();
    vault
        .put_edge(&neighbor, crate::EdgeKind::Mentions, &id, 1.0)
        .unwrap();
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let scope = crate::FederationGrantScope::vault(7);
    document_grant(
        &vault,
        grant_id,
        FederationGrant::new(
            scope,
            member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
    );
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![turn_band()],
    );
    let registry = DocumentRegistry::new(vault.clone());
    let doc = registry.open(id).unwrap();
    doc.import_from_peer(
        document_sub_tags::UPDATE,
        &peer_update("one hop"),
        scope,
        &selector,
    )
    .unwrap();
    let before = doc.version_vector().unwrap();
    // A candidate's unselected stamp beats a neighboring seed, just as on export.
    vault
        .put_edge(&id, crate::EdgeKind::FacetOf, &other, 1.0)
        .unwrap();
    assert_document_denied(
        doc.import_from_peer(
            document_sub_tags::UPDATE,
            &peer_update("hidden"),
            scope,
            &selector,
        )
        .unwrap_err(),
    );
    vault
        .delete_edge(&id, crate::EdgeKind::FacetOf, &other)
        .unwrap();
    // Removing the sole seed cannot leave the remembered admission live.
    vault
        .delete_edge(&neighbor, crate::EdgeKind::FacetOf, &facet)
        .unwrap();
    assert_document_denied(
        doc.import_from_peer(
            document_sub_tags::UPDATE,
            &peer_update("no seed"),
            scope,
            &selector,
        )
        .unwrap_err(),
    );
    assert_eq!(doc.text().unwrap(), "one hop");
    assert_eq!(doc.version_vector().unwrap(), before);
}
