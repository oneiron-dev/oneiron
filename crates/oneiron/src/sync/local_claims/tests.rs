use std::sync::Arc;

use loro::{LoroDoc, VersionVector};
use rmpv::Value;

use crate::blob_artifact::esign::{
    DocumentKind, EsignAuditActor, EsignDocument, EsignItem, EsignRecipient, RecipientRole,
};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body, selector_range_of,
};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON,
};
use crate::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use crate::sync::loro_support::{
    export_snapshot, import_doc, map_delete, map_get_bytes, map_insert_bytes,
};
use crate::sync::schema::create_window_doc;
use crate::sync::selector::{SyncSelector, SyncSelectorWorld, filtered_window_doc};
use crate::sync::types::WindowKey;
use crate::sync::window::{
    LoadedWindow, export_window_updates_since, history_free_window_required,
    replay_pending_mirrors, reverse_rematerialize,
};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Result, TimeRange, Vault, VaultConfig};

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    key: WindowKey,
    now: u64,
    event: EntityId,
    event_raw: Vec<u8>,
    ordinary: EntityId,
    ordinary_raw: Vec<u8>,
    artifact: EntityId,
}

impl Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        let key = WindowKey::new("2026-03");
        let now = key.start_timestamp().unwrap() + 60;
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        let owner = EntityId::now();
        vault.put_entity(&owner, ENTITY_TYPE_PERSON, occurred, now, b"owner")?;
        let artifact = EntityId::now();
        vault.put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
            occurred,
            now,
        )?;
        vault.append_blob_artifact_version(
            &artifact,
            b"%PDF-1.7\n",
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            occurred,
            now,
        )?;
        // Exercise the real authenticated local writer with sync observers
        // already attached. It must not publish a claim before recovery either.
        let window =
            LoadedWindow::new("local", key.clone(), &vault, &Arc::new(Materializer::new()));
        vault.create_esign_document(
            artifact,
            &EsignDocument {
                schema_version: 1,
                kind: DocumentKind::Document,
                title: "local-only-esign-egress-sentinel".into(),
                sequential: false,
                expires_at: now + 1000,
                items: vec![EsignItem {
                    artifact_ref: artifact.to_hex(),
                    original_version: 1,
                }],
                recipients: vec![EsignRecipient {
                    id: EntityId::now().to_hex(),
                    email: "signer@example.test".into(),
                    name: "Signer".into(),
                    role: RecipientRole::Signer,
                    order: 0,
                    expires_at: now + 1000,
                    principal_ref: None,
                    automated: false,
                }],
                fields: Vec::new(),
                full_trail_appendix: true,
            },
            EsignAuditActor {
                actor: owner.to_hex(),
                ip: None,
                user_agent: None,
            },
            now,
        )?;
        let event = vault
            .claims_for_subject(&artifact)?
            .into_iter()
            .find(|id| vault.get_claim(id).unwrap().unwrap().predicate == "esign.draft")
            .unwrap();
        let event_raw = vault.get_raw(&event)?.unwrap();
        assert!(map_get_bytes(&window.doc.get_map("entities"), &event.to_hex()).is_none());
        assert_eq!(vault.esign_audit(artifact)?.len(), 1);
        let ordinary = EntityId::from_bytes([0xB1; 16])?;
        let mut body = ClaimBody::new(
            "sync.egress_control",
            ClaimSubject::Entity(artifact),
            Value::from("ordinary claim"),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        vault.put_claim(&ordinary, &body, occurred, now)?;
        let ordinary_raw = vault.get_raw(&ordinary)?.unwrap();
        vault.put_edge(&ordinary, EdgeKind::Mentions, &event, 0.5)?;
        Ok(Self {
            _dir: dir,
            vault,
            key,
            now,
            event,
            event_raw,
            ordinary,
            ordinary_raw,
            artifact,
        })
    }

    fn assert_clean(&self, doc: &LoroDoc) {
        let entities = doc.get_map("entities");
        assert_eq!(
            map_get_bytes(&entities, &self.ordinary.to_hex()),
            Some(self.ordinary_raw.clone())
        );
        assert!(map_get_bytes(&entities, &self.event.to_hex()).is_none());
        let edge = format_edge_key(&self.ordinary, EdgeKind::Mentions, &self.event);
        assert!(map_get_bytes(&doc.get_map("edges"), &edge).is_none());
        // The local state machine and durable audit remain present.
        assert_eq!(
            self.vault.get_raw(&self.event).unwrap(),
            Some(self.event_raw.clone())
        );
        assert_eq!(self.vault.esign_audit(self.artifact).unwrap().len(), 1);
    }

    fn contaminate(&self, doc: &LoroDoc) -> Result<Vec<String>> {
        let entities = doc.get_map("entities");
        map_insert_bytes(&entities, &self.ordinary.to_hex(), &self.ordinary_raw)?;
        // A stale ordinary body at a local event's id must not defeat the
        // local identity check. An injected uppercase event alias must also
        // exclude its otherwise ordinary canonical occupant and both edges.
        map_insert_bytes(&entities, &self.event.to_hex(), &self.ordinary_raw)?;
        let injected = EntityId::from_bytes([0xAD; 16])?;
        map_insert_bytes(&entities, &injected.to_hex(), &self.ordinary_raw)?;
        let alias = injected.to_hex().to_ascii_uppercase();
        map_insert_bytes(&entities, &alias, &self.event_raw)?;
        map_insert_bytes(&entities, "malformed-event-key", &self.event_raw)?;
        let malformed = EntityId::from_bytes([0xAC; 16])?.to_hex();
        map_insert_bytes(&entities, &malformed, &[ENTITY_TYPE_CLAIM])?;
        let value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, self.now, None, None)?;
        for id in [self.event, injected] {
            for (src, tgt) in [(self.ordinary, id), (id, self.ordinary)] {
                map_insert_bytes(
                    &doc.get_map("edges"),
                    &format_edge_key(&src, EdgeKind::Mentions, &tgt),
                    &value,
                )?;
            }
        }
        doc.commit();
        Ok(vec![
            self.event.to_hex(),
            injected.to_hex(),
            alias,
            "malformed-event-key".into(),
            malformed,
        ])
    }
}

#[test]
fn esign_event_reverse_mirror_excludes_local_claim_and_incident_edges() -> Result<()> {
    let f = Fixture::new()?;
    let doc = create_window_doc("reverse", &f.key);
    reverse_rematerialize(&f.vault, &doc, &f.key)?;
    f.assert_clean(&doc);

    map_insert_bytes(
        &doc.get_map("entities"),
        &f.event.to_hex().to_ascii_uppercase(),
        &f.event_raw,
    )?;
    doc.commit();
    reverse_rematerialize(&f.vault, &doc, &f.key)?;
    f.assert_clean(&doc);
    assert!(
        map_get_bytes(
            &doc.get_map("entities"),
            &f.event.to_hex().to_ascii_uppercase()
        )
        .is_none()
    );
    assert!(history_free_window_required(&f.vault, &f.key)?);
    Ok(())
}

#[test]
fn esign_event_pending_mirror_excludes_full_and_byte_equal_recovery() -> Result<()> {
    let f = Fixture::new()?;
    let doc = create_window_doc("pending", &f.key);
    let event_marker = format!("pm:{}:{}", f.key, f.event.to_hex());
    let ordinary_marker = format!("pm:{}:{}", f.key, f.ordinary.to_hex());
    for contaminated in [false, true] {
        if contaminated {
            // Byte-equal event residue is excluded BEFORE equality can bless it.
            map_insert_bytes(&doc.get_map("entities"), &f.event.to_hex(), &f.event_raw)?;
            let value = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, f.now, None, None)?;
            map_insert_bytes(
                &doc.get_map("edges"),
                &format_edge_key(&f.ordinary, EdgeKind::Mentions, &f.event),
                &value,
            )?;
            doc.commit();
        }
        f.vault.sync_state_put(&event_marker, &[1])?;
        f.vault.sync_state_put(&ordinary_marker, &[1])?;
        replay_pending_mirrors(&f.vault, &doc, &f.key)?;
        f.assert_clean(&doc);
        assert!(f.vault.sync_state_get(&event_marker)?.is_none());
        assert!(f.vault.sync_state_get(&ordinary_marker)?.is_none());
    }
    assert!(history_free_window_required(&f.vault, &f.key)?);
    Ok(())
}

#[test]
fn esign_event_raw_exports_scrub_aliases_stale_bodies_and_history() -> Result<()> {
    for export_kind in 0..3 {
        let f = Fixture::new()?;
        let doc = create_window_doc("raw", &f.key);
        let forbidden = f.contaminate(&doc)?;
        if export_kind == 1 {
            // An edge-only local event must also be withheld when its entity
            // carrier belongs to another window or was already removed.
            map_delete(&doc.get_map("entities"), &f.event.to_hex())?;
            doc.commit();
        }
        let dirty_frontiers = doc.oplog_frontiers();
        let bytes = match export_kind {
            0 => export_window_updates_since(
                &f.vault,
                &f.key,
                &doc,
                &VersionVector::default().encode(),
            )?,
            1 => crate::sync::server_state::persist_window_snapshot(&f.vault, &f.key, &doc)?,
            _ => {
                // Live persistence must scrub AFTER it merges the on-disk
                // snapshot, rather than trusting the previously clean cache.
                f.vault
                    .sync_state_put(&format!("d:w:{}", f.key), &export_snapshot(&doc)?)?;
                let window = LoadedWindow::new(
                    "persist",
                    f.key.clone(),
                    &f.vault,
                    &Arc::new(Materializer::new()),
                );
                window.persist_state(&f.vault)?
            }
        };
        let peer = create_window_doc("peer", &f.key);
        import_doc(&peer, &bytes)?;
        f.assert_clean(&peer);
        for key in forbidden {
            assert!(map_get_bytes(&peer.get_map("entities"), &key).is_none());
            if export_kind != 2 {
                assert!(map_get_bytes(&doc.get_map("entities"), &key).is_none());
            }
        }
        assert_eq!(peer.get_map("edges").len(), 0);
        assert!(peer.is_shallow());
        assert!(
            peer.checkout(&dirty_frontiers).is_err(),
            "pre-scrub state must be absent from exported history"
        );
        assert!(history_free_window_required(&f.vault, &f.key)?);
        // Re-export after the scrub must still exclude the historical body.
        let again = export_window_updates_since(
            &f.vault,
            &f.key,
            &doc,
            &VersionVector::default().encode(),
        )?;
        let reopened = create_window_doc("again", &f.key);
        import_doc(&reopened, &again)?;
        assert!(reopened.checkout(&dirty_frontiers).is_err());
    }
    Ok(())
}

#[test]
fn esign_event_selector_excludes_injected_aliases_and_stale_local_identity() -> Result<()> {
    let f = Fixture::new()?;
    let source = create_window_doc("selector-source", &f.key);
    let forbidden = f.contaminate(&source)?;
    // Every grant reads an empty selector axis as bottom, so the ordinary
    // claim reaches the peer only as the seed of a named facet.
    let facet = EntityId::now();
    f.vault.put_entity(
        &facet,
        ENTITY_TYPE_FACET,
        TimeRange {
            start: f.now,
            end: f.now,
        },
        f.now,
        b"facet",
    )?;
    map_insert_bytes(
        &source.get_map("edges"),
        &format_edge_key(&f.ordinary, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 1.0, f.now, None, None)?,
    )?;
    source.commit();
    let scope = FederationGrantScope::vault(7);
    let member = EntityId::now();
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    f.vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange {
                start: f.now,
                end: f.now,
            },
            f.now,
            &encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![selector_range_of(ENTITY_TYPE_CLAIM).unwrap()],
    );
    let filtered = filtered_window_doc(&f.vault, &source, &f.key, scope, &selector)?;
    let peer = create_window_doc("selector-peer", &f.key);
    import_doc(&peer, &export_snapshot(&filtered)?)?;
    f.assert_clean(&peer);
    for key in forbidden {
        assert!(map_get_bytes(&peer.get_map("entities"), &key).is_none());
        assert!(map_get_bytes(&source.get_map("entities"), &key).is_some());
    }
    assert_eq!(peer.get_map("edges").len(), 0);
    Ok(())
}
