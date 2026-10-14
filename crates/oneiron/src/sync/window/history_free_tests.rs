//! The stall ticket's invariants over the code's own list of pin causes and replacement steps.
//!
//! S1: a peer behind a window this vault keeps history-free comes level through the export
//! door, by updates it can apply or a replacement it installs, and never receives what the pin
//! withholds. S2: installing a replacement keeps every write the receiving vault made that the
//! peer never saw, and names the ones it cannot keep.

use std::sync::Arc;

use loro::json::{JsonOpContent, MapOp};
use loro::{ExportMode, LoroDoc, LoroValue, VersionVector};

use super::{
    LoadedWindow, ReplacementConflict, WindowExport, export_window_since,
    export_window_updates_since, history_free_window_required, load_window_from_state,
    prepare_replacement,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use crate::sync::bridge::Materializer;
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    (dir, vault)
}

fn blob(entity_type: u8, at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = vec![entity_type];
    for _ in 0..3 {
        blob.extend_from_slice(&at.to_be_bytes());
    }
    blob.extend_from_slice(data);
    blob
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    id
}

/// Writes one row into `doc` by its own commit; returns its key.
fn write_row(doc: &LoroDoc, at: u64, body: &[u8]) -> String {
    let key = EntityId::now().to_hex();
    map_insert_bytes(
        &doc.get_map("entities"),
        &key,
        &blob(ENTITY_TYPE_TURN, at, body),
    )
    .unwrap();
    doc.commit();
    key
}

/// Whether any operation `doc` still holds sets `key` in the entities map.
fn history_sets(doc: &LoroDoc, key: &str) -> bool {
    doc.export_json_updates(&VersionVector::default(), &doc.oplog_vv())
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .any(|op| matches!(&op.content, JsonOpContent::Map(MapOp::Insert { key: set, .. }) if set == key))
}

/// Why a window keeps its history to itself.
#[derive(Clone, Copy, Debug)]
enum PinCause {
    /// This vault erased a row a peer had put back.
    WithdrawnDelete,
    /// An identity attribution names an author whose attribution was redacted.
    RedactedAttribution,
    /// A secret custody record bound to this device.
    Custody,
    /// A diagnostic, which never syncs.
    LocalOnly,
    /// A claim whose predicate no replay door accepts.
    LocalClaim,
    /// A native NOTE refreshed out of the window after its deletion.
    NoteRefresh,
    /// No pin: the window is already shallow, rooted past the peer.
    AlreadyShallow,
}

const PIN_CAUSES: [PinCause; 7] = [
    PinCause::WithdrawnDelete,
    PinCause::RedactedAttribution,
    PinCause::Custody,
    PinCause::LocalOnly,
    PinCause::LocalClaim,
    PinCause::NoteRefresh,
    PinCause::AlreadyShallow,
];

/// A window in `vault` with a shared prefix, two later rows and `cause` applied.
struct Pinned {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    key: WindowKey,
    doc: LoroDoc,
    /// The window's history at the prefix, as a peer holds it.
    prefix: Vec<u8>,
    rows: Vec<String>,
    carrier: Option<String>,
}

fn pinned(cause: PinCause) -> Pinned {
    let (dir, vault) = test_vault();
    let author = person(&vault);
    let actor = WriteActor::new(author, EdgeActorClass::Human);
    let note = matches!(cause, PinCause::NoteRefresh).then(|| {
        vault
            .create_note("research", "private note", actor)
            .unwrap()
    });
    let at = vault.store.clock.now_recorded_at();
    let key = WindowKey::from_timestamp(at);
    let doc = create_window_doc("source", &key);
    let mut rows = vec![write_row(&doc, at, b"shared prefix")];
    let prefix = doc.export(ExportMode::all_updates()).unwrap();
    rows.push(write_row(&doc, at + 1, b"first survivor"));
    rows.push(write_row(&doc, at + 2, b"second survivor"));
    let entities = doc.get_map("entities");
    let mut carrier = Some(EntityId::now().to_hex());
    let id = || EntityId::from_hex(carrier.as_deref().unwrap()).unwrap();
    match cause {
        PinCause::WithdrawnDelete => {
            let erased = id();
            vault
                .put_entity(
                    &erased,
                    ENTITY_TYPE_TURN,
                    TimeRange { start: at, end: at },
                    at,
                    b"erased body",
                )
                .unwrap();
            map_insert_bytes(
                &entities,
                &erased.to_hex(),
                &vault.get_raw(&erased).unwrap().unwrap(),
            )
            .unwrap();
            vault
                .delete_entity_with_reason(&erased, crate::DeleteReason::GdprDelete)
                .unwrap();
        }
        PinCause::RedactedAttribution => {
            let (attribution, bytes) = redacted_attribution(&vault, at);
            carrier = Some(attribution.to_hex());
            map_insert_bytes(&entities, &attribution.to_hex(), &bytes).unwrap();
        }
        PinCause::Custody => {
            let (custody, raw) = device_bound_secret(&vault, at);
            carrier = Some(custody.to_hex());
            map_insert_bytes(&entities, &custody.to_hex(), &raw).unwrap();
        }
        PinCause::LocalOnly => {
            map_insert_bytes(
                &entities,
                &id().to_hex(),
                &blob(ENTITY_TYPE_DIAGNOSTIC, at, b"diag"),
            )
            .unwrap();
        }
        PinCause::LocalClaim => {
            let body = ClaimBody::new(
                "esign.signature",
                ClaimSubject::Entity(author),
                rmpv::Value::from("signed"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .unwrap();
            let claim = blob(
                ENTITY_TYPE_CLAIM,
                at,
                &crate::claim::encode_claim_body(&body).unwrap(),
            );
            map_insert_bytes(&entities, &id().to_hex(), &claim).unwrap();
        }
        PinCause::NoteRefresh => {
            let note = note.unwrap();
            carrier = Some(note.to_hex());
            crate::sync::note::refresh(&vault, &doc, &key).unwrap();
            assert!(
                map_get_bytes(&entities, &note.to_hex()).is_some(),
                "fixture: NOTE mirrored"
            );
            vault
                .delete_entity_with_options(
                    &note,
                    crate::deletion::DeleteEntityOptions { purge: true },
                )
                .unwrap();
        }
        PinCause::AlreadyShallow => carrier = None,
    }
    doc.commit();
    let doc = if matches!(cause, PinCause::AlreadyShallow) {
        LoroDoc::from_snapshot(
            &doc.export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
                .unwrap(),
        )
        .unwrap()
    } else {
        doc
    };
    Pinned {
        _dir: dir,
        vault,
        key,
        doc,
        prefix,
        rows,
        carrier,
    }
}

/// An identity merge's author attribution whose author was then redacted, and its bytes from
/// before the redaction.
fn redacted_attribution(vault: &Vault, at: u64) -> (EntityId, Vec<u8>) {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        StoredIdentityOpAction, SurvivorshipPlan,
    };
    let (author, source, survivor) = (person(vault), person(vault), person(vault));
    let outcome = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![source],
                survivor,
                evidence: IdentityOpEvidence::default(),
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred)
                .with_actor(WriteActor::new(author, EdgeActorClass::Human)),
            at,
        )
        .unwrap();
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("authored merge must apply");
    };
    let carrier = {
        let txn = vault.store.env.read_txn().unwrap();
        let mut found = None;
        for entry in vault
            .store
            .type_index
            .prefix_iter(
                &txn,
                &[crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT],
            )
            .unwrap()
        {
            let (index_key, _) = entry.unwrap();
            let id = crate::vault::entity_id_from_type_index_key(&index_key).unwrap();
            let raw = vault
                .store
                .entities
                .get(&txn, id.as_bytes())
                .unwrap()
                .unwrap();
            let row = crate::identity_topology::decode_identity_topology_event_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .unwrap();
            if matches!(row.action, StoredIdentityOpAction::AuthorAttribution { target, .. } if target == event)
            {
                found = Some((id, raw.to_vec()));
            }
        }
        found.expect("independent author carrier")
    };
    vault
        .with_write_txn(|txn| {
            crate::identity_topology::redact_author_attribution_in_txn(vault, txn, event, at + 1)?;
            Ok(())
        })
        .unwrap();
    carrier
}

/// A secret custody record bound to this device, and its stored bytes.
fn device_bound_secret(vault: &Vault, at: u64) -> (EntityId, Vec<u8>) {
    use crate::secret_custody::{
        CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding,
        SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus,
    };
    let id = vault
        .register_secret(SecretCustodyRecord {
            schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
            name: "fixture-name".to_owned(),
            class: CustodyClass::CustodyDeviceBound,
            device_only: false,
            value_bytes: b"placeholder value".to_vec(),
            status: SecretCustodyStatus::Active,
            registered_at: at,
            rotated_at: None,
            rotation_generation: 0,
            bindings: vec![SecretBinding {
                effector: "door:receive-pack".to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes: vec!["read".to_owned()],
            }],
            manifest_ref: "secrets.toml".to_owned(),
            declared_paths: vec![".secrets/fixture".to_owned()],
            policy_floor_snapshot: SecretCustodyFloor::default(),
        })
        .unwrap();
    let raw = vault
        .get_raw_unsealed(&id)
        .unwrap()
        .expect("custody row present");
    (id, raw)
}

/// S1 done-means, per pin cause: a peer holding only the window's prefix asks with its version
/// vector until it is level, taking each answer the way a peer must (an update it merges, a
/// replacement it installs). Every update must apply without parked changes; the peer must end
/// level, holding every row; and neither its state nor any history it holds may carry what the
/// pin withholds.
#[test]
fn a_peer_behind_a_history_free_window_comes_level_without_what_it_withholds() {
    for cause in PIN_CAUSES {
        let fx = pinned(cause);
        let mut peer = LoroDoc::new();
        peer.import(&fx.prefix).unwrap();
        let mut replaced = false;
        for _ in 0..5 {
            if peer.oplog_vv() == fx.doc.oplog_vv() {
                break;
            }
            match export_window_since(&fx.vault, &fx.key, &fx.doc, &peer.oplog_vv().encode(), None)
                .unwrap()
            {
                WindowExport::Update(update) => {
                    let status = peer.import(&update).unwrap();
                    assert!(
                        status.pending.is_none(),
                        "{cause:?}: an update the peer cannot apply"
                    );
                }
                WindowExport::Replacement(snapshot) => {
                    peer = LoroDoc::from_snapshot(&snapshot).unwrap();
                    replaced = true;
                }
            }
        }
        assert_eq!(
            peer.oplog_vv(),
            fx.doc.oplog_vv(),
            "{cause:?}: the peer never came level"
        );
        assert!(
            replaced,
            "{cause:?}: only a replacement brings this peer level"
        );
        for row in &fx.rows {
            assert!(
                map_get_bytes(&peer.get_map("entities"), row).is_some(),
                "{cause:?}: the peer lacks a row"
            );
        }
        if let Some(carrier) = &fx.carrier {
            assert!(
                peer.get_map("entities").get(carrier).is_none() && !history_sets(&peer, carrier),
                "{cause:?}: the withheld carrier reached the peer"
            );
            assert!(
                history_free_window_required(&fx.vault, &fx.key).unwrap(),
                "{cause:?}: the scrub pinned the window"
            );
        }
        // Level, the door answers with history again.
        assert!(matches!(
            export_window_updates_since(&fx.vault, &fx.key, &fx.doc, &peer.oplog_vv().encode())
                .unwrap(),
            WindowExport::Update(_)
        ));
    }
}

/// What the receiving vault did that the hub never saw.
#[derive(Clone, Copy, Debug)]
enum LocalWork {
    /// Two rows written past the receiver's own root.
    PastRoot,
    /// The same rows, folded into a root the receiver re-cut at its newest operation before it
    /// ever sent them.
    BelowRoot,
    /// An edit of a row the hub also edited, by a writer the receiver has not fully seen, both
    /// below the receiver's root.
    Conflict,
}

/// S2 done-means: a receiver that shares the hub's prefix and then did `LocalWork` installs the
/// hub's replacement through the production seam. Every row the hub holds and every row the
/// receiver wrote must be in the new window and in the receiver's LMDB; an edit it could not keep
/// must come back as a conflict carrying its value; the persisted window must reload as the
/// installed one, and the replaced window's pending updates must be gone.
#[test]
fn a_replacement_keeps_every_write_the_hub_never_saw() {
    for work in [
        LocalWork::PastRoot,
        LocalWork::BelowRoot,
        LocalWork::Conflict,
    ] {
        let (_dir, vault) = test_vault();
        let at = vault.store.clock.now_recorded_at();
        let key = WindowKey::from_timestamp(at);
        let hub = create_window_doc("hub", &key);
        let shared = write_row(&hub, at, b"shared prefix");
        let materializer = Arc::new(Materializer::new());
        let receiver = LoadedWindow::new("receiver", key.clone(), &vault, &materializer);
        receiver
            .doc
            .import(&hub.export(ExportMode::all_updates()).unwrap())
            .unwrap();
        let hub_rows = [
            write_row(&hub, at + 1, b"hub row"),
            write_row(&hub, at + 2, b"hub row two"),
        ];
        let mut local = Vec::new();
        let mut contested = None;
        match work {
            LocalWork::PastRoot | LocalWork::BelowRoot => {
                for n in 0..2 {
                    let id = EntityId::now();
                    vault
                        .put_entity(
                            &id,
                            ENTITY_TYPE_TURN,
                            TimeRange { start: at, end: at },
                            at + 10 + n,
                            b"unsent local row",
                        )
                        .unwrap();
                    map_insert_bytes(
                        &receiver.doc.get_map("entities"),
                        &id.to_hex(),
                        &vault.get_raw(&id).unwrap().unwrap(),
                    )
                    .unwrap();
                    receiver.doc.commit();
                    local.push(id);
                }
            }
            LocalWork::Conflict => {
                let theirs = blob(ENTITY_TYPE_TURN, at + 3, b"hub edit");
                map_insert_bytes(&hub.get_map("entities"), &shared, &theirs).unwrap();
                hub.commit();
                let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                receiver.doc.commit();
                contested = Some((theirs, ours));
            }
        }
        let old = if matches!(work, LocalWork::PastRoot) {
            receiver.doc.fork()
        } else {
            LoroDoc::from_snapshot(
                &receiver
                    .doc
                    .export(ExportMode::shallow_snapshot(
                        &receiver.doc.oplog_frontiers(),
                    ))
                    .unwrap(),
            )
            .unwrap()
        };
        drop(receiver);
        hub.commit();
        let snapshot = hub
            .export(ExportMode::shallow_snapshot(&hub.oplog_frontiers()))
            .unwrap();

        let prepared = prepare_replacement(
            &vault,
            &materializer,
            &key,
            &old,
            &snapshot,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        let entities = prepared.doc.get_map("entities");
        for row in hub_rows.iter().chain([&shared]) {
            assert!(
                entities.get(row).is_some(),
                "{work:?}: a hub row is missing"
            );
        }
        for id in &local {
            assert!(
                map_get_bytes(&entities, &id.to_hex()).is_some(),
                "{work:?}: an unsent local row left the window"
            );
            assert!(
                vault.get_raw(id).unwrap().is_some(),
                "{work:?}: an unsent local row left LMDB"
            );
        }
        match contested {
            Some((theirs, ours)) => {
                assert_eq!(map_get_bytes(&entities, &shared), Some(theirs), "{work:?}");
                assert_eq!(
                    prepared.conflicts,
                    vec![ReplacementConflict {
                        map: "entities".to_owned(),
                        key: shared.clone(),
                        held: Some(LoroValue::Binary(ours.into())),
                    }],
                    "{work:?}: the edit it could not keep is not named"
                );
            }
            None => assert!(
                prepared.conflicts.is_empty(),
                "{work:?}: {:?}",
                prepared.conflicts
            ),
        }
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            crate::sync::window_rows::WINDOW_UPDATE
                .iter_from(&vault.store, &rtxn, format!("{key}:").as_bytes())
                .unwrap()
                .next()
                .is_none(),
            "{work:?}: the replaced window's pending updates survive it"
        );
        drop(rtxn);
        let reloaded = load_window_from_state(&vault, "receiver", &key).unwrap();
        assert_eq!(
            reloaded.oplog_vv(),
            prepared.doc.oplog_vv(),
            "{work:?}: persisted state"
        );
        assert_eq!(
            reloaded.get_deep_value(),
            prepared.doc.get_deep_value(),
            "{work:?}"
        );
    }
}
