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

/// Whether the state at `doc`'s own shallow root holds `key` in any root map: a snapshot carries
/// that state beside the operations past it.
fn root_state_holds(doc: &LoroDoc, key: &str) -> bool {
    if !doc.is_shallow() {
        return false;
    }
    let at_root = doc.fork();
    at_root.checkout(&doc.shallow_since_frontiers()).unwrap();
    let mut held = false;
    for name in ["entities", "note_proposals"] {
        held |= at_root.get_map(name).get(key).is_some();
    }
    held
}

/// Whether any value `doc` holds, in its live state, its root's state or any operation it keeps,
/// contains `marker`.
fn holds_bytes(doc: &LoroDoc, marker: &[u8]) -> bool {
    let contains = |value: &LoroValue| matches!(value, LoroValue::Binary(bytes) if bytes.windows(marker.len()).any(|w| w == marker));
    let in_state = |state: &LoroDoc| {
        let LoroValue::Map(roots) = state.get_deep_value() else {
            return false;
        };
        roots
            .values()
            .any(|root| matches!(root, LoroValue::Map(map) if map.values().any(contains)))
    };
    let at_root = doc.fork();
    if doc.is_shallow() {
        at_root.checkout(&doc.shallow_since_frontiers()).unwrap();
    }
    in_state(doc)
        || in_state(&at_root)
        || doc
            .export_json_updates(&VersionVector::default(), &doc.oplog_vv())
            .changes
            .iter()
            .flat_map(|change| &change.ops)
            .any(|op| matches!(&op.content, JsonOpContent::Map(MapOp::Insert { value, .. }) if contains(value)))
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
    /// A scrub rewrote a value it keeps under its key, as a NOTE proposal's explainer is
    /// redacted in place.
    RewrittenValue,
    /// The window is shallow and its root's state holds a diagnostic a scrub then removed.
    CarrierInRootState,
    /// After a scrub, two concurrent ordinary edits leave the window with two heads, so Loro
    /// roots any snapshot before both and its root state holds the values they overwrote.
    ConcurrentEdits,
}

const PIN_CAUSES: [PinCause; 10] = [
    PinCause::WithdrawnDelete,
    PinCause::RedactedAttribution,
    PinCause::Custody,
    PinCause::LocalOnly,
    PinCause::LocalClaim,
    PinCause::NoteRefresh,
    PinCause::AlreadyShallow,
    PinCause::RewrittenValue,
    PinCause::CarrierInRootState,
    PinCause::ConcurrentEdits,
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
    /// The key of the entity carrier the pin withholds, if any.
    carrier: Option<String>,
    /// Bytes the pin withholds, found nowhere a peer receives.
    marker: Option<&'static [u8]>,
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
    let fresh = EntityId::now();
    let mut carrier = Some(fresh.to_hex());
    let mut marker: Option<&'static [u8]> = None;
    match cause {
        PinCause::WithdrawnDelete => {
            let erased = fresh;
            marker = Some(b"placeholder erased body");
            vault
                .put_entity(
                    &erased,
                    ENTITY_TYPE_TURN,
                    TimeRange { start: at, end: at },
                    at,
                    b"placeholder erased body",
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
            marker = Some(b"placeholder value");
            map_insert_bytes(&entities, &custody.to_hex(), &raw).unwrap();
        }
        PinCause::LocalOnly | PinCause::CarrierInRootState => {
            marker = Some(b"placeholder diagnostic");
            let diagnostic = blob(ENTITY_TYPE_DIAGNOSTIC, at, b"placeholder diagnostic");
            map_insert_bytes(&entities, &fresh.to_hex(), &diagnostic).unwrap();
        }
        PinCause::LocalClaim => {
            let body = ClaimBody::new(
                "esign.signature",
                ClaimSubject::Entity(author),
                rmpv::Value::from("placeholder signature"),
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
            map_insert_bytes(&entities, &fresh.to_hex(), &claim).unwrap();
            marker = Some(b"placeholder signature");
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
        PinCause::ConcurrentEdits => {
            marker = Some(b"placeholder diagnostic");
            let diagnostic = blob(ENTITY_TYPE_DIAGNOSTIC, at, b"placeholder diagnostic");
            map_insert_bytes(&entities, &fresh.to_hex(), &diagnostic).unwrap();
            doc.commit();
            assert!(
                super::egress::scrub_local_only_carriers(&vault, &key, &doc).unwrap(),
                "fixture: the diagnostic scrubbed"
            );
            doc.commit();
            let branch = doc.fork();
            let theirs = blob(ENTITY_TYPE_TURN, at + 1, b"first survivor, edited");
            map_insert_bytes(&branch.get_map("entities"), &rows[1], &theirs).unwrap();
            branch.commit();
            let ours = blob(ENTITY_TYPE_TURN, at + 2, b"second survivor, edited");
            map_insert_bytes(&entities, &rows[2], &ours).unwrap();
            doc.commit();
            doc.import(&branch.export(ExportMode::all_updates()).unwrap())
                .unwrap();
            assert_eq!(doc.oplog_frontiers().len(), 2, "fixture: two heads");
        }
        PinCause::AlreadyShallow => carrier = None,
        PinCause::RewrittenValue => {
            // The key stays, so only the rewritten bytes are withheld.
            carrier = None;
            marker = Some(b"placeholder private explainer");
            let proposals = doc.get_map("note_proposals");
            let proposal = fresh.to_hex();
            map_insert_bytes(&proposals, &proposal, b"placeholder private explainer").unwrap();
            doc.commit();
            map_insert_bytes(&proposals, &proposal, b"redacted").unwrap();
            crate::sync::window::require_history_free_window(&vault, &key).unwrap();
        }
    }
    doc.commit();
    let doc = if matches!(
        cause,
        PinCause::AlreadyShallow | PinCause::CarrierInRootState
    ) {
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
        marker,
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
        let mut received = Vec::new();
        for _ in 0..5 {
            if peer.oplog_vv() == fx.doc.oplog_vv() {
                break;
            }
            match export_window_since(&fx.vault, &fx.key, &fx.doc, &peer.oplog_vv().encode(), None)
                .unwrap()
            {
                WindowExport::Update(update) => {
                    let status = peer.import(&update).unwrap();
                    received.push(update);
                    assert!(
                        status.pending.is_none(),
                        "{cause:?}: an update the peer cannot apply"
                    );
                }
                WindowExport::Replacement(snapshot) => {
                    peer = LoroDoc::from_snapshot(&snapshot).unwrap();
                    received.push(snapshot);
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
                peer.get_map("entities").get(carrier).is_none()
                    && !history_sets(&peer, carrier)
                    && !root_state_holds(&peer, carrier),
                "{cause:?}: the withheld carrier reached the peer"
            );
        }
        if let Some(marker) = fx.marker {
            assert!(
                !holds_bytes(&peer, marker)
                    && !received
                        .iter()
                        .any(|bytes| bytes.windows(marker.len()).any(|window| window == marker)),
                "{cause:?}: withheld bytes reached the peer"
            );
        }
        if !matches!(cause, PinCause::AlreadyShallow) {
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

/// S1 done-means for a value the check must let through: a world window keeps a user-deleted
/// claim as its exact header-only shell beside its world witness, a carrier no claim door
/// decodes. Pinned for an unrelated reason, the window must still bring a peer behind it level,
/// shell and witness included, and the claim's deleted body must reach the peer nowhere.
#[test]
fn a_pinned_world_window_keeping_a_deleted_claim_shell_still_serves_a_peer_behind_it() {
    let (_dir, vault) = test_vault();
    let world = EntityId::now();
    let person = EntityId::now();
    let claim = EntityId::now();
    let key = WindowKey::for_world(1_771_027_200, world);
    let at = key.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault
        .put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            occurred,
            at,
            b"world",
        )
        .unwrap();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, occurred, at, b"person")
        .unwrap();
    let mut body = ClaimBody::new(
        "test.retained_shell",
        ClaimSubject::Entity(person),
        rmpv::Value::from("placeholder deleted body"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    vault.put_claim(&claim, &body, occurred, at).unwrap();
    vault
        .batch()
        .edge(&claim, crate::EdgeKind::About, &person, 1.0)
        .commit()
        .unwrap();
    let manager = Arc::new(crate::sync::WindowManager::new(
        vault.clone(),
        Arc::new(Materializer::new()),
        "test",
    ));
    let window = manager.open_window(&key).unwrap();
    let mut peer = LoroDoc::new();
    peer.import(&window.doc.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    vault
        .delete_entity_with_reason(&claim, crate::DeleteReason::UserDelete)
        .unwrap();
    crate::sync::window::require_history_free_window(&vault, &key).unwrap();
    write_row(&window.doc, at + 1, b"row after the delete");

    let marker = b"placeholder deleted body";
    let mut received = Vec::new();
    for _ in 0..5 {
        if peer.oplog_vv() == window.doc.oplog_vv() {
            break;
        }
        match export_window_since(&vault, &key, &window.doc, &peer.oplog_vv().encode(), None)
            .expect("a pinned window keeping a retained shell is served")
        {
            WindowExport::Update(update) => {
                let status = peer.import(&update).unwrap();
                assert!(status.pending.is_none(), "an update the peer cannot apply");
                received.push(update);
            }
            WindowExport::Replacement(snapshot) => {
                peer = LoroDoc::from_snapshot(&snapshot).unwrap();
                received.push(snapshot);
            }
        }
    }
    assert_eq!(
        peer.oplog_vv(),
        window.doc.oplog_vv(),
        "the peer never came level"
    );
    assert_eq!(
        map_get_bytes(&peer.get_map("entities"), &claim.to_hex()).map(|shell| shell.len()),
        Some(crate::batch::ENTITY_METADATA_HEADER_LEN),
        "the peer lacks the retained shell"
    );
    assert!(
        peer.get_map("retained_claim_worlds")
            .get(&claim.to_hex())
            .is_some(),
        "the peer lacks the shell's world witness"
    );
    assert!(
        !received
            .iter()
            .any(|bytes| bytes.windows(marker.len()).any(|window| window == marker)),
        "the deleted claim's body reached the peer"
    );
}

/// S1 done-means for the device-only flag: a row a device-only world keeps that a window once
/// held, then removed on one of two concurrent branches, stays in the state at the root Loro cuts
/// a snapshot of that window at. Neither the export door nor the last send may let that root out.
#[test]
fn a_device_only_row_rides_in_no_snapshot_root() {
    let (_dir, vault) = test_vault();
    let at = vault.store.clock.now_recorded_at();
    let world = EntityId::now();
    let marker = b"placeholder private world";
    vault
        .put_entity(
            &world,
            crate::registry::ENTITY_TYPE_WORLD,
            TimeRange { start: at, end: at },
            at,
            marker,
        )
        .unwrap();
    let key = WindowKey::from_timestamp(at);
    let doc = create_window_doc("source", &key);
    map_insert_bytes(
        &doc.get_map("entities"),
        &world.to_hex(),
        &vault.get_raw(&world).unwrap().unwrap(),
    )
    .unwrap();
    doc.commit();
    let public = write_row(&doc, at, b"public row");
    let branch = doc.fork();
    crate::sync::loro_support::map_delete(&branch.get_map("entities"), &world.to_hex()).unwrap();
    branch.commit();
    map_insert_bytes(
        &doc.get_map("entities"),
        &public,
        &blob(ENTITY_TYPE_TURN, at + 1, b"public row, edited"),
    )
    .unwrap();
    doc.commit();
    doc.import(&branch.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    assert_eq!(doc.oplog_frontiers().len(), 2, "fixture: two heads");
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .unwrap();
    let carries = |bytes: &[u8]| bytes.windows(marker.len()).any(|window| window == marker);

    match export_window_since(&vault, &key, &doc, &VersionVector::default().encode(), None) {
        Ok(export) => assert!(
            !carries(&export.into_bytes()),
            "the export door let the row out in a snapshot root"
        ),
        Err(crate::error::Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: crate::error::SyncProtocolValidation::HistoryFreeRootUnavailable,
        })) => {}
        Err(other) => panic!("not the typed refusal: {:?}", other.kind()),
    }
    let cut = doc
        .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
        .unwrap();
    assert!(
        carries(&cut),
        "fixture: Loro roots the snapshot before the removal"
    );
    let manager = Arc::new(crate::sync::WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "test",
    ));
    assert_eq!(
        super::device_only::raw_update_verdict(&manager, key.as_str(), &cut),
        super::device_only::UpdateVerdict::Withheld,
        "the last send let the row out in a snapshot root"
    );
}

/// A pinned window whose two heads leave no root the check passes (a NOTE proposal rewritten in
/// place on one branch) still persists, and the state it persists reloads; only an export to a
/// peer behind it is refused, typed.
#[test]
fn a_pinned_window_with_no_clean_root_still_persists() {
    let (_dir, vault) = test_vault();
    let at = vault.store.clock.now_recorded_at();
    let key = WindowKey::from_timestamp(at);
    let doc = create_window_doc("source", &key);
    let prefix_row = write_row(&doc, at, b"shared prefix");
    let peer = LoroDoc::new();
    peer.import(&doc.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    let proposals = doc.get_map("note_proposals");
    let proposal = EntityId::now().to_hex();
    map_insert_bytes(&proposals, &proposal, b"placeholder private explainer").unwrap();
    doc.commit();
    write_row(&doc, at + 1, b"common row");
    let branch = doc.fork();
    map_insert_bytes(&branch.get_map("note_proposals"), &proposal, b"redacted").unwrap();
    branch.commit();
    write_row(&doc, at + 2, b"concurrent row");
    doc.import(&branch.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    assert_eq!(doc.oplog_frontiers().len(), 2, "fixture: two heads");
    crate::sync::window::require_history_free_window(&vault, &key).unwrap();

    let persisted = super::egress::export_scrubbed_window_snapshot(&vault, &key, &doc)
        .expect("a pinned window persists without a clean root");
    let reloaded = LoroDoc::from_snapshot(&persisted).unwrap();
    assert_eq!(reloaded.oplog_vv(), doc.oplog_vv());
    assert!(map_get_bytes(&reloaded.get_map("entities"), &prefix_row).is_some());
    assert!(matches!(
        export_window_since(&vault, &key, &doc, &peer.oplog_vv().encode(), None),
        Err(crate::error::Error::Sync(
            crate::error::SyncError::SyncProtocolError {
                context: crate::error::SyncProtocolValidation::HistoryFreeRootUnavailable,
            }
        ))
    ));
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
    /// An unsent edit that lost to a later hub edit the receiver took in, before the hub edited
    /// the row again: the hub's newest value stands.
    LostToHub,
    /// An unsent edit of a row the hub edited concurrently, where the hub's edit lies below the
    /// replacement's root: no order can be read, so the hub's value stands and the edit is named.
    Concurrent,
    /// The same, with the hub's edit past the replacement's root and the receiver's edit later
    /// in Loro's order: it ends where an ordinary merge would.
    ConcurrentOrdered,
    /// An unsent edit of a row the hub changed and then wrote back byte for byte, later in
    /// Loro's order, below the replacement's root: the value and writer the receiver last saw
    /// are back, but the hub's write is newer, so its value stands and the edit is named.
    ChangeAndRevert,
    /// An unsent edit of a row the hub wrote long ago, ordered after everything the
    /// replacement's root holds: it ends where an ordinary merge would.
    EditAfterRoot,
    /// The same edit, of a row the hub then hard-deleted: delete wins, so the body stays out and
    /// the edit is named.
    HardDeletedByHub,
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
        LocalWork::LostToHub,
        LocalWork::Concurrent,
        LocalWork::ConcurrentOrdered,
        LocalWork::ChangeAndRevert,
        LocalWork::EditAfterRoot,
        LocalWork::HardDeletedByHub,
    ] {
        let (_dir, vault) = test_vault();
        let at = vault.store.clock.now_recorded_at();
        let key = WindowKey::from_timestamp(at);
        let hub = create_window_doc("hub", &key);
        let shared = write_row(&hub, at, b"shared prefix");
        let prefix = hub.oplog_frontiers();
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
        let mut newest = None;
        let mut erased = None;
        match work {
            LocalWork::PastRoot | LocalWork::BelowRoot | LocalWork::ConcurrentOrdered => {
                for n in 0..3 {
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
                if matches!(work, LocalWork::ConcurrentOrdered) {
                    let theirs = blob(ENTITY_TYPE_TURN, at + 3, b"hub edit");
                    map_insert_bytes(&hub.get_map("entities"), &shared, &theirs).unwrap();
                    hub.commit();
                    let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                    map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                    receiver.doc.commit();
                    let merged = hub.fork();
                    merged
                        .import(&receiver.doc.export(ExportMode::all_updates()).unwrap())
                        .unwrap();
                    assert_eq!(
                        map_get_bytes(&merged.get_map("entities"), &shared),
                        Some(ours.clone()),
                        "fixture: an ordinary merge keeps the receiver's edit"
                    );
                    newest = Some(ours);
                }
            }
            LocalWork::ChangeAndRevert => {
                let base = map_get_bytes(&hub.get_map("entities"), &shared).unwrap();
                let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                receiver.doc.commit();
                let temporary = blob(ENTITY_TYPE_TURN, at + 3, b"hub temporary edit");
                map_insert_bytes(&hub.get_map("entities"), &shared, &temporary).unwrap();
                hub.commit();
                map_insert_bytes(&hub.get_map("entities"), &shared, &base).unwrap();
                hub.commit();
                write_row(&hub, at + 5, b"hub row after the revert");
                let merged = hub.fork();
                merged
                    .import(&receiver.doc.export(ExportMode::all_updates()).unwrap())
                    .unwrap();
                assert_eq!(
                    map_get_bytes(&merged.get_map("entities"), &shared),
                    Some(base.clone()),
                    "fixture: an ordinary merge keeps the hub's write-back"
                );
                contested = Some((base, ours));
            }
            LocalWork::HardDeletedByHub => {
                for n in 0..4 {
                    write_row(&receiver.doc, at + 10 + n, b"receiver row");
                }
                let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                receiver.doc.commit();
                let tombstone = crate::deletion::TombstoneValueV2 {
                    reason: crate::deletion::TombstoneReason::UserHardDelete,
                    deleted_at: at + 5,
                    request_id: [0x42; 16],
                }
                .encode();
                map_insert_bytes(&hub.get_map("tombstones"), &shared, &tombstone).unwrap();
                crate::sync::loro_support::map_delete(&hub.get_map("entities"), &shared).unwrap();
                hub.commit();
                erased = Some(ours);
            }
            LocalWork::EditAfterRoot => {
                for n in 0..4 {
                    write_row(&receiver.doc, at + 10 + n, b"receiver row");
                }
                let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                receiver.doc.commit();
                let merged = hub.fork();
                merged
                    .import(&receiver.doc.export(ExportMode::all_updates()).unwrap())
                    .unwrap();
                assert_eq!(
                    map_get_bytes(&merged.get_map("entities"), &shared),
                    Some(ours.clone()),
                    "fixture: an ordinary merge keeps the receiver's edit"
                );
                newest = Some(ours);
            }
            LocalWork::Conflict | LocalWork::Concurrent => {
                let theirs = blob(ENTITY_TYPE_TURN, at + 3, b"hub edit");
                map_insert_bytes(&hub.get_map("entities"), &shared, &theirs).unwrap();
                hub.commit();
                let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                receiver.doc.commit();
                contested = Some((theirs, ours));
            }
            LocalWork::LostToHub => {
                let ours = blob(ENTITY_TYPE_TURN, at + 4, b"receiver edit");
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &ours).unwrap();
                receiver.doc.commit();
                let winner = blob(ENTITY_TYPE_TURN, at + 5, b"hub edit the receiver took in");
                map_insert_bytes(&hub.get_map("entities"), &shared, &winner).unwrap();
                hub.commit();
                receiver
                    .doc
                    .import(
                        &hub.export(ExportMode::updates(&receiver.doc.oplog_vv()))
                            .unwrap(),
                    )
                    .unwrap();
                assert_eq!(
                    map_get_bytes(&receiver.doc.get_map("entities"), &shared),
                    Some(winner),
                    "fixture: the hub's edit wins on the receiver"
                );
                let last = blob(ENTITY_TYPE_TURN, at + 6, b"newest hub edit");
                map_insert_bytes(&hub.get_map("entities"), &shared, &last).unwrap();
                hub.commit();
                newest = Some(last);
            }
        }
        let old = if matches!(
            work,
            LocalWork::PastRoot
                | LocalWork::LostToHub
                | LocalWork::Concurrent
                | LocalWork::ConcurrentOrdered
                | LocalWork::ChangeAndRevert
                | LocalWork::EditAfterRoot
                | LocalWork::HardDeletedByHub
        ) {
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
        let root = if matches!(work, LocalWork::ConcurrentOrdered) {
            prefix
        } else {
            hub.oplog_frontiers()
        };
        let snapshot = hub.export(ExportMode::shallow_snapshot(&root)).unwrap();

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
        let kept = (erased.is_none()).then_some(&shared);
        for row in hub_rows.iter().chain(kept) {
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
        if let Some(ours) = &erased {
            assert!(
                entities.get(&shared).is_none(),
                "{work:?}: a carried write put a hard-deleted body back"
            );
            assert_eq!(
                prepared.conflicts,
                vec![ReplacementConflict {
                    map: "entities".to_owned(),
                    key: shared.clone(),
                    held: Some(LoroValue::Binary(ours.clone().into())),
                }],
                "{work:?}: the edit delete beat is not named"
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
            None if newest.is_some() => {
                assert_eq!(
                    map_get_bytes(&entities, &shared),
                    newest,
                    "{work:?}: a stale value"
                );
                assert!(prepared.conflicts.is_empty(), "{work:?}");
            }
            None if erased.is_some() => {}
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
            crate::sync::loro_support::replicated_deep_value(&reloaded),
            crate::sync::loro_support::replicated_deep_value(&prepared.doc),
            "{work:?}"
        );
    }
}

/// A hub window holding one row, the receiver's live window that took in all of it, and the
/// materializer they share.
fn shared_hub(vault: &Arc<Vault>, at: u64, key: &WindowKey) -> (LoroDoc, String, LoadedWindow) {
    let hub = create_window_doc("hub", key);
    let shared = write_row(&hub, at, b"shared prefix");
    let materializer = Arc::new(Materializer::new());
    let receiver = LoadedWindow::new("receiver", key.clone(), vault, &materializer);
    receiver
        .doc
        .import(&hub.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    (hub, shared, receiver)
}

/// Installs `hub`'s history-free snapshot, rooted at `root`, over the receiver's `old` window.
fn install(
    vault: &Vault,
    key: &WindowKey,
    old: &LoroDoc,
    hub: &LoroDoc,
    root: &loro::Frontiers,
) -> super::PreparedReplacement {
    let snapshot = hub.export(ExportMode::shallow_snapshot(root)).unwrap();
    prepare_replacement(
        vault,
        &Materializer::new(),
        key,
        old,
        &snapshot,
        &std::collections::HashMap::new(),
    )
    .unwrap()
}

/// Bug repro (SOL-S3-006, ASTRA-S3-006): the receiver's unsent soft delete of a row, later in
/// Loro's order than the hub's hard delete of the same row, was carried over it, so the installed
/// window forgot the hard delete. Done-means: delete semantics never weaken, and the soft delete
/// comes back as a conflict.
#[test]
fn a_replacement_never_softens_the_hubs_hard_delete() {
    let (_dir, vault) = test_vault();
    let at = vault.store.clock.now_recorded_at();
    let key = WindowKey::from_timestamp(at);
    let (hub, shared, receiver) = shared_hub(&vault, at, &key);
    let tombstone = |reason| {
        crate::deletion::TombstoneValueV2 {
            reason,
            deleted_at: at + 5,
            request_id: [0x42; 16],
        }
        .encode()
    };
    for n in 0..6 {
        write_row(&receiver.doc, at + 10 + n, b"receiver row");
    }
    let soft = tombstone(crate::deletion::TombstoneReason::UserDelete);
    map_insert_bytes(&receiver.doc.get_map("tombstones"), &shared, &soft).unwrap();
    receiver.doc.commit();
    let hard = tombstone(crate::deletion::TombstoneReason::UserHardDelete);
    map_insert_bytes(&hub.get_map("tombstones"), &shared, &hard).unwrap();
    crate::sync::loro_support::map_delete(&hub.get_map("entities"), &shared).unwrap();
    hub.commit();
    let old = receiver.doc.fork();
    drop(receiver);

    let prepared = install(&vault, &key, &old, &hub, &hub.oplog_frontiers());
    let held = map_get_bytes(&prepared.doc.get_map("tombstones"), &shared)
        .expect("the hub's tombstone is gone");
    assert!(
        crate::deletion::decode_tombstone_value(&held).is_hard(),
        "the hub's hard delete was softened"
    );
    assert!(prepared.doc.get_map("entities").get(&shared).is_none());
    assert!(
        prepared.conflicts.contains(&ReplacementConflict {
            map: "tombstones".to_owned(),
            key: shared,
            held: Some(LoroValue::Binary(soft.to_vec().into())),
        }),
        "the soft delete it could not keep is not named: {:?}",
        prepared.conflicts
    );
}

/// Bug repro (SOL-S3-003, ASTRA-S3-007, ASTRA-S4-001, ASTRA-S5-001): a queued send whose write
/// lost Loro's order to the hub's concurrent edit of the same row was retired with no conflict,
/// where the candidate took it in, where the old window did, and where the old window already
/// held it. Done-means: the value it wrote comes back as a conflict in each case, and a queued
/// write the installed window keeps is none (ASTRA-S5-003).
#[test]
fn a_queued_send_the_hub_overrides_comes_back_as_a_conflict() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Applies {
        Candidate,
        OldWindow,
        AlreadyHeld,
    }
    for applies in [Applies::Candidate, Applies::OldWindow, Applies::AlreadyHeld] {
        for hub_overrides in [true, false] {
            let (_dir, vault) = test_vault();
            let at = vault.store.clock.now_recorded_at();
            let key = WindowKey::from_timestamp(at);
            let (hub, shared, receiver) = shared_hub(&vault, at, &key);
            if applies == Applies::Candidate {
                // History the receiver's window never took in, which the queued send builds on.
                write_row(&hub, at + 1, b"hub row the receiver lacks");
            }
            let built_on = hub.oplog_frontiers();
            let queued = blob(ENTITY_TYPE_TURN, at + 2, b"queued receiver edit");
            let update = if applies == Applies::AlreadyHeld {
                let from = receiver.doc.oplog_vv();
                map_insert_bytes(&receiver.doc.get_map("entities"), &shared, &queued).unwrap();
                receiver.doc.commit();
                receiver.doc.export(ExportMode::updates(&from)).unwrap()
            } else {
                let author = hub.fork();
                map_insert_bytes(&author.get_map("entities"), &shared, &queued).unwrap();
                author.commit();
                author.export(ExportMode::updates(&hub.oplog_vv())).unwrap()
            };
            crate::sync::queue::SyncQueue::new(Arc::clone(&vault))
                .unwrap()
                .push(key.as_str(), &update)
                .unwrap();
            if hub_overrides {
                for n in 0..2 {
                    let theirs = blob(ENTITY_TYPE_TURN, at + 3 + n, b"hub edit");
                    map_insert_bytes(&hub.get_map("entities"), &shared, &theirs).unwrap();
                    hub.commit();
                }
                if applies != Applies::Candidate {
                    receiver
                        .doc
                        .import(&hub.export(ExportMode::all_updates()).unwrap())
                        .unwrap();
                }
            }
            let old = receiver.doc.fork();
            drop(receiver);
            assert_eq!(
                old.fork()
                    .import(&update)
                    .is_ok_and(|status| status.pending.is_none()),
                applies != Applies::Candidate,
                "fixture: where the queued send applies: {applies:?}"
            );
            let root = if applies == Applies::Candidate {
                built_on
            } else {
                hub.oplog_frontiers()
            };

            let prepared = install(&vault, &key, &old, &hub, &root);
            assert_eq!(
                map_get_bytes(&prepared.doc.get_map("entities"), &shared) == Some(queued.clone()),
                !hub_overrides,
                "fixture: {applies:?}: whether the hub's later edit wins Loro's order"
            );
            assert_eq!(
                prepared.conflicts.contains(&ReplacementConflict {
                    map: "entities".to_owned(),
                    key: shared,
                    held: Some(LoroValue::Binary(queued.into())),
                }),
                hub_overrides,
                "{applies:?}, hub overrides: {hub_overrides}: whether the queued edit is named: \
                 {:?}",
                prepared.conflicts
            );
        }
    }
}

/// Bug repro (ASTRA-S4-002): this vault's own hard delete of a row, carried into the candidate,
/// was softened by a queued soft delete the candidate took in later in Loro's order, since only
/// the hub's hard deletes were guarded. Done-means: no hard delete this vault holds softens
/// either, and the soft delete comes back as a conflict.
#[test]
fn a_queued_send_never_softens_this_vaults_hard_delete() {
    let (_dir, vault) = test_vault();
    let at = vault.store.clock.now_recorded_at();
    let key = WindowKey::from_timestamp(at);
    let (hub, shared, receiver) = shared_hub(&vault, at, &key);
    let tombstone = |reason| {
        crate::deletion::TombstoneValueV2 {
            reason,
            deleted_at: at + 5,
            request_id: [0x42; 16],
        }
        .encode()
    };
    // History the receiver's window never took in, which the queued send builds on.
    write_row(&hub, at + 1, b"hub row the receiver lacks");
    let root = hub.oplog_frontiers();
    let author = hub.fork();
    for n in 0..8 {
        write_row(&author, at + 10 + n, b"queued row");
    }
    let soft = tombstone(crate::deletion::TombstoneReason::UserDelete);
    map_insert_bytes(&author.get_map("tombstones"), &shared, &soft).unwrap();
    author.commit();
    let update = author.export(ExportMode::updates(&hub.oplog_vv())).unwrap();
    let hard = tombstone(crate::deletion::TombstoneReason::UserHardDelete);
    map_insert_bytes(&receiver.doc.get_map("tombstones"), &shared, &hard).unwrap();
    crate::sync::loro_support::map_delete(&receiver.doc.get_map("entities"), &shared).unwrap();
    receiver.doc.commit();
    let old = receiver.doc.fork();
    drop(receiver);
    // Queued once the live window is gone: materializing this vault's own hard delete there scrubs
    // the window's outbox (ONE-1135), and the state under test is a queue that outlived it.
    crate::sync::queue::SyncQueue::new(Arc::clone(&vault))
        .unwrap()
        .push(key.as_str(), &update)
        .unwrap();
    assert!(
        old.fork()
            .import(&update)
            .is_ok_and(|status| status.pending.is_some()),
        "fixture: the old window cannot apply the queued send"
    );

    let prepared = install(&vault, &key, &old, &hub, &root);
    let held = map_get_bytes(&prepared.doc.get_map("tombstones"), &shared)
        .expect("this vault's tombstone is gone");
    assert!(
        crate::deletion::decode_tombstone_value(&held).is_hard(),
        "this vault's hard delete was softened"
    );
    assert!(
        prepared.conflicts.contains(&ReplacementConflict {
            map: "tombstones".to_owned(),
            key: shared,
            held: Some(LoroValue::Binary(soft.to_vec().into())),
        }),
        "the soft delete it could not keep is not named: {:?}",
        prepared.conflicts
    );
}

/// Bug repro (SOL-S3-005): a pending-mirror marker a crash left behind put LMDB's value of a row
/// back over the hub's edit of it, which the hub made after seeing that value. Done-means: a
/// pending mirror is judged like any other write of this vault, so the hub's newer edit stands.
#[test]
fn a_pending_mirror_never_overwrites_the_hubs_newer_edit() {
    let (_dir, vault) = test_vault();
    let at = vault.store.clock.now_recorded_at();
    let key = WindowKey::from_timestamp(at);
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            b"mirrored value",
        )
        .unwrap();
    let raw = vault.get_raw(&id).unwrap().unwrap();
    let hub = create_window_doc("hub", &key);
    map_insert_bytes(&hub.get_map("entities"), &id.to_hex(), &raw).unwrap();
    hub.commit();
    let old = create_window_doc("receiver", &key);
    old.import(&hub.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    let newer = blob(ENTITY_TYPE_TURN, at + 1, b"hub newer edit");
    map_insert_bytes(&hub.get_map("entities"), &id.to_hex(), &newer).unwrap();
    hub.commit();
    vault
        .sync_state_put(&format!("pm:{key}:{}", id.to_hex()), &[1])
        .unwrap();

    let prepared = install(&vault, &key, &old, &hub, &hub.oplog_frontiers());
    assert_eq!(
        map_get_bytes(&prepared.doc.get_map("entities"), &id.to_hex()),
        Some(newer),
        "a pending mirror put a superseded value back"
    );
}

/// Bug repro (ASTRA-S4-006): a replacement refused after its pending-mirror replay had already
/// cleared the mirror's marker, while the write it replayed went only into the copy the refusal
/// threw away, so no later open replayed it. Done-means: a refused replacement leaves the marker,
/// and an installed one clears it.
#[test]
fn a_refused_replacement_keeps_its_pending_mirror() {
    for refused in [false, true] {
        let (_dir, vault) = test_vault();
        let at = vault.store.clock.now_recorded_at();
        let key = WindowKey::from_timestamp(at);
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: at, end: at },
                at,
                b"unsent local edit",
            )
            .unwrap();
        let hub = create_window_doc("hub", &key);
        write_row(&hub, at, b"hub row");
        let old = create_window_doc("receiver", &key);
        old.import(&hub.export(ExportMode::all_updates()).unwrap())
            .unwrap();
        if refused {
            // An operation no carry-over reads, which refuses the replacement after the replay.
            old.get_list("unreadable").push(1).unwrap();
            old.commit();
        }
        let marker = format!("pm:{key}:{}", id.to_hex());
        vault.sync_state_put(&marker, &[1]).unwrap();
        let snapshot = hub
            .export(ExportMode::shallow_snapshot(&hub.oplog_frontiers()))
            .unwrap();

        let prepared = prepare_replacement(
            &vault,
            &Materializer::new(),
            &key,
            &old,
            &snapshot,
            &std::collections::HashMap::new(),
        );
        assert_eq!(
            prepared.is_err(),
            refused,
            "fixture: {:?}",
            prepared.as_ref().err()
        );
        assert_eq!(
            vault.sync_state_get(&marker).unwrap().is_some(),
            refused,
            "refused: {refused}: the pending mirror's marker"
        );
    }
}
