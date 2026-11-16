//! Room bodies leave non-owner transports without shared pins, while pin policy stays.
//! No Connect guest door is tested: a room is stamped in the base world at birth and
//! never moves, and a Connect grant never holds the base world, so a guest envelope
//! or guest document never carries a room.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test room_pins_transport_release`
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::Arc;

use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPinPolicy};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{FederationGrantRole, FederationGrantScope, Scope, ScopeAxis};
use oneiron::memory::{ExportOptions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, filtered_window_doc, filtered_window_doc_for_peer,
};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::workspace_roster::{RoomPinPolicySet, RoomPinRequest};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WINDOW: &str = "2026-03";
const LEARNED_AT: u64 = 1_773_532_800;
const SHARED: u64 = 42;

struct Fixture {
    vault: Arc<Vault>,
    owner: EntityId,
    authenticated_owner: AuthenticatedOwner,
    member: EntityId,
    room: EntityId,
    stored_body: Value,
    raw: Vec<u8>,
    // Keep the directory alive until all vault handles have been dropped.
    _directory: tempfile::TempDir,
}

fn open_vault() -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open_owned(directory.path(), VaultConfig::default())?);
    Ok((directory, vault))
}

fn scan_off(vault: &Vault) -> TestResult<AuthenticatedOwner> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let authenticated =
        vault.authenticate_owner(owner, "owen@example.com", true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&authenticated, SecretScanMode::Off, LEARNED_AT)?;
    Ok(authenticated)
}

fn decode_body(bytes: &[u8]) -> TestResult<Value> {
    let mut cursor = Cursor::new(bytes);
    let body = rmpv::decode::read_value(&mut cursor)?;
    assert_eq!(
        cursor.position(),
        bytes.len() as u64,
        "one complete MessagePack body"
    );
    assert!(
        body.as_map().is_some(),
        "the room body is a MessagePack map"
    );
    Ok(body)
}

fn field<'a>(body: &'a Value, name: &str) -> Option<&'a Value> {
    body.as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

fn open_fixture() -> TestResult<Fixture> {
    let (directory, vault) = open_vault()?;
    let authenticated_owner = scan_off(&vault)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let member = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &member,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"yuki",
    )?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(member, "yuki@example.com", now)?,
    )?;
    vault.preclear_contact_disclosure(&proof, "yuki", &[contact], Scope::top())?;
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(member.to_hex()),
        effector: "core:read".into(),
        scope: Scope::top(),
        selectors: None,
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let room = EntityId::now();
    vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![member],
            ..Default::default()
        },
        WriteActor::new(owner, EdgeActorClass::Human),
        LEARNED_AT,
    )?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: member,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: now,
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    let target = EntityId::now();
    // An ordinary room records its member's trunk MESSAGE through witness.
    vault
        .memory(member, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(target.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "yuki".into(),
                parts: None,
                metadata: Some(serde_json::Value::Object(serde_json::Map::new())),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    let pinned = vault
        .memory(member, EdgeActorClass::Human)
        .rooms_pins_pin(&RoomPinRequest { room, target })?;
    assert_eq!(
        pinned.pin.pinned_by, member,
        "the seated PERSON creates the pin"
    );
    assert_eq!(pinned.pin.target, target, "the pin names the room MESSAGE");
    vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_pins_policy_set(&RoomPinPolicySet {
            room,
            policy: RoomPinPolicy::Managers,
        })?;
    let stored = vault.conversation_body(room)?;
    assert!(
        !stored.pins.is_empty(),
        "the stored room has a nonempty pin list before transport"
    );
    assert_eq!(
        stored.pin_policy,
        RoomPinPolicy::Managers,
        "the stored policy is Managers"
    );
    let bytes = vault.get(&room)?.ok_or("stored room body missing")?;
    let stored_body = decode_body(&bytes)?;
    assert!(
        field(&stored_body, "pins").is_some(),
        "the stored map has the pins key"
    );
    assert!(
        field(&stored_body, "pin_policy").is_some(),
        "the stored map has the pin_policy key"
    );
    assert!(
        field(&stored_body, "member_ids").is_some(),
        "the stored map has its membership"
    );
    let raw = vault.get_raw(&room)?.ok_or("stored room row missing")?;
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        bytes.as_slice(),
        "raw row holds the asserted body"
    );
    Ok(Fixture {
        vault,
        owner,
        authenticated_owner,
        member,
        room,
        stored_body,
        raw,
        _directory: directory,
    })
}

fn manager(vault: &Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "owen",
    ))
}

fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn assert_released_room(doc: &LoroDoc, fixture: &Fixture) -> TestResult {
    let raw = map_get_bytes(&doc.get_map("entities"), &fixture.room.to_hex())
        .ok_or("the transport must admit the room row")?;
    assert!(
        raw.len() >= ENTITY_METADATA_HEADER_LEN,
        "the received room includes metadata"
    );
    assert_eq!(
        &raw[..ENTITY_METADATA_HEADER_LEN],
        &fixture.raw[..ENTITY_METADATA_HEADER_LEN],
        "dropping pins preserves the room metadata"
    );
    let body = decode_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    assert!(
        field(&body, "pins").is_none(),
        "the released room has no pins key, not even an empty list"
    );
    assert_eq!(
        field(&body, "pin_policy"),
        field(&fixture.stored_body, "pin_policy"),
        "the released room keeps pin_policy"
    );
    assert_eq!(
        field(&body, "member_ids"),
        field(&fixture.stored_body, "member_ids"),
        "the released room keeps member_ids"
    );
    Ok(())
}

fn assert_stored_room_unchanged(fixture: &Fixture) -> TestResult {
    assert_eq!(
        fixture.vault.get_raw(&fixture.room)?.as_deref(),
        Some(fixture.raw.as_slice()),
        "transport leaves the stored room row byte-exact"
    );
    Ok(())
}

#[test]
fn member_window_room_leaves_without_pins() -> TestResult {
    let fixture = open_fixture()?;
    let issuer = HostSlipIssuer::from_secret(b"room-pins-member")?;
    fixture.vault.ensure_host_root_slip(&issuer)?;
    fixture
        .vault
        .initialize_shared_vault(&fixture.authenticated_owner, SHARED, None, &[], 1)?;
    let grant = stand_member_grant(
        &fixture.vault,
        fixture.member,
        SHARED,
        FederationGrantRole::Member,
    )?;
    let selector = SyncSelector::new(
        grant,
        fixture.member,
        SyncSelectorWorld::Base,
        vec![],
        vec![],
    );
    let manager = manager(&fixture.vault);
    let key = WindowKey::new(WINDOW);
    let window = manager.open_window(&key)?;
    // The own-machine wrapper must retain the exact row, including the pin list.
    let own = filtered_window_doc(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &selector,
    )?;
    assert_eq!(
        map_get_bytes(&own.get_map("entities"), &fixture.room.to_hex()).as_deref(),
        Some(fixture.raw.as_slice()),
        "the own-machine window keeps the pinned room byte-exact"
    );
    let peer = filtered_window_doc_for_peer(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &selector,
        PeerMachine::Unknown,
    )?;
    assert_released_room(&peer, &fixture)?;
    assert_stored_room_unchanged(&fixture)?;
    Ok(())
}

fn json_room_body(bundle: &serde_json::Value, room: EntityId) -> TestResult<&serde_json::Value> {
    let row = bundle["entities"]
        .as_array()
        .ok_or("JSON export entities missing")?
        .iter()
        .find(|row| row["id"].as_str() == Some(room.to_hex().as_str()))
        .ok_or("the JSON export must admit the room")?;
    assert_eq!(
        row["entity_type"],
        serde_json::json!(ENTITY_TYPE_CONVERSATION),
        "the exported JSON row is a CONVERSATION"
    );
    let body = row.get("body").ok_or("JSON room body missing")?;
    assert!(body.is_object(), "the JSON room body is an object");
    Ok(body)
}

#[test]
fn contact_bundle_room_leaves_without_pins() -> TestResult {
    let fixture = open_fixture()?;
    let stored_json = oneiron::serialize::msgpack_value_to_json(&fixture.stored_body);
    let whole: serde_json::Value = serde_json::from_slice(&fixture.vault.export_vault_json()?)?;
    let own_body = json_room_body(&whole, fixture.room)?;
    assert_eq!(
        own_body, &stored_json,
        "the owner's whole-vault JSON keeps the complete stored room body"
    );
    let bundle: serde_json::Value =
        serde_json::from_slice(&fixture.vault.export_entity_bundle_json(&[fixture.room])?)?;
    let body = json_room_body(&bundle, fixture.room)?;
    assert!(
        body.get("pins").is_none(),
        "the contact bundle omits the whole pins key"
    );
    assert_eq!(
        body.get("pin_policy"),
        stored_json.get("pin_policy"),
        "the contact bundle keeps pin_policy"
    );
    assert_eq!(
        body.get("member_ids"),
        stored_json.get("member_ids"),
        "the contact bundle keeps member_ids"
    );
    assert_eq!(
        bundle["manifest"]["secrets_nulled"]["payloads"],
        serde_json::json!(false),
        "dropping room pins does not report nulled credential payloads"
    );
    assert_eq!(
        bundle["manifest"]["secrets_nulled"]["structural_placeholders"],
        serde_json::json!(false),
        "dropping room pins does not report credential placeholders"
    );
    assert_stored_room_unchanged(&fixture)?;
    Ok(())
}

fn archive_room_body(
    vault: &Vault,
    archive: &[u8],
    room: EntityId,
) -> TestResult<oneiron::serialize::ExportValue> {
    let document = vault.read_whole_vault_archive(archive)?;
    let row = document
        .evidence_ledger
        .entities
        .iter()
        .find(|row| row.id == room.to_hex())
        .ok_or("the archive must admit the room")?;
    assert_eq!(
        row.entity_type, ENTITY_TYPE_CONVERSATION,
        "the archive row is a CONVERSATION"
    );
    let oneiron::serialize::ExportBody::MessagePack(body) = &row.body else {
        return Err("the archive room must have a typed MessagePack body".into());
    };
    assert!(
        matches!(body, oneiron::serialize::ExportValue::Map(_)),
        "the archive room body is a typed map"
    );
    Ok(body.clone())
}

fn archive_field<'a>(
    body: &'a oneiron::serialize::ExportValue,
    name: &str,
) -> Option<&'a oneiron::serialize::ExportValue> {
    use oneiron::serialize::ExportValue;
    let ExportValue::Map(fields) = body else {
        return None;
    };
    fields.iter().find_map(|(key, value)| {
        matches!(key, ExportValue::String(key) if key == name).then_some(value)
    })
}

#[test]
fn code_run_export_room_leaves_without_pins() -> TestResult {
    use oneiron::serialize::ExportValue;
    let fixture = open_fixture()?;
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let own_export = owner.export(&ExportOptions {
        in_code_run: false,
        ..ExportOptions::default()
    })?;
    let own = archive_room_body(&fixture.vault, &own_export.archive, fixture.room)?;
    let stored_members = field(&fixture.stored_body, "member_ids")
        .and_then(Value::as_array)
        .ok_or("stored membership array missing")?;
    let expected_members = ExportValue::Array(
        stored_members
            .iter()
            .map(|member| {
                member
                    .as_str()
                    .map(|member| ExportValue::String(member.to_owned()))
                    .ok_or("stored room member must be an id string")
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let expected_policy = ExportValue::String("managers".into());
    assert_eq!(
        archive_field(&own, "member_ids"),
        Some(&expected_members),
        "the owner's archive keeps stored member_ids"
    );
    assert_eq!(
        archive_field(&own, "pin_policy"),
        Some(&expected_policy),
        "the owner's archive keeps pin_policy"
    );
    let Some(ExportValue::Array(pins)) = archive_field(&own, "pins") else {
        return Err("the owner's archive must keep its pins array".into());
    };
    assert_eq!(
        pins.len(),
        1,
        "the owner's archive keeps the one stored pin record"
    );
    let stored_pins = field(&fixture.stored_body, "pins")
        .and_then(Value::as_array)
        .ok_or("stored pins array missing")?;
    for name in ["target", "pinned_by"] {
        let expected = ExportValue::String(
            field(&stored_pins[0], name)
                .and_then(Value::as_str)
                .ok_or("stored pin identity missing")?
                .to_owned(),
        );
        assert_eq!(
            archive_field(&pins[0], name),
            Some(&expected),
            "the owner's archive keeps pin {name}"
        );
    }
    let expected_time = ExportValue::Integer(
        field(&stored_pins[0], "pinned_at")
            .and_then(Value::as_u64)
            .ok_or("stored pin time missing")?
            .to_string(),
    );
    assert_eq!(
        archive_field(&pins[0], "pinned_at"),
        Some(&expected_time),
        "the owner's archive keeps the pin timestamp"
    );
    assert_eq!(
        archive_field(&pins[0], "acting_agent"),
        Some(&ExportValue::Nil),
        "the owner's archive keeps the direct PERSON attribution"
    );
    let code_export = owner.export(&ExportOptions {
        in_code_run: true,
        ..ExportOptions::default()
    })?;
    let code = archive_room_body(&fixture.vault, &code_export.archive, fixture.room)?;
    assert!(
        archive_field(&code, "pins").is_none(),
        "the code-run archive omits the whole pins key"
    );
    assert_eq!(
        archive_field(&code, "pin_policy"),
        Some(&expected_policy),
        "the code-run archive keeps pin_policy"
    );
    assert_eq!(
        archive_field(&code, "member_ids"),
        Some(&expected_members),
        "the code-run archive keeps stored member_ids"
    );
    assert_stored_room_unchanged(&fixture)?;
    Ok(())
}
