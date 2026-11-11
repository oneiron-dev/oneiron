//! Credentials never cross Connect guest envelopes, guest documents or federation
//! windows; the owner's own-machine windows keep the exact stored rows.
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test transport_credential_release`
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};
use oneiron::authority::{HostSlipIssuer, PeerMachine};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationDirectionScope, FederationGrantRole, FederationGrantScope, Scope, ScopeAxis, ScopeId,
    Sensitivity, SensitivityCeiling,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::{Materializer, parse_edge_key};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::selector::{
    GuestDocumentShareRequest, export_guest_document_for_guest, share_guest_document_as_owner,
};
use oneiron::sync::types::WindowKey;
use oneiron::sync::{
    ConnectExportRequest, SyncClient, SyncSelector, SyncSelectorWorld, filtered_window_doc,
    filtered_window_doc_for_peer,
};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeKind, EntityId, Result, TimeRange, Vault, VaultConfig};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

const WINDOW: &str = "2026-03";
const LEARNED_AT: u64 = 1_773_532_800;
const SHARED: u64 = 42;
const FILE_SECRETS: [&[u8]; 2] = [b"residual-file-credential", b"residual-signature"];

fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, Arc::new(vault))
}

fn scan_off(vault: &Vault) -> Result<AuthenticatedOwner> {
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, "owen@example.com", true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, LEARNED_AT)?;
    Ok(owner)
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode fixture");
    bytes
}

fn person_body() -> Vec<u8> {
    let credential = format!("ghp_{}", "a".repeat(36));
    let nested_payload = encode(&Value::Map(vec![(
        Value::from("password"),
        Value::from("nested-secret"),
    )]));
    let byte_map_payload = encode(&Value::Map(vec![(
        Value::from("password"),
        Value::from("byte-map-secret"),
    )]));
    let json_bytes_payload = br#"{"api_key":"json-secret"}"#.to_vec();
    let json_encoded_bytes =
        serde_json::json!({"payload": credential.bytes().collect::<Vec<_>>()}).to_string();
    let json_encoded_map =
        serde_json::json!({"payload": br#"{"password":"array-wrapped-secret"}"#.to_vec()})
            .to_string();
    let bytes = encode(&Value::Map(vec![
        (Value::from("name"), Value::from("owen")),
        (
            Value::from("api_key"),
            Value::from("unrecognizable-but-named-secret"),
        ),
        (
            Value::from("binary"),
            Value::Binary(credential.as_bytes().to_vec()),
        ),
        (
            Value::from("nested_binary"),
            Value::Binary(nested_payload.clone()),
        ),
        (
            Value::from("byte_array"),
            Value::Array(credential.bytes().map(Value::from).collect()),
        ),
        (
            Value::from("json_bytes"),
            Value::Binary(json_bytes_payload.clone()),
        ),
        (
            Value::from("public_binary"),
            Value::Binary(b"inspectable public bytes".to_vec()),
        ),
        (
            Value::from("byte_map"),
            Value::Array(byte_map_payload.iter().copied().map(Value::from).collect()),
        ),
        (
            Value::from("json_encoded_bytes"),
            Value::from(json_encoded_bytes.as_str()),
        ),
        (
            Value::from("json_encoded_map"),
            Value::from(json_encoded_map.as_str()),
        ),
        (Value::from("signature"), Value::Binary(vec![1, 2, 3])),
    ]));
    bytes
}

struct StoredRow {
    id: EntityId,
    body: Vec<u8>,
    raw: Vec<u8>,
}

fn store_row(vault: &Vault, kind: u8, body: Vec<u8>, world: Option<EntityId>) -> Result<StoredRow> {
    let id = EntityId::now();
    let mut batch = vault.batch().put(
        &id,
        kind,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
        &body,
    );
    // An ASSET needs its birth facet in the same writer, or a selector has
    // no stamped position to admit. InWorld alone does not give it one.
    if kind == ENTITY_TYPE_ASSET {
        batch = batch.edge(&id, EdgeKind::FacetOf, &vault.default_facet()?, 1.0);
    }
    if let Some(world) = world {
        batch = batch.edge(&id, EdgeKind::InWorld, &world, 1.0);
    }
    batch.commit()?;
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some(body.as_slice()),
        "scan-Off storage must keep the fixture body byte-exact"
    );
    let raw = vault.get_raw(&id)?.expect("stored metadata and body");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], body.as_slice());
    Ok(StoredRow { id, body, raw })
}

struct FileRows {
    private_script: StoredRow,
    signature_json: StoredRow,
    clean: StoredRow,
}

fn store_files(vault: &Vault, world: Option<EntityId>) -> Result<FileRows> {
    Ok(FileRows {
        // CONS-06 copies of scripts/private.py and signature.json.
        private_script: store_row(
            vault,
            ENTITY_TYPE_ASSET,
            b"api_key = 'residual-file-credential'\n".to_vec(),
            world,
        )?,
        signature_json: store_row(
            vault,
            ENTITY_TYPE_ASSET,
            br#"{"signature":"residual-signature"}"#.to_vec(),
            world,
        )?,
        clean: store_row(
            vault,
            ENTITY_TYPE_ASSET,
            b"Exact reference bytes.\n".to_vec(),
            world,
        )?,
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

fn import_update(update: &[u8]) -> LoroDoc {
    let doc = LoroDoc::new();
    doc.import(update).expect("import the exported Loro update");
    doc
}

fn assert_exact(doc: &LoroDoc, row: &StoredRow) {
    assert_eq!(
        map_get_bytes(&doc.get_map("entities"), &row.id.to_hex()).as_deref(),
        Some(row.raw.as_slice()),
        "the admitted row keeps its metadata and body: {}",
        row.id.to_hex()
    );
}

fn assert_unchanged(vault: &Vault, rows: &[&StoredRow]) -> Result<()> {
    for row in rows {
        assert_eq!(vault.get(&row.id)?.as_deref(), Some(row.body.as_slice()));
        assert_eq!(
            vault.get_raw(&row.id)?.as_deref(),
            Some(row.raw.as_slice()),
            "export must not rewrite the stored row"
        );
    }
    Ok(())
}

fn assert_files_withheld(doc: &LoroDoc, files: &FileRows) {
    let entities = doc.get_map("entities");
    for row in [&files.private_script, &files.signature_json] {
        assert!(
            entities.get(&row.id.to_hex()).is_none(),
            "credential-bearing ASSET is withheld"
        );
        // ASSET_BODY_REFS_MAP is crate-private; read its documented wire name.
        assert!(
            doc.get_map("asset_body_refs")
                .get(&row.id.to_hex())
                .is_none(),
            "a withheld ASSET has no file-body reference"
        );
    }
    entities.for_each(|_, value| {
        let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
            panic!("entity values must be binary metadata plus body");
        };
        for secret in FILE_SECRETS {
            assert!(
                !bytes.windows(secret.len()).any(|part| part == secret),
                "no exported entity carries a file credential"
            );
        }
    });
    doc.get_map("edges").for_each(|key, _| {
        let (source, _, target) = parse_edge_key(key).expect("canonical edge key");
        for row in [&files.private_script, &files.signature_json] {
            assert!(
                source != row.id && target != row.id,
                "a withheld ASSET has no edge"
            );
        }
    });
}

// Locally written opaque rows start Sensitive, while the shipped Connect
// ceiling is Private. Let this fixture's owner admit Sensitive rows so the
// clean ASSET proves admission independently of credential release. All other
// policy rows and all record positions stay unchanged.
fn admit_sensitive_guest_rows(vault: &Vault, owner: &AuthenticatedOwner) -> Result<()> {
    let ids = vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)?;
    assert_eq!(ids.len(), 1, "a fresh vault has one seeded policy manifest");
    let id = ids[0];
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&id)?.expect("seeded policy"))
            .expect("decode seeded policy");
    let rows = manifest["federation_grant_rows"]
        .as_array_mut()
        .expect("grant policy rows");
    let row = rows
        .iter_mut()
        .find(|row| row["kind"] == "connect_guest_ceiling")
        .expect("Connect guest ceiling");
    let mut scope: Scope =
        serde_json::from_value(row["scope"].clone()).expect("guest ceiling scope");
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Sensitive);
    row["scope"] = serde_json::to_value(scope).expect("guest ceiling scope");
    vault.install_owner_policy_manifest(
        owner,
        id,
        rmp_serde::to_vec_named(&manifest).expect("encode seeded policy"),
        LEARNED_AT,
    )?;
    Ok(())
}

fn guest_scope(world: EntityId) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some([ScopeId(world)].into());
    scope.verbs = ScopeAxis::Some(["read".to_owned(), "propose".to_owned()].into());
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Sensitive);
    scope
}

fn guest_direction(world: EntityId) -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: ScopeAxis::Some([ScopeId(world)].into()),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    }
}

struct GuestFixture {
    _source_dir: tempfile::TempDir,
    _recipient_dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    manager: Arc<WindowManager>,
    world: EntityId,
    grant: EntityId,
    guest: EntityId,
    scope: Scope,
    pact: String,
    files: FileRows,
}

fn guest_fixture() -> Result<GuestFixture> {
    let (source_dir, vault) = open_vault();
    let owner = scan_off(&vault)?;
    let issuer = HostSlipIssuer::from_secret(b"transport-credential-source")?;
    vault.ensure_host_root_slip(&issuer)?;
    admit_sensitive_guest_rows(&vault, &owner)?;
    let world = vault.create_world(&owner, "owen", LEARNED_AT)?;
    let files = store_files(&vault, Some(world))?;

    let (recipient_dir, recipient) = open_vault();
    let recipient_owner = scan_off(&recipient)?;
    let recipient_issuer = HostSlipIssuer::from_secret(b"transport-credential-recipient")?;
    recipient.ensure_host_root_slip(&recipient_issuer)?;
    admit_sensitive_guest_rows(&recipient, &recipient_owner)?;
    let recipient_world = recipient.create_world(&recipient_owner, "yuki", LEARNED_AT)?;
    let source_id = vault.authority_fold()?.vault_id.expect("rooted source");
    let recipient_id = recipient
        .authority_fold()?
        .vault_id
        .expect("rooted recipient");
    let minted = vault.mint_connect_grant(&owner, recipient_id, guest_scope(world), None, None)?;
    let reciprocal = recipient.mint_connect_grant(
        &recipient_owner,
        source_id,
        guest_scope(recipient_world),
        None,
        None,
    )?;
    let offer = vault.propose_connect_as(
        &owner,
        &issuer,
        minted.grant,
        recipient_id,
        guest_direction(world),
        guest_direction(recipient_world),
    )?;
    let (_, counter) = recipient.accept_connect_as(
        &recipient_owner,
        &recipient_issuer,
        reciprocal.grant,
        &offer,
    )?;
    vault.accept_connect_as(&owner, &issuer, minted.grant, &counter)?;
    let pact = offer
        .pact_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let manager = manager(&vault);
    manager.open_window(&WindowKey::new(WINDOW))?;
    Ok(GuestFixture {
        _source_dir: source_dir,
        _recipient_dir: recipient_dir,
        vault,
        owner,
        issuer,
        manager,
        world,
        grant: minted.grant,
        guest: minted.guest_actor,
        scope: minted.resolved_scope,
        pact,
        files,
    })
}

#[test]
fn connect_guest_envelope_withholds_credential_files() -> Result<()> {
    let fixture = guest_fixture()?;
    let delivery = SyncClient::export_connect_window_as(
        &fixture.manager,
        &fixture.owner,
        &fixture.issuer,
        ConnectExportRequest {
            pact: fixture.pact.clone(),
            window_key: WINDOW.to_owned(),
            world_ref: fixture.world,
            facets: vec![],
            bands: vec![],
        },
    )?;
    let doc = import_update(&delivery.body.update);
    assert_exact(&doc, &fixture.files.clean);
    assert_files_withheld(&doc, &fixture.files);
    assert_unchanged(
        &fixture.vault,
        &[
            &fixture.files.private_script,
            &fixture.files.signature_json,
            &fixture.files.clean,
        ],
    )?;
    Ok(())
}

#[test]
fn guest_document_share_and_fetch_withhold_credential_files() -> Result<()> {
    let fixture = guest_fixture()?;
    let input = GuestDocumentShareRequest {
        grant_ref: fixture.grant,
        world_ref: fixture.world,
        window_key: WINDOW.to_owned(),
        facets: vec![],
        bands: vec![],
    };
    let (shared, _) =
        share_guest_document_as_owner(&fixture.manager, &fixture.owner, &fixture.issuer, &input)?;

    // Logged, grant-bound guest credential with a real holder signature;
    // no VerifiedSlip or peer-machine proof is constructed by hand.
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let holder = SigningKey::from_bytes(&[0x65; 32]);
    let mut claims = root.claims;
    claims.slip_id = [0x65; 32];
    claims.parent_id = None;
    claims.holder_ref = fixture.guest.to_hex();
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.grant_ref = Some(fixture.grant.to_hex());
    claims.scope = fixture.scope.clone();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    let challenge = b"oneiron-request:transport-credential-release";
    let signature = holder.sign(&slip.binding_transcript(challenge)?).to_bytes();
    let proof = fixture.vault.verify_capability_slip_with_host_key(
        &fixture.issuer.public_key(),
        &slip,
        challenge,
        &signature,
    )?;
    let (fetched, _) = export_guest_document_for_guest(
        &fixture.manager,
        &proof,
        oneiron::claim::CallerLocality::OffDevice,
        &fixture.issuer,
        &input,
    )?;
    let shared_doc = import_update(&shared.envelope.body.update);
    let fetched_doc = import_update(&fetched.envelope.body.update);
    // Prove both doors admit the control before inspecting either's secrets.
    assert_exact(&shared_doc, &fixture.files.clean);
    assert_exact(&fetched_doc, &fixture.files.clean);
    assert_files_withheld(&shared_doc, &fixture.files);
    assert_files_withheld(&fetched_doc, &fixture.files);
    assert_unchanged(
        &fixture.vault,
        &[
            &fixture.files.private_script,
            &fixture.files.signature_json,
            &fixture.files.clean,
        ],
    )?;
    Ok(())
}

struct MemberFixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    selector: SyncSelector,
    person: StoredRow,
    clean_person: StoredRow,
    files: FileRows,
}

fn member_fixture() -> Result<MemberFixture> {
    let (dir, vault) = open_vault();
    let owner = scan_off(&vault)?;
    let issuer = HostSlipIssuer::from_secret(b"transport-credential-member")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.initialize_shared_vault(&owner, SHARED, None, &[], 1)?;
    let person = store_row(&vault, ENTITY_TYPE_PERSON, person_body(), None)?;
    let clean_person = store_row(
        &vault,
        ENTITY_TYPE_PERSON,
        encode(&Value::Map(vec![(
            Value::from("name"),
            Value::from("yuki"),
        )])),
        None,
    )?;
    let files = store_files(&vault, None)?;
    let grant = stand_member_grant(&vault, clean_person.id, SHARED, FederationGrantRole::Member)?;
    let selector = SyncSelector::new(
        grant,
        clean_person.id,
        SyncSelectorWorld::Base,
        vec![],
        vec![],
    );
    let manager = manager(&vault);
    Ok(MemberFixture {
        _dir: dir,
        vault,
        manager,
        selector,
        person,
        clean_person,
        files,
    })
}

#[test]
fn member_peer_window_nulls_person_credentials() -> Result<()> {
    let fixture = member_fixture()?;
    let key = WindowKey::new(WINDOW);
    let window = fixture.manager.open_window(&key)?;
    let doc = filtered_window_doc_for_peer(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
        PeerMachine::Unknown,
    )?;
    assert_exact(&doc, &fixture.clean_person);
    assert_exact(&doc, &fixture.files.clean);
    let row = map_get_bytes(&doc.get_map("entities"), &fixture.person.id.to_hex())
        .expect("the credential-bearing PERSON is still admitted under its original id");
    assert_eq!(
        &row[..ENTITY_METADATA_HEADER_LEN],
        &fixture.person.raw[..ENTITY_METADATA_HEADER_LEN],
        "nulling preserves the stored header"
    );
    let body = &row[ENTITY_METADATA_HEADER_LEN..];
    let mut cursor = std::io::Cursor::new(body);
    let decoded = rmpv::decode::read_value(&mut cursor).expect("released PERSON MessagePack");
    assert_eq!(cursor.position(), body.len() as u64, "one complete body");
    let fields = decoded.as_map().expect("PERSON map");
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    assert_eq!(field("name"), Some(&Value::from("owen")));
    for name in [
        "api_key",
        "binary",
        "nested_binary",
        "byte_array",
        "json_bytes",
        "byte_map",
        "json_encoded_bytes",
        "json_encoded_map",
        "signature",
    ] {
        assert!(
            field(name).is_none_or(|value| value == &Value::Nil),
            "credential member {name} must be nil or absent"
        );
    }
    assert_eq!(
        field("public_binary"),
        Some(&Value::Binary(b"inspectable public bytes".to_vec()))
    );
    let credential = format!("ghp_{}", "a".repeat(36));
    for secret in [
        credential.as_bytes(),
        b"unrecognizable-but-named-secret",
        b"nested-secret",
        b"byte-map-secret",
        b"json-secret",
        b"array-wrapped-secret",
        &[1, 2, 3],
    ] {
        assert!(
            !body.windows(secret.len()).any(|part| part == secret),
            "the released PERSON carries no original credential value"
        );
    }
    assert_files_withheld(&doc, &fixture.files);
    assert_unchanged(
        &fixture.vault,
        &[
            &fixture.person,
            &fixture.clean_person,
            &fixture.files.private_script,
            &fixture.files.signature_json,
            &fixture.files.clean,
        ],
    )?;
    Ok(())
}

#[test]
fn own_machine_window_keeps_rows_as_stored() -> Result<()> {
    let fixture = member_fixture()?;
    let key = WindowKey::new(WINDOW);
    let window = fixture.manager.open_window(&key)?;
    // No existing integration test proves a PeerMachine. This public wrapper
    // explicitly selects OwnMachines; it is not the Unknown-peer transport.
    let doc = filtered_window_doc(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
    )?;
    assert_exact(&doc, &fixture.clean_person);
    assert_exact(&doc, &fixture.files.clean);
    assert_exact(&doc, &fixture.person);
    assert_exact(&doc, &fixture.files.private_script);
    assert_exact(&doc, &fixture.files.signature_json);
    assert_unchanged(
        &fixture.vault,
        &[
            &fixture.person,
            &fixture.clean_person,
            &fixture.files.private_script,
            &fixture.files.signature_json,
            &fixture.files.clean,
        ],
    )?;
    Ok(())
}
