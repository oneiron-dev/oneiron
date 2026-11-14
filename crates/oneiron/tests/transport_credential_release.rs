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
use oneiron::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_POLICY_MANIFEST,
};
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
use oneiron::write_envelope::claim_body::decode_claim_body;
use oneiron::write_envelope::{
    ClaimCandidate, MachineWriteSignature, WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind, EntityId, Result,
    TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
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
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
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
    issuer: HostSlipIssuer,
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
        issuer,
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

fn read_stored_row(vault: &Vault, id: EntityId) -> Result<StoredRow> {
    let body = vault.get(&id)?.expect("stored body");
    let raw = vault.get_raw(&id)?.expect("stored metadata and body");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], body.as_slice());
    Ok(StoredRow { id, body, raw })
}

fn member_fixture_with_machine_signed_claim(
    value: Value,
) -> Result<(MemberFixture, StoredRow, StoredRow)> {
    let fixture = member_fixture()?;
    let machine = store_row(&fixture.vault, ENTITY_TYPE_MACHINE, b"owen".to_vec(), None)?;
    let signing = SigningKey::from_bytes(&[0x4d; 32]);
    fixture.vault.enroll_machine_identity(
        &fixture.issuer,
        machine.id,
        signing.verifying_key().to_bytes(),
        [0x54; 32],
        |transcript| Ok(signing.sign(transcript).to_bytes()),
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine.id, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine output"))?,
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "test.machine.transport",
        ClaimSubject::Entity(machine.id),
        value.clone(),
        1.0,
    );
    let id = EntityId::now();
    let transcript = fixture
        .vault
        .machine_claim_transcript(&id, &candidate, &envelope)?;
    let public_key = signing.verifying_key().to_bytes();
    let signature = signing.sign(&transcript).to_bytes();
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key,
        signature,
    });
    fixture
        .vault
        .batch()
        .claim_candidate(
            &id,
            candidate,
            &signed,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
        )
        .commit()?;
    let claim = read_stored_row(&fixture.vault, id)?;
    let decoded = decode_claim_body(&claim.body, true)?;
    assert_eq!(decoded.value, value, "scan-Off keeps the signed content");
    let evidence = decoded.evidence.expect("machine evidence");
    let signature_value = evidence
        .as_map()
        .expect("machine evidence map")
        .iter()
        .find(|(key, _)| key.as_str() == Some("machine_signature"))
        .map(|(_, value)| value);
    assert_eq!(
        signature_value,
        Some(&Value::Array(vec![
            Value::Binary(public_key.to_vec()),
            Value::Binary(signature.to_vec()),
        ])),
        "the stored CLAIM must carry the real machine proof"
    );
    Ok((fixture, machine, claim))
}

// Signed engine rows cross to a member peer on their content: every
// AUTHORITY_LOG row and a clean machine-signed CLAIM keep their stored bytes.
#[test]
fn member_peer_window_keeps_signed_engine_rows() -> Result<()> {
    let (fixture, machine, claim) =
        member_fixture_with_machine_signed_claim(Value::from("Exact reference fact."))?;
    let authority_rows = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)?
        .into_iter()
        .map(|id| read_stored_row(&fixture.vault, id))
        .collect::<Result<Vec<_>>>()?;
    assert!(
        !authority_rows.is_empty(),
        "the fixture creates authority rows"
    );
    let mut months = std::collections::BTreeSet::new();
    for row in authority_rows.iter().chain(std::iter::once(&claim)) {
        months.insert(
            WindowKey::from_timestamp(fixture.vault.get_learned_at(&row.id)?)
                .as_str()
                .to_owned(),
        );
    }
    let claim_key = WindowKey::from_timestamp(fixture.vault.get_learned_at(&claim.id)?);
    let mut own_windows = Vec::new();
    let mut own_authority_count = 0;
    for month in months {
        let key = WindowKey::new(&month);
        let window = fixture.manager.open_window(&key)?;
        let own = filtered_window_doc(
            &fixture.vault,
            &window.doc,
            &key,
            FederationGrantScope::vault(SHARED),
            &fixture.selector,
        )?;
        own.get_map("entities").for_each(|_, value| {
            let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
                panic!("entity values must be binary metadata plus body");
            };
            if EntityMetadataHeader::parse(&bytes)
                .expect("entity metadata header")
                .entity_type
                == ENTITY_TYPE_AUTHORITY_LOG
            {
                own_authority_count += 1;
            }
        });
        own_windows.push((key, own));
    }
    assert!(
        own_authority_count > 0,
        "own-machine windows must actually admit AUTHORITY_LOG rows"
    );
    let (_, own_claim_window) = own_windows
        .iter()
        .find(|(key, _)| key == &claim_key)
        .expect("the signed CLAIM's learned month was opened");
    assert_exact(own_claim_window, &claim);

    for (key, own) in &own_windows {
        let window = fixture.manager.open_window(key)?;
        let member = filtered_window_doc_for_peer(
            &fixture.vault,
            &window.doc,
            key,
            FederationGrantScope::vault(SHARED),
            &fixture.selector,
            PeerMachine::Unknown,
        )?;
        own.get_map("entities").for_each(|id, value| {
            let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
                panic!("entity values must be binary metadata plus body");
            };
            if EntityMetadataHeader::parse(&bytes)
                .expect("entity metadata header")
                .entity_type
                == ENTITY_TYPE_AUTHORITY_LOG
            {
                let stored = authority_rows
                    .iter()
                    .find(|row| row.id.to_hex() == id)
                    .expect("own-machine authority row has a stored snapshot");
                assert_exact(own, stored);
                assert_eq!(
                    map_get_bytes(&member.get_map("entities"), id),
                    Some(bytes.to_vec()),
                    "every own-machine AUTHORITY_LOG row crosses byte-exact: {id}"
                );
                assert_exact(&member, stored);
            }
        });
        if key == &claim_key {
            assert_exact(&member, &claim);
        }
    }
    let mut stored_rows = authority_rows.iter().collect::<Vec<_>>();
    stored_rows.extend([&machine, &claim]);
    assert_unchanged(&fixture.vault, &stored_rows)?;
    Ok(())
}

// A machine-signed CLAIM whose content holds a credential is withheld whole;
// its proof is never rewritten and storage keeps the original row.
#[test]
fn member_peer_window_withholds_machine_signed_claim_with_credential() -> Result<()> {
    let credential = format!("ghp_{}", "a".repeat(36));
    let (fixture, machine, claim) =
        member_fixture_with_machine_signed_claim(Value::from(credential.as_str()))?;
    assert!(
        claim
            .body
            .windows(credential.len())
            .any(|part| part == credential.as_bytes()),
        "the original credential must really be stored before export"
    );
    let key = WindowKey::from_timestamp(fixture.vault.get_learned_at(&claim.id)?);
    let window = fixture.manager.open_window(&key)?;
    let own = filtered_window_doc(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
    )?;
    assert_exact(&own, &claim);
    let member = filtered_window_doc_for_peer(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
        PeerMachine::Unknown,
    )?;
    let entities = member.get_map("entities");
    assert!(
        entities.get(&claim.id.to_hex()).is_none(),
        "a signed CLAIM with credential-bearing content is withheld whole"
    );
    entities.for_each(|_, value| {
        let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
            panic!("entity values must be binary metadata plus body");
        };
        assert!(
            !bytes
                .windows(credential.len())
                .any(|part| part == credential.as_bytes()),
            "no member entity may carry the original credential bytes"
        );
    });
    assert_unchanged(&fixture.vault, &[&machine, &claim])?;
    Ok(())
}

fn witness_message_with_signature(
    vault: &Vault,
    conversation: EntityId,
    signature: &str,
) -> Result<StoredRow> {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&oneiron::WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![oneiron::WitnessMessage {
                id: None,
                author: oneiron::WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "hello".to_owned(),
                parts: Some(vec![oneiron::ContentPart::Text {
                    text: "hello".to_owned(),
                    signature: Some(signature.to_owned()),
                }]),
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: LEARNED_AT,
            assertions: oneiron::memory::WitnessAssertions::default(),
        })
        .expect("the public witness door accepts the canonical signed text part");
    let id = EntityId::from_hex(&receipt.messages[0].id)?;
    let row = read_stored_row(vault, id)?;
    let body: serde_json::Value =
        rmp_serde::from_slice(&row.body).expect("canonical witness MESSAGE map");
    assert_eq!(body["parts"][0]["kind"], "text");
    assert_eq!(body["parts"][0]["signature"], signature);
    Ok(row)
}

#[test]
fn member_peer_window_withholds_message_with_credential_signature() -> Result<()> {
    let fixture = member_fixture()?;
    let credential = format!("ghp_{}", "a".repeat(36));
    let conversation = EntityId::now();
    let control_message = witness_message_with_signature(
        &fixture.vault,
        conversation,
        "provider-signature-reference",
    )?;
    let credential_message =
        witness_message_with_signature(&fixture.vault, conversation, &credential)?;
    assert!(
        credential_message
            .body
            .windows(credential.len())
            .any(|part| part == credential.as_bytes()),
        "scan-Off stores the original signature credential before export"
    );
    let mut control_body: serde_json::Value =
        rmp_serde::from_slice(&control_message.body).expect("control MESSAGE");
    control_body["parts"][0]["signature"] = serde_json::Value::String(credential.clone());
    let credential_body: serde_json::Value =
        rmp_serde::from_slice(&credential_message.body).expect("credential MESSAGE");
    assert_eq!(control_body, credential_body, "only the signature differs");
    let key = WindowKey::new(WINDOW);
    let window = fixture.manager.open_window(&key)?;
    assert_exact(&window.doc, &control_message);
    assert_exact(&window.doc, &credential_message);
    let member = filtered_window_doc_for_peer(
        &fixture.vault,
        &window.doc,
        &key,
        FederationGrantScope::vault(SHARED),
        &fixture.selector,
        PeerMachine::Unknown,
    )?;
    // CONTROL: a signed MESSAGE crosses byte-exact, including its signature.
    assert_exact(&member, &control_message);
    let entities = member.get_map("entities");
    assert!(
        entities.get(&credential_message.id.to_hex()).is_none(),
        "a MESSAGE with a credential signature stays home whole"
    );
    entities.for_each(|_, value| {
        let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
            panic!("entity values must be binary metadata plus body");
        };
        assert!(
            !bytes
                .windows(credential.len())
                .any(|part| part == credential.as_bytes()),
            "no member entity may carry the original credential bytes"
        );
    });
    assert_unchanged(&fixture.vault, &[&control_message, &credential_message])?;
    Ok(())
}

#[test]
fn member_peer_window_withholds_note_with_credential_proposal() -> Result<()> {
    let fixture = member_fixture()?;
    let vault = &fixture.vault;
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let actor = WriteActor::new(owner_id, EdgeActorClass::Human);
    let credential = format!("ghp_{}", "a".repeat(36));
    let control_text = "Move the standup to Tuesday.";
    let credential_text = format!("Rotate the token {credential} before Tuesday.");
    let control_note = vault
        .create_note("research", "The weekly review covers the schedule.", actor)
        .expect("control NOTE");
    let credential_note = vault
        .create_note("research", "The weekly review covers the agenda.", actor)
        .expect("credential NOTE");
    let control_fork = vault
        .fork_note(
            control_note,
            &oneiron::note::NoteProgramEdit::Rewrite {
                text: control_text.to_owned(),
            },
            actor,
        )
        .expect("undecided control fork");
    let credential_fork = vault
        .fork_note(
            credential_note,
            &oneiron::note::NoteProgramEdit::Rewrite {
                text: credential_text.clone(),
            },
            actor,
        )
        .expect("undecided credential fork");
    let carrier_key = |note: EntityId, fork: EntityId| {
        format!("note_proposal_doc:v1:{}:{}", note.to_hex(), fork.to_hex())
    };
    let control_carrier = carrier_key(control_note, control_fork);
    let credential_carrier = carrier_key(credential_note, credential_fork);
    let control_stored = read_stored_row(vault, control_note)?;
    let credential_stored = read_stored_row(vault, credential_note)?;
    let control_month = WindowKey::from_timestamp(vault.get_learned_at(&control_note)?);
    let credential_month = WindowKey::from_timestamp(vault.get_learned_at(&credential_note)?);
    let months = std::collections::BTreeSet::from([
        control_month.as_str().to_owned(),
        credential_month.as_str().to_owned(),
    ]);
    let mut member_docs = Vec::new();
    for month in months {
        let key = WindowKey::new(month);
        let window = fixture.manager.open_window(&key)?;
        if key == credential_month {
            let bytes = map_get_bytes(&window.doc.get_map("documents"), &credential_carrier)
                .expect("the opened window mirrors the stored credential proposal");
            let stored: String = rmp_serde::from_slice(&bytes).expect("stored proposal text");
            assert_eq!(stored, credential_text);
            assert!(
                bytes
                    .windows(credential.len())
                    .any(|part| part == credential.as_bytes()),
                "scan-Off stores the original proposal credential before export"
            );
        }
        let member = filtered_window_doc_for_peer(
            vault,
            &window.doc,
            &key,
            FederationGrantScope::vault(SHARED),
            &fixture.selector,
            PeerMachine::Unknown,
        )?;
        member_docs.push((key, member));
    }
    let member_of = |month: &WindowKey| {
        member_docs
            .iter()
            .find(|(key, _)| key == month)
            .map(|(_, doc)| doc)
            .expect("member export of the NOTE month")
    };
    // CONTROL: the clean NOTE and its undecided proposal carrier cross.
    let control_doc = member_of(&control_month);
    assert_exact(control_doc, &control_stored);
    let control_bytes = map_get_bytes(&control_doc.get_map("documents"), &control_carrier)
        .expect("the clean proposal carrier crosses to the member peer");
    let control_carried: String =
        rmp_serde::from_slice(&control_bytes).expect("decode clean proposal text");
    assert_eq!(control_carried, control_text);

    let credential_doc = member_of(&credential_month);
    assert!(
        credential_doc
            .get_map("entities")
            .get(&credential_note.to_hex())
            .is_none(),
        "a NOTE with a credential proposal stays home whole"
    );
    assert!(
        credential_doc
            .get_map("documents")
            .get(&credential_carrier)
            .is_none(),
        "the credential proposal document stays home"
    );
    assert!(
        credential_doc
            .get_map("note_forks")
            .get(&credential_fork.to_hex())
            .is_none(),
        "the credential NOTE fork stays home"
    );
    let credential_documents = format!("note_proposal_doc:v1:{}:", credential_note.to_hex());
    for (_, doc) in &member_docs {
        doc.get_map("documents").for_each(|key, _| {
            assert!(
                !key.starts_with(&credential_documents),
                "no document carrier of the withheld NOTE may cross"
            );
        });
        doc.get_map("note_proposals").for_each(|_, _| {
            panic!("bare undecided forks have no proposal bundles");
        });
        for map in ["entities", "documents", "note_forks", "note_proposals"] {
            doc.get_map(map).for_each(|_, value| {
                let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value else {
                    panic!("{map} values must be binary carriers");
                };
                assert!(
                    !bytes
                        .windows(credential.len())
                        .any(|part| part == credential.as_bytes()),
                    "no member {map} carrier may hold the credential bytes"
                );
            });
        }
    }
    assert_unchanged(vault, &[&control_stored, &credential_stored])?;
    Ok(())
}
