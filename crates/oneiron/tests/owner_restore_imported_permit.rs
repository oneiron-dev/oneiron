//! Owner whole-vault restore carries expression preferences under a call-scoped permit.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test owner_restore_imported_permit`.
//!
//! Public doors only; vaults in tempdirs; neutral fixtures (`owen`, `yuki`).
//! Each destination opens at least one wall-clock second after its source (sleep
//! 1100 ms), so the pack seeds' seconds differ, copied from
//! `whole_vault_restore_seeds.rs`. Owner proofs come from public
//! `Vault::authenticate_owner` over the embedded owner.
//!
//! Base behaviour (this file copied onto base `07893d84df1` with only
//! `restore_as_owner` and `verify_restore_owner` swapped for their base bodies):
//! * `owner_restore_carries_expression_preferences` is red: the base has no
//!   owner restore door, so the base helper falls back to the actor-taking
//!   door, which holds no Imported-source Auto grant and refuses with
//!   `FamilyRequiresAutoGrant`.
//! * `owner_restore_permit_ends_with_the_restore` is red: it starts from a
//!   successful owner restore, which the base refuses, so it fails at the
//!   restore step before it reaches the later-write check.
//! * `archive_without_expressions_restores_with_no_bound_owner` is green on base and head:
//!   it uses only the existing actorless door and ordinary PERSON put/get, with no
//!   destination owner proof or binding.
//! * `archive_restore_owner_probe_refuses_an_unbound_owner` is red on the base only at
//!   the probe assertion: its base helper returns `Ok(())`, while the head probe refuses
//!   the rooted destination's missing human binding. Its actorless ordinary restore
//!   uses existing APIs and remains allowed.
//! * `actorless_restore_still_refuses_expression_preferences`,
//!   `owner_actor_without_the_owner_door_gains_no_permit` and
//!   `owner_restore_refuses_another_vaults_proof` are green on base and head:
//!   the actorless door, the actor-taking door and a cross-vault proof refuse
//!   the same way with or without the new owner door.

use std::collections::BTreeMap;
use std::io::Cursor;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, DeviceAuthority, GenesisRecoveryStep, ROLE_OWNER, authority_transcript,
};
use oneiron::claim::{
    ExpressionPreferenceChange, ExpressionPreferenceOrigin, ExpressionPreferenceValue,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    Result, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

fn restore_as_owner(
    dest: &Vault,
    archive: &[u8],
    owner: &AuthenticatedOwner,
) -> Result<Option<String>> {
    dest.import_whole_vault_archive_from_with_actor(
        Cursor::new(archive),
        &WriteActor::new(owner.revalidate(dest)?, EdgeActorClass::Human),
    )
    .map(|_| None)
}

fn verify_restore_owner(_dest: &Vault, _owner: &AuthenticatedOwner) -> oneiron::Result<()> {
    Ok(())
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_actor(vault: &Vault) -> WriteActor {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    WriteActor::new(owner, EdgeActorClass::Human)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn person_body(name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode PERSON");
    body
}

/// A whole-vault archive with an ordinary PERSON row, not an expression preference.
fn seed_source_without_expressions() -> (tempfile::TempDir, Vault, EntityId, Vec<u8>) {
    let (dir, source) = open_vault();
    let owen = EntityId::now();
    source
        .put_entity(
            &owen,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &person_body("owen"),
        )
        .expect("ordinary owen PERSON");
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export without expressions")
        .bytes()
        .to_vec();
    (dir, source, owen, archive)
}

struct SeededIds {
    owen: EntityId,
    yuki: EntityId,
    owen_claim: EntityId,
    yuki_claim: EntityId,
}

/// A source vault holding two expression preferences of different kinds
/// (language on `owen`, style on `yuki`), written by its owner, plus the
/// whole-vault archive bytes carrying them.
fn seed_source_with_expressions() -> (tempfile::TempDir, Vault, SeededIds, Vec<u8>) {
    let (dir, source) = open_vault();
    let owner = owner_actor(&source);
    let owen = EntityId::now();
    source
        .put_entity(
            &owen,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 50, end: 50 },
            50,
            &person_body("owen"),
        )
        .expect("owen PERSON");
    let yuki = EntityId::now();
    source
        .put_entity(
            &yuki,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 50, end: 50 },
            50,
            &person_body("yuki"),
        )
        .expect("yuki PERSON");
    let owen_claim = EntityId::now();
    source
        .set_expression_preference(
            &owner,
            owen_claim,
            ExpressionPreferenceChange {
                subject: owen,
                value: ExpressionPreferenceValue::Language("en-US".to_owned()),
                origin: ExpressionPreferenceOrigin::ExplicitUser,
                valid_from: 100,
            },
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("owen language preference");
    let yuki_claim = EntityId::now();
    source
        .set_expression_preference(
            &owner,
            yuki_claim,
            ExpressionPreferenceChange {
                subject: yuki,
                value: ExpressionPreferenceValue::Style("compact-neutral".to_owned()),
                origin: ExpressionPreferenceOrigin::ExplicitUser,
                valid_from: 100,
            },
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("yuki style preference");
    let bytes = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    (
        dir,
        source,
        SeededIds {
            owen,
            yuki,
            owen_claim,
            yuki_claim,
        },
        bytes,
    )
}

/// Raw bytes of every policy manifest row, keyed by id hex. The row list
/// comes from public `Vault::entities_by_type`; each row comes from public
/// `Vault::get_raw`. The seeded default manifest is pinned through public
/// `oneiron_store::policy_record::default_policy_manifest_id`.
fn snapshot_policy_manifests(vault: &Vault) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut map = BTreeMap::new();
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let bytes = vault.get_raw(&id)?.expect("policy manifest row");
        map.insert(id.to_hex(), bytes);
    }
    let default_id =
        oneiron_store::policy_record::default_policy_manifest_id().expect("default policy id");
    assert!(
        map.contains_key(&default_id.to_hex()),
        "a seeded vault holds the default policy manifest"
    );
    Ok(map)
}

fn find_gate_receipt(
    vault: &Vault,
    receipt_ref: &str,
) -> Result<Option<oneiron::receipt::ReceiptRecord>> {
    let receipts = vault.receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Gate))?;
    Ok(receipts
        .into_iter()
        .find(|row| row.receipt_id == receipt_ref))
}

fn assert_no_expression_preferences(vault: &Vault, owen: &EntityId, yuki: &EntityId) -> Result<()> {
    let owen_prefs = vault.expression_preferences(owen, 200)?;
    assert!(
        owen_prefs.language.is_none()
            && owen_prefs.style.is_none()
            && owen_prefs.register.is_none()
            && owen_prefs.keigo.is_none()
            && owen_prefs.winning_claim_ids.is_empty(),
        "no preference lands for owen"
    );
    let yuki_prefs = vault.expression_preferences(yuki, 200)?;
    assert!(
        yuki_prefs.language.is_none()
            && yuki_prefs.style.is_none()
            && yuki_prefs.register.is_none()
            && yuki_prefs.keigo.is_none()
            && yuki_prefs.winning_claim_ids.is_empty(),
        "no preference lands for yuki"
    );
    Ok(())
}

/// The CLI's no-owner path keeps restoring ordinary archives without a destination owner proof.
#[test]
fn archive_without_expressions_restores_with_no_bound_owner() -> Result<()> {
    let (_source_dir, _source, owen, archive) = seed_source_without_expressions();
    let (_dest_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(archive.as_slice()))?;
    assert_eq!(
        dest.get(&owen)?.as_deref(),
        Some(person_body("owen").as_slice()),
        "the ordinary PERSON restores without authenticating or binding the destination owner"
    );
    Ok(())
}

/// A rooted vault with no human binding must not turn an ordinary restore into an owner act.
#[test]
fn archive_restore_owner_probe_refuses_an_unbound_owner() -> Result<()> {
    let (_source_dir, _source, owen, archive) = seed_source_without_expressions();
    let (_dest_dir, dest) = open_later_vault();
    let signing = SigningKey::from_bytes(&[7; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut genesis = AuthorityLogEntry {
        schema_version: 1,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
            genesis_nonce: [8; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 7,
    };
    genesis.signer.signature = signing
        .sign(&authority_transcript(&genesis)?)
        .to_bytes()
        .to_vec();
    dest.put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)?;
    let proof = owner_proof(&dest);
    assert!(
        dest.is_live_vault_owner(&proof)?,
        "the owner census alone does not prove the active human binding"
    );
    let error = verify_restore_owner(&dest, &proof)
        .expect_err("the rooted destination has no active human owner binding");
    match error {
        oneiron::Error::Claim(oneiron::error::ClaimError::ActorLacksClaimAuthority { reason }) => {
            assert_eq!(reason, "writer has no active authority binding");
        }
        other => panic!("expected an unbound owner refusal, got {other:?}"),
    }
    dest.import_whole_vault_archive_from(Cursor::new(archive.as_slice()))?;
    assert_eq!(
        dest.get(&owen)?.as_deref(),
        Some(person_body("owen").as_slice()),
        "the ordinary PERSON still restores when the owner probe refuses"
    );
    Ok(())
}

/// The owner door restores both expression preferences, leaves every policy
/// manifest byte untouched, and leaves a durable owner-act receipt naming
/// the archive digest.
#[test]
fn owner_restore_carries_expression_preferences() -> Result<()> {
    let (_source_dir, source, ids, archive) = seed_source_with_expressions();
    let source_owen = source.expression_preferences(&ids.owen, 200)?;
    let source_yuki = source.expression_preferences(&ids.yuki, 200)?;
    assert_eq!(
        source_owen.language.as_deref(),
        Some("en-US"),
        "the source holds the owen language"
    );
    assert_eq!(
        source_yuki.style.as_deref(),
        Some("compact-neutral"),
        "the source holds the yuki style"
    );
    let document = source.read_whole_vault_archive(&archive)?;
    let manifest_bytes = serde_json::to_vec(&document.manifest).expect("encode full manifest");
    let expected_digest = blake3::hash(&manifest_bytes).to_hex().to_string();
    let (dest_dir, dest) = open_later_vault();
    let before = snapshot_policy_manifests(&dest)?;
    let proof = owner_proof(&dest);
    let dest_owner_hex = dest
        .ensure_embedded_owner_actor()
        .expect("destination owner")
        .to_hex();
    let receipt_ref =
        restore_as_owner(&dest, &archive, &proof)?.expect("the owner restore names its receipt");
    assert!(
        receipt_ref.starts_with("gate:"),
        "the receipt ref is a gate ref, got {receipt_ref}"
    );
    let dest_owen = dest.expression_preferences(&ids.owen, 200)?;
    let dest_yuki = dest.expression_preferences(&ids.yuki, 200)?;
    assert_eq!(
        dest_owen, source_owen,
        "the destination restores the owen preferences"
    );
    assert_eq!(
        dest_yuki, source_yuki,
        "the destination restores the yuki preferences"
    );
    let after = snapshot_policy_manifests(&dest)?;
    assert_eq!(
        after, before,
        "the restore changes no policy manifest byte and adds no manifest row"
    );
    let receipt = find_gate_receipt(&dest, &receipt_ref)?.expect("the restore receipt reads back");
    assert_eq!(
        receipt.actor.as_deref(),
        Some(dest_owner_hex.as_str()),
        "the receipt names the destination owner"
    );
    assert_eq!(receipt.outcome, "allow", "the owner act is allowed");
    assert_eq!(
        receipt.fields.get("content_kind").map(String::as_str),
        Some("owner_archive_restore"),
        "the receipt content kind names the owner restore"
    );
    let reason = receipt
        .policy_trace
        .iter()
        .find(|reason| reason.starts_with("gate.allow.owner_archive_restore."))
        .expect("a receipt reason names the archive digest")
        .clone();
    let digest = reason
        .strip_prefix("gate.allow.owner_archive_restore.")
        .expect("digest suffix");
    assert_eq!(digest.len(), 64, "the digest is a 32-byte hex");
    assert_eq!(
        digest, expected_digest,
        "the receipt names the parsed full document manifest, not just storage"
    );
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the digest is lowercase hex, got {digest}"
    );
    let expected_grant = format!("archive_restore:{digest}");
    assert_eq!(
        receipt.fields.get("grant_ref").map(String::as_str),
        Some(expected_grant.as_str()),
        "the grant ref names the same digest"
    );
    assert_eq!(
        receipt.fields.get("diff_handle").map(String::as_str),
        Some(digest),
        "the diff handle carries the same digest"
    );
    let path = dest_dir.path().to_path_buf();
    drop(dest);
    drop(proof);
    let dest = Vault::open(&path, VaultConfig::default())?;
    let receipt = find_gate_receipt(&dest, &receipt_ref)?.expect("the receipt survives a reopen");
    assert_eq!(
        receipt.actor.as_deref(),
        Some(dest_owner_hex.as_str()),
        "the reopened receipt still names the owner"
    );
    assert_eq!(
        receipt.fields.get("content_kind").map(String::as_str),
        Some("owner_archive_restore"),
        "the reopened receipt keeps its content kind"
    );
    assert_eq!(
        dest.expression_preferences(&ids.owen, 200)?,
        source_owen,
        "the owen preferences survive a reopen"
    );
    assert_eq!(
        dest.expression_preferences(&ids.yuki, 200)?,
        source_yuki,
        "the yuki preferences survive a reopen"
    );
    Ok(())
}

/// The same archive through the actorless door is still refused, and nothing
/// lands.
#[test]
fn actorless_restore_still_refuses_expression_preferences() -> Result<()> {
    let (_source_dir, _source, ids, archive) = seed_source_with_expressions();
    let (_dest_dir, dest) = open_later_vault();
    let error = dest
        .import_whole_vault_archive_from(Cursor::new(archive.as_slice()))
        .expect_err("the actorless door refuses expression preferences");
    assert!(
        error
            .to_string()
            .contains("host-authenticated local WriteActor"),
        "unexpected actorless refusal: {error}"
    );
    assert_no_expression_preferences(&dest, &ids.owen, &ids.yuki)?;
    assert!(
        dest.get_claim(&ids.owen_claim)?.is_none(),
        "the refused owen claim leaves no row"
    );
    assert!(
        dest.get_claim(&ids.yuki_claim)?.is_none(),
        "the refused yuki claim leaves no row"
    );
    Ok(())
}

/// After a successful owner restore and a reopen, an ordinary Imported+Auto
/// write by the same owner is still refused: the permit ends with the call.
#[test]
fn owner_restore_permit_ends_with_the_restore() -> Result<()> {
    let (_source_dir, _source, _ids, archive) = seed_source_with_expressions();
    let (dest_dir, dest) = open_later_vault();
    let proof = owner_proof(&dest);
    let receipt_ref =
        restore_as_owner(&dest, &archive, &proof)?.expect("the owner restore succeeds");
    assert!(
        receipt_ref.starts_with("gate:"),
        "the receipt ref is a gate ref, got {receipt_ref}"
    );
    let path = dest_dir.path().to_path_buf();
    drop(dest);
    drop(proof);
    let dest = Vault::open(&path, VaultConfig::default())?;
    let owner = owner_actor(&dest);
    let event = EntityId::now();
    dest.put_entity(
        &event,
        ENTITY_TYPE_EVENT,
        TimeRange {
            start: 150,
            end: 151,
        },
        150,
        b"busy elsewhere",
    )?;
    let claim_id = EntityId::now();
    let envelope = WriteEnvelope::new(
        owner,
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("one-1813-oracle")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "calendar.time_kind",
        ClaimSubject::Entity(event),
        Value::Map(vec![
            (Value::from("kind"), Value::from("absolute")),
            (Value::from("busy_transparency"), Value::from("busy")),
        ]),
        1.0,
    );
    let error = dest
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            &envelope,
            TimeRange {
                start: 150,
                end: 150,
            },
            150,
        )
        .commit()
        .expect_err("the later Imported+Auto write is refused");
    match error {
        oneiron::Error::Gate(oneiron::error::GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
            assert_eq!(outcome, "pending", "the later write pends");
            assert_eq!(
                reason_codes.as_slice(),
                ["gate.pending.source_trust"],
                "the later write pends on source trust"
            );
        }
        other => panic!("expected a source-trust pending, got {other:?}"),
    }
    assert!(
        dest.get_claim(&claim_id)?.is_none(),
        "the refused later write leaves no row"
    );
    assert!(
        dest.claims_for_subject(&event)?.is_empty(),
        "the refused later write leaves no subject index row"
    );
    Ok(())
}

/// The same archive through the actor-taking door with the destination owner
/// actor still refuses: the actor alone gains no permit.
#[test]
fn owner_actor_without_the_owner_door_gains_no_permit() -> Result<()> {
    let (_source_dir, _source, ids, archive) = seed_source_with_expressions();
    let (_dest_dir, dest) = open_later_vault();
    let owner = owner_actor(&dest);
    let error = dest
        .import_whole_vault_archive_from_with_actor(Cursor::new(archive.as_slice()), &owner)
        .expect_err("the owner actor without the owner door gains no permit");
    match error {
        oneiron::Error::Gate(oneiron::error::GateError::FamilyRequiresAutoGrant { family }) => {
            assert_eq!(
                family, "expression preference",
                "the family refusal names expression preferences"
            );
        }
        other => panic!("expected FamilyRequiresAutoGrant, got {other:?}"),
    }
    assert!(
        dest.get_claim(&ids.owen_claim)?.is_none(),
        "the refused owen claim leaves no row"
    );
    assert!(
        dest.get_claim(&ids.yuki_claim)?.is_none(),
        "the refused yuki claim leaves no row"
    );
    Ok(())
}

/// An owner proof authenticated on another vault refuses, and the destination
/// gains neither preferences nor an owner restore receipt.
#[test]
fn owner_restore_refuses_another_vaults_proof() -> Result<()> {
    let (_source_dir, source, ids, archive) = seed_source_with_expressions();
    let (_dest_dir, dest) = open_later_vault();
    let foreign_proof = owner_proof(&source);
    let error = restore_as_owner(&dest, &archive, &foreign_proof)
        .expect_err("another vault's proof refuses");
    match &error {
        oneiron::Error::Gate(oneiron::error::GateError::ConsentOwnerNotAuthenticated(_)) => {}
        other => panic!("expected an owner authentication refusal, got {other:?}"),
    }
    assert!(
        error.to_string().contains("another vault"),
        "unexpected cross-vault refusal: {error}"
    );
    assert_no_expression_preferences(&dest, &ids.owen, &ids.yuki)?;
    assert!(
        dest.get_claim(&ids.owen_claim)?.is_none(),
        "the refused owen claim leaves no row"
    );
    assert!(
        dest.get_claim(&ids.yuki_claim)?.is_none(),
        "the refused yuki claim leaves no row"
    );
    let receipts = dest.receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Gate))?;
    assert!(
        !receipts
            .iter()
            .any(|row| row.fields.get("content_kind").map(String::as_str)
                == Some("owner_archive_restore")),
        "no owner restore receipt lands"
    );
    Ok(())
}
