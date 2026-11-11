//! Public-path pins for the Owner's whole-vault archive credential promises
//! (ARCH-0038 #promise-cons-06, owner ruling 2026-10-17; CONS-06/07/09).
//!
//! Canon: "The Owner's whole-vault export keeps credentials, those in skill
//! source files and in JSON bodies included; scoped and contact exports null
//! them."
//!
//! * `owner_archive_keeps_skill_source_credentials_and_restores_them` pins
//!   CONS-06: skill source files keep their credential bytes, the tree keeps
//!   its identity hash, nothing is omitted or refused, and a fresh vault
//!   restores the exact source.
//! * `owner_archive_keeps_json_text_credentials` pins CONS-07: JSON text
//!   bodies that hide a token behind escapes or duplicate keys ship
//!   byte-equal in the owner's archive.
//! * `owner_archive_keeps_credential_fields_and_binary_payloads` pins CONS-09:
//!   a PERSON MessagePack body keeps its credential fields and encoded
//!   payloads, and a fresh vault restores every field.
//!
//! Every test also pins the nulling side: scoped record vectors and contact
//! bundles never carry the credential text. Custody is skipped: custody
//! already travels in the owner's archive today, and `SecretCustodyRecord`
//! value fields are crate-private, so no public door seeds one here.
//!
//! Public doors only: no `#[cfg(test)]` helpers, no crate-private items, no
//! feature flags. These tests are intended to fail on main edffeb5696f for
//! their promises' reasons (the writer nulls) and pass with owner retention.
//! They have not been compiled or run here.

use oneiron::batch::export::{ExportImportRefusal, ExportSourceContent};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::federation::Scope;
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::serialize::ExportBody;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn scan_off(vault: &Vault, principal: &str, at: u64) -> Result<()> {
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(owner_id, principal, true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, at)?;
    Ok(())
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode fixture");
    bytes
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .as_map()
        .expect("fixture map")
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
        .expect("fixture field")
}

fn package() -> HubPackage {
    let record = SkillRecord::new(
        "fixture.bundle",
        "Portable skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        Value::Map(vec![(Value::from("fixture"), Value::from("source-bundle"))]),
    );
    let mut package = HubPackage::new(
        record,
        vec![
            HubFile::new(
                "SKILL.md",
                b"---\nname: fixture.bundle\ndescription: Portable skill\nversion: 1.0.0\n---\nCount input lines.\n"
                    .to_vec(),
            ),
            HubFile::new("scripts/count.py", b"print(3)\n".to_vec()),
            HubFile::new("references/readme.md", b"Exact reference bytes.\n".to_vec()),
        ],
        SkillCapabilitySurface::default(),
    );
    let hash = package.content_hash().expect("bundle fixture");
    package.record.content_hash = Some(hash);
    package
}

/// CONS-06: the Owner's whole-vault export keeps source-file credentials
/// byte-equal to stored, while scoped and contact exports still null them.
#[test]
fn owner_archive_keeps_skill_source_credentials_and_restores_them() -> Result<()> {
    let (_dir, vault) = open_vault();
    // The tainted package of the in-crate CONS-06 contract, built through
    // public doors only.
    let mut tainted = package();
    tainted.files.push(HubFile::new(
        "scripts/private.py",
        b"api_key = 'residual-file-credential'\n".to_vec(),
    ));
    tainted.files.push(HubFile::new(
        "signature.json",
        b"{\"signature\":\"residual-signature\"}".to_vec(),
    ));
    let hash = tainted.content_hash()?;
    tainted.record.content_hash = Some(hash);
    let id = vault.import_skill_from_hub(
        &HubRef::new(EntityId::now(), "fixture/redacted", HubPin::None)?,
        &tainted,
        TimeRange {
            start: 100,
            end: 120,
        },
        130,
    )?;
    // The Owner's whole-vault export keeps every source file byte-equal to
    // stored, keeps the tree's identity hash, and names no redaction.
    let export = vault.export_whole_vault(true)?;
    export.manifest().validate()?;
    assert!(export.manifest().secrets_included);
    let document = vault.read_whole_vault_archive(export.bytes())?;
    let tree = document
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == id.to_hex())
        .expect("skill bundle")
        .source_tree
        .as_ref()
        .expect("skill source tree");
    assert_eq!(
        tree.content_hash,
        Some(tainted.content_hash()?.to_hex()),
        "the owner's archive keeps the skill's exact source identity"
    );
    for want in &tainted.files {
        let got = tree
            .files
            .iter()
            .find(|file| file.path == want.path)
            .expect("carried source file");
        assert_eq!(
            got.content,
            ExportSourceContent::Text(
                String::from_utf8(want.content.clone()).expect("UTF-8 fixture")
            ),
            "the owner's archive keeps {} byte-equal",
            want.path
        );
        assert!(got.sha256.is_some(), "a kept file keeps its proof");
    }
    assert_eq!(tree.files.len(), tainted.files.len());
    assert!(
        !document
            .manifest
            .bundle_omissions
            .iter()
            .any(|omission| omission.entity_id == id.to_hex()),
        "the owner's archive names no redaction for its skill"
    );
    assert!(
        !document
            .manifest
            .import_refusals
            .iter()
            .any(|refusal| matches!(
                refusal,
                ExportImportRefusal::Entity { entity_id, .. } if entity_id == &id.to_hex()
            )),
        "the owner's archive refuses nothing of its skill"
    );
    // The owner's archive restores the skill's exact source on import: a
    // fresh vault's own archive carries the same tree.
    let (_fresh_dir, fresh) = open_vault();
    fresh.import_whole_vault_archive(export.bytes())?;
    let again = fresh.export_whole_vault(true)?;
    assert!(again.manifest().secrets_included);
    let again_document = fresh.read_whole_vault_archive(again.bytes())?;
    let again_tree = again_document
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == id.to_hex())
        .expect("restored skill bundle")
        .source_tree
        .as_ref()
        .expect("restored skill source tree");
    assert_eq!(
        again_tree, tree,
        "import restores the exact source tree, and it re-exports byte-equal"
    );
    // Substantive negative checks need selected rows that hold the bytes: a
    // skill row alone carries metadata, not source. Seed scan-off ASSET
    // copies of every source file, as the in-crate contract does.
    scan_off(&vault, "principal:contact-source-residue", 131)?;
    let mut selected = vec![id];
    let mut source_files = Vec::new();
    for file in &tainted.files {
        let file_id = EntityId::now();
        vault.put_entity(
            &file_id,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: 100,
                end: 120,
            },
            130,
            &file.content,
        )?;
        assert_eq!(
            vault.get(&file_id)?.as_deref(),
            Some(file.content.as_slice()),
            "scan-off storage keeps {} byte-equal",
            file.path
        );
        selected.push(file_id);
        source_files.push((file_id, file.path.as_str()));
    }
    // A scoped record vector never carries the credential text.
    let top = Scope::top();
    let scoped = vault.export_records_in_scope(&top, &top, &top)?;
    let shipped: Vec<u8> = scoped
        .iter()
        .flat_map(|record| record.bytes.iter().copied())
        .collect();
    let shipped = String::from_utf8_lossy(&shipped);
    assert!(
        !shipped.contains("residual-file-credential"),
        "a scoped export carries no file credential"
    );
    assert!(
        !shipped.contains("residual-signature"),
        "a scoped export carries no signature credential"
    );
    // A contact bundle over the skill alone, and over the skill plus the
    // selected source copies, never carries the credential text.
    for ids in [&[id][..], &selected[..]] {
        let bundle: serde_json::Value =
            serde_json::from_slice(&vault.export_entity_bundle_json(ids)?)
                .expect("contact bundle JSON");
        let emitted = bundle.to_string();
        assert!(
            !emitted.contains("residual-file-credential"),
            "contact bundle: {emitted}"
        );
        assert!(
            !emitted.contains("residual-signature"),
            "contact bundle: {emitted}"
        );
    }
    let bundle: serde_json::Value =
        serde_json::from_slice(&vault.export_entity_bundle_json(&selected)?)
            .expect("contact bundle JSON");
    let entities = bundle["entities"].as_array().expect("contact entities");
    for (file_id, path) in &source_files {
        let carried = entities
            .iter()
            .find(|row| row["id"] == file_id.to_hex())
            .expect("contact output contains the selected source file");
        match *path {
            "scripts/private.py" => assert!(
                carried["body"].is_null(),
                "the credential file is nulled: {}",
                carried["body"]
            ),
            "signature.json" => assert!(
                carried["body"]["signature"].is_null(),
                "the credential member is nulled: {}",
                carried["body"]
            ),
            _ => {}
        }
    }
    Ok(())
}

/// CONS-07: the typed export still reads JSON text through every member, so a
/// token hidden behind JSON escapes or duplicate keys never leaves a scoped
/// or contact export; the Owner's whole-vault export keeps those bytes
/// byte-equal to stored.
#[test]
fn owner_archive_keeps_json_text_credentials() -> Result<()> {
    let (_dir, vault) = open_vault();
    scan_off(&vault, "principal:json-text-residue", 10)?;
    // A token-shaped value whose `p` is a JSON escape: no text rule reads it.
    let suffix = "0123456789abcdefghijklmnopqrstuvwxyz";
    let escaped = format!(r"gh\u0070_{suffix}");
    let scalar = format!(r#""{escaped}""#);
    let repeated = format!(r#"{{"note":"{escaped}","note":"kept"}}"#);
    let bodies = [scalar, repeated];
    let mut ids = Vec::new();
    for body in &bodies {
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_ASSET,
                TimeRange { start: 1, end: 1 },
                1,
                body.as_bytes(),
            )
            .commit()?;
        assert_eq!(
            vault.get(&id)?.as_deref(),
            Some(body.as_bytes()),
            "scan-off storage keeps the JSON text byte-equal"
        );
        ids.push(id);
    }
    // The Owner's whole-vault export keeps each body byte-equal to stored.
    let export = vault.export_whole_vault(true)?;
    export.manifest().validate()?;
    assert!(export.manifest().secrets_included);
    let document = vault.read_whole_vault_archive(export.bytes())?;
    for (id, body) in ids.iter().zip(bodies.iter()) {
        let row = document
            .evidence_ledger
            .entities
            .iter()
            .find(|row| row.id == id.to_hex())
            .expect("exported row");
        assert_eq!(
            row.body,
            ExportBody::Utf8(body.clone()),
            "the owner's archive keeps {body} byte-equal"
        );
    }
    // A scoped export still nulls them: an ASSET the release filter would
    // change leaves whole or not at all.
    let top = Scope::top();
    let scoped = vault.export_records_in_scope(&top, &top, &top)?;
    for id in &ids {
        for record in scoped.iter().filter(|record| record.id == *id) {
            assert!(
                !String::from_utf8_lossy(&record.bytes).contains(suffix),
                "a scoped record carries no token"
            );
        }
    }
    let shipped: Vec<u8> = scoped
        .iter()
        .flat_map(|record| record.bytes.iter().copied())
        .collect();
    assert!(
        !String::from_utf8_lossy(&shipped).contains(suffix),
        "the scoped export carries no token"
    );
    // A contact's shareable bundle still nulls them.
    let bundle: serde_json::Value = serde_json::from_slice(&vault.export_entity_bundle_json(&ids)?)
        .expect("contact bundle JSON");
    assert!(
        !bundle.to_string().contains(suffix),
        "contact bundle: {bundle}"
    );
    let entities = bundle["entities"].as_array().expect("contact entities");
    assert_eq!(entities.len(), 2);
    assert!(
        entities[0]["body"].is_null(),
        "the scalar token is nulled: {}",
        entities[0]["body"]
    );
    assert_eq!(bundle["manifest"]["secrets_nulled"]["payloads"], true);
    Ok(())
}

/// CONS-09: the Owner's whole-vault export keeps credential fields and
/// encoded payloads byte-equal to stored, while scoped and contact exports
/// still null them.
#[test]
fn owner_archive_keeps_credential_fields_and_binary_payloads() -> Result<()> {
    let (_dir, vault) = open_vault();
    scan_off(&vault, "principal:person-residue", 10)?;
    let id = EntityId::now();
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
        (Value::from("name"), Value::from("portable person")),
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
    // Residual credentials already on disk, through the public write door
    // with the owner's scan off: the door stores them as given.
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: 123,
            end: 456,
        },
        789,
        &bytes,
    )?;
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some(bytes.as_slice()),
        "scan-off storage keeps the person body byte-equal"
    );
    // The Owner's whole-vault export keeps the body typed, not nulled.
    let export = vault.export_whole_vault(true)?;
    export.manifest().validate()?;
    assert!(export.manifest().secrets_included);
    let document = vault.read_whole_vault_archive(export.bytes())?;
    let row = document
        .evidence_ledger
        .entities
        .iter()
        .find(|row| row.id == id.to_hex())
        .expect("person row");
    assert!(
        matches!(row.body, ExportBody::MessagePack(_)),
        "the owner's archive keeps the person body typed, not nulled"
    );
    // The destination owner also disables masking so this check isolates
    // exact archive restoration from the destination's write-scan policy.
    let (_fresh_dir, fresh) = open_vault();
    scan_off(&fresh, "principal:person-restore-residue", 10)?;
    fresh.import_whole_vault_archive(export.bytes())?;
    let stored = fresh.get(&id)?.expect("restored person row");
    let mut cursor = std::io::Cursor::new(&stored);
    let restored = rmpv::decode::read_value(&mut cursor).expect("restored person MessagePack");
    assert_eq!(field(&restored, "name"), &Value::from("portable person"));
    assert_eq!(
        field(&restored, "api_key"),
        &Value::from("unrecognizable-but-named-secret")
    );
    assert_eq!(
        field(&restored, "binary"),
        &Value::Binary(credential.as_bytes().to_vec())
    );
    assert_eq!(
        field(&restored, "nested_binary"),
        &Value::Binary(nested_payload.clone())
    );
    let Value::Array(byte_array) = field(&restored, "byte_array") else {
        panic!("byte array kept as an array");
    };
    assert_eq!(
        byte_array
            .iter()
            .map(|item| item.as_u64().expect("byte"))
            .collect::<Vec<_>>(),
        credential.bytes().map(u64::from).collect::<Vec<_>>()
    );
    assert_eq!(
        field(&restored, "json_bytes"),
        &Value::Binary(json_bytes_payload.clone())
    );
    assert_eq!(
        field(&restored, "public_binary"),
        &Value::Binary(b"inspectable public bytes".to_vec())
    );
    let Value::Array(byte_map) = field(&restored, "byte_map") else {
        panic!("byte map kept as an array");
    };
    assert_eq!(
        byte_map
            .iter()
            .map(|item| item.as_u64().expect("byte"))
            .collect::<Vec<_>>(),
        byte_map_payload
            .iter()
            .copied()
            .map(u64::from)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        field(&restored, "json_encoded_bytes"),
        &Value::from(json_encoded_bytes.as_str())
    );
    assert_eq!(
        field(&restored, "json_encoded_map"),
        &Value::from(json_encoded_map.as_str())
    );
    assert_eq!(field(&restored, "signature"), &Value::Binary(vec![1, 2, 3]));
    // A scoped export still nulls them: the row ships with its credentials
    // redacted in place and its safe fields kept.
    let top = Scope::top();
    let scoped = vault.export_records_in_scope(&top, &top, &top)?;
    let record = scoped
        .iter()
        .find(|record| record.id == id)
        .expect("the person ships scoped");
    let shipped = String::from_utf8_lossy(&record.bytes);
    for secret in [
        credential.as_str(),
        "unrecognizable-but-named-secret",
        "nested-secret",
        "json-secret",
        "byte-map-secret",
        "array-wrapped-secret",
    ] {
        assert!(
            !shipped.contains(secret),
            "a scoped record carries no credential"
        );
    }
    assert!(shipped.contains("portable person"));
    let shipped_all: Vec<u8> = scoped
        .iter()
        .flat_map(|record| record.bytes.iter().copied())
        .collect();
    assert!(
        !String::from_utf8_lossy(&shipped_all).contains(credential.as_str()),
        "the scoped export carries no token"
    );
    // A contact's shareable bundle still nulls them.
    let bundle: serde_json::Value =
        serde_json::from_slice(&vault.export_entity_bundle_json(&[id])?)
            .expect("contact bundle JSON");
    let entities = bundle["entities"].as_array().expect("contact entities");
    assert_eq!(entities.len(), 1);
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
            entities[0]["body"][name].is_null(),
            "contact bundle nulls {name}: {}",
            entities[0]["body"][name]
        );
    }
    assert_eq!(
        entities[0]["body"]["name"],
        serde_json::json!("portable person")
    );
    assert!(
        entities[0]["body"]["public_binary"]
            .to_string()
            .contains("inspectable public bytes")
    );
    assert_eq!(bundle["manifest"]["secrets_nulled"]["payloads"], true);
    Ok(())
}
