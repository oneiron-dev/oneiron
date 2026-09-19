//! Observable whole-vault export/import contracts.
use super::*;
use crate::affect::Vad;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::context_pack::PackFormat;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SECRET_CUSTODY};
use crate::serialize::{ExportBody, ExportValue};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;
use crate::{Vault, VaultConfig};
use rmpv::Value;

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).unwrap();
    bytes
}

fn range() -> TimeRange {
    TimeRange {
        start: 123,
        end: 456,
    }
}

fn raw_residue(vault: &Vault, id: &crate::EntityId, kind: u8, bytes: &[u8]) -> Result<()> {
    let mut raw = vec![kind];
    raw.extend_from_slice(&123_u64.to_be_bytes());
    raw.extend_from_slice(&456_u64.to_be_bytes());
    raw.extend_from_slice(&789_u64.to_be_bytes());
    raw.extend_from_slice(bytes);
    vault.with_write_txn(|txn| {
        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
        Ok(())
    })
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, v)| v)
        .unwrap()
}

#[test]
fn whole_vault_all_five_formats_null_credentials_and_encoded_payloads() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let id = crate::EntityId::now();
    let credential = format!("ghp_{}", "a".repeat(36));
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
            Value::Binary(encode(&Value::Map(vec![(
                Value::from("password"),
                Value::from("nested-secret"),
            )]))),
        ),
        (
            Value::from("byte_array"),
            Value::Array(credential.bytes().map(Value::from).collect()),
        ),
        (
            Value::from("json_bytes"),
            Value::Binary(br#"{"api_key":"json-secret"}"#.to_vec()),
        ),
        (
            Value::from("public_binary"),
            Value::Binary(b"inspectable public bytes".to_vec()),
        ),
        (
            Value::from("byte_map"),
            Value::Array(
                encode(&Value::Map(vec![(
                    Value::from("password"),
                    Value::from("byte-map-secret"),
                )]))
                .into_iter()
                .map(Value::from)
                .collect(),
            ),
        ),
        (
            Value::from("json_encoded_bytes"),
            Value::from(
                serde_json::json!({"payload": credential.bytes().collect::<Vec<_>>()}).to_string(),
            ),
        ),
        (
            Value::from("json_encoded_map"),
            Value::from(
                serde_json::json!({"payload": br#"{"password":"array-wrapped-secret"}"#.to_vec()})
                    .to_string(),
            ),
        ),
        (Value::from("signature"), Value::Binary(vec![1, 2, 3])),
    ]));
    // Simulate residual credentials already on disk, bypassing only the TEST
    // fixture's write wall. The export uses its real serializer and enumerator.
    raw_residue(&vault, &id, ENTITY_TYPE_PERSON, &bytes)?;
    raw_residue(
        &vault,
        &crate::EntityId::now(),
        ENTITY_TYPE_SECRET_CUSTODY,
        b"custody-value-never-serialized",
    )?;
    for format in [
        PackFormat::Json,
        PackFormat::Yaml,
        PackFormat::Toon,
        PackFormat::Markdown,
        PackFormat::Plaintext,
    ] {
        let export = vault.export_whole_vault(format)?;
        let text = std::str::from_utf8(export.bytes()).unwrap();
        export.manifest().validate(format)?;
        assert!(export.manifest().secrets_nulled);
        assert!(text.contains("portable person"));
        for secret in [
            credential.as_str(),
            "unrecognizable-but-named-secret",
            "nested-secret",
            "json-secret",
            "byte-map-secret",
            "custody-value-never-serialized",
        ] {
            assert!(!text.contains(secret), "credential escaped in {format:?}");
        }
        assert!(text.contains("evidence_ledger"));
        assert!(text.contains("derivation_envelopes"));
        assert!(text.contains("agent_packs"));
        if format == PackFormat::Json {
            let document = vault.read_whole_vault_json(export.bytes())?;
            let row = document
                .evidence_ledger
                .entities
                .iter()
                .find(|row| row.id == id.to_hex())
                .unwrap();
            let ExportBody::MessagePack(body) = &row.body else {
                panic!("MessagePack body expected");
            };
            let body = body.to_msgpack()?;
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
                assert_eq!(field(&body, name), &Value::Nil);
            }
            assert_eq!(
                field(&body, "public_binary"),
                &Value::Binary(b"inspectable public bytes".to_vec())
            );
            assert!(
                document
                    .entities()
                    .all(|row| row.entity_type != ENTITY_TYPE_SECRET_CUSTODY)
            );
        }
    }
    Ok(())
}

#[test]
fn whole_vault_json_roundtrip_preserves_ids_types_times_fields_graph_and_demotes_claims()
-> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let person = crate::EntityId::now();
    let peer = crate::EntityId::now();
    let claim = crate::EntityId::now();
    let body = encode(&Value::Map(vec![
        (Value::from("name"), Value::from("archive person")),
        (
            Value::from("unknown_metadata"),
            Value::Array(vec![Value::F32(-0.0), Value::from(u64::MAX)]),
        ),
    ]));
    source.put_entity(&person, ENTITY_TYPE_PERSON, range(), 789, &body)?;
    source.put_entity(&peer, ENTITY_TYPE_PERSON, range(), 789, b"peer")?;
    let mut knowledge = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(person),
        Value::from("matcha"),
        0.75,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    knowledge.salience = Some(0.625);
    knowledge.evidence = Some(Value::Map(vec![(
        Value::from("source_document"),
        Value::from("fixture"),
    )]));
    knowledge.valid_from = Some(10);
    knowledge.valid_to = Some(20);
    knowledge.world = Some(crate::EntityId::now());
    knowledge.rel = Some(crate::EntityId::now());
    knowledge.scope = Some(Value::Map(vec![(
        Value::from("export_scope"),
        Value::from("private"),
    )]));
    source.put_claim(&claim, &knowledge, range(), 789)?;
    let vad = Vad {
        valence: 0.2,
        arousal: 0.3,
        dominance: 0.4,
    };
    source
        .batch()
        .edge_with_created_at_and_vad(&person, EdgeKind::Mentions, &peer, 0.7, 654, vad)
        .commit()?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    let document = target.read_whole_vault_json(export.bytes())?;
    assert!(document.claims.iter().any(|row| row.id == claim.to_hex()));
    let receipt = target.import_whole_vault_json(export.bytes())?;
    assert!(receipt.inserted_entities >= 3);
    assert_ne!(
        receipt.authority.classification,
        VaultImportClassification::ByteFaithfulOwnerRestore
    );
    assert_eq!(target.get_raw(&person)?, source.get_raw(&person)?);
    assert_eq!(target.get_raw(&peer)?, source.get_raw(&peer)?);
    let imported = target.get_claim(&claim)?.unwrap();
    knowledge.source = Some(ClaimSource::Imported);
    knowledge.approval = ClaimApprovalStatus::Proposed;
    assert_eq!(imported, knowledge);
    let source_edges = source.edges_out(&person)?;
    let target_edges = target.edges_out(&person)?;
    assert_eq!(target_edges.len(), source_edges.len());
    assert_eq!(target_edges[0].target, peer);
    assert_eq!(target_edges[0].created_at, 654);
    assert_eq!(target_edges[0].vad, Some(vad));
    assert_eq!(target_edges[0].weight, 0.7);
    let repeated = target.import_whole_vault_json(export.bytes())?;
    assert_eq!(repeated.inserted_entities, 0);
    Ok(())
}

#[test]
fn whole_vault_import_rejects_manifest_drift_false_proof_and_forged_binary() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let id = crate::EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_PERSON, range(), 789, b"public")?;
    let export = vault.export_whole_vault(PackFormat::Json)?;
    let value: serde_json::Value = serde_json::from_slice(export.bytes()).unwrap();
    for path in ["manifest_version", "format", "secrets_nulled"] {
        let mut modified = value.clone();
        modified["manifest"][path] = match path {
            "manifest_version" => serde_json::json!(99),
            "format" => serde_json::json!("yaml"),
            _ => serde_json::json!(false),
        };
        assert!(matches!(
            vault.read_whole_vault_json(&serde_json::to_vec(&modified).unwrap()),
            Err(Error::InvalidConfig(_))
        ));
    }
    let mut document = vault.read_whole_vault_json(export.bytes())?;
    document
        .evidence_ledger
        .entities
        .iter_mut()
        .find(|row| row.id == id.to_hex())
        .unwrap()
        .body =
        ExportBody::MessagePack(ExportValue::EntityReference(b"a-key-in-bytes!!?".to_vec()));
    assert!(
        vault
            .read_whole_vault_json(&serde_json::to_vec(&document).unwrap())
            .is_err()
    );
    Ok(())
}

#[test]
fn whole_vault_import_collision_aborts_without_partial_writes() -> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let new = crate::EntityId::now();
    let collision = crate::EntityId::now();
    source.put_entity(&new, ENTITY_TYPE_PERSON, range(), 789, b"new")?;
    source.put_entity(&collision, ENTITY_TYPE_PERSON, range(), 789, b"source")?;
    target.put_entity(&collision, ENTITY_TYPE_PERSON, range(), 789, b"target")?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    assert!(target.import_whole_vault_json(export.bytes()).is_err());
    assert_eq!(target.get(&new)?, None);
    assert_eq!(target.get(&collision)?, Some(b"target".to_vec()));
    Ok(())
}

#[test]
fn whole_vault_export_skips_live_overlay_members_without_refusing_export() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let session = vault.off_record_session_vault().enter(
        "export-doc-session",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let overlay = session.overlay();
    let member = crate::EntityId::now();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        member.as_bytes(),
        b"private-overlay",
    )?;
    segment.commit()?;
    let public = crate::EntityId::now();
    vault.put_entity(&public, ENTITY_TYPE_PERSON, range(), 789, b"public-base")?;
    let export = vault.export_whole_vault(PackFormat::Json)?;
    let document = vault.read_whole_vault_json(export.bytes())?;
    assert!(document.entities().all(|row| row.id != member.to_hex()));
    assert!(document.entities().any(|row| row.id == public.to_hex()));
    session.close()?;
    Ok(())
}

#[test]
fn foreign_archive_authority_and_witness_rows_remain_data_not_local_rights() -> Result<()> {
    use crate::registry::*;
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let person = crate::EntityId::now();
    source.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        range(),
        789,
        b"portable person",
    )?;
    let mut ids = Vec::new();
    // Hostile/historical archive bytes must not become local acts merely because
    // their type byte claims to be an authority, audit, note or witness record.
    for kind in [
        ENTITY_TYPE_AUTHORITY_LOG,
        ENTITY_TYPE_FEDERATION_GRANT,
        ENTITY_TYPE_ACCESS_GRANT,
        ENTITY_TYPE_CONNECTOR_KEY,
        ENTITY_TYPE_CHANNEL_IDENTITY,
        ENTITY_TYPE_COUNTERPARTY_CONTACT,
        ENTITY_TYPE_OUTBOUND_GRANT,
        ENTITY_TYPE_DIAGNOSTIC,
        ENTITY_TYPE_REDACTION_AUDIT,
        ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
        ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        ENTITY_TYPE_COMM_RECORD,
        ENTITY_TYPE_PSYCH_PROFILE,
        ENTITY_TYPE_MESSAGE,
        ENTITY_TYPE_NOTE,
    ] {
        let id = crate::EntityId::now();
        raw_residue(&source, &id, kind, b"foreign local-act evidence")?;
        ids.push(id);
    }
    let export = source.export_whole_vault(PackFormat::Json)?;
    let document = target.read_whole_vault_json(export.bytes())?;
    assert!(document.manifest.import_refusals.is_empty());
    for id in &ids {
        assert!(document.entities().any(|row| row.id == id.to_hex()));
        assert!(
            document
                .manifest
                .import_omissions
                .iter()
                .any(|row| row.entity_id == id.to_hex())
        );
    }
    target.import_whole_vault_json(export.bytes())?;
    assert!(target.get_entity_type(&person)?.is_some());
    for id in ids {
        assert!(target.get_entity_type(&id)?.is_none());
    }
    // Re-import cannot turn omitted foreign rows into native authority either.
    let replay = target.import_whole_vault_json(export.bytes())?;
    assert_eq!(replay.inserted_entities, 0);
    Ok(())
}

#[test]
fn whole_vault_provenance_restore_replays_history_with_local_model_binding_and_policy() -> Result<()>
{
    use crate::edge::EdgeActorClass;
    use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let actor = crate::EntityId::now();
    let from = crate::EntityId::now();
    let to = crate::EntityId::now();
    for id in [actor, from, to] {
        source.put_entity(&id, ENTITY_TYPE_PERSON, range(), 789, b"archive actor")?;
    }
    let substrate = source.ensure_model_substrate("fixture model", "v1", 10)?;
    let local_substrate = target.ensure_model_substrate("fixture model", "v1", 1)?;
    assert_ne!(substrate, local_substrate);
    let edge = EdgeRef::new(from, EdgeKind::EmployedBy, to);
    source
        .batch()
        .edge_with_created_at_and_vad(&from, edge.kind, &to, 0.8, 8, crate::affect::Vad::NEUTRAL)
        .commit()?;
    let first = crate::EntityId::now();
    let second = crate::EntityId::now();
    let mut record = EdgeProvenanceClaimBody::new(actor, 0.7, SupersessionStatus::Proposed);
    record.substrate_ref = Some(substrate);
    source.put_edge_provenance(&first, &edge, &record, EdgeActorClass::Human, 10)?;
    record.confidence = 0.9;
    record.supersession_status = SupersessionStatus::Confirmed;
    source.put_edge_provenance(&second, &edge, &record, EdgeActorClass::Human, 20)?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    assert!(
        target
            .read_whole_vault_json(export.bytes())?
            .manifest
            .import_refusals
            .is_empty()
    );
    assert!(target.import_whole_vault_json(export.bytes()).is_err());
    assert!(target.get_claim(&first)?.is_none());
    assert!(target.get_entity_type(&actor)?.is_none());
    // This fixture explicitly installs a LOCAL Imported-source permit. The
    // production importer never mints or widens it from the archive.
    let mut policy =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice()).unwrap();
    let Value::Map(entries) = &mut policy else {
        panic!("policy");
    };
    let (_, Value::Map(trust)) = entries
        .iter_mut()
        .find(|(k, _)| k.as_str() == Some("source_trust"))
        .unwrap()
    else {
        panic!("trust");
    };
    trust.retain(|(key, _)| key.as_str() != Some("imported"));
    trust.push((
        "imported".into(),
        Value::Map(vec![
            ("actor_ref".into(), actor.to_hex().into()),
            (
                "max_auto_sensitivity".into(),
                u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND).into(),
            ),
            ("receipted".into(), true.into()),
            ("warned".into(), true.into()),
        ]),
    ));
    crate::test_util::put_policy_manifest_bytes(
        &target,
        crate::gate::default_policy_manifest_id()?,
        &encode(&policy),
    )?;
    target.import_whole_vault_json(export.bytes())?;
    let prior = target.get_claim(&first)?.unwrap();
    let head = target.get_claim(&second)?.unwrap();
    assert_eq!(prior.source, Some(ClaimSource::Imported));
    assert_eq!(prior.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(head.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        crate::provenance::decode_edge_provenance_body(&head.value)?.substrate_ref,
        Some(local_substrate)
    );
    let replay = target.import_whole_vault_json(export.bytes())?;
    assert_eq!(replay.inserted_entities, 0);
    Ok(())
}
