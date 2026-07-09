use super::*;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use crate::store::Store;
use crate::types::VaultConfig;

const MINIMAL_TRANSCRIPT_FIXTURE: &str =
    include_str!("../../tests/fixtures/ingest/minimal_transcript.jsonl");
const NULL_OPTIONAL_METADATA_FIXTURE: &str =
    include_str!("../../tests/fixtures/ingest/null_optional_metadata.jsonl");

fn expected_jsonl_transcript_config() -> IngestSourceConfig {
    IngestSourceConfig {
        source_id: JSONL_TRANSCRIPT_SOURCE_ID,
        label: "JSONL transcript",
        format: IngestSourceFormat::JsonlTranscript,
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    }
}

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid test id")
}

fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = crate::Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn normalized_imported_claim() -> NormalizedIngestClaim {
    NormalizedIngestClaim {
        source_record_id: "turn-001".to_owned(),
        predicate: "profile.name".to_owned(),
        value: Value::String("Ada".to_owned()),
    }
}

fn proposed_admission(
    claim_id: EntityId,
    subject: EntityId,
    actor: EntityId,
) -> ImportedEvidenceAdmission {
    ImportedEvidenceAdmission::proposed(
        JSONL_TRANSCRIPT_SOURCE_ID,
        claim_id,
        ImportedEvidenceEntityResolution::subject(subject),
        WriteActor::new(actor, EdgeActorClass::Human),
        test_time(10),
        10,
    )
}

fn put_actor_and_subject(vault: &crate::Vault, actor: &EntityId, subject: &EntityId) {
    vault
        .put_entity(actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"import actor")
        .expect("put actor");
    vault
        .put_entity(
            subject,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"resolved subject",
        )
        .expect("put subject");
}

fn put_malformed_policy_manifest(vault: &crate::Vault, id: &EntityId) {
    let mut payload = Vec::new();
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(b"not a messagepack manifest");

    vault
        .with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
        .expect("put malformed policy manifest");
}

fn evidence_field<'a>(value: &'a MsgpackValue, field: &str) -> Option<&'a MsgpackValue> {
    let MsgpackValue::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(field)).then_some(value))
}

#[test]
fn ingest_registry_equals_known_harness_config() {
    let registry_configs = INGEST_SOURCE_REGISTRY.source_configs().collect::<Vec<_>>();
    let harness_configs = KNOWN_INGEST_HARNESS_CONFIG
        .source_configs()
        .collect::<Vec<_>>();

    assert!(std::ptr::eq(
        KNOWN_INGEST_HARNESS_CONFIG.registry(),
        &INGEST_SOURCE_REGISTRY
    ));
    assert_eq!(registry_configs, harness_configs);
    assert_eq!(registry_configs, [expected_jsonl_transcript_config()]);
}

#[test]
fn jsonl_transcript_policy_defaults_to_proposed_and_fails_closed_for_auto() {
    let config = INGEST_SOURCE_REGISTRY
        .get_config(JSONL_TRANSCRIPT_SOURCE_ID)
        .expect("jsonl source config");

    assert_eq!(config, expected_jsonl_transcript_config());
    assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
    assert_eq!(config.trust_ceiling.max_auto_sensitivity, None);
    assert_eq!(config.default_admission, ClaimApprovalStatus::Proposed);
    assert!(!config.trust_ceiling.permits_auto(Some(0)));
    assert!(!config.trust_ceiling.permits_auto(None));
}

#[test]
fn imported_evidence_admission_defaults_to_proposed_claim() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x11);
    let subject = test_id(0x12);
    let claim_id = test_id(0x13);
    put_actor_and_subject(&vault, &actor, &subject);

    admit_imported_evidence_claim(
        &vault,
        &normalized_imported_claim(),
        proposed_admission(claim_id, subject, actor),
    )?;

    let body = vault
        .get_claim(&claim_id)?
        .expect("imported evidence claim stored for review");
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(ClaimSource::Imported));
    assert_eq!(body.subject, ClaimSubject::Entity(subject));
    assert_eq!(body.value, MsgpackValue::from("Ada"));
    let evidence = body.evidence.expect("write envelope evidence");
    let candidate_evidence = evidence_field(
        &evidence,
        crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    )
    .expect("candidate evidence");
    assert_eq!(
        evidence_field(candidate_evidence, "source_record_id").and_then(MsgpackValue::as_str),
        Some("turn-001")
    );
    Ok(())
}

#[test]
fn imported_evidence_rejects_blank_source_id_before_persistence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x51);
    let subject = test_id(0x52);
    let claim_id = test_id(0x53);
    put_actor_and_subject(&vault, &actor, &subject);
    let mut admission = proposed_admission(claim_id, subject, actor);
    admission.source_id = " \t\n".to_owned();

    let err = admit_imported_evidence_claim(&vault, &normalized_imported_claim(), admission)
        .expect_err("blank source_id must fail before persistence");

    assert!(
        matches!(
            err,
            Error::InvalidClaimBody("imported evidence missing source_id")
        ),
        "expected InvalidClaimBody for blank source_id, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_rejects_blank_source_record_id_before_persistence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x61);
    let subject = test_id(0x62);
    let claim_id = test_id(0x63);
    put_actor_and_subject(&vault, &actor, &subject);
    let mut claim = normalized_imported_claim();
    claim.source_record_id = " \t\n".to_owned();

    let err =
        admit_imported_evidence_claim(&vault, &claim, proposed_admission(claim_id, subject, actor))
            .expect_err("blank source_record_id must fail before persistence");

    assert!(
        matches!(
            err,
            Error::InvalidClaimBody("imported evidence missing source_record_id")
        ),
        "expected InvalidClaimBody for blank source_record_id, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_auto_denial_leaves_no_candidate_claim() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x21);
    let subject = test_id(0x22);
    let claim_id = test_id(0x23);
    put_actor_and_subject(&vault, &actor, &subject);
    let admission =
        proposed_admission(claim_id, subject, actor).with_approval(ClaimApprovalStatus::Auto);

    let err = admit_imported_evidence_claim(&vault, &normalized_imported_claim(), admission)
        .expect_err("imported auto claim must be denied by default");

    assert!(
        matches!(
            err,
            Error::GateWriteRejected {
                outcome: "pending",
                ref reason_codes,
            } if reason_codes == &["gate.pending.source_trust"]
        ),
        "expected imported write-gate source-trust pending, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_requires_explicit_resolved_entity_before_persistence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x31);
    let missing_subject = test_id(0x32);
    let claim_id = test_id(0x33);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"import actor")?;

    let err = admit_imported_evidence_claim(
        &vault,
        &normalized_imported_claim(),
        proposed_admission(claim_id, missing_subject, actor),
    )
    .expect_err("missing resolved subject entity must abort admission");

    assert!(matches!(err, Error::EntityNotFound), "got {err:?}");
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_gate_denial_leaves_no_candidate_claim() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x41);
    let subject = test_id(0x42);
    let claim_id = test_id(0x43);
    put_actor_and_subject(&vault, &actor, &subject);
    put_malformed_policy_manifest(&vault, &test_id(0x44));

    let err = admit_imported_evidence_claim(
        &vault,
        &normalized_imported_claim(),
        proposed_admission(claim_id, subject, actor),
    )
    .expect_err("Gate fail-closed denial must abort admission");

    assert!(
        matches!(
            err,
            Error::GateWriteRejected {
                outcome: "deny",
                ref reason_codes
            } if reason_codes.as_slice() == ["gate.deny.policy_fail_closed"]
        ),
        "expected Gate deny, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn ingest_jsonl_transcript_fixture_normalizes_records_without_claims() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(JSONL_TRANSCRIPT_SOURCE_ID, MINIMAL_TRANSCRIPT_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(batch.source_id, JSONL_TRANSCRIPT_SOURCE_ID);
    assert_eq!(batch.records.len(), 2);
    assert!(
        batch.claims.is_empty(),
        "source normalization must not write claims"
    );

    assert_eq!(
        batch.records[0],
        NormalizedIngestRecord {
            source_record_id: "turn-001".to_owned(),
            thread_id: Some("dream-session-001".to_owned()),
            speaker: Some("dreamer".to_owned()),
            occurred_at: Some(1_773_532_800),
            text: "I saw a blue door at the end of a long hallway.".to_owned(),
        }
    );
    assert_eq!(
        batch.records[1],
        NormalizedIngestRecord {
            source_record_id: "turn-002".to_owned(),
            thread_id: Some("dream-session-001".to_owned()),
            speaker: Some("assistant".to_owned()),
            occurred_at: Some(1_773_532_806),
            text: "What did the door feel like?".to_owned(),
        }
    );
}

#[test]
fn ingest_jsonl_transcript_optional_null_metadata_is_absent() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(JSONL_TRANSCRIPT_SOURCE_ID, NULL_OPTIONAL_METADATA_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(
        batch.records.as_slice(),
        [NormalizedIngestRecord {
            source_record_id: "turn-null".to_owned(),
            thread_id: None,
            speaker: None,
            occurred_at: None,
            text: "Null optional metadata is omitted.".to_owned(),
        }]
    );
}

#[test]
fn ingest_jsonl_transcript_required_null_field_is_invalid() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            JSONL_TRANSCRIPT_SOURCE_ID,
            r#"{"id":null,"text":"required id is null"}"#,
        )
        .expect_err("required null field must fail");

    assert_eq!(
        err,
        IngestError::InvalidStringField {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            line: 1,
            field: "id",
        }
    );
}
