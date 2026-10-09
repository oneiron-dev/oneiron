use super::*;
use crate::unix_seconds_now;

mod employment;
mod source_binding;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, GateError};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> LinkedInLeadCorpus {
    LinkedInLeadCorpus {
        schema_version: 1,
        companies: (1..=2)
            .map(|i| LinkedInCompanySeed {
                external_id: format!("synthetic-company-{i}"),
                display_name: format!("Synthetic Company {i}"),
                profile_url: Some(format!("https://linkedin.example/company/synthetic-{i}")),
                website_domain: Some(format!("company-{i}.example")),
            })
            .collect(),
        contacts: (1..=3)
            .map(|i| LinkedInContactSeed {
                external_id: format!("synthetic-person-{i}"),
                display_name: "Synthetic Person".into(),
                company_external_id: format!("synthetic-company-{}", if i < 3 { 1 } else { 2 }),
                title: Some("Synthetic Buyer".into()),
                profile_url: Some(format!("https://linkedin.example/in/synthetic-{i}")),
            })
            .collect(),
    }
}

fn put_fixture_entity(vault: &Vault, id: &EntityId, kind: u8, data: &[u8]) -> crate::Result<()> {
    vault.put_entity(id, kind, TimeRange { start: 1, end: 1 }, 1, data)
}

fn setup() -> (tempfile::TempDir, Vault, WriteActor) {
    let temp = tempfile::tempdir().expect("fixture");
    let vault = Vault::open(temp.path(), VaultConfig::default()).expect("fixture");
    let id = EntityId::from_bytes([0x31; 16]).expect("fixture");
    put_fixture_entity(&vault, &id, ENTITY_TYPE_PERSON, b"").expect("fixture");
    employment::permit_imported(&vault, id).expect("fixture");
    (temp, vault, WriteActor::new(id, EdgeActorClass::Human))
}

fn key(person: bool, i: usize) -> LinkedInExternalKey {
    if person {
        LinkedInExternalKey::person(&format!("synthetic-person-{i}")).expect("fixture")
    } else {
        LinkedInExternalKey::company(&format!("synthetic-company-{i}")).expect("fixture")
    }
}

fn id(key: &LinkedInExternalKey) -> EntityId {
    EntityId::derive(LINKEDIN_ENTITY, &[key.source_ref().as_bytes()]).expect("fixture")
}

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

fn snapshot(vault: &Vault) -> Vec<Rows> {
    let txn = vault.store.env.read_txn().expect("fixture");
    [
        &vault.store.entities,
        &vault.store.edges_out,
        &vault.store.edges_in,
        &vault.store.type_index,
        &vault.store.temporal_learned,
    ]
    .iter()
    .map(|db| {
        db.iter(&txn)
            .expect("fixture")
            .map(|row| {
                let (key, value) = row.expect("fixture");
                (key.to_vec(), value.to_vec())
            })
            .collect()
    })
    .collect()
}

fn field<'a>(value: &'a rmpv::Value, name: &str) -> &'a rmpv::Value {
    evidence_field(value, name).expect("fixture")
}

fn display_name_claim_id(person: bool, i: usize) -> EntityId {
    EntityId::derive(
        LINKEDIN_CLAIM,
        &[
            key(person, i).source_ref().as_bytes(),
            b"linkedin.display_name",
        ],
    )
    .expect("fixture")
}

#[test]
fn linkedin_preload_facts_use_imported_evidence_admission() -> TestResult {
    let (_temp, vault, actor) = setup();
    let initial_claims = vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?;
    let mut corpus = fixture();
    corpus.contacts[0].display_name = "  Synthetic Person \t".into();
    let before = unix_seconds_now();
    assert_eq!(
        apply_linkedin_lead_corpus(&vault, corpus, actor)?.claims_admitted,
        15
    );
    for (person, count, predicates) in [
        (
            false,
            2,
            [
                "linkedin.display_name",
                "linkedin.profile_url",
                "linkedin.website_domain",
            ],
        ),
        (
            true,
            3,
            [
                "linkedin.display_name",
                "linkedin.title",
                "linkedin.profile_url",
            ],
        ),
    ] {
        for i in 1..=count {
            let source = key(person, i).source_ref();
            for predicate in predicates {
                let claim_id =
                    EntityId::derive(LINKEDIN_CLAIM, &[source.as_bytes(), predicate.as_bytes()])?;
                let body = vault.get_claim(&claim_id)?.expect("fixture");
                assert_eq!(body.subject, ClaimSubject::Entity(id(&key(person, i))));
                assert_eq!(body.predicate, predicate);
                assert_eq!(body.source, Some(ClaimSource::Imported));
                assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
                assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
                let evidence = body.evidence.expect("fixture");
                assert_eq!(
                    field(&evidence, "actor_entity_ref"),
                    &rmpv::Value::Binary(actor.entity_ref().as_bytes().to_vec())
                );
                for name in ["provenance", "candidate_evidence"] {
                    assert_eq!(
                        field(field(&evidence, name), "source_id").as_str(),
                        Some("linkedin-lead-corpus")
                    );
                    assert_eq!(
                        field(field(&evidence, name), "source_record_id").as_str(),
                        Some(source.as_str())
                    );
                }
                if person && i == 1 && predicate == "linkedin.display_name" {
                    assert_eq!(body.value.as_str(), Some("  Synthetic Person \t"));
                }
                let raw = vault.get_raw(&claim_id)?.expect("fixture");
                let header = EntityMetadataHeader::parse(&raw).expect("fixture");
                assert!((before..=unix_seconds_now()).contains(&header.learned_at));
                assert_eq!(
                    (header.occurred_start, header.occurred_end),
                    (header.learned_at, header.learned_at)
                );
            }
        }
    }
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?,
        initial_claims + 18
    );
    Ok(())
}

#[test]
fn linkedin_preload_schema_required_strings_and_actor_fail_before_writes() {
    let (_temp, vault, actor) = setup();
    let before = snapshot(&vault);
    for case in 0..7 {
        let mut corpus = fixture();
        match case {
            0 => corpus.schema_version = 2,
            1 => corpus.companies[1].display_name = " \t".into(),
            2 => corpus.contacts[2].display_name = " \n".into(),
            3 => corpus.contacts[2].external_id = "synthetic\0-id".into(),
            4 => corpus.companies[1].external_id.clear(),
            5 => corpus.contacts[2].company_external_id = " \t".into(),
            _ => corpus.companies[1].external_id = "synthetic\u{7f}".into(),
        }
        let error = apply_linkedin_lead_corpus(&vault, corpus, actor).expect_err("must reject");
        assert!(matches!(
            error,
            LinkedInLeadPreloadError::Malformed { .. }
                | LinkedInLeadPreloadError::SchemaVersionUnsupported {
                    found: 2,
                    supported: 1
                }
        ));
        assert!(!format!("{error:?}").contains("synthetic"));
        assert_eq!(snapshot(&vault), before);
    }
    let missing = WriteActor::new(id(&key(true, 1)), EdgeActorClass::Human);
    for corpus in [
        fixture(),
        LinkedInLeadCorpus {
            schema_version: 1,
            companies: vec![],
            contacts: vec![],
        },
    ] {
        assert!(matches!(
            apply_linkedin_lead_corpus(&vault, corpus, missing),
            Err(LinkedInLeadPreloadError::Vault(Error::EntityNotFound))
        ));
        assert_eq!(snapshot(&vault), before);
    }
}

#[test]
fn linkedin_preload_preserves_provenanced_employment_edges() -> TestResult {
    let (_temp, vault, actor) = setup();
    apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    let claim_id = employment::employment_claim_id();
    vault.retract_edge_provenance(&claim_id, unix_seconds_now())?;
    let before = snapshot(&vault);
    assert_eq!(
        apply_linkedin_lead_corpus(&vault, fixture(), actor)?.employed_by_reused,
        3
    );
    assert_eq!(snapshot(&vault), before);
    Ok(())
}

#[test]
fn linkedin_preload_gate_failure_and_claim_id_collision_do_not_bypass_admission() -> TestResult {
    let (_temp, vault, actor) = setup();
    let claim_id = display_name_claim_id(false, 1);
    put_fixture_entity(&vault, &claim_id, ENTITY_TYPE_PERSON, b"")?;
    let occupied = vault.get_raw(&claim_id)?;
    assert!(matches!(
        apply_linkedin_lead_corpus(&vault, fixture(), actor),
        Err(LinkedInLeadPreloadError::Vault(Error::InvalidClaimBody(_)))
    ));
    assert_eq!(vault.get_raw(&claim_id)?, occupied);
    let (_other_temp, other, other_actor) = setup();
    let initial_claims = other.count_entities_by_type(ENTITY_TYPE_CLAIM)?;
    crate::test_util::put_policy_manifest_bytes(
        &other,
        EntityId::from_bytes([0x33; 16])?,
        b"synthetic-invalid-manifest",
    )?;
    assert!(matches!(
        apply_linkedin_lead_corpus(&other, fixture(), other_actor),
        Err(LinkedInLeadPreloadError::Vault(Error::Gate(
            GateError::GateWriteRejected { .. }
        )))
    ));
    assert_eq!(
        other.count_entities_by_type(ENTITY_TYPE_CLAIM)?,
        initial_claims
    );
    assert_eq!(
        other.get_entity_type(&id(&key(false, 1)))?,
        Some(ENTITY_TYPE_ORG)
    );
    Ok(())
}

#[test]
fn linkedin_preload_actor_class_mismatch_rejects_empty_fresh_and_reused_without_writes()
-> TestResult {
    for state in ["empty", "fresh", "reused"] {
        let (_temp, vault, actor) = setup();
        let mut corpus = fixture();
        if state == "empty" {
            corpus.companies.clear();
            corpus.contacts.clear();
        } else if state == "reused" {
            apply_linkedin_lead_corpus(&vault, corpus.clone(), actor)?;
        }
        let before = snapshot(&vault);
        let invalid = WriteActor::new(actor.entity_ref(), EdgeActorClass::System);
        let error = apply_linkedin_lead_corpus(&vault, corpus, invalid).expect_err("must reject");
        assert!(
            matches!(error, LinkedInLeadPreloadError::Vault(Error::Claim(ClaimError::ActorClassMismatch {
            actor_entity_type: ENTITY_TYPE_PERSON, actor_class,
        })) if actor_class == EdgeActorClass::System as u8)
        );
        assert_eq!(snapshot(&vault), before, "{state}");
    }
    Ok(())
}

#[test]
fn linkedin_preload_rejects_structurally_valid_occupied_claim_identity_mismatches() -> TestResult {
    for (section, name) in [
        ("claim", "subject"),
        ("claim", "predicate"),
        ("claim", "source"),
        ("claim", "evidence"),
        ("provenance", "source_id"),
        ("provenance", "source_record_id"),
        ("candidate_evidence", "source_id"),
        ("candidate_evidence", "source_record_id"),
        ("provenance", "kind"),
        ("candidate_evidence", "kind"),
        ("provenance", "duplicate"),
        ("claim", "duplicate"),
    ] {
        let (_temp, vault, actor) = setup();
        let external = key(false, 1);
        let company = resolve_linkedin_entity(&vault, external.clone())?.0;
        let facts = [("linkedin.display_name", Some("Synthetic Company 1"))];
        assert_eq!(admit_facts(&vault, &external, company, actor, &facts)?, 1);
        let claim_id = display_name_claim_id(false, 1);
        let mut body = vault.get_claim(&claim_id)?.expect("fixture");
        match (section, name) {
            ("claim", "subject") => body.subject = ClaimSubject::Entity(actor.entity_ref()),
            ("claim", "predicate") => body.predicate = "synthetic.unrelated".into(),
            ("claim", "source") => body.source = Some(ClaimSource::UserStated),
            ("claim", "evidence") => body.evidence = None,
            _ => {
                let rmpv::Value::Map(entries) = body.evidence.as_mut().expect("fixture") else {
                    panic!("fixture");
                };
                if section == "claim" {
                    entries.push(
                        entries
                            .iter()
                            .find(|(k, _)| k.as_str() == Some("provenance"))
                            .expect("fixture")
                            .clone(),
                    );
                } else {
                    let metadata = &mut entries
                        .iter_mut()
                        .find(|(k, _)| k.as_str() == Some(section))
                        .expect("fixture")
                        .1;
                    let rmpv::Value::Map(fields) = metadata else {
                        panic!("fixture");
                    };
                    if name == "duplicate" {
                        fields.push(
                            fields
                                .iter()
                                .find(|(k, _)| k.as_str() == Some("source_id"))
                                .expect("fixture")
                                .clone(),
                        );
                    } else {
                        fields
                            .iter_mut()
                            .find(|(k, _)| k.as_str() == Some(name))
                            .expect("fixture")
                            .1 = rmpv::Value::from("synthetic-unrelated-private");
                    }
                }
            }
        }
        vault.put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)?;
        vault.get_claim(&claim_id)?.expect("valid CLAIM fixture");
        let before = snapshot(&vault);
        let error = apply_linkedin_lead_corpus(&vault, fixture(), actor).expect_err("must reject");
        assert!(
            matches!(
                error,
                LinkedInLeadPreloadError::Vault(Error::InvalidClaimBody(_))
            ),
            "{section}.{name}"
        );
        assert!(!format!("{error:?} {error}").contains("synthetic"));
        assert_eq!(snapshot(&vault), before, "{section}.{name}");
    }
    Ok(())
}
