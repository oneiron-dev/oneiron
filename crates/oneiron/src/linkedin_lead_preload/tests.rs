use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::provenance::{EdgeRef, SupersessionStatus};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};

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

fn setup() -> (tempfile::TempDir, Vault, WriteActor) {
    let temp = tempfile::tempdir().expect("fixture");
    let vault = Vault::open(temp.path(), VaultConfig::default()).expect("fixture");
    let id = EntityId::from_bytes([0x31; 16]).expect("fixture");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"",
        )
        .expect("fixture");
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
    derived_id(b"oneiron.linkedin.entity.v1", &[&key.source_ref()]).expect("fixture")
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

#[derive(Debug, Eq, PartialEq)]
struct Graph {
    entities: Vec<(Vec<u8>, u8)>,
    edges: Vec<Vec<u8>>,
    active_claims: Vec<EntityId>,
}

fn graph(vault: &Vault) -> Graph {
    let rows = snapshot(vault);
    Graph {
        entities: rows[0]
            .iter()
            .map(|(key, value)| (key.clone(), value[0]))
            .collect(),
        edges: rows[1].iter().map(|(key, _)| key.clone()).collect(),
        active_claims: vault
            .entities_by_type(ENTITY_TYPE_CLAIM)
            .expect("fixture")
            .into_iter()
            .filter(|id| {
                vault
                    .get_claim(id)
                    .expect("fixture")
                    .expect("fixture")
                    .lifecycle
                    == ClaimLifecycleStatus::Active
            })
            .collect(),
    }
}

fn field<'a>(value: &'a rmpv::Value, name: &str) -> &'a rmpv::Value {
    &value
        .as_map()
        .expect("fixture")
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .expect("fixture")
        .1
}

#[test]
fn linkedin_entity_id_is_domain_separated_and_stable() -> TestResult {
    let (temp, vault, _) = setup();
    let key = LinkedInExternalKey::person(" \tsynthetic-shared\r\n")?;
    assert_eq!(key.source_ref(), "linkedin:person:synthetic-shared");
    let expected = blake3::hash(b"oneiron.linkedin.entity.v1linkedin:person:synthetic-shared");
    let before = unix_seconds_now();
    let (person, disposition) = resolve_linkedin_entity(&vault, key.clone())?;
    assert_eq!(person.as_bytes().as_slice(), &expected.as_bytes()[..16]);
    assert_eq!(disposition, Disposition::Created);
    let raw = vault.get_raw(&person)?.expect("fixture");
    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN);
    let header = EntityMetadataHeader::parse(&raw).expect("fixture");
    assert_eq!(header.entity_type, ENTITY_TYPE_PERSON);
    assert_eq!(
        (header.occurred_start, header.occurred_end),
        (header.learned_at, header.learned_at)
    );
    assert!((before..=unix_seconds_now()).contains(&header.learned_at));
    let company = LinkedInExternalKey::company("synthetic-shared")?;
    assert_eq!(company.source_ref(), "linkedin:company:synthetic-shared");
    assert_ne!(person, resolve_linkedin_entity(&vault, company)?.0);
    drop(vault);
    let reopened = Vault::open(temp.path(), VaultConfig::default())?;
    assert_eq!(
        resolve_linkedin_entity(&reopened, key)?,
        (person, Disposition::Reused)
    );
    assert_eq!(reopened.get_raw(&person)?.expect("fixture"), raw);
    Ok(())
}

#[test]
fn linkedin_external_ids_are_opaque_and_resolver_revalidates() -> TestResult {
    for value in [
        "Synthetic:ID /?x=1",
        "synthetic-id",
        "SYNTHETIC-ID",
        "\u{a0}",
        "synthetic\u{85}id",
    ] {
        assert_eq!(LinkedInExternalKey::person(value)?.external_id, value);
    }
    assert_ne!(
        id(&LinkedInExternalKey::person("synthetic-id")?),
        id(&LinkedInExternalKey::person("SYNTHETIC-ID")?)
    );
    let (_temp, vault, _) = setup();
    let before = snapshot(&vault);
    for value in [
        "",
        " \t\r\n",
        "synthetic\n-id",
        "synthetic\0-id",
        "synthetic\u{7f}",
    ] {
        let key = LinkedInExternalKey {
            kind: LinkedInEntityKind::Person,
            external_id: value.into(),
        };
        let error = resolve_linkedin_entity(&vault, key).expect_err("must reject");
        if value.trim_ascii().is_empty() {
            assert!(matches!(error, LinkedInResolutionError::EmptySourceId));
        } else {
            assert!(matches!(
                error,
                LinkedInResolutionError::MalformedExternalId
            ));
        }
        assert_eq!(snapshot(&vault), before);
    }
    Ok(())
}

#[test]
fn linkedin_resolver_concurrent_invocations_create_once() -> TestResult {
    let (_temp, vault, _) = setup();
    let barrier = std::sync::Barrier::new(2);
    let (left, right) = std::thread::scope(|scope| {
        let resolve = || {
            barrier.wait();
            resolve_linkedin_entity(&vault, key(true, 99))
        };
        let left = scope.spawn(resolve);
        let right = scope.spawn(resolve);
        (
            left.join().expect("resolver"),
            right.join().expect("resolver"),
        )
    });
    let (left, right) = (left?, right?);
    assert_eq!(left.0, right.0);
    assert_ne!(left.1, right.1);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?, 0);
    Ok(())
}

#[test]
fn linkedin_resolver_reuses_expected_type_and_refuses_wrong_type() -> TestResult {
    for kind in [ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON] {
        let (_temp, vault, _) = setup();
        let external = key(true, 1);
        let expected = id(&external);
        vault.put_entity(
            &expected,
            kind,
            TimeRange { start: 1, end: 1 },
            1,
            b"synthetic",
        )?;
        let before = snapshot(&vault);
        let resolved = resolve_linkedin_entity(&vault, external);
        if kind == ENTITY_TYPE_PERSON {
            assert_eq!(resolved?, (expected, Disposition::Reused));
        } else {
            assert!(matches!(resolved, Err(LinkedInResolutionError::Vault(_))));
        }
        assert_eq!(snapshot(&vault), before);
    }
    Ok(())
}

#[test]
fn linkedin_preload_second_run_creates_nothing() -> TestResult {
    let (_temp, vault, actor) = setup();
    let first = apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    assert_eq!(
        first,
        LinkedInLeadPreloadReport {
            companies_created: 2,
            contacts_created: 3,
            employed_by_created: 3,
            claims_admitted: 15,
            ..Default::default()
        }
    );
    let before = snapshot(&vault);
    let second = apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    assert_eq!(
        second,
        LinkedInLeadPreloadReport {
            companies_reused: 2,
            contacts_reused: 3,
            employed_by_reused: 3,
            ..Default::default()
        }
    );
    assert_eq!((second.created_entities(), second.created_edges()), (0, 0));
    assert_eq!((second.companies_seen(), second.contacts_seen()), (2, 3));
    let missing = WriteActor::new(EntityId::from_bytes([0x34; 16])?, EdgeActorClass::Human);
    assert!(matches!(
        apply_linkedin_lead_corpus(&vault, fixture(), missing),
        Err(LinkedInLeadPreloadError::Vault(Error::EntityNotFound))
    ));
    assert_eq!(snapshot(&vault), before);
    let claim_id = derived_id(
        b"oneiron.linkedin.claim.v1",
        &[&key(true, 1).source_ref(), "linkedin.display_name"],
    )?;
    vault.retract_claim(&claim_id, unix_seconds_now())?;
    let closed = snapshot(&vault);
    assert_eq!(
        apply_linkedin_lead_corpus(&vault, fixture(), actor)?.claims_admitted,
        0
    );
    assert_eq!(snapshot(&vault), closed);
    Ok(())
}

#[test]
fn linkedin_preload_partial_prior_state_converges_without_duplicates() -> TestResult {
    let (_temp, vault, actor) = setup();
    let (_clean_temp, clean, clean_actor) = setup();
    let company = resolve_linkedin_entity(&vault, key(false, 1))?.0;
    let person = resolve_linkedin_entity(&vault, key(true, 1))?.0;
    resolve_employment(&vault, person, company)?;
    assert_eq!(
        admit_facts(
            &vault,
            &key(false, 1),
            company,
            actor,
            &[("linkedin.display_name", Some("Synthetic Company 1"))]
        )?,
        1
    );
    let report = apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    assert_eq!(
        report,
        LinkedInLeadPreloadReport {
            companies_created: 1,
            companies_reused: 1,
            contacts_created: 2,
            contacts_reused: 1,
            employed_by_created: 2,
            employed_by_reused: 1,
            claims_admitted: 14,
        }
    );
    apply_linkedin_lead_corpus(&clean, fixture(), clean_actor)?;
    assert_eq!(graph(&vault), graph(&clean));
    Ok(())
}

#[test]
fn linkedin_preload_creates_no_counterparty_contact_rows() -> TestResult {
    let (_temp, vault, actor) = setup();
    let before = vault.count_entities_by_type(ENTITY_TYPE_COUNTERPARTY_CONTACT)?;
    apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_COUNTERPARTY_CONTACT)?,
        before
    );
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_ORG)?, 2);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_PERSON)?, 4); // Includes actor.
    for i in 1..=3 {
        let person = id(&key(true, i));
        let company = id(&key(false, if i < 3 { 1 } else { 2 }));
        assert_eq!(
            vault.targets(&person, EdgeKind::EmployedBy, Some(ENTITY_TYPE_ORG))?,
            vec![company]
        );
        assert!(!vault.edge_exists(&company, EdgeKind::EmployedBy, &person)?);
        let edge = vault
            .edges_out(&person)?
            .into_iter()
            .find(|edge| edge.kind == EdgeKind::EmployedBy)
            .expect("fixture");
        assert_eq!(Some(edge.weight), EdgeKind::EmployedBy.default_weight());
    }
    assert_ne!(id(&key(true, 1)), id(&key(true, 2))); // Same name, different ids.
    Ok(())
}

#[test]
fn linkedin_preload_facts_use_imported_evidence_admission() -> TestResult {
    let (_temp, vault, actor) = setup();
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
                let preimage = format!("oneiron.linkedin.claim.v1{source}{predicate}");
                let hash = blake3::hash(preimage.as_bytes());
                let claim_id = EntityId::from_bytes(hash.as_bytes()[..16].try_into()?)?;
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
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_CLAIM)?, 15);
    Ok(())
}

#[test]
fn linkedin_preload_metadata_order_and_omissions_do_not_reidentify_or_delete() -> TestResult {
    let (_temp, vault, actor) = setup();
    let mut corpus = fixture();
    corpus.contacts[0].title = None;
    assert_eq!(
        apply_linkedin_lead_corpus(&vault, corpus.clone(), actor)?.claims_admitted,
        14
    );
    let original = snapshot(&vault);
    corpus.contacts[0].title = Some("Synthetic New Title".into());
    corpus.contacts[0].display_name = "Synthetic Renamed Person".into();
    corpus.companies[0].website_domain = Some("changed.example".into());
    corpus.companies.reverse();
    corpus.contacts.reverse();
    let report = apply_linkedin_lead_corpus(&vault, corpus, actor)?;
    assert_eq!(
        (
            report.created_entities(),
            report.created_edges(),
            report.claims_admitted
        ),
        (0, 0, 1)
    );
    let before = snapshot(&vault);
    for (old, new) in original.iter().zip(&before) {
        assert!(old.iter().all(|row| new.contains(row)));
    }
    let empty = LinkedInLeadCorpus {
        schema_version: 1,
        companies: vec![],
        contacts: vec![],
    };
    assert_eq!(
        apply_linkedin_lead_corpus(&vault, empty, actor)?,
        LinkedInLeadPreloadReport::default()
    );
    assert_eq!(snapshot(&vault), before);
    Ok(())
}

#[test]
fn linkedin_preload_rejects_bad_cross_reference_before_writes() {
    let (_temp, vault, actor) = setup();
    let before = snapshot(&vault);
    let mut corpus = fixture();
    corpus.contacts[2].company_external_id = "synthetic-missing".into();
    assert!(matches!(
        apply_linkedin_lead_corpus(&vault, corpus, actor),
        Err(LinkedInLeadPreloadError::CrossRefUnresolved { contact_index: 2 })
    ));
    assert_eq!(snapshot(&vault), before);
}

#[test]
fn linkedin_preload_rejects_duplicate_external_id_before_writes() {
    let (_temp, vault, actor) = setup();
    let before = snapshot(&vault);
    for company in [true, false] {
        let mut corpus = fixture();
        if company {
            corpus.companies[1].external_id = " \tsynthetic-company-1\n".into();
        } else {
            corpus.contacts[2].external_id = " synthetic-person-1 ".into();
        }
        let error = apply_linkedin_lead_corpus(&vault, corpus, actor).expect_err("must reject");
        assert!(matches!(
            error,
            LinkedInLeadPreloadError::Malformed {
                reason: "duplicate external id",
                ..
            }
        ));
        assert_eq!(snapshot(&vault), before);
    }
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
fn linkedin_preload_trims_ids_and_allows_same_bytes_across_kinds() -> TestResult {
    let (_temp, vault, actor) = setup();
    let mut corpus = fixture();
    corpus.companies[0].external_id = " \tsynthetic-shared\n".into();
    corpus.contacts[0].external_id = "synthetic-shared".into();
    for contact in &mut corpus.contacts[..2] {
        contact.company_external_id = " synthetic-shared ".into();
    }
    apply_linkedin_lead_corpus(&vault, corpus, actor)?;
    let person = id(&LinkedInExternalKey::person("synthetic-shared")?);
    let company = id(&LinkedInExternalKey::company("synthetic-shared")?);
    assert_ne!(person, company);
    assert!(vault.edge_exists(&person, EdgeKind::EmployedBy, &company)?);
    Ok(())
}

#[test]
fn linkedin_preload_preserves_provenanced_employment_edges() -> TestResult {
    let (_temp, vault, actor) = setup();
    apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    let bound = vault.as_actor(actor.entity_ref(), EdgeActorClass::Human);
    let body = bound.provenance_body(0.9, SupersessionStatus::Confirmed);
    let subject = EdgeRef::new(id(&key(true, 1)), EdgeKind::EmployedBy, id(&key(false, 1)));
    bound.put_edge_provenance(
        &EntityId::from_bytes([0x32; 16])?,
        &subject,
        &body,
        unix_seconds_now(),
    )?;
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
    let claim_id = derived_id(
        b"oneiron.linkedin.claim.v1",
        &[&key(false, 1).source_ref(), "linkedin.display_name"],
    )
    .expect("fixture");
    vault.put_entity(
        &claim_id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"",
    )?;
    let occupied = vault.get_raw(&claim_id)?;
    assert!(matches!(
        apply_linkedin_lead_corpus(&vault, fixture(), actor),
        Err(LinkedInLeadPreloadError::Vault(Error::InvalidClaimBody(_)))
    ));
    assert_eq!(vault.get_raw(&claim_id)?, occupied);
    let (_other_temp, other, other_actor) = setup();
    crate::test_util::put_policy_manifest_bytes(
        &other,
        EntityId::from_bytes([0x33; 16])?,
        b"synthetic-invalid-manifest",
    )?;
    assert!(matches!(
        apply_linkedin_lead_corpus(&other, fixture(), other_actor),
        Err(LinkedInLeadPreloadError::Vault(
            Error::GateWriteRejected { .. }
        ))
    ));
    assert_eq!(other.count_entities_by_type(ENTITY_TYPE_CLAIM)?, 0);
    assert_eq!(
        other.get_entity_type(&id(&key(false, 1)))?,
        Some(ENTITY_TYPE_ORG)
    );
    Ok(())
}

#[test]
fn linkedin_preload_explicit_path_rejects_document_shapes_without_writes() -> TestResult {
    let (_temp, vault, actor) = setup();
    let file = tempfile::NamedTempFile::new()?;
    let before = snapshot(&vault);
    for document in [
        r#"[]"#, r#"[1,[],[]]"#, r#"null"#, r#"{}"#, r#"{"schemaVersion":1,"companies":[],"contacts":[],"synthetic-secret":"synthetic-private"}"#,
        r#"{"schemaVersion":1,"companies":[{"externalId":"synthetic-c","displayName":"Synthetic","synthetic-secret":1}],"contacts":[]}"#,
        r#"{"schemaVersion":1,"companies":[],"contacts":[{"externalId":"synthetic-p","displayName":"Synthetic","companyExternalId":"synthetic-c","synthetic-secret":1}]}"#,
        r#"{"schemaVersion":1,"schemaVersion":1,"companies":[],"contacts":[]}"#,
        r#"{"schemaVersion":1,"companies":[["synthetic-c","Synthetic",null,null]],"contacts":[]}"#,
        r#"{"schemaVersion":1,"companies":[],"contacts":[]} trailing"#,
    ].into_iter().map(str::as_bytes).chain([b"\xff".as_slice()]) {
        std::fs::write(file.path(), document)?;
        let error = vault.preload_linkedin_lead_corpus(file.path(), actor).expect_err("must reject");
        assert!(matches!(error, LinkedInLeadPreloadError::Malformed { kind: "document", index: 0, .. }));
        assert!(!format!("{error:?}").contains("synthetic"));
        assert_eq!(snapshot(&vault), before);
    }
    std::fs::write(
        file.path(),
        r#"{"schemaVersion":1,"companies":[{"externalId":"synthetic-c","displayName":"Synthetic Company"}],"contacts":[]}"#,
    )?;
    let report = vault.preload_linkedin_lead_corpus(file.path(), actor)?;
    assert_eq!((report.companies_created, report.claims_admitted), (1, 1));
    let missing = file.path().with_extension("synthetic-missing");
    assert!(matches!(
        vault.preload_linkedin_lead_corpus(missing, actor),
        Err(LinkedInLeadPreloadError::Vault(Error::Io(_)))
    ));
    Ok(())
}

#[test]
fn linkedin_preload_fixture_is_synthetic() {
    let corpus = fixture();
    for company in corpus.companies {
        assert!(company.external_id.starts_with("synthetic-"));
        assert!(company.display_name.starts_with("Synthetic "));
        assert!(
            company
                .website_domain
                .expect("fixture")
                .ends_with(".example")
        );
        assert!(
            company
                .profile_url
                .expect("fixture")
                .starts_with("https://linkedin.example/")
        );
    }
    for contact in corpus.contacts {
        assert!(contact.external_id.starts_with("synthetic-"));
        assert!(contact.company_external_id.starts_with("synthetic-"));
        assert!(contact.display_name.starts_with("Synthetic "));
        assert!(contact.title.expect("fixture").starts_with("Synthetic "));
        assert!(
            contact
                .profile_url
                .expect("fixture")
                .starts_with("https://linkedin.example/")
        );
    }
}
