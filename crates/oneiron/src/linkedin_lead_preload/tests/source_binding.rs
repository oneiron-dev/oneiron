use super::*;

#[test]
fn linkedin_preload_rejects_caller_chosen_expected_type_entity_without_source_binding() -> TestResult
{
    for person in [false, true] {
        let (_temp, vault, actor) = setup();
        let file = tempfile::NamedTempFile::new()?;
        let mut document = serde_json::json!({
            "schemaVersion": 1,
            "companies": [{
                "externalId": "synthetic-company-1",
                "displayName": "Synthetic Imported Company"
            }],
            "contacts": []
        });
        if person {
            // Resolve the company first so refusal of the occupied person cannot
            // be confused with permitted partial progress on an earlier row.
            std::fs::write(file.path(), serde_json::to_vec(&document)?)?;
            vault.preload_linkedin_lead_corpus(file.path(), actor)?;
            document["contacts"] = serde_json::json!([{
                "externalId": "synthetic-person-1",
                "displayName": "Synthetic Imported Person",
                "companyExternalId": "synthetic-company-1"
            }]);
        }
        let external = key(person, 1);
        let occupied = id(&external);
        // The ordinary caller-chosen-id write door creates an unrelated entity
        // of the expected type, not a resolver-owned source identity.
        put_fixture_entity(
            &vault,
            &occupied,
            external.kind.entity_type(),
            b"synthetic unrelated caller-owned entity",
        )?;
        let original = vault.get_raw(&occupied)?.expect("occupied entity");
        let claim_id = display_name_claim_id(person, 1);
        assert!(vault.get_claim(&claim_id)?.is_none());
        let before = snapshot(&vault);
        std::fs::write(file.path(), serde_json::to_vec(&document)?)?;

        let result = vault.preload_linkedin_lead_corpus(file.path(), actor);
        let imported = vault.get_claim(&claim_id)?;
        assert!(
            result.is_err(),
            "an expected type at a caller-chosen derived id is not a source binding: \
             person={person}, preload={result:?}, absorbed_imported_fact={imported:?}"
        );
        assert_eq!(vault.get_raw(&occupied)?.as_ref(), Some(&original));
        assert!(
            imported.is_none(),
            "refusal must not attach imported facts to the unrelated occupied entity"
        );
        assert_eq!(snapshot(&vault), before);
    }
    Ok(())
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
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        b"\x81\xaesource_binding\x83\xa8provider\xa8linkedin\xa4kind\xa6person\xabexternal_id\xb0synthetic-shared"
    );
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
fn linkedin_resolver_requires_bound_expected_type_and_refuses_wrong_type() -> TestResult {
    for person in [false, true] {
        for bound in [false, true] {
            for kind in [ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON] {
                let (_temp, vault, _) = setup();
                let external = key(person, 1);
                let expected = id(&external);
                let data = if bound {
                    encode_body(&binding_body(person))?
                } else {
                    b"synthetic".to_vec()
                };
                put_fixture_entity(&vault, &expected, kind, &data)?;
                let before = snapshot(&vault);
                let resolved = resolve_linkedin_entity(&vault, external.clone());
                if bound && kind == external.kind.entity_type() {
                    assert_eq!(resolved?, (expected, Disposition::Reused));
                } else {
                    assert!(matches!(resolved, Err(LinkedInResolutionError::Vault(_))));
                }
                assert_eq!(snapshot(&vault), before);
            }
        }
    }
    Ok(())
}

// Independent fixture encoder: tests do not ask the production encoder to
// manufacture the identity proof that its own reader is expected to accept.
fn binding_body(person: bool) -> rmpv::Value {
    rmpv::Value::Map(vec![(
        "source_binding".into(),
        rmpv::Value::Map(vec![
            ("provider".into(), "linkedin".into()),
            (
                "kind".into(),
                if person { "person" } else { "company" }.into(),
            ),
            ("external_id".into(), key(person, 1).external_id.into()),
        ]),
    )])
}

fn encode_body(value: &rmpv::Value) -> TestResultBytes {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)?;
    Ok(bytes)
}

type TestResultBytes = Result<Vec<u8>, Box<dyn std::error::Error>>;

fn one_company_corpus() -> LinkedInLeadCorpus {
    let mut corpus = fixture();
    corpus.companies.truncate(1);
    corpus.contacts.clear();
    corpus
}

#[test]
fn linkedin_preload_rejects_unbound_mismatched_and_ambiguous_bindings_before_facts_or_edges()
-> TestResult {
    for person in [false, true] {
        for case in [
            "empty",
            "missing",
            "provider",
            "kind",
            "external_id",
            "untrimmed",
            "missing_inner",
            "duplicate_inner",
            "duplicate_outer",
            "extra_inner",
            "wrong_value_type",
            "wrong_shape",
            "trailing",
            "truncated",
        ] {
            let (_temp, vault, actor) = setup();
            let mut corpus = one_company_corpus();
            if person {
                // Earlier rows are already complete: a contact rejection must
                // leave no facts or employment edge on the occupied person.
                apply_linkedin_lead_corpus(&vault, corpus.clone(), actor)?;
                corpus.contacts.push(fixture().contacts.remove(0));
            }
            let mut body = binding_body(person);
            let rmpv::Value::Map(outer) = &mut body else {
                panic!("fixture")
            };
            if case == "duplicate_outer" {
                outer.push(outer[0].clone());
            } else {
                let rmpv::Value::Map(inner) = &mut outer[0].1 else {
                    panic!("fixture")
                };
                match case {
                    "provider" => inner[0].1 = "synthetic-other-provider".into(),
                    "kind" => inner[1].1 = if person { "company" } else { "person" }.into(),
                    "external_id" => inner[2].1 = "synthetic-other-private-id".into(),
                    "untrimmed" => inner[2].1 = format!(" {} ", key(person, 1).external_id).into(),
                    "missing_inner" => {
                        inner.pop();
                    }
                    "duplicate_inner" => {
                        inner[2] = inner[0].clone();
                    }
                    "extra_inner" => inner.push(("unexpected".into(), "synthetic".into())),
                    "wrong_value_type" => inner[2].1 = 1.into(),
                    _ => {}
                }
            }
            let mut bytes = match case {
                "empty" => Vec::new(),
                "missing" => encode_body(&rmpv::Value::Map(vec![(
                    "notes".into(),
                    "synthetic".into(),
                )]))?,
                "wrong_shape" => encode_body(&rmpv::Value::Array(vec![body]))?,
                _ => encode_body(&body)?,
            };
            if case == "trailing" {
                bytes.push(0xc0);
            } else if case == "truncated" {
                bytes.pop();
            }
            let external = key(person, 1);
            let occupied = id(&external);
            put_fixture_entity(&vault, &occupied, external.kind.entity_type(), &bytes)?;
            let before = snapshot(&vault);
            let error = apply_linkedin_lead_corpus(&vault, corpus, actor).expect_err("must reject");
            assert!(
                matches!(
                    error,
                    LinkedInLeadPreloadError::Resolution(LinkedInResolutionError::Vault(
                        Error::InvariantViolation(_)
                    ))
                ),
                "person={person}, case={case}, error={error:?}"
            );
            assert!(!format!("{error:?} {error}").contains("synthetic"));
            assert!(
                vault
                    .get_claim(&display_name_claim_id(person, 1))?
                    .is_none()
            );
            assert_eq!(snapshot(&vault), before, "person={person}, case={case}");
        }
    }
    Ok(())
}

#[test]
fn linkedin_bound_reruns_preserve_user_data_metadata_and_claim_edits() -> TestResult {
    let (temp, vault, actor) = setup();
    apply_linkedin_lead_corpus(&vault, fixture(), actor)?;
    for person in [false, true] {
        let external = key(person, 1);
        let mut body = binding_body(person);
        let rmpv::Value::Map(fields) = &mut body else {
            panic!("fixture")
        };
        fields.push(("notes".into(), "synthetic user edit".into()));
        fields.push(("custom".into(), rmpv::Value::Binary(vec![0, 255, 1])));
        // Map order is not identity. A valid exact binding in user-edited data
        // must be checked, then preserved byte-for-byte rather than normalized.
        let rmpv::Value::Map(binding) = &mut fields[0].1 else {
            panic!("fixture")
        };
        binding.reverse();
        fields.reverse();
        vault.put_entity(
            &id(&external),
            external.kind.entity_type(),
            TimeRange { start: 8, end: 11 },
            17,
            &encode_body(&body)?,
        )?;
        let claim_id = display_name_claim_id(person, 1);
        let mut claim = vault.get_claim(&claim_id)?.expect("imported claim");
        claim.value = "Synthetic user-corrected name".into();
        vault.put_claim(&claim_id, &claim, TimeRange { start: 2, end: 3 }, 19)?;
        vault.retract_claim(&claim_id, 21)?;
    }
    let before = snapshot(&vault);
    drop(vault);
    let reopened = Vault::open(temp.path(), VaultConfig::default())?;
    let mut corpus = fixture();
    corpus.companies[0].display_name = "Synthetic replacement company name".into();
    corpus.contacts[0].display_name = "Synthetic replacement person name".into();
    let report = apply_linkedin_lead_corpus(&reopened, corpus, actor)?;
    assert_eq!(
        (
            report.created_entities(),
            report.created_edges(),
            report.claims_admitted
        ),
        (0, 0, 0)
    );
    assert_eq!((report.companies_reused, report.contacts_reused), (2, 3));
    assert_eq!(snapshot(&reopened), before);
    Ok(())
}

#[test]
fn linkedin_replacing_bound_body_cannot_leave_a_stale_reuse_proof() -> TestResult {
    for person in [false, true] {
        let (_temp, vault, _) = setup();
        let external = key(person, 1);
        let (occupied, _) = resolve_linkedin_entity(&vault, external.clone())?;
        put_fixture_entity(
            &vault,
            &occupied,
            external.kind.entity_type(),
            b"synthetic replacement body",
        )?;
        let before = snapshot(&vault);
        assert!(matches!(
            resolve_linkedin_entity(&vault, external),
            Err(LinkedInResolutionError::Vault(Error::InvariantViolation(_)))
        ));
        assert_eq!(snapshot(&vault), before);
    }
    Ok(())
}

fn binding_transaction_snapshot(vault: &Vault) -> Vec<Rows> {
    let mut rows = snapshot(vault);
    let txn = vault.store.env.read_txn().expect("fixture");
    for db in [
        &vault.store.vault_meta,
        &vault.store.short_ids,
        &vault.store.short_ids_reverse,
        &vault.store.temporal_occurred_start,
        &vault.store.temporal_occurred_end,
        &vault.store.temporal_long_intervals,
    ] {
        rows.push(
            db.iter(&txn)
                .expect("fixture")
                .map(|row| {
                    let (key, value) = row.expect("fixture");
                    (key.to_vec(), value.to_vec())
                })
                .collect(),
        );
    }
    rows
}

#[test]
fn linkedin_entity_and_binding_roll_back_together_with_secondary_indexes() -> TestResult {
    for person in [false, true] {
        let (_temp, vault, _) = setup();
        let external = key(person, 1);
        let expected = id(&external);
        let before = binding_transaction_snapshot(&vault);
        let result: crate::Result<()> = vault.with_write_txn(|wtxn| {
            assert_eq!(
                crate::linkedin_lead_preload::source_binding::resolve_in_txn(
                    &vault, wtxn, &expected, &external,
                )?,
                Disposition::Created,
            );
            let raw = vault
                .get_raw_in(wtxn, &expected)?
                .expect("staged bound entity");
            let mut cursor = std::io::Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
            let rmpv::Value::Map(staged) =
                rmpv::decode::read_value(&mut cursor).expect("bound body")
            else {
                panic!("bound body must contain binding fields")
            };
            let rmpv::Value::Map(required) = binding_body(person) else {
                panic!("fixture")
            };
            for (binding_name, required_binding) in required {
                let (_, staged_binding) = staged
                    .iter()
                    .find(|(name, _)| name == &binding_name)
                    .expect("required source binding");
                let rmpv::Value::Map(staged_fields) = staged_binding else {
                    panic!("source binding must contain identity fields")
                };
                let rmpv::Value::Map(required_fields) = required_binding else {
                    panic!("fixture")
                };
                for (field, value) in required_fields {
                    let (_, staged_value) = staged_fields
                        .iter()
                        .find(|(name, _)| name == &field)
                        .expect("required binding identity field");
                    assert_eq!(staged_value, &value);
                }
            }
            // Fail after both entity and binding have been staged. This is the
            // same production transaction helper, with no test-only write path.
            Err(Error::InvariantViolation("synthetic forced rollback"))
        });
        assert!(matches!(result, Err(Error::InvariantViolation(_))));
        assert!(vault.get_raw(&expected)?.is_none());
        assert_eq!(binding_transaction_snapshot(&vault), before);
        assert_eq!(
            resolve_linkedin_entity(&vault, external.clone())?,
            (expected, Disposition::Created)
        );
        assert_eq!(
            resolve_linkedin_entity(&vault, external)?,
            (expected, Disposition::Reused)
        );
    }
    Ok(())
}
