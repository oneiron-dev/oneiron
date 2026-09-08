//! Trust boundary: manifest fail-closed behavior, federated admission, and replication quarantine.

use super::*;

#[test]
fn policy_manifest_missing_fixture_fails_closed_where_required() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.criticality_for_predicate("profile.name"),
        PolicyCriticality::Critical
    );

    assert_auto_source_rejected(&vault, 0x64, ClaimSource::ToolOutput)?;
    assert_auto_source_rejected(&vault, 0x65, ClaimSource::Imported)?;
    assert_auto_source_rejected(&vault, 0x66, ClaimSource::Generated)?;

    let id = test_id(0x67);
    let body = source_trust_claim(ClaimSource::Observed);
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
        .commit()?;
    assert!(vault.get_raw(&id)?.is_some());
    Ok(())
}

#[test]
fn policy_manifest_malformed_fixture_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x52), b"not-msgpack")?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().malformed_manifest_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.criticality_for_predicate("profile.name"),
        PolicyCriticality::Critical
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x67,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn policy_manifest_malformed_source_trust_fails_closed_with_diagnostics() -> Result<()> {
    enum SourceTrustMalformed {
        Duplicate,
        NotAMap,
    }

    let cases = [
        (
            "duplicate_source_trust",
            0xB0,
            SourceTrustMalformed::Duplicate,
        ),
        ("source_trust_not_map", 0xB2, SourceTrustMalformed::NotAMap),
    ];

    for (case_name, seed, malformed) in cases {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![]);
        rewrite_policy_manifest_entries(&mut data, |entries| match malformed {
            SourceTrustMalformed::Duplicate => {
                let entry = source_trust_entry(ClaimSource::UserStated, 0);
                entries.push(entry.clone());
                entries.push(entry);
            }
            SourceTrustMalformed::NotAMap => {
                entries.push((Value::from(POLICY_SOURCE_TRUST_KEY), Value::from("bad")));
            }
        });
        put_policy_manifest_bytes(&vault, test_id(seed), &data)?;

        let policy = resolve(&vault)?;
        assert!(
            policy.diagnostics().malformed_manifest_seen,
            "{case_name}: malformed source_trust must set manifest diagnostics"
        );
        assert!(
            policy.is_fail_closed(),
            "{case_name}: policy must fail closed"
        );
        assert!(
            policy.enforces_write_gate(),
            "{case_name}: loaded malformed manifest must still enforce Gate"
        );

        let claim_id = test_id(seed + 1);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        let err = match vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(4), 4)
            .commit()
        {
            Ok(()) => {
                panic!("{case_name}: fail-closed policy must reject non-auto normal claim")
            }
            Err(err) => err,
        };

        assert_gate_rejected(err, "deny", &["gate.deny.policy_fail_closed"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
    }

    Ok(())
}

#[test]
fn policy_manifest_missing_schema_fixture_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
    ]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
    });
    put_policy_manifest_bytes(&vault, test_id(0x54), &data)?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().unsupported_schema_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x69,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn policy_manifest_version_fixture_degrades_to_most_restrictive() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
    ]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_MIN_ENGINE_VERSION_KEY) {
                *value = Value::from("999.0.0");
            }
        }
    });
    put_policy_manifest_bytes(&vault, test_id(0x53), &data)?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().engine_version_floor_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.actor_ceiling("first_party", None),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        policy.criticality_for_predicate("health.allergy"),
        PolicyCriticality::Critical
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x68,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn policy_manifest_unknown_axis_fails_closed_and_exposes_no_scoped_grants() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![
        source_trust_entry(ClaimSource::ToolOutput, 0),
        scoped_grants_entry(),
    ]);
    rewrite_policy_manifest_entries(&mut data, |entries| {
        for (key, value) in entries {
            if key.as_str() == Some(POLICY_DEFAULTS_KEY) {
                let Value::Map(defaults) = value else {
                    unreachable!("defaults are a map");
                };
                defaults.push((Value::from("future_axis"), Value::from("permit")));
            }
        }
    });
    put_policy_manifest_bytes(&vault, test_id(0x55), &data)?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert!(policy.diagnostics().unknown_axis_seen);
    assert!(policy.scoped_grants().is_empty());
    assert_eq!(
        policy.sensitivity_for_predicate("profile.name"),
        PolicySensitivity::Sensitive
    );
    assert_auto_source_gate_rejected(
        &vault,
        0x6A,
        ClaimSource::ToolOutput,
        "deny",
        &["gate.deny.policy_fail_closed"],
    )
}

#[test]
fn legacy_source_trust_pack_entity_does_not_relax_policy_inputs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut legacy = Vec::new();
    rmpv::encode::write_value(
        &mut legacy,
        &Value::Map(vec![
            (
                Value::from("manifest"),
                Value::from("dec_0005_predicate_pack"),
            ),
            source_trust_entry(ClaimSource::ToolOutput, 0),
        ]),
    )
    .expect("legacy source-trust encode");

    vault.put_entity(
        &test_id(0x56),
        crate::registry::ENTITY_TYPE_TASK_LIST,
        test_time(1),
        1,
        &legacy,
    )?;

    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert_eq!(policy.diagnostics().manifest_count, 0);
    assert_auto_source_rejected(&vault, 0x6B, ClaimSource::ToolOutput)
}

#[cfg(feature = "sync")]
#[test]
fn replay_path_skips_policy_source_trust_gate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x81);
    let data = source_trust_claim_data(ClaimSource::ToolOutput);

    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &data,
        )
        .commit()?;

    assert!(
        vault.get_raw(&id)?.is_some(),
        "replicated replay must not re-gate remote source trust"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_generated_auto_claim_merges_but_is_not_consolidatable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let strict_policy = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
    put_policy_manifest_bytes(&vault, test_id(0x87), &strict_policy)?;

    let id = test_id(0x88);
    let data = source_trust_claim_data(ClaimSource::Generated);
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &data,
        )
        .commit()?;

    let raw = vault
        .get_raw(&id)?
        .expect("foreign-manifest-approved descendant still merges");
    let body = decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], false)?;
    assert_eq!(body.source, Some(ClaimSource::Generated));
    assert!(
        crate::claim::claim_surfaceable(&body),
        "foreign-approved Auto/Generated descendant may still surface"
    );
    assert!(
        !crate::claim::claim_consolidatable(&body),
        "strict local consolidation must decline it as corroboration"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_allows_and_restamps_imported_claim() -> Result<()> {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::sync::loro_support::{import_doc, map_get_bytes};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
    put_policy_manifest_bytes(&vault, test_id(0x8A), &data)?;

    let id = test_id(0x8B);
    let remote_body = public_stamped(source_trust_claim(ClaimSource::ToolOutput));
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");
    let admitted =
        admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)?;

    let doc = create_window_doc("receiver", &key);
    import_doc(&doc, &admitted)?;
    let blob = map_get_bytes(&doc.get_map("entities"), &id.to_hex()).ok_or(Error::InvalidKey)?;
    let body = decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], false)?;
    assert_eq!(body.source, Some(ClaimSource::Imported));
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_denies_untrusted_import_with_auditable_reason() -> Result<()> {
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x8C);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");

    let err = admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Guest)
        .expect_err("imported auto claims need an explicit local trust floor");
    assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_denies_preapproved_untrusted_import() -> Result<()> {
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x8F);
    let mut remote_body = source_trust_claim(ClaimSource::ToolOutput);
    remote_body.approval = ClaimApprovalStatus::Approved;
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");

    let err = admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)
        .expect_err("preapproved federated claims still need local imported trust");
    assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn federated_admission_denial_does_not_regress_own_device_replay() -> Result<()> {
    use crate::sync::types::WindowKey;
    use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x8D);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body)?;
    let key = WindowKey::new("2026-03");
    let err = admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)
        .expect_err("federated path must enforce local imported trust floor");
    assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);

    let replay_id = test_id(0x8E);
    let replay_data = crate::claim::encode_claim_body(&remote_body)?;
    vault
        .batch()
        .put_replicated(
            &replay_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &replay_data,
        )
        .commit()?;
    assert!(
        vault.get_raw(&replay_id)?.is_some(),
        "own-device replicated replay remains trust-blind"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn gate_chokepoint_replicated_claim_stays_trust_blind() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![]);
    put_policy_manifest_bytes(&vault, test_id(0x80), &data)?;

    let id = test_id(0x83);
    let claim = source_trust_claim_data(ClaimSource::ToolOutput);
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time(5),
            5,
            &claim,
        )
        .commit()?;

    assert!(
        vault.get_raw(&id)?.is_some(),
        "replicated replay must not call the local Gate chokepoint"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_policy_manifest_is_rejected_and_cannot_relax_source_trust() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    let occurred = test_time(1);

    let batch_id = test_id(0x82);
    let err = vault
        .batch()
        .put_replicated(&batch_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
        .commit()
        .expect_err("replicated policy manifests must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
        "expected policy manifest maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&batch_id)?.is_none());

    let txn_id = test_id(0x83);
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(&txn_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
                .apply(wtxn)
        })
        .expect_err("txn replicated policy manifests must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
        "expected policy manifest maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&txn_id)?.is_none());

    assert_auto_source_rejected(&vault, 0x84, ClaimSource::ToolOutput)
}

#[cfg(feature = "sync")]
#[test]
fn replicated_access_grant_is_rejected_and_cannot_mint_local_grant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let principal = test_id(0x90);
    let person = test_id(0x91);
    let persona = test_id(0x92);
    let data = crate::access_grant::encode_access_grant_body(
        &crate::AccessGrant::companion_profile_read(principal, person, persona, 1),
    )?;
    let occurred = test_time(1);

    let batch_id = test_id(0x93);
    let err = vault
        .batch()
        .put_replicated(&batch_id, ENTITY_TYPE_ACCESS_GRANT, occurred, 1, &data)
        .commit()
        .expect_err("replicated access grants must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_ACCESS_GRANT),
        "expected access grant maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&batch_id)?.is_none());
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None
    );

    let txn_id = test_id(0x94);
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(&txn_id, ENTITY_TYPE_ACCESS_GRANT, occurred, 1, &data)
                .apply(wtxn)
        })
        .expect_err("txn replicated access grants must be rejected");
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_ACCESS_GRANT),
        "expected access grant maintenance rejection, got {err:?}"
    );
    assert!(vault.get_raw(&txn_id)?.is_none());
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None
    );

    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_quarantines_replicated_policy_manifest() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
    let id = test_id(0x85);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("local", &window_key);
    let blob = policy_manifest_blob(&data);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
        .expect("insert policy manifest into CRDT");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(materialized, 0);
    assert!(vault.get_raw(&id)?.is_none());
    let records = quarantined_records(&vault)?;
    assert!(
        records.iter().any(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "MaintenanceKindNotWritable"
        }),
        "rejected policy manifest replay should be quarantined, got {records:?}"
    );

    assert_auto_source_rejected(&vault, 0x86, ClaimSource::ToolOutput)
}

#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_quarantines_malformed_authority_log() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let id = test_id(0x87);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("local", &window_key);
    let blob = authority_log_blob(b"not an authority log body");
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
        .expect("insert malformed authority log into CRDT");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(materialized, 0);
    assert!(vault.get_raw(&id)?.is_none());
    let records = quarantined_records(&vault)?;
    assert!(
        records.iter().any(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "InvalidAuthorityLogBody"
        }),
        "malformed authority log replay should be quarantined, got {records:?}"
    );

    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn forward_rematerialize_quarantines_replicated_access_grant() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_insert_bytes;
    use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::forward_rematerialize;

    let (_tmp, vault) = temp_vault();
    let principal = test_id(0x95);
    let person = test_id(0x96);
    let persona = test_id(0x97);
    let data = crate::access_grant::encode_access_grant_body(
        &crate::AccessGrant::companion_profile_read(principal, person, persona, 1),
    )?;
    let id = test_id(0x98);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("local", &window_key);
    let blob = access_grant_blob(&data);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
        .expect("insert access grant into CRDT");
    doc.commit();

    let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
    assert_eq!(materialized, 0);
    assert!(vault.get_raw(&id)?.is_none());
    assert_eq!(
        vault.companion_profile_access_grant(&principal, &person, &persona)?,
        None
    );
    let records = quarantined_records(&vault)?;
    assert!(
        records.iter().any(|(_, record)| {
            record.container == QuarantineContainer::Entities
                && record.reason_code == "MaintenanceKindNotWritable"
        }),
        "rejected access grant replay should be quarantined, got {records:?}"
    );

    Ok(())
}
