use super::*;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::edge::EdgeActorClass;
use crate::gate::{ClaimGateWrite, GateWriteMode};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use crate::test_util::{entity, put_policy_manifest_bytes};
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use rmpv::Value;

fn fixture() -> Result<(tempfile::TempDir, crate::Vault, ClaimBody, WriteEnvelope)> {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    vault.with_write_txn(|wtxn| {
        let ids = vault
            .store
            .type_index
            .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
            .map(|row| {
                let (key, _) = row?;
                EntityId::from_bytes(key[1..].try_into().expect("type index id"))
            })
            .collect::<Result<Vec<_>>>()?;
        for id in ids {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
        }
        Ok(())
    })?;
    let manifest = serde_json::json!({
        "schema_version": "1.1", "pack_id": "receipt-rollback", "pack_version": "1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": { "criticality": "normal", "sensitivity": "normal" },
        "rules": [],
        "actor_ceilings": [{ "actor_class": "agent", "ceiling": "auto" }],
        "source_trust": { "generated": { "max_auto_sensitivity": 0, "receipted": true, "warned": true } },
        "signatures": [{ "alg": "ed25519", "key_id": "owner", "sig": "test-signature" }]
    });
    let data = rmp_serde::to_vec_named(&manifest).expect("encode policy");
    put_policy_manifest_bytes(&vault, entity(0x70), &data)?;
    let actor = entity(0x40);
    let subject = entity(0x50);
    for id in [actor, subject] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"fixture",
        )?;
    }
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        Value::from("Ada"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    body.evidence = Some(Value::Map(vec![(
        Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
        crate::dreamer_consolidation::encode_consolidation_evidence(
            &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
                refs: vec![subject],
                chain: Vec::new(),
                source_meet: ClaimSource::Generated,
            },
        ),
    )]));
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("runner"),
                Value::from(crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (Value::from("run_id"), Value::from("receipt-late-error")),
        ]))?,
        ClaimApprovalStatus::Auto,
    );
    Ok((dir, vault, body, envelope))
}

#[test]
fn a_structural_refusal_preserves_only_its_receipt_and_no_candidate_rows() -> Result<()> {
    let (_dir, vault, body, envelope) = fixture()?;
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let mut staged = Vec::new();
    let mut ids = HashMap::new();
    for (index, claim) in [entity(0x30), entity(0x31)].into_iter().enumerate() {
        let mut candidate = body.clone();
        if index == 1 {
            candidate.value = Value::from("");
        }
        let mut recorded = None;
        let result = crate::gate::check_claim_policy_for_write_with_record(
            &vault.store,
            &mut wtxn,
            &claim,
            ClaimGateWrite {
                body: &candidate,
                envelope: Some(&envelope),
                auto_checker: None,
                defer_metrics_until_commit: true,
            },
            &policy,
            GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
                include_source_in_gate_input: false,
            },
            &mut recorded,
        );
        let staged_result = stage_preflight_decision(
            &vault.store,
            &mut wtxn,
            &claim,
            recorded,
            result,
            &mut staged,
            &mut ids,
        );
        if index == 0 {
            staged_result?;
        } else {
            let error = staged_result.expect_err("empty output is refused");
            assert_eq!(
                error
                    .gate_denial()
                    .expect("typed denial")
                    .outcome()
                    .as_str(),
                "deny"
            );
        }
    }
    wtxn.commit()?;
    let decisions = vault.store.gate_decisions(256)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].claim_id, Some(*entity(0x31).as_bytes()));
    assert_eq!(decisions[0].outcome, "deny");
    assert_eq!(
        decisions[0].reason_codes,
        ["gate.deny.dreamer_precommit.degenerate_output"]
    );
    for claim in [entity(0x30), entity(0x31)] {
        assert!(vault.get_raw(&claim)?.is_none());
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .pending_gate_consent_in_txn(&rtxn, &claim)?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn late_refusal_preserves_only_its_receipt() -> Result<()> {
    let (_dir, vault, mut body, envelope) = fixture()?;
    let mut txn = vault.store.env.write_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let mut staged = Vec::new();
    let mut ids = HashMap::new();
    for (index, claim) in [entity(0x30), entity(0x31)].into_iter().enumerate() {
        if index == 1 {
            body.approval = ClaimApprovalStatus::Proposed;
        }
        let pending_envelope = WriteEnvelope::new(
            WriteActor::new(entity(0x41), EdgeActorClass::Agent),
            ClaimSource::Generated,
            envelope.provenance().clone(),
            ClaimApprovalStatus::Proposed,
        );
        let active_envelope = if index == 0 {
            &envelope
        } else {
            &pending_envelope
        };
        let mut recorded = None;
        crate::gate::check_claim_policy_for_write_with_record(
            &vault.store,
            &mut txn,
            &claim,
            ClaimGateWrite {
                body: &body,
                envelope: Some(active_envelope),
                auto_checker: None,
                defer_metrics_until_commit: true,
            },
            &policy,
            GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
                include_source_in_gate_input: false,
            },
            &mut recorded,
        )?;
        if index == 0 {
            assert_eq!(recorded.as_ref().unwrap().outcome(), "allow");
            stage_preflight_decision(
                &vault.store,
                &mut txn,
                &claim,
                recorded,
                Ok(()),
                &mut staged,
                &mut ids,
            )?;
        } else {
            assert_eq!(recorded.as_ref().unwrap().outcome(), "pending");
            let error = crate::Error::Gate(crate::error::GateError::SourceNotTrustedForAuto {
                claim_source: "generated",
            });
            assert!(
                stage_preflight_decision(
                    &vault.store,
                    &mut txn,
                    &claim,
                    recorded,
                    Err(error),
                    &mut staged,
                    &mut ids
                )
                .is_err()
            );
        }
    }
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].outcome(), "pending");
    txn.commit()?;
    let decisions = vault.store.gate_decisions(256)?;
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].claim_id, Some(*entity(0x31).as_bytes()));
    Ok(())
}
