use super::*;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::edge::EdgeActorClass;
use crate::gate::{ClaimGateWrite, GateOutcome, GateWriteMode};
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
        "schema_version": "1.1", "pack_id": "breaker-rollback", "pack_version": "1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": { "criticality": "normal", "sensitivity": "normal" },
        "rules": [],
        "actor_ceilings": [{ "actor_class": "agent", "ceiling": "auto" }],
        "source_trust": { "generated": { "max_auto_sensitivity": 0, "receipted": true, "warned": true } },
        "signatures": [{ "alg": "ed25519", "key_id": "owner", "sig": "test-signature" }],
        "actor_burst_breaker": { "max_events": 1, "window_secs": 600 }
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
            (Value::from("run_id"), Value::from("breaker-late-error")),
        ]))?,
        ClaimApprovalStatus::Auto,
    );
    Ok((dir, vault, body, envelope))
}

#[test]
fn rejected_pending_decision_unwinds_even_the_preserved_receipts_breaker() -> Result<()> {
    let (_dir, vault, body, envelope) = fixture()?;
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let mut staged = Vec::new();
    let mut ids = HashMap::new();
    let mut breaker_key = None;
    for (index, claim) in [entity(0x30), entity(0x31)].into_iter().enumerate() {
        let mut recorded = None;
        crate::gate::check_claim_policy_for_write_as_original_event(
            &vault.store,
            &mut wtxn,
            &claim,
            ClaimGateWrite {
                body: &body,
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
        )?;
        let decision = recorded.as_ref().expect("recorded original event");
        if index == 0 {
            assert_eq!(decision.decision().outcome(), GateOutcome::Allow);
            breaker_key = Some(decision.breaker_undo().expect("first mutation").0.clone());
            stage_preflight_decision(
                &vault.store,
                &mut wtxn,
                &claim,
                recorded,
                Ok(()),
                &mut staged,
                &mut ids,
            )?;
        } else {
            assert_eq!(decision.decision().outcome(), GateOutcome::Pending);
            assert!(decision.breaker_demoted());
            assert!(decision.breaker_undo().expect("trip mutation").2.is_some());
            // Model any validation error after the pending decision was
            // recorded. This boundary must remain safe even when the current
            // evaluator detects missing source permits earlier.
            let error = stage_preflight_decision(
                &vault.store,
                &mut wtxn,
                &claim,
                recorded,
                Err(crate::Error::SourceNotTrustedForAuto {
                    claim_source: "generated",
                }),
                &mut staged,
                &mut ids,
            )
            .expect_err("late validation rejects the claim");
            assert!(matches!(
                error,
                crate::Error::SourceNotTrustedForAuto { .. }
            ));
        }
    }
    assert!(
        vault
            .store
            .vault_meta
            .get(&wtxn, &breaker_key.expect("breaker key"))?
            .is_none()
    );
    assert_eq!(staged.len(), 1, "retain only the refusal receipt");
    assert_eq!(staged[0].outcome(), "pending");
    wtxn.commit()?;
    assert!(
        !vault
            .gate_breaker_run_projection("breaker-late-error")?
            .gate_breaker_paused
    );
    let decisions = vault.store.gate_decisions(256)?;
    assert_eq!(
        decisions.len(),
        1,
        "no orphan trip or earlier allow receipt"
    );
    assert_eq!(decisions[0].claim_id, Some(*entity(0x31).as_bytes()));
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
fn staged_outcomes_follow_receipt_fifo_including_empty_slots() -> Result<()> {
    let (_dir, vault, body, envelope) = fixture()?;
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &wtxn)?;
    let claim = entity(0x30);
    let mut staged = Vec::new();
    let mut ids = HashMap::new();
    for _ in 0..2 {
        stage_preflight_decision(
            &vault.store,
            &mut wtxn,
            &claim,
            None,
            Ok(()),
            &mut staged,
            &mut ids,
        )?;
        let mut recorded = None;
        crate::gate::check_claim_policy_for_write_as_original_event(
            &vault.store,
            &mut wtxn,
            &claim,
            ClaimGateWrite {
                body: &body,
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
        )?;
        stage_preflight_decision(
            &vault.store,
            &mut wtxn,
            &claim,
            recorded,
            Ok(()),
            &mut staged,
            &mut ids,
        )?;
    }
    let outcomes = staged_claim_gate_outcomes(&staged);
    assert_eq!(
        outcomes.len(),
        2,
        "same claim ID retains both original events"
    );
    let mut take = || {
        ids.get_mut(&claim)
            .and_then(VecDeque::pop_front)
            .flatten()
            .and_then(|decision_id| outcomes.get(&decision_id))
    };
    assert!(take().is_none());
    let first = take().expect("first original event");
    assert_eq!(first.outcome, GateOutcome::Allow);
    assert!(!first.breaker_demoted);
    assert!(take().is_none());
    let second = take().expect("second original event");
    assert_eq!(second.outcome, GateOutcome::Pending);
    assert!(second.breaker_demoted);
    assert_ne!(first.decision_id, second.decision_id);
    assert!(take().is_none());
    Ok(())
}
