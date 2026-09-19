use super::tripwires::*;
use super::*;
use crate::receipt::{ReceiptKind, ReceiptRecord};
fn vault() -> (tempfile::TempDir, Vault) {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::open(d.path(), crate::VaultConfig::device()).unwrap();
    (d, v)
}
fn receipt(outcome: &str, kind: &str) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: format!("gate:{}", EntityId::now().to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: 100,
        actor: None,
        on_behalf_of: None,
        outcome: outcome.into(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: vec![],
        fields: BTreeMap::from([("content_kind".into(), kind.into())]),
    }
}
#[test]
fn consolidation_receipt_is_stable_and_malformed_input_is_silent() {
    let (_d, v) = vault();
    let mut r = receipt("denied", "claim");
    r.policy_trace
        .push("gate.deny.dreamer_precommit.degenerate_output".into());
    let ids = v
        .project_receipt_tripwires("run", std::slice::from_ref(&r), 100)
        .unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        ids,
        v.project_receipt_tripwires("run", std::slice::from_ref(&r), 100)
            .unwrap()
    );
    let e = decode_diagnostic_event_body(&v.get(&ids[0]).unwrap().unwrap()).unwrap();
    assert_eq!(e.event_class, DiagnosticEventClass::ConsolidationError);
    r.receipt_id = "malformed".into();
    assert!(
        v.project_receipt_tripwires("run", &[r], 100)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn manifest_bound_fires_at_equality_and_window_excludes_old_receipts() {
    let (_d, v) = vault();
    set_bounds(
        &v,
        TripwireBounds {
            window_secs: 60,
            consent_depth: 2,
            actor_writes: 3,
        },
    );
    let r = pending_receipt(&v);
    assert!(
        v.project_receipt_tripwires("run", std::slice::from_ref(&r), 100)
            .unwrap()
            .is_empty()
    );
    let second = pending_receipt(&v);
    assert_eq!(
        v.project_receipt_tripwires("run", &[r.clone(), second.clone()], 100)
            .unwrap()
            .len(),
        1
    );
    // Windowing uses the stored pending time, not a caller-provided timestamp.
    assert!(
        v.project_receipt_tripwires("run", &[r, second], 161)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn closed_form_degenerate_and_silent_runs_not_healthy_runs() {
    let (_d, v) = vault();
    let mut r = DreamerRunFacts {
        run_ref: EntityId::now(),
        completed_at: 100,
        completed: true,
        output_expected: true,
        output: "".into(),
        error_count: 1,
        conversation: false,
    };
    let ids = v
        .run_dreamer_output_tripwires("run", std::slice::from_ref(&r))
        .unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        decode_diagnostic_event_body(&v.get(&ids[0]).unwrap().unwrap())
            .unwrap()
            .event_class,
        DiagnosticEventClass::DreamerRunDegenerate
    );
    r.conversation = true;
    r.error_count = 0;
    let ids = v
        .run_dreamer_output_tripwires("run", std::slice::from_ref(&r))
        .unwrap();
    assert_eq!(
        decode_diagnostic_event_body(&v.get(&ids[0]).unwrap().unwrap())
            .unwrap()
            .event_class,
        DiagnosticEventClass::SilentConversationDegradation
    );
    r.output = "actual output".into();
    assert!(
        v.run_dreamer_output_tripwires("run", &[r])
            .unwrap()
            .is_empty()
    );
}
#[test]
fn signed_runs_persist_but_unsigned_tampered_and_foreign_runs_are_silent() {
    let (_d, v) = vault();
    // Use the canonical consent detector token from the receipt projector.
    let mut r = receipt("denied", crate::consent::CONSENT_CONTENT_KIND);
    r.policy_trace
        .push(crate::consent::CONSENT_REASON_DENIED.into());
    let observations = [DiagnosticObservation::from_consent_receipt(&r)
        .unwrap()
        .expect("canonical denied receipt projects an observation")];
    let input = DiagnosticWorkingSet {
        scope_ref: "scheduled-run",
        observations: &observations,
    };
    let run = v
        .sign_detector_run("scheduler", &input, &[&ConsentDeniedDetector])
        .unwrap();
    let mut unsigned = run.clone();
    unsigned.signature.clear();
    assert!(v.accept_signed_detector_run(&unsigned).unwrap().is_empty());
    let mut broken = run.clone();
    broken.run_ref.push('x');
    assert!(v.accept_signed_detector_run(&broken).unwrap().is_empty());
    let (_other_d, other) = vault();
    assert!(other.accept_signed_detector_run(&run).unwrap().is_empty());
    assert!(
        v.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)
            .unwrap()
            .is_empty()
    );
    let ids = v.accept_signed_detector_run(&run).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(v.is_signed_tripwire(&ids[0]).unwrap());
}

fn set_bounds(v: &Vault, bounds: TripwireBounds) {
    let id = crate::gate::default_policy_manifest_id().unwrap();
    let body = v.get(&id).unwrap().unwrap();
    let mut policy = rmpv::decode::read_value(&mut std::io::Cursor::new(body)).unwrap();
    let Value::Map(entries) = &mut policy else {
        panic!("manifest map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("diagnostic_bounds"));
    entries.push((
        Value::from("diagnostic_bounds"),
        Value::Map(vec![
            (Value::from("window_secs"), Value::from(bounds.window_secs)),
            (
                Value::from("consent_depth"),
                Value::from(bounds.consent_depth),
            ),
            (
                Value::from("actor_writes"),
                Value::from(bounds.actor_writes),
            ),
        ]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &policy).unwrap();
    super::test_support::replace_default_manifest(v, &bytes);
}
#[test]
fn retrieval_miss_reads_native_telemetry_and_malformed_projection_is_silent() {
    let (_d, v) = vault();
    let run = crate::store::RetrievalRunRecord::new(
        crate::store::RetrievalRunId::now(),
        crate::store::RetrievalAction::Pipeline,
        100,
        1,
        vec![crate::store::RetrievalSignal::Text],
        vec![],
        3,
        0,
        Some("no_results".into()),
    );
    v.store.record_retrieval_run(&run).unwrap();
    let ids = v.run_retrieval_miss_detector("retrieval", 10).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids, v.run_retrieval_miss_detector("retrieval", 10).unwrap());
    assert_eq!(
        decode_diagnostic_event_body(&v.get(&ids[0]).unwrap().unwrap())
            .unwrap()
            .event_class,
        DiagnosticEventClass::RetrievalMiss
    );
    let mut malformed = run.clone();
    malformed.claims_suppressed = 4;
    assert!(DiagnosticObservation::from_retrieval_run(&malformed).is_none());
    v.store.delete_retrieval_run(run.run_id).unwrap();
    v.store.record_retrieval_run(&malformed).unwrap();
    assert!(
        v.run_retrieval_miss_detector("retrieval", 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn predicate_write_rate_uses_manifest_criticality_actor_and_fixed_window() {
    for bound in [3, TripwireBounds::default().actor_writes] {
        let (_d, v) = vault();
        set_bounds(
            &v,
            TripwireBounds {
                window_secs: 60,
                consent_depth: 10,
                actor_writes: bound,
            },
        );
        let policy_id = crate::gate::default_policy_manifest_id().unwrap();
        let mut policy = rmpv::decode::read_value(&mut std::io::Cursor::new(
            v.get(&policy_id).unwrap().unwrap(),
        ))
        .unwrap();
        let Value::Map(entries) = &mut policy else {
            panic!("manifest map")
        };
        let rules = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("rules"))
            .unwrap();
        let Value::Array(rules) = &mut rules.1 else {
            panic!("rules array")
        };
        rules.push(Value::Map(vec![
            (Value::from("prefix"), Value::from("memory.fact")),
            (Value::from("exact"), Value::from(true)),
            (
                Value::from("axes"),
                Value::Map(vec![(Value::from("criticality"), Value::from("critical"))]),
            ),
        ]));
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &policy).unwrap();
        super::test_support::replace_default_manifest(&v, &bytes);
        let actor = EntityId::now();
        let mut receipts: Vec<_> = (0..bound)
            .map(|_| {
                let mut r = receipt("allow", "claim");
                r.actor = Some(actor.to_hex());
                r.fields.insert("predicate".into(), "memory.fact".into());
                r.fields.insert("criticality".into(), "normal".into());
                r
            })
            .collect();
        assert!(
            v.project_receipt_tripwires("drift", &receipts[..receipts.len() - 1], 100)
                .unwrap()
                .is_empty()
        );
        let ids = v
            .project_receipt_tripwires("drift", &receipts, 100)
            .unwrap();
        assert_eq!(ids.len(), 1);
        let event = decode_diagnostic_event_body(&v.get(&ids[0]).unwrap().unwrap()).unwrap();
        assert_eq!(event.actor_ref, Some(actor));
        assert_eq!(event.actual, Value::from(bound));
        receipts[0].occurred_at = 40;
        assert!(
            v.project_receipt_tripwires("drift", &receipts, 100)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn malformed_manifest_bounds_never_create_tripwires() {
    for bounds in [
        TripwireBounds {
            window_secs: 0,
            consent_depth: 2,
            actor_writes: 2,
        },
        TripwireBounds {
            window_secs: 60,
            consent_depth: 0,
            actor_writes: 2,
        },
        TripwireBounds {
            window_secs: 60,
            consent_depth: 2,
            actor_writes: 0,
        },
    ] {
        let (_dir, vault) = vault();
        set_bounds(&vault, bounds);
        let receipts = vec![
            receipt("pending", crate::consent::CONSENT_CONTENT_KIND),
            receipt("pending", crate::consent::CONSENT_CONTENT_KIND),
        ];
        assert!(vault.tripwire_bounds().unwrap().is_none());
        assert!(
            vault
                .project_receipt_tripwires("invalid", &receipts, 100)
                .unwrap()
                .is_empty()
        );
        assert!(
            vault
                .entities_by_type(ENTITY_TYPE_DIAGNOSTIC)
                .unwrap()
                .is_empty()
        );
    }
}

fn pending_receipt(v: &Vault) -> ReceiptRecord {
    let claim = EntityId::now();
    let mut r = receipt("pending", crate::consent::CONSENT_CONTENT_KIND);
    let decision = crate::store::GateDecisionId::from_bytes(
        *EntityId::from_hex(r.receipt_id.strip_prefix("gate:").unwrap())
            .unwrap()
            .as_bytes(),
    );
    r.trigger_ref = Some(format!("claim:{}", claim.to_hex()));
    v.with_write_txn(|txn| {
        v.store.put_pending_gate_consent_in_txn(
            txn,
            &crate::store::PendingGateConsentRecord {
                version: crate::store::PENDING_GATE_CONSENT_VERSION,
                claim_id: *claim.as_bytes(),
                decision_id: decision,
                created_at: r.occurred_at,
                diff_handle: vec![1],
                read_frontier_hash: [1; 32],
                reason_codes: vec!["gate.pending.test".into()],
                dreamer_run_id: None,
            },
        )
    })
    .unwrap();
    r
}

#[test]
fn resolved_or_replaced_consents_and_duplicate_receipts_do_not_inflate_depth() {
    let (_d, v) = vault();
    set_bounds(
        &v,
        TripwireBounds {
            window_secs: 60,
            consent_depth: 2,
            actor_writes: 3,
        },
    );
    let first = pending_receipt(&v);
    let second = pending_receipt(&v);
    assert!(
        v.project_receipt_tripwires("duplicate", &[first.clone(), first.clone()], 100)
            .unwrap()
            .is_empty()
    );
    let claim = EntityId::from_hex(
        second
            .trigger_ref
            .as_deref()
            .unwrap()
            .strip_prefix("claim:")
            .unwrap(),
    )
    .unwrap();
    // Resolution consumes the tray row; the immutable receipt remains.
    v.with_write_txn(|txn| v.store.delete_pending_gate_consent_in_txn(txn, &claim))
        .unwrap();
    assert!(
        v.project_receipt_tripwires("resolved", &[first.clone(), second.clone()], 100)
            .unwrap()
            .is_empty()
    );
    // A different decision for the same claim cannot reactivate the old receipt.
    v.with_write_txn(|txn| {
        v.store.put_pending_gate_consent_in_txn(
            txn,
            &crate::store::PendingGateConsentRecord {
                version: crate::store::PENDING_GATE_CONSENT_VERSION,
                claim_id: *claim.as_bytes(),
                decision_id: crate::store::GateDecisionId::now(),
                created_at: 100,
                diff_handle: vec![1],
                read_frontier_hash: [1; 32],
                reason_codes: vec!["gate.pending.test".into()],
                dreamer_run_id: None,
            },
        )
    })
    .unwrap();
    assert!(
        v.project_receipt_tripwires("replaced", &[first, second], 100)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unavailable_or_oversized_tripwire_inputs_are_not_reported_as_healthy() {
    let (_d, v) = vault();
    v.with_write_txn(|txn| {
        v.store
            .vault_meta
            .put(txn, b"retr_run:v0:invalid-key", b"invalid-row")
    })
    .unwrap();
    assert!(matches!(
        v.run_retrieval_miss_detector("corrupt", 10),
        Err(crate::Error::CorruptedIndex(_))
    ));
    let receipts =
        vec![receipt("pending", crate::consent::CONSENT_CONTENT_KIND); MAX_EVENTS_PER_RUN + 1];
    assert!(matches!(
        v.project_receipt_tripwires("oversized", &receipts, 100),
        Err(crate::Error::InvalidConfig(_))
    ));
    for bounds in [
        TripwireBounds {
            consent_depth: MAX_EVENTS_PER_RUN as u64 + 1,
            ..TripwireBounds::default()
        },
        TripwireBounds {
            actor_writes: MAX_EVENTS_PER_RUN as u64 + 1,
            ..TripwireBounds::default()
        },
    ] {
        set_bounds(&v, bounds);
        assert!(v.tripwire_bounds().unwrap().is_none());
    }
}

#[test]
fn signed_detector_run_fits_a_bounded_vault_without_per_event_receipt_copies() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crate::VaultConfig::device();
    config.map_size = 8 * 1024 * 1024;
    let v = Vault::open(dir.path(), config).unwrap();
    let mut r = receipt("denied", crate::consent::CONSENT_CONTENT_KIND);
    r.policy_trace
        .push(crate::consent::CONSENT_REASON_DENIED.into());
    let observations = [DiagnosticObservation::from_consent_receipt(&r)
        .unwrap()
        .unwrap()];
    let input = DiagnosticWorkingSet {
        scope_ref: "bounded-signed-run",
        observations: &observations,
    };
    let mut event = ConsentDeniedDetector.detect(&input).pop().unwrap();
    event.untrusted_detail = Some("x".repeat(4096));
    struct ManyEvents(DiagnosticEvent);
    impl DeterministicDetector for ManyEvents {
        fn detector_id(&self) -> &'static str {
            ConsentDeniedDetector.detector_id()
        }
        fn detect(&self, _: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
            (0..64)
                .map(|offset| {
                    let mut event = self.0.clone();
                    event.valid_from += offset;
                    event.valid_to = None;
                    event
                })
                .collect()
        }
    }
    let run = v
        .sign_detector_run("scheduler", &input, &[&ManyEvents(event)])
        .unwrap();
    let ids = v.accept_signed_detector_run(&run).unwrap();
    assert_eq!(ids.len(), 64);
    assert!(v.is_signed_tripwire(&ids[0]).unwrap());
    assert!(v.is_signed_tripwire(ids.last().unwrap()).unwrap());
}
