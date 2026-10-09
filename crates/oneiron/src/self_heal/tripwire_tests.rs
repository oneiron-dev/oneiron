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
    crate::test_util::put_policy_manifest_bytes(v, id, &bytes).unwrap();
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
