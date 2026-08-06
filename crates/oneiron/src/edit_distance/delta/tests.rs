use super::*;

use crate::edit_distance::{LoroOpRef, OpAttribution, OpSpan, ProposalArtifactRef};

// ─── fixtures ───────────────────────────────────────────────────────────

fn body(entries: &[(&str, Value)]) -> Vec<u8> {
    let value = Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), value.clone()))
            .collect(),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode fixture body");
    bytes
}

fn span(before: &str, after: &str) -> (OpAttribution, OpSpan) {
    (
        OpAttribution::DevicePeer,
        OpSpan {
            peer_id: 1,
            counter: 0,
            len: 1,
            lamport: 0,
            timestamp: 0,
            before_text: before.to_owned(),
            after_text: after.to_owned(),
        },
    )
}

/// A two-change window: "hello world" grows a word, then that word is
/// rewritten. The rewrite is exactly the churn an endpoint comparison cannot
/// see.
fn churned_window() -> FinalizedProposalText {
    FinalizedProposalText {
        artifact_ref: ProposalArtifactRef::mint(),
        proposed_ref: LoroOpRef::from_bytes(vec![0x01, 0x02]),
        final_ref: LoroOpRef::from_bytes(vec![0x03, 0x04]),
        ops_by_actor: vec![
            span("hello world", "hello there world"),
            span("hello there world", "hello brave world"),
        ],
        proposed_text: "hello world".to_owned(),
        final_text: "hello brave world".to_owned(),
        source_turn_ref: None,
    }
}

// ─── schema bytes ───────────────────────────────────────────────────────

/// The receipt slot carries exactly the six ARCH-0056 §2 names, and the
/// payload round-trips — the Δ a consumer reads back is the Δ that was
/// measured, not a lossy summary of it.
#[test]
fn encoded_delta_projects_the_six_arch_0056_names_and_round_trips() {
    let delta = delta_from_field_diff(
        &body(&[("survivor", Value::from(1))]),
        &body(&[("survivor", Value::from(2))]),
    )
    .expect("field diff");

    let encoded = delta.encode().expect("encode");
    let json: serde_json::Value = serde_json::from_slice(&encoded).expect("canonical json");
    let names: Vec<&str> = json
        .as_object()
        .expect("delta encodes as an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        names,
        [
            "d_norm",
            "engine_ver",
            "final_ref",
            "ops_summary",
            "proposed_ref",
            "source",
        ],
        "canonical json sorts the six field names"
    );
    assert_eq!(json["source"], "field_diff");
    assert_eq!(delta.engine_ver, env!("CARGO_PKG_VERSION"));
    assert_eq!(AmendmentDelta::decode(&encoded).expect("decode"), delta);
}

/// Canonical encoding means STABLE bytes: two Δs equal in content encode
/// identically regardless of how their maps were built.
#[test]
fn encoding_is_byte_stable_for_equal_deltas() {
    let left =
        delta_from_field_diff(&body(&[("a", Value::from(1))]), &body(&[("a", Value::from(2))]))
            .expect("left");
    let right =
        delta_from_field_diff(&body(&[("a", Value::from(1))]), &body(&[("a", Value::from(2))]))
            .expect("right");
    assert_eq!(left.encode().expect("left"), right.encode().expect("right"));
}

#[test]
fn decode_rejects_a_payload_this_engine_did_not_write() {
    assert!(AmendmentDelta::decode(b"not a delta").is_err());
}

// ─── field-diff lane ────────────────────────────────────────────────────

/// A changed leaf is one deletion AND one insertion (the field was
/// rewritten); an added leaf is an insertion alone; an equal leaf is kept —
/// including one nested under an unchanged map, which is walked rather than
/// compared whole.
#[test]
fn field_diff_counts_changed_leaves_not_bytes() {
    let proposed = body(&[
        ("a", Value::from(1)),
        ("b", Value::from("x")),
        ("c", Value::Map(vec![(Value::from("d"), Value::from(2))])),
    ]);
    let amended = body(&[
        ("a", Value::from(1)),
        ("b", Value::from("y")),
        ("c", Value::Map(vec![(Value::from("d"), Value::from(2))])),
        ("e", Value::from(3)),
    ]);

    let delta = delta_from_field_diff(&proposed, &amended).expect("field diff");
    assert_eq!(delta.source, DeltaSource::FieldDiff);
    assert_eq!(
        delta.ops_summary,
        OpsSummary {
            ins: 2,
            del: 1,
            kept: 2,
            moved: 0
        }
    );
    // (2 + 1) / (3 before-leaves + 4 after-leaves).
    assert!((delta.d_norm - 3.0 / 7.0).abs() < 1e-6, "{}", delta.d_norm);
    // The refs are the two bodies' own content hashes, so a consumer can
    // verify the pair it was handed.
    assert_eq!(
        delta.proposed_ref,
        bytes_to_hex_lower(blake3::hash(&proposed).as_bytes())
    );
    assert_ne!(delta.proposed_ref, delta.final_ref);
}

/// The two ends of the scale: an untouched body scores 0, a body whose every
/// leaf was rewritten scores 1 — the same score a full text rewrite gets, so
/// the two lanes' numbers are comparable.
#[test]
fn field_diff_spans_the_full_normalized_range() {
    let proposed = body(&[("a", Value::from(1)), ("b", Value::from(2))]);
    let untouched = delta_from_field_diff(&proposed, &proposed).expect("untouched");
    assert_eq!(untouched.d_norm, 0.0);
    assert_eq!(
        untouched.ops_summary,
        OpsSummary {
            ins: 0,
            del: 0,
            kept: 2,
            moved: 0
        }
    );

    let rewritten = delta_from_field_diff(
        &proposed,
        &body(&[("a", Value::from(9)), ("b", Value::from(8))]),
    )
    .expect("rewritten");
    assert_eq!(rewritten.d_norm, 1.0);
}

/// A type change is not a partial edit: the whole subtree on each side is
/// charged, so replacing an array with a scalar cannot read as one small
/// change.
#[test]
fn field_diff_charges_whole_subtrees_across_a_type_change() {
    let delta = delta_from_field_diff(
        &body(&[(
            "scope",
            Value::Array(vec![Value::from(1), Value::from(2), Value::from(3)]),
        )]),
        &body(&[("scope", Value::from("none"))]),
    )
    .expect("field diff");
    assert_eq!(
        delta.ops_summary,
        OpsSummary {
            ins: 1,
            del: 3,
            kept: 0,
            moved: 0
        }
    );
}

#[test]
fn field_diff_rejects_bytes_that_are_not_a_body() {
    // A one-element array header with no element: truncated, not a body.
    assert!(delta_from_field_diff(b"\x91", &body(&[])).is_err());
    // Trailing bytes are rejected too: a body with a tail is not the body the
    // door validated.
    let mut tail = body(&[("a", Value::from(1))]);
    tail.push(0x00);
    assert!(delta_from_field_diff(&tail, &body(&[])).is_err());
}

/// Nesting deeper than the traversal cap is compared as one opaque leaf. The
/// number degrades; the process does not.
#[test]
fn field_diff_bottoms_out_past_the_depth_cap_without_recursing() {
    let nest = |leaf: Value| {
        let mut value = leaf;
        for _ in 0..(MAX_FIELD_DIFF_DEPTH + 40) {
            value = Value::Array(vec![value]);
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode nest");
        bytes
    };
    let delta =
        delta_from_field_diff(&nest(Value::from(1)), &nest(Value::from(2))).expect("deep diff");
    assert_eq!(delta.d_norm, 1.0);
}

// ─── recorded-ops lane ──────────────────────────────────────────────────

/// The recorded lane counts CHURN — the word inserted by the first change and
/// then rewritten by the second is charged twice — while `kept` is measured
/// at the window's endpoints, where "hello world" survives whole.
#[test]
fn recorded_ops_counts_churn_and_endpoint_survivors() {
    let delta = delta_from_recorded_ops(&churned_window());
    assert_eq!(delta.source, DeltaSource::RecordedOps);
    assert_eq!(
        delta.ops_summary,
        OpsSummary {
            ins: 10,
            del: 4,
            kept: 11,
            moved: 0
        }
    );
    // 14 / (11 + 17).
    assert_eq!(delta.d_norm, 0.5);
    assert_eq!(delta.proposed_ref, "0102");
    assert_eq!(delta.final_ref, "0304");
}

/// An endpoint comparison would score this window at zero. The recorded lane
/// sees the work: that gap IS the lane's reason to outrank field-diff.
#[test]
fn recorded_ops_sees_work_that_the_endpoints_hide() {
    let mut window = churned_window();
    window.ops_by_actor = vec![
        span("draft", "wholly different"),
        span("wholly different", "draft"),
    ];
    window.proposed_text = "draft".to_owned();
    window.final_text = "draft".to_owned();

    let delta = delta_from_recorded_ops(&window);
    assert!(delta.ops_summary.ins > 0 && delta.ops_summary.del > 0);
    assert!(delta.d_norm > 0.0);
}

/// An empty window is `0.0`, not a division by zero.
#[test]
fn recorded_ops_on_an_empty_window_is_zero_not_a_panic() {
    let mut window = churned_window();
    window.ops_by_actor.clear();
    window.proposed_text.clear();
    window.final_text.clear();

    let delta = delta_from_recorded_ops(&window);
    assert_eq!(delta.d_norm, 0.0);
    assert_eq!(delta.ops_summary, OpsSummary::default());
}

/// A repeated run must not let prefix and suffix double-count the same
/// characters into a negative change.
#[test]
fn recorded_ops_does_not_overlap_prefix_and_suffix() {
    let mut window = churned_window();
    window.ops_by_actor = vec![span("aaa", "aaaaa")];
    window.proposed_text = "aaa".to_owned();
    window.final_text = "aaaaa".to_owned();

    let delta = delta_from_recorded_ops(&window);
    assert_eq!(
        delta.ops_summary,
        OpsSummary {
            ins: 2,
            del: 0,
            kept: 3,
            moved: 0
        }
    );
}

// ─── chooser ────────────────────────────────────────────────────────────

/// The r2 precedence is structural, pinned here so ED-02 rewires no call
/// site: a context offering BOTH lanes takes the recorded one.
#[test]
fn chooser_prefers_recorded_ops_over_field_diff() {
    let window = churned_window();
    let proposed = body(&[("a", Value::from(1))]);
    let amended = body(&[("a", Value::from(2))]);
    let ctx = DeltaCaptureContext {
        recorded: Some(&window),
        bodies: Some((&proposed, &amended)),
    };
    assert_eq!(
        capture_delta_best(&ctx).expect("capture").source,
        DeltaSource::RecordedOps
    );

    let bodies_only = DeltaCaptureContext::from_bodies(&proposed, &amended);
    assert_eq!(
        capture_delta_best(&bodies_only).expect("capture").source,
        DeltaSource::FieldDiff
    );
}

/// The reconstructed arm is typed, not a string: ED-02 (ONE-1758) fills it,
/// and until then callers match the error instead of sniffing a message.
#[test]
fn chooser_reports_reconstructed_as_unavailable() {
    let ctx = DeltaCaptureContext {
        recorded: None,
        bodies: None,
    };
    assert!(matches!(
        capture_delta_best(&ctx),
        Err(Error::DeltaCaptureUnavailable(_))
    ));
    // The variant exists from day one so the enum never migrates.
    assert_eq!(DeltaSource::Reconstructed.as_str(), "reconstructed");
}

// ─── side-ledger ────────────────────────────────────────────────────────

/// A Δ measures a window that is already closed, so the FIRST measurement
/// stands: a second pass cannot make a receipt's Δ drift under a reader who
/// already quoted it.
#[test]
fn recorded_delta_is_write_once_and_first_writer_wins() {
    let (_tmp, vault) = crate::edit_distance::tests::temp_vault();
    let first = delta_from_recorded_ops(&churned_window());
    let mut second = first.clone();
    second.d_norm = 0.25;

    let wrote_first = vault
        .with_write_txn(|wtxn| put_amendment_delta_in_txn(&vault, wtxn, "gate:one", &first))
        .expect("first write");
    let wrote_second = vault
        .with_write_txn(|wtxn| put_amendment_delta_in_txn(&vault, wtxn, "gate:one", &second))
        .expect("second write");

    assert!(wrote_first);
    assert!(!wrote_second, "a re-measurement must not overwrite");
    assert_eq!(
        amendment_delta(&vault, "gate:one").expect("read"),
        Some(first)
    );
    assert_eq!(amendment_delta(&vault, "gate:other").expect("absent"), None);
}

/// Attachment fills the reserved slot only for amended outcomes: an
/// unamended receipt has no Δ by definition, and the common query pays no
/// lookup for one.
#[test]
fn attachment_fills_the_reserved_slot_for_amended_outcomes_only() {
    let (_tmp, vault) = crate::edit_distance::tests::temp_vault();
    let delta = delta_from_recorded_ops(&churned_window());
    vault
        .with_write_txn(|wtxn| put_amendment_delta_in_txn(&vault, wtxn, "gate:amended", &delta))
        .expect("write delta");

    let record = |receipt_id: &str, outcome: &str| ReceiptRecord {
        receipt_id: receipt_id.to_owned(),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: 1,
        actor: None,
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: std::collections::BTreeMap::new(),
    };
    let mut records = vec![
        record("gate:amended", OUTCOME_APPROVED_AMENDED),
        record("gate:amended", "approved"),
    ];

    let rtxn = vault.store.env.read_txn().expect("read txn");
    attach_amendment_deltas(&vault, &rtxn, &mut records).expect("attach");

    let attached = records[0]
        .fields
        .get(FIELD_AMENDMENT_DELTA)
        .expect("amended receipt carries the delta");
    assert_eq!(
        *attached,
        bytes_to_hex_lower(&delta.encode().expect("encode"))
    );
    assert!(
        !records[1].fields.contains_key(FIELD_AMENDMENT_DELTA),
        "an unamended outcome has nothing to attach"
    );
}
