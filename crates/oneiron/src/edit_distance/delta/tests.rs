use super::*;

use crate::edit_distance::myers::MOVE_DISCOUNT;
use crate::edit_distance::{LoroOpRef, OpAttribution, OpSpan, ProposalArtifactRef};
use crate::error::ArtifactError;

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
    let left = delta_from_field_diff(
        &body(&[("a", Value::from(1))]),
        &body(&[("a", Value::from(2))]),
    )
    .expect("left");
    let right = delta_from_field_diff(
        &body(&[("a", Value::from(1))]),
        &body(&[("a", Value::from(2))]),
    )
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
            moved: 0,
            approx: false,
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
            moved: 0,
            approx: false,
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
            moved: 0,
            approx: false,
        }
    );
    // 14 / (11 + 17).
    assert_eq!(delta.d_norm, 0.5);
    assert_eq!(delta.proposed_ref, "0102");
    assert_eq!(delta.final_ref, "0304");
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
            moved: 0,
            approx: false,
        }
    );
}

// ─── chooser ────────────────────────────────────────────────────────────

/// The r2 precedence is structural, pinned here so no caller hand-picks a
/// lane: a context offering ALL THREE takes the recorded one, and a context
/// offering the last two takes the field diff.
///
/// `moved` is the tell that the Myers lane never ran: the texts offered here
/// are a pure relocation, so a Δ measuring THEM would carry `moved > 0`,
/// while the recorded window moves nothing and the field diff never pairs.
#[test]
fn chooser_prefers_recorded_ops_then_field_diff_over_reconstructed() {
    let window = churned_window();
    let proposed = body(&[("a", Value::from(1))]);
    let amended = body(&[("a", Value::from(2))]);
    let (before, after) = ("one\ntwo\nthree\nfour", "three\nfour\none\ntwo");
    assert_ne!(
        delta_from_reconstructed(before, after).ops_summary.moved,
        0,
        "fixture must be a relocation, or it proves nothing about the lane"
    );

    let ctx = DeltaCaptureContext {
        recorded: Some(&window),
        bodies: Some((&proposed, &amended)),
        texts: Some((before, after)),
    };
    let recorded = capture_delta_best(&ctx).expect("capture");
    assert_eq!(recorded.source, DeltaSource::RecordedOps);
    assert_eq!(recorded, delta_from_recorded_ops(&window));
    assert_eq!(recorded.ops_summary.moved, 0);

    let without_ops = DeltaCaptureContext {
        recorded: None,
        ..ctx
    };
    let field = capture_delta_best(&without_ops).expect("capture");
    assert_eq!(field.source, DeltaSource::FieldDiff);
    assert_eq!(field.ops_summary.moved, 0);

    assert_eq!(
        capture_delta_best(&DeltaCaptureContext::from_texts(before, after))
            .expect("capture")
            .source,
        DeltaSource::Reconstructed
    );
}

/// A context offering nothing is a typed error, not a Δ of zero: "nothing to
/// measure with" and "measured, and nothing changed" are different facts.
#[test]
fn chooser_reports_an_empty_context_as_unavailable() {
    let ctx = DeltaCaptureContext {
        recorded: None,
        bodies: None,
        texts: None,
    };
    assert!(matches!(
        capture_delta_best(&ctx),
        Err(Error::Artifact(ArtifactError::DeltaCaptureUnavailable(_)))
    ));
}

// ─── reconstructed lane ─────────────────────────────────────────────────

/// The out-of-band lane carries verifiable ends (each side's own blake3) and
/// the source token a consumer reads the refs THROUGH.
#[test]
fn reconstructed_lane_carries_content_hashes_of_both_ends() {
    let (before, after) = ("alpha\nbravo\n", "alpha\nbravo\ncharlie\n");
    let delta = delta_from_reconstructed(before, after);

    assert_eq!(delta.source, DeltaSource::Reconstructed);
    assert_eq!(DeltaSource::Reconstructed.as_str(), "reconstructed");
    assert_eq!(
        delta.proposed_ref,
        bytes_to_hex_lower(blake3::hash(before.as_bytes()).as_bytes())
    );
    assert_eq!(
        delta.final_ref,
        bytes_to_hex_lower(blake3::hash(after.as_bytes()).as_bytes())
    );
    // Characters, a terminator per line: `charlie` arrived, `alpha` and
    // `bravo` stayed.
    assert_eq!(
        delta.ops_summary,
        OpsSummary {
            ins: 8,
            del: 0,
            kept: 12,
            moved: 0,
            approx: false,
        }
    );
}

/// A capped diff says so THROUGH THE PAYLOAD. The flag is the one thing
/// standing between a consumer and reading a bound as an exact measurement,
/// so the test reads it back the way a consumer does: off the encoded bytes.
#[test]
fn a_capped_reconstructed_diff_decodes_as_approximate() {
    let wall = |tag: char| {
        (0..4_000)
            .map(|line| format!("{tag}{line}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let delta = delta_from_reconstructed(&wall('a'), &wall('b'));
    let decoded = AmendmentDelta::decode(&delta.encode().expect("encode")).expect("decode");

    assert!(decoded.ops_summary.approx, "a capped script must say so");
    assert_eq!(decoded, delta);

    // The exact path is the control: nothing sets the flag by accident.
    assert!(!delta_from_reconstructed("a\nb", "a\nc").ops_summary.approx);
}

/// The `moved` discount reaches `d_norm` through the SHARED formula, not a
/// number the reconstructed lane computes for itself.
#[test]
fn the_move_discount_reaches_d_norm_through_the_pinned_formula() {
    let delta = delta_from_reconstructed("one\ntwo\nsix\nten", "six\nten\none\ntwo");
    assert_eq!(delta.ops_summary.moved, 8);
    assert_eq!(delta.d_norm, delta.ops_summary.d_norm(16, 16));
    // Eight relocated characters cost 1.6 where rewriting them would cost 16.
    assert!((delta.d_norm - 0.05).abs() < 1e-6, "{}", delta.d_norm);
}

// ─── what the text lanes read (ARCH-0056 §3, owner 2026-10-08) ─────────

/// One recorded change from `before` to `after`: a decider's single
/// correction run as the op log replays it.
fn one_change_window(before: &str, after: &str) -> FinalizedProposalText {
    let mut window = churned_window();
    window.ops_by_actor = vec![span(before, after)];
    window.proposed_text = before.to_owned();
    window.final_text = after.to_owned();
    window
}

const LONG_LINE: &str = "The quarterly report covers revenue, churn and hiring across all \
    four regions, and it closes with the risks the board asked us to watch before the next \
    planning cycle begins in spring.";

/// A one-character typo in a long line charges the character, not the
/// line: in both text lanes it reads far below the same line replaced.
#[test]
fn a_typo_in_a_long_line_reads_far_below_the_line_replaced_in_both_lanes() {
    let before = format!("Summary\n{LONG_LINE}\nRegards");
    let typo = before.replacen("revenue", "revenoe", 1);
    let replaced = before.replacen(
        LONG_LINE,
        "Ship the new onboarding flow to every customer by the end of the month.",
        1,
    );

    let reconstructed_typo = delta_from_reconstructed(&before, &typo).d_norm;
    let reconstructed_line = delta_from_reconstructed(&before, &replaced).d_norm;
    let recorded_typo = delta_from_recorded_ops(&one_change_window(&before, &typo)).d_norm;
    let recorded_line = delta_from_recorded_ops(&one_change_window(&before, &replaced)).d_norm;

    for (lane, typo, line) in [
        ("reconstructed", reconstructed_typo, reconstructed_line),
        ("recorded", recorded_typo, recorded_line),
    ] {
        assert!(typo > 0.0, "{lane}: a typo is still an edit");
        assert!(typo < 0.01, "{lane}: a typo scored {typo}");
        assert!(
            typo * 50.0 < line,
            "{lane}: typo {typo} is not far below the replaced line {line}"
        );
    }
}

/// A real rewrite still reads as one: two unrelated sentences share letters
/// by chance, and the reconstructed lane still charges the line whole, as it
/// did when it counted lines.
#[test]
fn a_rewritten_line_still_scores_a_full_rewrite() {
    let delta = delta_from_reconstructed(
        "The deploy runs at noon on Fridays and the team reviews the logs afterwards.",
        "Please send the invoice to accounting before the end of the month, thanks.",
    );
    assert_eq!(delta.d_norm, 1.0);
}

/// Re-wrapping a paragraph, re-spacing it and adding blank lines changes no
/// word, so it measures zero in both text lanes; one changed word does not.
#[test]
fn a_layout_only_edit_measures_zero_in_both_lanes() {
    let before = "The deploy window opens at noon on Fridays, and the on-call\n\
                  engineer confirms the rollback plan before anything ships.\n\
                  \n\
                  Questions go to the release channel.";
    let rewrapped = "The deploy window opens at noon on Fridays,\n\
                     and the on-call engineer confirms the rollback\n\
                     plan  before\tanything ships.\n\
                     \n\
                     \n\
                     \u{20}  Questions go to the   release channel.  \n";

    assert_eq!(delta_from_reconstructed(before, rewrapped).d_norm, 0.0);
    assert_eq!(
        delta_from_recorded_ops(&one_change_window(before, rewrapped)).d_norm,
        0.0
    );

    let reworded = rewrapped.replacen("noon", "midnight", 1);
    assert!(delta_from_reconstructed(before, &reworded).d_norm > 0.0);
    assert!(delta_from_recorded_ops(&one_change_window(before, &reworded)).d_norm > 0.0);
}

/// A paragraph moved to the end costs a tenth of deleting it and inserting a
/// different paragraph of the same size there, in both text lanes. The
/// recorded lane sees the move as the op log has it: a cut, then a paste.
#[test]
fn a_moved_paragraph_costs_a_tenth_of_a_replaced_one_in_both_lanes() {
    let moving = "Pricing stays flat for the first year.\nRenewals follow the standard schedule.";
    // Same lengths line by line, no shared line: ROT13 of `moving`.
    let stand_in = rot13(moving);
    let first = "Hi Sam,\nthanks for the call today.";
    let second = "The contract is attached.\nSign it when you are ready.";

    let before = format!("{moving}\n\n{first}\n\n{second}");
    let cut = format!("{first}\n\n{second}");
    let moved = format!("{cut}\n\n{moving}");
    let replaced = format!("{cut}\n\n{stand_in}");

    let reconstructed_move = delta_from_reconstructed(&before, &moved);
    let reconstructed_swap = delta_from_reconstructed(&before, &replaced);
    assert_ne!(reconstructed_move.ops_summary.moved, 0);
    assert!(
        (reconstructed_move.d_norm - MOVE_DISCOUNT * reconstructed_swap.d_norm).abs() < 1e-6,
        "reconstructed: {} is not {MOVE_DISCOUNT}x {}",
        reconstructed_move.d_norm,
        reconstructed_swap.d_norm
    );

    let window = |end: &str| {
        let mut window = one_change_window(&before, end);
        window.ops_by_actor = vec![span(&before, &cut), span(&cut, end)];
        window
    };
    let recorded_move = delta_from_recorded_ops(&window(&moved));
    let recorded_swap = delta_from_recorded_ops(&window(&replaced));
    assert_ne!(recorded_move.ops_summary.moved, 0);
    assert_eq!(recorded_swap.ops_summary.moved, 0);
    assert!(
        (recorded_move.d_norm - MOVE_DISCOUNT * recorded_swap.d_norm).abs() < 1e-6,
        "recorded: {} is not {MOVE_DISCOUNT}x {}",
        recorded_move.d_norm,
        recorded_swap.d_norm
    );
}

/// Text typed and then deleted is churn, not a move: it is in neither
/// endpoint, so the recorded lane charges it in full, alone or next to a
/// real move.
#[test]
fn recorded_churn_never_pairs_as_a_move() {
    let mut window = one_change_window("keep this line", "keep this line");
    window.ops_by_actor = vec![
        span("keep this line", "keep this line\nan aside"),
        span("keep this line\nan aside", "keep this line"),
    ];
    let delta = delta_from_recorded_ops(&window);
    assert_eq!(delta.ops_summary.moved, 0);
    assert_eq!((delta.ops_summary.ins, delta.ops_summary.del), (9, 9));

    // Review repro: a move whose line weighs more than the region the op log
    // shows must not soak up churn typed and deleted in the same window.
    let swap = |churn: &[(&str, &str)]| {
        let mut window = one_change_window("aaa\naa", "aa\naaa");
        window
            .ops_by_actor
            .extend(churn.iter().map(|(before, after)| span(before, after)));
        delta_from_recorded_ops(&window)
    };
    let plain = swap(&[]);
    let churned = swap(&[("aa\naaa", "aa\naaaq"), ("aa\naaaq", "aa\naaa")]);
    // The `q` in and out: two characters over 6 + 6, at full price.
    assert!(
        (churned.d_norm - plain.d_norm - 2.0 / 12.0).abs() < 1e-6,
        "churn {} over move {} is not full price",
        churned.d_norm,
        plain.d_norm
    );
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
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

/// A capture that FAILED projects its own marker, never a Δ field holding
/// something that is not a Δ. Three receipt states stay distinguishable: Δ
/// measured, measurement failed, and not yet projected (neither field).
#[test]
fn attachment_surfaces_a_failed_capture_as_its_own_marker() {
    let (_tmp, vault) = crate::edit_distance::tests::temp_vault();
    vault
        .with_write_txn(|wtxn| {
            put_amendment_row_in_txn(&vault, wtxn, "gate:unmeasured", &DeltaRow::Uncaptured)
        })
        .expect("write the uncaptured marker");

    let mut records = vec![
        amended_record("gate:unmeasured"),
        amended_record("gate:none"),
    ];
    let rtxn = vault.store.env.read_txn().expect("read txn");
    attach_amendment_deltas(&vault, &rtxn, &mut records).expect("attach");
    drop(rtxn);

    assert_eq!(
        records[0]
            .fields
            .get(FIELD_AMENDMENT_DELTA_UNCAPTURED)
            .map(String::as_str),
        Some("true"),
    );
    assert!(
        !records[0].fields.contains_key(FIELD_AMENDMENT_DELTA),
        "the marker is not a Δ, and must never be projected as one",
    );
    // An unprojected receipt carries NEITHER amendment field; unrelated
    // receipt fields remain legal.
    assert!(!records[1].fields.contains_key(FIELD_AMENDMENT_DELTA));
    assert!(
        !records[1]
            .fields
            .contains_key(FIELD_AMENDMENT_DELTA_UNCAPTURED),
    );
    // The Δ accessor stays honest about the marker row: there is no Δ to read
    // and it is not corruption either.
    assert_eq!(
        amendment_delta(&vault, "gate:unmeasured").expect("read"),
        None,
    );
}

fn amended_record(receipt_id: &str) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: receipt_id.to_owned(),
        receipt_kind: ReceiptKind::ProposalOutcome,
        occurred_at: 1,
        actor: None,
        on_behalf_of: None,
        outcome: OUTCOME_APPROVED_AMENDED.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: std::collections::BTreeMap::new(),
    }
}

// ─── identity-topology projection ───────────────────────────────────────

/// Parks a `Proposed` merge, handing back its event id and the two persons it
/// names — the proposal side of an amendment window.
fn parked_merge_proposal(vault: &Vault) -> (EntityId, EntityId, EntityId) {
    let survivor = put_person(vault, 0xE4);
    let source = put_person(vault, 0xE5);
    let outcome = vault
        .apply_identity_topology_op(
            &merge_op(vec![source], survivor),
            &crate::identity_topology::IdentityOpWrite {
                approval: crate::claim::ClaimApprovalStatus::Proposed,
                ..crate::identity_topology::IdentityOpWrite::auto(
                    crate::claim::ClaimSource::Inferred,
                )
            },
            100,
        )
        .expect("park the proposal");
    match outcome {
        crate::identity_topology::IdentityOpOutcome::Parked { event } => (event, survivor, source),
        other => panic!("a Proposed merge must park, got {other:?}"),
    }
}

fn put_person(vault: &Vault, byte: u8) -> EntityId {
    let id = crate::test_util::entity(byte);
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"delta projection fixture",
        )
        .expect("put person");
    id
}

fn merge_op(
    sources: Vec<EntityId>,
    survivor: EntityId,
) -> crate::identity_topology::IdentityTopologyOp {
    crate::identity_topology::IdentityTopologyOp::Merge(crate::identity_topology::MergeOp {
        sources,
        survivor,
        evidence: crate::identity_topology::IdentityOpEvidence {
            refs: Vec::new(),
            rationale: "delta projection fixture".to_owned(),
        },
        survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
    })
}

/// The proposal-outcome receipt shape the projection reads, with `amended`
/// as the producer artifact.
fn amended_outcome_receipt(proposal: EntityId, amended: &[u8]) -> ReceiptRecord {
    let mut record = amended_record(&format!("proposal_outcome:{}", proposal.to_hex()));
    record.trigger_ref = Some(format!("{PROPOSAL_TRIGGER_PREFIX}{}", proposal.to_hex()));
    record
        .fields
        .insert("amended_body".to_owned(), bytes_to_hex_lower(amended));
    assert_eq!(
        proposal_outcome_amended_body(&record).as_deref(),
        Some(amended),
        "fixture must speak the producer's own field key"
    );
    record
}

/// Once BOTH ends of the window exist, the projection reports what happened
/// to the MEASUREMENT — never silence.
///
/// Silence was the defect: a capture error collapsed to `None`, which is the
/// same answer this pass gives a receipt it has nothing to measure for. The
/// resulting receipt carried no Δ and no marker, so it was indistinguishable
/// from one the pass had never visited — and permanently, since the pass only
/// revisits receipts carrying neither field.
///
/// The corrupt body is not reachable through ONE-1747's resolve door today
/// (it round-trips the amendment through `encode_identity_op_amendment`
/// before storing it). The contract is written for the producers that follow
/// — the blueprint's requirement is that capture failure be non-fatal but
/// RECEIPTED, and a door that can only be honest while its inputs are perfect
/// is not honest.
#[test]
fn an_unmeasurable_identity_amendment_projects_as_uncaptured() {
    let (_tmp, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (proposal, survivor, source) = parked_merge_proposal(&vault);

    // Valid hex, undecodable body: an array header promising an element that
    // is not there.
    let undecodable = amended_outcome_receipt(proposal, b"\x91");
    assert!(
        matches!(
            identity_amendment_delta(&vault, &undecodable).expect("project"),
            Some(ProjectedDelta::Uncaptured)
        ),
        "a measurement that failed must be recorded, not dropped"
    );

    // The positive boundary: a body the field-diff lane CAN read still
    // measures, so the marker cannot swallow real captures.
    let narrowed =
        crate::identity_topology::encode_identity_op_amendment(&merge_op(vec![survivor], source))
            .expect("encode amendment");
    assert!(matches!(
        identity_amendment_delta(&vault, &amended_outcome_receipt(proposal, &narrowed))
            .expect("project"),
        Some(ProjectedDelta::Captured(_))
    ));

    // A receipt with no amendment has no PAIR — still `None`, still eligible
    // for a later pass. That distinction is what the marker protects.
    assert!(
        identity_amendment_delta(&vault, &amended_record("proposal_outcome:none"))
            .expect("project")
            .is_none()
    );
}
