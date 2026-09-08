//! ONE-1296 auto_checker knob: decode and fold, checker routing, and lineage.

// ---------------------------------------------------------------------------
// ONE-1296 `auto_checker` manifest knob: decode/merge/hash, the write door's
// consult predicate, and the fail-closed mapping.
//
// All fixtures and helpers stay inside this module; the GATE-12/GATE-13
// Dreamer fixtures above are reused, not modified.
// ---------------------------------------------------------------------------

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use crate::inbox::{InboxExceptionClass, InboxQuery};
use crate::llm::{
    AutoCheckCandidate, AutoCheckCandidateOwned, AutoCheckOutcome, AutoChecker, BoundedAutoChecker,
};

const CHECKER_REF: &str = "host-checker-v1";
const OTHER_CHECKER_REF: &str = "host-checker-v2";
const CHECKER_RUN_ID: &str = "one1296-checker-run";
/// A host names its reasons in PROSE — punctuation, spaces and all. This
/// exact string is the one that made the ledger refuse the decision row
/// before the reasons were rendered into its token vocabulary.
const HOLD_REASON: &str = "checker: hedged verdict";

/// [`HOLD_REASON`] as the receipt records it. The `checker_` prefix is the
/// ENGINE's family marker and is always applied, so the host's own leading
/// "checker:" word renders into the slug after it; the WHY stays legible.
const HOLD_RECEIPT_REASON: &str = "checker_checker_hedged_verdict";

/// Counts every consult and records what it was shown.
struct RecordingAutoChecker {
    outcome: AutoCheckOutcome,
    calls: AtomicUsize,
    seen: Mutex<Vec<AutoCheckCandidateOwned>>,
}

impl RecordingAutoChecker {
    fn new(outcome: AutoCheckOutcome) -> Self {
        Self {
            outcome,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn allow() -> Self {
        Self::new(AutoCheckOutcome::Allow)
    }

    fn hold() -> Self {
        Self::new(AutoCheckOutcome::Hold {
            reasons: vec![HOLD_REASON.to_owned()],
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(AtomicOrdering::Relaxed)
    }

    fn seen(&self) -> Vec<AutoCheckCandidateOwned> {
        self.seen.lock().expect("checker log").clone()
    }
}

impl AutoChecker for RecordingAutoChecker {
    fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        let _ = self.calls.fetch_add(1, AtomicOrdering::Relaxed);
        self.seen
            .lock()
            .expect("checker log")
            .push(AutoCheckCandidateOwned::from(candidate));
        self.outcome.clone()
    }
}

/// A host implementation that unwinds instead of answering.
struct PanickingAutoChecker;

impl AutoChecker for PanickingAutoChecker {
    fn check(&self, _candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        panic!("host auto checker panicked");
    }
}

/// A host implementation that answers long after the gate stopped waiting.
struct SlowAutoChecker;

impl AutoChecker for SlowAutoChecker {
    fn check(&self, _candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        std::thread::sleep(Duration::from_millis(
            crate::llm::AUTO_CHECKER_DEADLINE_MS + 500,
        ));
        AutoCheckOutcome::Allow
    }
}

fn bounded(checker: impl AutoChecker) -> crate::llm::BoundedAutoChecker {
    crate::llm::BoundedAutoChecker::new(std::sync::Arc::new(checker))
}

fn checker_entry(value: &str) -> (Value, Value) {
    (
        Value::from(POLICY_AUTO_CHECKER_KEY),
        Value::from(value.to_owned()),
    )
}

/// The precommit vault's manifest — an `agent` actor ceiling of `auto`, an
/// explicit auto permit for `generated`, and a signature — plus whatever
/// `auto_checker` rows the case under test wants.
fn checker_manifest(extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ];
    entries.extend(extra);
    let mut data = encode_policy_manifest(entries);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &first_party_connector_actor_ref(), "auto"),
    );
    data
}

fn checker_vault(knob: Option<&str>) -> Result<(tempfile::TempDir, crate::Vault)> {
    let (tmp, vault) = temp_vault();
    let extra = knob.map(checker_entry).into_iter().collect();
    put_policy_manifest_bytes(&vault, test_id(0x22), &checker_manifest(extra))?;
    Ok((tmp, vault))
}

/// A valid Dreamer candidate: non-degenerate value, resolving evidence,
/// public sensitivity band, no isolation-classed predicate.
fn checker_body(vault: &crate::Vault, approval: ClaimApprovalStatus) -> Result<ClaimBody> {
    let evidence_ref = test_id(0x36);
    seed_precommit_evidence_entity(vault, &evidence_ref)?;
    let mut body = precommit_body(
        Value::from("Ada Lovelace"),
        Some(precommit_evidence(vec![evidence_ref])),
    );
    body.approval = approval;
    Ok(body)
}

fn dreamer_parts(
    vault: &crate::Vault,
    body: &ClaimBody,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    dreamer_claim_candidate_write_parts(
        vault,
        body,
        first_party_connector_actor_id(),
        CHECKER_RUN_ID,
    )
}

/// The ONE production injection: the checker-aware promotion terminal.
fn attempt_checked_candidate_write(
    vault: &crate::Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
    checker: Option<&BoundedAutoChecker>,
) -> Result<()> {
    let (candidate, envelope) = dreamer_parts(vault, body)?;
    if let Some(checker) = checker {
        vault
            .batch()
            .claim_candidate(claim_id, candidate, &envelope, test_time(3), 3)
            .commit_with_checker_and_then(checker, |_| Ok(()))
    } else {
        vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(claim_id, candidate, &envelope, test_time(3), 3)
                .apply_recording_gate_decisions(wtxn)
        })
    }
}

/// The claim write door itself, with the checker under test injected. The
/// transaction commits either way, so a parked write leaves its receipt
/// and its pending-consent row behind exactly as the write path would.
fn gate_claim_write(
    vault: &crate::Vault,
    claim_id: &EntityId,
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    checker: Option<&BoundedAutoChecker>,
    persist_pending_consent: bool,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &wtxn)?;
    let mut recorded_decision = None;
    let result = check_claim_policy_for_write_with_record(
        &vault.store,
        &mut wtxn,
        claim_id,
        ClaimGateWrite {
            body,
            envelope: Some(envelope),
            auto_checker: checker,
            defer_metrics_until_commit: false,
        },
        &policy,
        GateWriteMode {
            record_decision: true,
            persist_pending_consent,
            resolve_pending: false,
            can_resolve_pending_consent: true,
            include_source_in_gate_input: true,
        },
        &mut recorded_decision,
    );
    wtxn.commit()?;
    result
}

/// Every recorded decision as `(reason_codes, receipt_reasons)`.
fn decision_rows(vault: &crate::Vault) -> Result<Vec<(Vec<String>, Vec<String>)>> {
    Ok(vault
        .store
        .gate_decisions(100)?
        .into_iter()
        .map(|record| (record.reason_codes, record.receipt_reasons))
        .collect())
}

/// 1. The knob parses, merges and hashes; and a manifest that never names
///    a checker is untouched by this ticket — same resolution, same
///    frontier hash contribution (none at all), same decisions, even with
///    a holding checker injected.
#[test]
fn knob_roundtrip_and_unset_is_identity() -> Result<()> {
    // Parse.
    let (_tmp, named) = checker_vault(Some(CHECKER_REF))?;
    assert_eq!(resolve(&named)?.auto_checker(), Some(CHECKER_REF));

    // Unset: nothing resolves, and the default resolution names nobody.
    let (_tmp, unset) = checker_vault(None)?;
    assert_eq!(resolve(&unset)?.auto_checker(), None);
    assert_eq!(PolicyManifestResolution::default().auto_checker(), None);

    // The value is frontier-relevant WHEN PRESENT, and only then.
    let named_hash = resolve(&named)?.read_frontier_hash()?;
    let unset_hash = resolve(&unset)?.read_frontier_hash()?;
    assert_ne!(named_hash, unset_hash);
    let (_tmp, other) = checker_vault(Some(OTHER_CHECKER_REF))?;
    assert_ne!(resolve(&other)?.read_frontier_hash()?, named_hash);
    let (_tmp, unset_again) = checker_vault(None)?;
    assert_eq!(resolve(&unset_again)?.read_frontier_hash()?, unset_hash);

    // A duplicate row inside ONE manifest is the same ambiguity
    // `on_budget_exhausted` refuses.
    let (_tmp, duplicated) = temp_vault();
    put_policy_manifest_bytes(
        &duplicated,
        test_id(0x22),
        &checker_manifest(vec![checker_entry(CHECKER_REF), checker_entry(CHECKER_REF)]),
    )?;
    assert!(resolve(&duplicated)?.diagnostics().malformed_manifest_seen);

    // A blank ref is a misconfigured knob, not "no checker".
    let (_tmp, blank) = temp_vault();
    put_policy_manifest_bytes(
        &blank,
        test_id(0x22),
        &checker_manifest(vec![checker_entry("   ")]),
    )?;
    assert!(resolve(&blank)?.diagnostics().malformed_manifest_seen);

    // Across manifests: the first identical value wins, a conflict fails
    // the whole gate closed.
    let (_tmp, agreed) = temp_vault();
    put_policy_manifest_bytes(
        &agreed,
        test_id(0x22),
        &checker_manifest(vec![checker_entry(CHECKER_REF)]),
    )?;
    put_policy_manifest_bytes(
        &agreed,
        test_id(0x23),
        &checker_manifest(vec![checker_entry(CHECKER_REF)]),
    )?;
    let agreed_policy = resolve(&agreed)?;
    assert_eq!(agreed_policy.auto_checker(), Some(CHECKER_REF));
    assert!(!agreed_policy.diagnostics().malformed_manifest_seen);

    let (_tmp, conflicting) = temp_vault();
    put_policy_manifest_bytes(
        &conflicting,
        test_id(0x22),
        &checker_manifest(vec![checker_entry(CHECKER_REF)]),
    )?;
    put_policy_manifest_bytes(
        &conflicting,
        test_id(0x23),
        &checker_manifest(vec![checker_entry(OTHER_CHECKER_REF)]),
    )?;
    let conflicting_policy = resolve(&conflicting)?;
    assert!(conflicting_policy.diagnostics().malformed_manifest_seen);
    assert!(conflicting_policy.is_fail_closed());

    // Decisions half of the identity: with NO knob, an injected checker
    // that would hold everything changes nothing. The manifest arms the
    // consult; the injection alone cannot.
    let claim_id = test_id(0x33);
    let body = checker_body(&unset, ClaimApprovalStatus::Auto)?;
    let checker = bounded(RecordingAutoChecker::hold());
    attempt_checked_candidate_write(&unset, &claim_id, &body, Some(&checker))?;
    assert_eq!(
        unset.get_claim(&claim_id)?.expect("claim landed").approval,
        ClaimApprovalStatus::Auto
    );
    Ok(())
}

fn posture_entry(value: &str) -> (Value, Value) {
    (
        Value::from(POLICY_COMM_OPT_OUT_POSTURE_KEY),
        Value::from(value),
    )
}

fn combined_manifest(posture: Option<&str>, checker: Option<&str>) -> Vec<u8> {
    let entries = posture
        .map(posture_entry)
        .into_iter()
        .chain(checker.map(checker_entry))
        .collect();
    encode_policy_manifest(entries)
}

#[test]
fn both_manifest_keys_parse_and_fold_independently() -> Result<()> {
    let opaque = "  host-checker/α  ";
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x22),
        &combined_manifest(Some("allow_with_receipt"), Some(opaque)),
    )?;
    let policy = resolve(&vault)?;
    assert!(!policy.is_fail_closed());
    assert_eq!(policy.auto_checker(), Some(opaque));
    assert_eq!(
        policy.comm_opt_out_posture(),
        CommOptOutPosture::AllowWithReceipt
    );

    // Omission contributes no value on either axis. Posture disagreement
    // restricts; checker disagreement alone is malformed. Try both orders.
    for (left_posture, right_posture, expected_posture) in [
        (
            None,
            Some("allow_with_receipt"),
            CommOptOutPosture::AllowWithReceipt,
        ),
        (
            Some("escalate"),
            Some("allow_with_receipt"),
            CommOptOutPosture::Escalate,
        ),
    ] {
        for (left_checker, right_checker, malformed) in [
            (None, Some(CHECKER_REF), false),
            (Some(CHECKER_REF), Some(CHECKER_REF), false),
            (Some(CHECKER_REF), Some(OTHER_CHECKER_REF), true),
        ] {
            let manifests = [
                combined_manifest(left_posture, left_checker),
                combined_manifest(right_posture, right_checker),
            ];
            for reverse in [false, true] {
                let (_tmp, folded) = temp_vault();
                let order = if reverse { [1, 0] } else { [0, 1] };
                for (id, index) in [test_id(0x22), test_id(0x23)].into_iter().zip(order) {
                    put_policy_manifest_bytes(&folded, id, &manifests[index])?;
                }
                let policy = resolve(&folded)?;
                assert_eq!(policy.comm_opt_out_posture(), expected_posture);
                assert_eq!(policy.diagnostics().malformed_manifest_seen, malformed);
                assert_eq!(policy.is_fail_closed(), malformed);
                if !malformed {
                    assert_eq!(policy.auto_checker(), Some(CHECKER_REF));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn either_manifest_key_rejects_malformed_values_and_duplicates() -> Result<()> {
    let oversized = format!("{}x", "é".repeat(128));
    for (key, values) in [
        (POLICY_AUTO_CHECKER_KEY, vec![Value::Nil]),
        (POLICY_AUTO_CHECKER_KEY, vec![Value::Boolean(true)]),
        (POLICY_AUTO_CHECKER_KEY, vec![Value::from(" \t ")]),
        (POLICY_AUTO_CHECKER_KEY, vec![Value::from(oversized)]),
        (POLICY_AUTO_CHECKER_KEY, vec![Value::from(CHECKER_REF); 2]),
        (POLICY_COMM_OPT_OUT_POSTURE_KEY, vec![Value::Nil]),
        (POLICY_COMM_OPT_OUT_POSTURE_KEY, vec![Value::from(1)]),
        (POLICY_COMM_OPT_OUT_POSTURE_KEY, vec![Value::from("allow")]),
        (
            POLICY_COMM_OPT_OUT_POSTURE_KEY,
            vec![Value::from("escalate"); 2],
        ),
    ] {
        // The other key is valid and present, not omitted as a shortcut.
        let mut entries = vec![if key == POLICY_AUTO_CHECKER_KEY {
            posture_entry("allow_with_receipt")
        } else {
            checker_entry(CHECKER_REF)
        }];
        entries.extend(values.into_iter().map(|value| (Value::from(key), value)));
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, test_id(0x22), &encode_policy_manifest(entries))?;
        let policy = resolve(&vault)?;
        assert!(policy.diagnostics().malformed_manifest_seen, "{key}");
        assert!(policy.is_fail_closed(), "{key}");
        let decision = policy.evaluate_gate(&gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        ));
        assert_eq!(decision.outcome(), GateOutcome::Deny, "{key}");
        assert_eq!(
            decision.reason_codes(),
            &[GateReasonCode::DenyPolicyFailClosed]
        );
    }
    Ok(())
}

// Independent preimage for the small frontier fixture below: landed main
// a56c0398edbecd8126ffebac525871444b629fd8's hash_policy_frontier_v0,
// plus ONE-1453's intentional breaker-presence byte. Posture still follows
// budget exhaustion even WITHOUT a checker; an absent checker adds no bytes.
fn integrated_no_checker_frontier(posture: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    fn len(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn text(bytes: &mut Vec<u8>, value: &str) {
        len(bytes, value.len() as u64);
        bytes.extend_from_slice(value.as_bytes());
    }

    let mut bytes = Vec::new();
    text(&mut bytes, "oneiron.gate.policy_frontier.v0");
    len(&mut bytes, 1); // one manifest
    bytes.extend_from_slice(&[0; 5]); // four diagnostics, source-trust malformed
    for source in [
        "user_stated",
        "observed",
        "inferred",
        "imported",
        "tool_output",
        "generated",
    ] {
        text(&mut bytes, source);
        bytes.push(0); // no source-trust row
    }
    text(&mut bytes, "suspend");
    text(&mut bytes, posture);
    len(&mut bytes, 0); // budget-policy rows
    len(&mut bytes, 1); // one pack
    text(&mut bytes, "gate-test");
    text(&mut bytes, "v1");
    text(&mut bytes, env!("CARGO_PKG_VERSION"));
    bytes.push(1);
    text(&mut bytes, "normal"); // default criticality
    bytes.push(1);
    text(&mut bytes, "normal"); // default sensitivity
    bytes.push(0); // unknown axis
    for _ in 0..5 {
        len(&mut bytes, 0); // rules, actor ceilings, delegations, revokes, scoped grants
    }
    bytes.extend_from_slice(&[0; 2]); // owner-policy enabled / rows dropped
    len(&mut bytes, 0); // owner-policy rows
    bytes.push(0); // no actor-burst-breaker override (ONE-1453 frontier domain)
    bytes.extend_from_slice(&[0; 3]); // document, output contract, patterns dropped
    len(&mut bytes, 0); // owner-policy patterns
    len(&mut bytes, 0); // signatures
    Sha256::digest(&bytes).into()
}

#[test]
fn checker_posture_frontier_matrix_preserves_main_and_rebinds_authority() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let body = public_stamped(source_trust_claim(ClaimSource::UserStated));
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        },
    };
    let mut bindings = Vec::new();
    for posture in [None, Some("escalate"), Some("allow_with_receipt")] {
        for checker in [None, Some(CHECKER_REF), Some(OTHER_CHECKER_REF)] {
            let mut data = combined_manifest(posture, checker);
            rewrite_policy_manifest_entries(&mut data, |entries| {
                for (key, value) in entries {
                    if matches!(
                        key.as_str(),
                        Some(POLICY_RULES_KEY | POLICY_ACTOR_CEILINGS_KEY)
                    ) {
                        *value = Value::Array(vec![]);
                    }
                }
            });
            put_policy_manifest_bytes(&vault, test_id(0x22), &data)?;
            let policy = resolve(&vault)?;
            assert!(!policy.is_fail_closed());
            assert_eq!(policy.auto_checker(), checker);
            let resolved_posture = posture.unwrap_or("escalate");
            assert_eq!(policy.comm_opt_out_posture().as_str(), resolved_posture);
            let hash = policy.read_frontier_hash()?;
            if checker.is_none() {
                assert_eq!(hash, integrated_no_checker_frontier(resolved_posture));
            }
            let rtxn = vault.store.env.read_txn()?;
            let consent = claim_consent_binding_parts(&vault.store, &rtxn, &body)?;
            let grant = standing_outbound_grant_binding_parts(&intent, &policy)?;
            assert_eq!(consent.1, hash);
            assert_eq!(grant.1, hash);
            bindings.push((resolved_posture, checker, hash, consent.0, grant.0));
        }
    }
    for left in &bindings {
        for right in &bindings {
            let same_policy = (left.0, left.1) == (right.0, right.1);
            assert_eq!(
                left.2 == right.2,
                same_policy,
                "posture and checker are independent"
            );
            assert_eq!(left.3, right.3, "claim content did not change");
            assert_eq!(left.4, right.4, "grant intent did not change");
            // Same diff handles cannot redeem a binding after either axis
            // moves: both binding tuples also require this frontier.
            assert_eq!((&left.3, left.2) == (&right.3, right.2), same_policy);
            assert_eq!((&left.4, left.2) == (&right.4, right.2), same_policy);
        }
    }
    Ok(())
}

/// Knob plus an injected Allow checker on an otherwise-Auto Dreamer write:
/// consulted exactly once, and still Auto.
#[test]
fn auto_routes_through_checker_allow() -> Result<()> {
    let (_tmp, vault) = checker_vault(Some(CHECKER_REF))?;
    let claim_id = test_id(0x33);
    let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let checker = Arc::new(RecordingAutoChecker::allow());
    let bounded_checker = BoundedAutoChecker::new(checker.clone());

    attempt_checked_candidate_write(&vault, &claim_id, &body, Some(&bounded_checker))?;

    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim landed").approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(checker.calls(), 1, "exactly one consult per candidate");

    let seen = checker.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].predicate, "profile.name");
    assert_eq!(seen[0].source, ClaimSource::Generated);
    assert_eq!(seen[0].actor_class, "agent");
    assert_eq!(seen[0].value_preview, "Ada Lovelace");
    assert_eq!(seen[0].sensitivity_band, Some(0));
    Ok(())
}

/// A hold drops the ceiling to Proposed with `gate.pending.checker`, the
/// checker's own reasons ride the receipt, and the EXISTING inbox
/// projection classifies the parked row as a checker hedge.
#[test]
fn checker_hold_falls_to_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Restricted lineage includes source/sensitivity even for Proposed
    // writes. Withhold the permit so setup genuinely parks on source trust.
    let mut setup_manifest = checker_manifest(vec![checker_entry(CHECKER_REF)]);
    rewrite_policy_manifest_entries(&mut setup_manifest, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SOURCE_TRUST_KEY));
    });
    put_policy_manifest_bytes(&vault, test_id(0x22), &setup_manifest)?;
    let claim_id = test_id(0x34);
    let body = checker_body(&vault, ClaimApprovalStatus::Proposed)?;
    let (candidate, envelope) = dreamer_parts(&vault, &body)?;

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;
    assert!(has_pending_gate_consent(&vault, &claim_id)?);
    let setup_pending = vault.pending_gate_consents(10)?;
    assert_eq!(setup_pending.len(), 1);
    assert_eq!(setup_pending[0].reason_codes, ["gate.pending.source_trust"]);

    // Add the explicit public Generated permit to the same manifest. The
    // ordinary verdict is now Auto; only the checker narrows it to Pending.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x22),
        &checker_manifest(vec![checker_entry(CHECKER_REF)]),
    )?;
    let body = vault.get_claim(&claim_id)?.expect("proposal landed");
    let checker = Arc::new(RecordingAutoChecker::hold());
    let bounded_checker = BoundedAutoChecker::new(checker.clone());
    gate_claim_write(
        &vault,
        &claim_id,
        &body,
        &envelope,
        Some(&bounded_checker),
        true,
    )?;
    assert_eq!(checker.calls(), 1);

    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim").approval,
        ClaimApprovalStatus::Proposed,
        "a held write stays Proposed; no new approval state exists"
    );

    let rows = decision_rows(&vault)?;
    let (reason_codes, receipt_reasons) = rows
        .iter()
        .find(|(reason_codes, _)| {
            reason_codes.as_slice() == [GateReasonCode::PendingChecker.as_str()]
        })
        .expect("the hold recorded its own decision");
    assert_eq!(reason_codes.as_slice(), ["gate.pending.checker"]);
    assert!(
        receipt_reasons
            .iter()
            .any(|reason| reason == HOLD_RECEIPT_REASON),
        "the checker's reasons append to the receipt, rendered into the \
             ledger's token vocabulary: {receipt_reasons:?}"
    );

    let pending = vault.pending_gate_consents(10)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].reason_codes.as_slice(), ["gate.pending.checker"]);
    assert!(
        pending[0]
            .reason_codes
            .iter()
            .any(|code| code.starts_with(crate::inbox::INBOX_REASON_CHECKER_PREFIX)),
        "the reason prefix the inbox already matches"
    );

    // Zero inbox changes: the existing projection classifies it.
    let groups = vault.inbox_groups(InboxQuery::at(100, 10))?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 1);
    assert!(
        groups[0].members[0]
            .exception_classes
            .contains(&InboxExceptionClass::CheckerHedge)
    );
    Ok(())
}

/// Unavailable, a panic, a malformed verdict, a host failure the wrapper
/// reports as unavailable, and a checker that blows the deadline all land
/// the SAME fail-closed answer — and none of them hangs or unwinds through
/// the gate.
#[test]
fn dead_checker_fail_closed() -> Result<()> {
    // Unavailable straight from the host: this is how a budget denial or a
    // fatal model error reaches the gate.
    let unavailable = bounded(RecordingAutoChecker::new(AutoCheckOutcome::Unavailable));
    // A hold that names no reason is a malformed verdict.
    let malformed = bounded(RecordingAutoChecker::new(AutoCheckOutcome::Hold {
        reasons: vec!["  ".to_owned()],
    }));
    // Prose naming no token the receipt vocabulary can keep is the same
    // malformed verdict one step later: the hold survives `normalized`
    // but renders to nothing, and an unexplained refusal must not be
    // recorded as an explained one.
    let untokenizable = bounded(RecordingAutoChecker::new(AutoCheckOutcome::Hold {
        reasons: vec!["...!!".to_owned()],
    }));
    let panicking = bounded(PanickingAutoChecker);
    let slow = bounded(SlowAutoChecker);
    let dead: [(&str, &BoundedAutoChecker); 5] = [
        ("unavailable", &unavailable),
        ("malformed verdict", &malformed),
        ("untokenizable reasons", &untokenizable),
        ("panic", &panicking),
        ("deadline", &slow),
    ];

    for (label, checker) in dead {
        let (_tmp, vault) = checker_vault(Some(CHECKER_REF))?;
        let claim_id = test_id(0x35);
        let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;

        let err = attempt_checked_candidate_write(&vault, &claim_id, &body, Some(checker))
            .expect_err("a checker that cannot answer must refuse the Auto request");
        let (outcome, reason_codes) = gate_rejection_parts(err);
        assert_eq!(outcome, "pending", "{label} must not deny, it parks");
        assert_eq!(
            reason_codes,
            vec!["gate.pending.checker.unavailable"],
            "{label} must fail closed with the unavailable reason"
        );
        assert!(
            vault.get_raw(&claim_id)?.is_none(),
            "{label} must leave no claim behind"
        );
        assert!(!has_pending_gate_consent(&vault, &claim_id)?);
        let records: Vec<_> = vault
            .store
            .gate_decisions(100)?
            .into_iter()
            .filter(|record| record.claim_id == Some(*claim_id.as_bytes()))
            .collect();
        assert_eq!(records.len(), 1, "{label} must retain its refusal receipt");
        assert_eq!(records[0].outcome, "pending");
        assert_eq!(
            records[0].reason_codes,
            ["gate.pending.checker.unavailable"]
        );
    }
    Ok(())
}

#[test]
fn checker_preflight_rejection_discards_earlier_allows_and_all_batch_writes() -> Result<()> {
    struct AllowThenHold {
        calls: AtomicUsize,
    }
    impl AutoChecker for AllowThenHold {
        fn check(&self, _candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
            if self.calls.fetch_add(1, AtomicOrdering::Relaxed) == 0 {
                AutoCheckOutcome::Allow
            } else {
                AutoCheckOutcome::Hold {
                    reasons: vec![HOLD_REASON.to_owned()],
                }
            }
        }
    }

    let (_tmp, vault) = checker_vault(Some(CHECKER_REF))?;
    let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let (candidate, envelope) = dreamer_parts(&vault, &body)?;
    let first_id = test_id(0x41);
    let held_id = test_id(0x43);
    let host = Arc::new(AllowThenHold {
        calls: AtomicUsize::new(0),
    });
    let checker = BoundedAutoChecker::new(host.clone());
    let receipts_before = vault.store.gate_decisions(100)?;
    let mut after_apply_ran = false;

    let error = vault
        .batch()
        .claim_candidate(&first_id, candidate.clone(), &envelope, test_time(3), 3)
        .claim_candidate(&held_id, candidate, &envelope, test_time(3), 3)
        .commit_with_checker_and_then(&checker, |_| {
            after_apply_ran = true;
            Ok(())
        })
        .expect_err("a later checker hold refuses the whole batch");

    let (outcome, reasons) = gate_rejection_parts(error);
    assert_eq!(outcome, "pending");
    assert_eq!(reasons, ["gate.pending.checker"]);
    assert_eq!(host.calls.load(AtomicOrdering::Relaxed), 2);
    assert!(!after_apply_ran);
    assert!(vault.get_raw(&first_id)?.is_none());
    assert!(vault.get_raw(&held_id)?.is_none());
    assert!(vault.pending_gate_consents(10)?.is_empty());
    let records = vault.store.gate_decisions(100)?;
    assert_eq!(records.len(), receipts_before.len() + 1);
    for prior in receipts_before {
        assert!(
            records.contains(&prior),
            "pre-existing receipts stay intact"
        );
    }
    assert!(
        !records
            .iter()
            .any(|record| record.claim_id == Some(*first_id.as_bytes()))
    );
    let rejection = records
        .iter()
        .find(|record| record.claim_id == Some(*held_id.as_bytes()))
        .expect("actual held candidate receipt");
    assert_eq!(rejection.outcome, "pending");
    assert_eq!(rejection.reason_codes, ["gate.pending.checker"]);
    assert_eq!(rejection.receipt_reasons, [HOLD_RECEIPT_REASON]);
    Ok(())
}

/// Reuse the signed checker fixture, but permit the restricted ToolOutput
/// lineage member for exactly one actor, not the benign Observed declaration.
fn lineage_manifest(knob: Option<&str>, permit_actor: Option<EntityId>) -> Vec<u8> {
    let mut data = checker_manifest(knob.map(checker_entry).into_iter().collect());
    rewrite_policy_manifest_entries(&mut data, |entries| {
        entries.retain(|(key, _)| key.as_str() != Some(POLICY_SOURCE_TRUST_KEY));
        if let Some(actor) = permit_actor {
            let mut permit = source_trust_entry(ClaimSource::ToolOutput, 0);
            let Value::Map(sources) = &mut permit.1 else {
                panic!("source-trust fixture is a map");
            };
            let Value::Map(row) = &mut sources[0].1 else {
                panic!("explicit permit fixture is a map");
            };
            row.push((Value::from(ACTOR_REF_KEY), Value::from(actor.to_hex())));
            entries.push(permit);
        }
    });
    trust_human_candidate_actor(&mut data);
    data
}

fn benign_source_lineage_parts(
    vault: &crate::Vault,
    body: &ClaimBody,
    restricted: bool,
    human: bool,
) -> Result<(ClaimCandidate, WriteEnvelope)> {
    use crate::write_envelope::SourceLineage;

    let (candidate, base) = dreamer_parts(vault, body)?;
    let actor = if human {
        claim_candidate_write_parts(vault, body)?.1.actor()
    } else {
        base.actor()
    };
    let source = ClaimSource::Observed;
    assert!(!source.requires_explicit_auto_permit());
    let lineage = if restricted {
        SourceLineage::of(source).with(ClaimSource::ToolOutput)
    } else {
        SourceLineage::of(source)
    };
    // Only this crate-internal constructor can supply nontrivial history.
    // Even the human control keeps Dreamer-shaped provenance: actor class
    // must exclude it, not the absence of a recognizable run marker.
    let envelope = WriteEnvelope::with_lineage(
        actor,
        source,
        base.provenance().clone(),
        body.approval,
        lineage,
    );
    assert_eq!(envelope.source(), source);
    assert_eq!(
        envelope.lineage().requires_explicit_auto_permit(),
        restricted
    );
    Ok((candidate, envelope))
}

fn commit_lineage_candidate(
    vault: &crate::Vault,
    claim_id: &EntityId,
    candidate: ClaimCandidate,
    envelope: &WriteEnvelope,
    checker: Option<&BoundedAutoChecker>,
) -> Result<()> {
    if let Some(checker) = checker {
        // The same terminal promotion uses: one consult in preflight,
        // then None in apply, with refusal receipts outside the rollback.
        vault
            .batch()
            .claim_candidate(claim_id, candidate, envelope, test_time(3), 3)
            .commit_with_checker_and_then(checker, |_| Ok(()))
    } else {
        vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(claim_id, candidate, envelope, test_time(3), 3)
                .apply_recording_gate_decisions(wtxn)
        })
    }
}

#[test]
fn restricted_lineage_consults_checker_once_and_preserves_declared_source() -> Result<()> {
    for (outcome, pending_reason, receipt_reasons) in [
        (AutoCheckOutcome::Allow, None, vec![]),
        (
            AutoCheckOutcome::Hold {
                reasons: vec![HOLD_REASON.to_owned()],
            },
            Some("gate.pending.checker"),
            vec![HOLD_RECEIPT_REASON],
        ),
        (
            AutoCheckOutcome::Unavailable,
            Some("gate.pending.checker.unavailable"),
            vec![],
        ),
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x22),
            &lineage_manifest(Some(CHECKER_REF), Some(first_party_connector_actor_id())),
        )?;
        let claim_id = test_id(0x33);
        let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
        let (candidate, envelope) = benign_source_lineage_parts(&vault, &body, true, false)?;
        let checker = Arc::new(RecordingAutoChecker::new(outcome));
        let bounded_checker = BoundedAutoChecker::new(checker.clone());
        let result = commit_lineage_candidate(
            &vault,
            &claim_id,
            candidate,
            &envelope,
            Some(&bounded_checker),
        );
        assert_eq!(
            checker.calls(),
            1,
            "restricted history must not skip or repeat the consult"
        );
        let seen = checker.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].source,
            ClaimSource::Observed,
            "history never relabels the candidate"
        );
        assert_eq!(seen[0].lineage.as_ref(), Some(envelope.lineage()));
        let request = crate::llm::auto_check_llm_request(CHECKER_REF, &seen[0].borrowed(), "");
        let crate::llm::ContentPart::Text { text } = &request.messages[1].content[0] else {
            panic!("checker request must carry candidate text");
        };
        assert!(text.contains("\nsource: observed\nlineage: observed, tool_output\n"));
        assert_eq!(seen[0].actor_class, "agent");
        assert_eq!(seen[0].predicate, "profile.name");
        assert_eq!(seen[0].value_preview, "Ada Lovelace");
        assert_eq!(seen[0].sensitivity_band, Some(0));
        if let Some(reason) = pending_reason {
            let (outcome, reasons) =
                gate_rejection_parts(result.expect_err("checker refuses Auto"));
            assert_eq!(outcome, "pending");
            assert_eq!(reasons, [reason]);
            assert!(
                vault.get_raw(&claim_id)?.is_none(),
                "refusal leaves no claim"
            );
        } else {
            result?;
            let landed = vault
                .get_claim(&claim_id)?
                .expect("ordinary Auto remains eligible");
            assert_eq!(landed.approval, ClaimApprovalStatus::Auto);
            assert_eq!(landed.source, Some(ClaimSource::Observed));
        }
        assert!(!has_pending_gate_consent(&vault, &claim_id)?);
        let records: Vec<_> = vault
            .store
            .gate_decisions(100)?
            .into_iter()
            .filter(|record| record.claim_id == Some(*claim_id.as_bytes()))
            .collect();
        assert_eq!(
            records.len(),
            1,
            "the actual decision survives exactly once"
        );
        assert_eq!(
            records[0].outcome,
            if pending_reason.is_some() {
                "pending"
            } else {
                "allow"
            }
        );
        assert_eq!(
            records[0].reason_codes,
            [pending_reason.unwrap_or("gate.allow")]
        );
        assert_eq!(records[0].receipt_reasons, receipt_reasons);
    }
    Ok(())
}

#[test]
fn source_aware_checker_holds_tool_output_history_with_observed_declaration() -> Result<()> {
    use crate::write_envelope::SourceLineage;

    struct SourceAwareChecker {
        calls: AtomicUsize,
    }

    impl AutoChecker for SourceAwareChecker {
        fn check(&self, candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
            let _ = self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            if candidate.source == ClaimSource::ToolOutput
                || candidate
                    .lineage
                    .is_some_and(|lineage| lineage.contains(ClaimSource::ToolOutput))
            {
                AutoCheckOutcome::Hold {
                    reasons: vec![HOLD_REASON.to_owned()],
                }
            } else {
                AutoCheckOutcome::Allow
            }
        }
    }

    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x22),
        &lineage_manifest(Some(CHECKER_REF), Some(first_party_connector_actor_id())),
    )?;
    let claim_id = test_id(0x33);
    let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let (candidate, envelope) = benign_source_lineage_parts(&vault, &body, true, false)?;
    let checker = Arc::new(SourceAwareChecker {
        calls: AtomicUsize::new(0),
    });
    let bounded_checker = BoundedAutoChecker::new(checker.clone());
    let error = commit_lineage_candidate(
        &vault,
        &claim_id,
        candidate,
        &envelope,
        Some(&bounded_checker),
    )
    .expect_err("the checker must see the ToolOutput history behind Observed");
    let (outcome, reasons) = gate_rejection_parts(error);
    assert_eq!(outcome, "pending");
    assert_eq!(reasons, ["gate.pending.checker"]);
    assert_eq!(checker.calls.load(AtomicOrdering::Relaxed), 1);
    assert!(vault.get_raw(&claim_id)?.is_none());

    // Pure Observed bypasses the gate's consult. Ask the host directly to
    // prove it allows that same declaration when ToolOutput is absent.
    let observed_lineage = SourceLineage::of(ClaimSource::Observed);
    let observed = AutoCheckCandidate {
        predicate: &body.predicate,
        value_preview: "Ada Lovelace",
        source: ClaimSource::Observed,
        lineage: Some(&observed_lineage),
        actor_class: "agent",
        sensitivity_band: Some(0),
    };
    assert_eq!(checker.check(&observed), AutoCheckOutcome::Allow);
    Ok(())
}

#[test]
fn restricted_lineage_without_matching_permit_never_consults_checker() -> Result<()> {
    for permit_actor in [None, Some(test_id(0x21))] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x22),
            &lineage_manifest(Some(CHECKER_REF), permit_actor),
        )?;
        let claim_id = test_id(0x33);
        let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
        let (candidate, envelope) = benign_source_lineage_parts(&vault, &body, true, false)?;
        let checker = Arc::new(RecordingAutoChecker::allow());
        let bounded_checker = BoundedAutoChecker::new(checker.clone());
        let error = commit_lineage_candidate(
            &vault,
            &claim_id,
            candidate,
            &envelope,
            Some(&bounded_checker),
        )
        .expect_err("neither a missing permit nor another actor's permit authorizes Auto");
        let (outcome, reasons) = gate_rejection_parts(error);
        assert_eq!(outcome, "pending");
        assert_eq!(reasons, ["gate.pending.source_trust"]);
        assert_eq!(
            checker.calls(),
            0,
            "ordinary Pending cannot be widened by the checker"
        );
        assert!(checker.seen().is_empty());
        assert!(vault.get_raw(&claim_id)?.is_none());
        assert!(!has_pending_gate_consent(&vault, &claim_id)?);
        let records: Vec<_> = vault
            .store
            .gate_decisions(100)?
            .into_iter()
            .filter(|record| record.claim_id == Some(*claim_id.as_bytes()))
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, "pending");
        assert_eq!(records[0].reason_codes, ["gate.pending.source_trust"]);
        assert!(records[0].receipt_reasons.is_empty());
    }
    Ok(())
}

#[test]
fn lineage_checker_exclusions_keep_ordinary_allow() -> Result<()> {
    for (label, restricted, human, knob, inject) in [
        (
            "trivial benign lineage",
            false,
            false,
            Some(CHECKER_REF),
            true,
        ),
        ("human", true, true, Some(CHECKER_REF), true),
        ("no knob", true, false, None, true),
        ("None injection", true, false, Some(CHECKER_REF), false),
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = if human {
            test_id(0x20)
        } else {
            first_party_connector_actor_id()
        };
        put_policy_manifest_bytes(&vault, test_id(0x22), &lineage_manifest(knob, Some(actor)))?;
        let claim_id = test_id(0x33);
        let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
        let (candidate, envelope) = benign_source_lineage_parts(&vault, &body, restricted, human)?;
        let checker = Arc::new(RecordingAutoChecker::hold());
        let bounded_checker = BoundedAutoChecker::new(checker.clone());
        commit_lineage_candidate(
            &vault,
            &claim_id,
            candidate,
            &envelope,
            inject.then_some(&bounded_checker),
        )?;
        assert_eq!(checker.calls(), 0, "{label}");
        assert!(checker.seen().is_empty(), "{label}");
        let landed = vault.get_claim(&claim_id)?.expect("ordinary allow lands");
        assert_eq!(landed.approval, ClaimApprovalStatus::Auto, "{label}");
        assert_eq!(landed.source, Some(ClaimSource::Observed), "{label}");
        assert!(!has_pending_gate_consent(&vault, &claim_id)?, "{label}");
        let records: Vec<_> = vault
            .store
            .gate_decisions(100)?
            .into_iter()
            .filter(|record| record.claim_id == Some(*claim_id.as_bytes()))
            .collect();
        assert_eq!(records.len(), 1, "{label}");
        assert_eq!(records[0].outcome, "allow", "{label}");
        assert_eq!(records[0].reason_codes, ["gate.allow"], "{label}");
        assert!(records[0].receipt_reasons.is_empty(), "{label}");
    }
    Ok(())
}

/// Owner/user writes never reach a checker, whatever the manifest says.
#[test]
fn user_writes_never_consult_checker() -> Result<()> {
    let (_tmp, vault) = checker_vault(Some(CHECKER_REF))?;
    let mut data = checker_manifest(vec![checker_entry(CHECKER_REF)]);
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x24), &data)?;

    let claim_id = test_id(0x37);
    let body = public_stamped(source_trust_claim(ClaimSource::UserStated));
    let (_candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
    let checker = Arc::new(RecordingAutoChecker::hold());
    let bounded_checker = BoundedAutoChecker::new(checker.clone());

    gate_claim_write(
        &vault,
        &claim_id,
        &body,
        &envelope,
        Some(&bounded_checker),
        false,
    )?;

    assert_eq!(
        checker.calls(),
        0,
        "a human/user_stated write records zero checker calls"
    );
    let rows = decision_rows(&vault)?;
    assert_eq!(rows.len(), 1, "one decision, and it is the ordinary one");
    assert_eq!(rows[0].0.as_slice(), ["gate.allow"]);
    Ok(())
}

/// Every other claim write door threads no checker at all, so a configured
/// knob changes nothing on them: the ordinary batch door lands the same
/// Dreamer write Auto while a holding checker sits unreachable beside it.
#[test]
fn non_dreamer_paths_pass_none() -> Result<()> {
    let (_tmp, vault) = checker_vault(Some(CHECKER_REF))?;
    let claim_id = test_id(0x38);
    let body = checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let (candidate, envelope) = dreamer_parts(&vault, &body)?;
    let unreachable = RecordingAutoChecker::hold();

    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
        .commit()?;

    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim landed").approval,
        ClaimApprovalStatus::Auto,
        "the ordinary batch door injects no checker, so the knob is inert there"
    );
    assert_eq!(unreachable.calls(), 0);

    // The compat promotion entry point is the same story: it passes None.
    let plain_id = test_id(0x39);
    attempt_checked_candidate_write(&vault, &plain_id, &body, None)?;
    assert_eq!(
        vault.get_claim(&plain_id)?.expect("claim landed").approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(unreachable.calls(), 0);
    Ok(())
}
