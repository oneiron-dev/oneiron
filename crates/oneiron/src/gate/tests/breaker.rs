use super::*;

// ONE-1453 per-actor burst breaker: a durable, per-(dreamer run, provenance
// actor) velocity-to-review conversion over the ONE-1452 consent-bundle path.
// Fail-closed means DEMOTE, never deny; a tripped row clears only through an
// owner-authenticated bundle approve or decline.

/// The optional `actor_burst_breaker` manifest dial, spelled exactly.
fn breaker_dial_entry(max_events: Value, window_secs: Value) -> (Value, Value) {
    (
        Value::from(GATE_BREAKER_POLICY_KEY),
        Value::Map(vec![
            (Value::from("max_events"), max_events),
            (Value::from("window_secs"), window_secs),
        ]),
    )
}

/// A manifest that grants every actor in `actors` a Dreamer `Generated` Auto
/// path, optionally under a valid burst-breaker dial.
fn breaker_manifest(actors: &[EntityId], dial: Option<(u64, u64)>) -> Vec<u8> {
    let mut extra = vec![
        source_trust_entry(ClaimSource::Generated, 0),
        signatures_entry(),
    ];
    if let Some((max_events, window_secs)) = dial {
        extra.push(breaker_dial_entry(
            Value::from(max_events),
            Value::from(window_secs),
        ));
    }
    let mut data = encode_policy_manifest(extra);
    for actor in actors {
        append_actor_ceiling(
            &mut data,
            actor_ceiling_row_for_ref("agent", &actor.to_hex(), "auto"),
        );
    }
    data
}

/// One Dreamer-authored agent write on `run_id`.
fn breaker_write(
    vault: &crate::Vault,
    claim_id: EntityId,
    actor: EntityId,
    subject_seed: u8,
    run_id: &str,
    approval: ClaimApprovalStatus,
    learned_at: u64,
) -> Result<()> {
    let mut body = public_stamped(source_trust_claim(ClaimSource::Generated));
    body.subject = ClaimSubject::Entity(test_id(subject_seed));
    body.approval = approval;
    body.evidence = Some(precommit_evidence(vec![test_id(subject_seed)]));
    let (candidate, envelope) = dreamer_claim_candidate_write_parts(vault, &body, actor, run_id)?;
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            &envelope,
            test_time(learned_at),
            learned_at,
        )
        .commit()
}

fn breaker_row(
    vault: &crate::Vault,
    run_id: &str,
    actor: &EntityId,
) -> Result<Option<GateBreakerRowV1>> {
    let rtxn = vault.store.env.read_txn()?;
    gate_breaker_row_for_test(&vault.store, &rtxn, run_id, actor)
}

fn breaker_row_bytes(
    vault: &crate::Vault,
    run_id: &str,
    actor: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    gate_breaker_row_bytes_for_test(&vault.store, &rtxn, run_id, actor)
}

fn breaker_run_row_count(vault: &crate::Vault, run_id: &str) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    gate_breaker_run_row_count_for_test(&vault.store, &rtxn, run_id)
}

/// Every synthetic trip receipt in the ordinary gate-decision ledger.
fn breaker_trip_receipts(vault: &crate::Vault) -> Result<Vec<GateDecisionRecord>> {
    Ok(vault
        .store
        .gate_decisions(256)?
        .into_iter()
        .filter(|record| record.content_kind == GATE_BREAKER_CONTENT_KIND)
        .collect())
}

fn claim_gate_decisions(
    vault: &crate::Vault,
    claim_id: &EntityId,
) -> Result<Vec<GateDecisionRecord>> {
    Ok(vault
        .store
        .gate_decisions(256)?
        .into_iter()
        .filter(|record| record.claim_id == Some(*claim_id.as_bytes()))
        .collect())
}

#[test]
fn burst_triggers_pause() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x40);
    let other_actor = test_id(0x41);
    let run = "breaker-burst-run";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x70),
        &breaker_manifest(&[actor, other_actor], Some((2, 600))),
    )?;

    // Exactly `max_events` ordinary events keep their ordinary outcome and
    // trip nothing.
    breaker_write(
        &vault,
        test_id(0x30),
        actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    breaker_write(
        &vault,
        test_id(0x31),
        actor,
        0x51,
        run,
        ClaimApprovalStatus::Auto,
        4,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x31))?.approval,
        ClaimApprovalStatus::Auto
    );
    let untripped = breaker_row(&vault, run, &actor)?.expect("counted row");
    assert_eq!(untripped.event_timestamps().len(), 2);
    assert_eq!(untripped.tripped_at(), None);
    assert!(breaker_trip_receipts(&vault)?.is_empty());
    assert!(!vault.gate_breaker_run_projection(run)?.gate_breaker_paused);

    // Event `max_events + 1` durably trips and lands Proposed.
    breaker_write(
        &vault,
        test_id(0x32),
        actor,
        0x52,
        run,
        ClaimApprovalStatus::Auto,
        5,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x32))?.approval,
        ClaimApprovalStatus::Proposed,
        "the triggering would-be-Auto claim lands Proposed, never denied or discarded"
    );
    assert!(has_pending_gate_consent(&vault, &test_id(0x32))?);
    assert!(vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    let tripped = breaker_row(&vault, run, &actor)?.expect("tripped row");
    let tripped_at = tripped.tripped_at().expect("durable trip instant");
    assert_eq!(tripped.event_timestamps().len(), 3);
    assert_eq!(tripped.thresholds().max_events, 2);
    assert_eq!(tripped.thresholds().window_secs, 600);

    // Exactly one additional decision record represents the transition, and
    // its `diff_handle` is independently recomputable from the trip facts.
    let receipts = breaker_trip_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.content_kind, GATE_BREAKER_CONTENT_KIND);
    assert_eq!(receipt.outcome, GATE_BREAKER_OUTCOME_TRIPPED);
    assert_eq!(receipt.reason_codes, vec![GATE_BREAKER_REASON_TRIPPED]);
    assert_eq!(receipt.claim_id, None);
    assert!(receipt.receipt_reasons.is_empty());
    assert!(receipt.system_notices.is_empty());
    assert_eq!(receipt.actor_ref.as_deref(), Some(actor.to_hex().as_str()));
    assert_eq!(
        receipt.diff_handle,
        gate_breaker_trip_handle(
            run,
            &actor,
            tripped_at,
            // Post-append count at the transition: `max_events + 1`.
            3,
            GateBreakerThresholds {
                max_events: 2,
                window_secs: 600,
            },
        )
        .to_vec()
    );

    // A later event while tripped is demoted with no second trip receipt, and
    // the already-tripped row is not rewritten.
    let tripped_bytes = breaker_row_bytes(&vault, run, &actor)?.expect("tripped bytes");
    breaker_write(
        &vault,
        test_id(0x33),
        actor,
        0x53,
        run,
        ClaimApprovalStatus::Auto,
        6,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x33))?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert_eq!(breaker_trip_receipts(&vault)?.len(), 1);
    assert_eq!(
        breaker_row_bytes(&vault, run, &actor)?.as_deref(),
        Some(tripped_bytes.as_slice()),
        "an already-tripped row short-circuits: no prune, no append, no rewrite"
    );

    // A DIFFERENT actor on the SAME run is evaluated independently.
    breaker_write(
        &vault,
        test_id(0x34),
        other_actor,
        0x54,
        run,
        ClaimApprovalStatus::Auto,
        7,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x34))?.approval,
        ClaimApprovalStatus::Auto
    );
    assert_eq!(
        breaker_row(&vault, run, &other_actor)?
            .expect("second actor row")
            .tripped_at(),
        None
    );
    Ok(())
}

#[test]
fn breaker_counts_auto_and_existing_proposals_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // `auto_actor` carries an agent Auto ceiling; `pend_actor` does not, so
    // its Proposed writes take the ordinary actor-ceiling pend and land in the
    // consent tray. The breaker counts BOTH shapes, on their own rows.
    let auto_actor = test_id(0x40);
    let pend_actor = test_id(0x41);
    let run = "breaker-counting-run";
    // The owner-interactive write at the end of this test is an ordinary
    // `human` candidate, so the manifest carries the human class ceiling that
    // lets it land. Without that row it is refused outright for
    // `gate.pending.actor_ceiling` — a would-be-`Auto` write whose ordinary
    // outcome is pending — before it can demonstrate anything about the
    // breaker. The AGENT rows stay exactly as the assertions below need them:
    // `auto_actor` alone carries the agent Auto ceiling.
    let mut data = breaker_manifest(&[auto_actor], Some((8, 600)));
    trust_human_candidate_actor(&mut data);
    put_policy_manifest_bytes(&vault, test_id(0x70), &data)?;

    // A would-be-Auto event counts.
    breaker_write(
        &vault,
        test_id(0x30),
        auto_actor,
        0x50,
        run,
        ClaimApprovalStatus::Auto,
        3,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x30))?.approval,
        ClaimApprovalStatus::Auto
    );

    // An already-Proposed event counts and keeps its own pending outcome.
    breaker_write(
        &vault,
        test_id(0x31),
        pend_actor,
        0x51,
        run,
        ClaimApprovalStatus::Proposed,
        4,
    )?;
    assert_eq!(
        stored_claim_body(&vault, &test_id(0x31))?.approval,
        ClaimApprovalStatus::Proposed
    );
    assert!(has_pending_gate_consent(&vault, &test_id(0x31))?);
    for actor in [auto_actor, pend_actor] {
        assert_eq!(
            breaker_row(&vault, run, &actor)?
                .expect("counted row")
                .event_timestamps()
                .len(),
            1
        );
    }

    // The already-Proposed event keeps its landed reason set; counting alone
    // never grafts the breaker reason onto it.
    let rtxn = vault.store.env.read_txn()?;
    let pending = vault
        .store
        .pending_gate_consent_in_txn(&rtxn, &test_id(0x31))?
        .expect("pending row");
    drop(rtxn);
    assert!(
        !pending
            .reason_codes
            .iter()
            .any(|reason| reason.as_str() == GATE_BREAKER_REASON_PENDING)
    );

    // A gate DENIAL is not a candidate: an evidence-free Dreamer body is
    // refused by the GATE-12 floor and touches no breaker row.
    let mut denied = public_stamped(source_trust_claim(ClaimSource::Generated));
    denied.subject = ClaimSubject::Entity(test_id(0x52));
    denied.evidence = None;
    let (candidate, envelope) =
        dreamer_claim_candidate_write_parts(&vault, &denied, auto_actor, run)?;
    assert!(
        vault
            .batch()
            .claim_candidate(&test_id(0x32), candidate, &envelope, test_time(5), 5)
            .commit()
            .is_err()
    );
    assert_eq!(
        breaker_row(&vault, run, &auto_actor)?
            .expect("row")
            .event_timestamps()
            .len(),
        1,
        "a denied event keeps its outcome and books nothing"
    );

    // An owner-interactive write is outside the breaker even on a vault whose
    // run is being counted.
    let mut human = public_stamped(source_trust_claim(ClaimSource::UserStated));
    human.subject = ClaimSubject::Entity(test_id(0x53));
    let (candidate, envelope) = claim_candidate_write_parts(&vault, &human)?;
    vault
        .batch()
        .claim_candidate(&test_id(0x33), candidate, &envelope, test_time(6), 6)
        .commit()?;
    assert_eq!(breaker_run_row_count(&vault, run)?, 2);

    // The synthetic trip receipt is never itself counted: none was appended,
    // and nothing tripped.
    assert!(breaker_trip_receipts(&vault)?.is_empty());
    assert!(!vault.gate_breaker_run_projection(run)?.gate_breaker_paused);
    Ok(())
}

#[path = "breaker_policy.rs"]
mod policy;
#[path = "breaker_regressions.rs"]
mod regressions;
#[path = "breaker_transactions.rs"]
mod transactions;
