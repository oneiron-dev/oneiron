use super::*;

use crate::config::VaultConfig;
use crate::edit_distance::ProposalArtifactRef;
use crate::edit_distance::attribution::{
    AmendmentCause, AmendmentEvidence, judge_amendment, record_amendment_evidence,
};
use crate::edit_distance::delta::{
    EndpointRef, MeasuredEnd, delta_from_reconstructed, put_amendment_delta_in_txn,
};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

// ─── fixtures ───────────────────────────────────────────────────────────

/// The two executor revisions the swap test folds under. Each is a full
/// `id@revision` identity on purpose: the executor stamp is what keys heads
/// apart, so a generation must read as a stamp.
const STACK_V2_MODEL: &str = "oneiron/orchestrator-default@2026-07-06";
const STACK_V1_MODEL: &str = "oneiron/orchestrator-default@2026-06-01";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn model(value: &str) -> ModelId {
    ModelId::new(value).expect("fixture model id")
}

fn put_actor(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"ed07 actor fixture",
    )?;
    Ok(id)
}

/// Lines in the fixture artifact every amendment is measured against.
const ARTIFACT_LINES: usize = 8;

/// An eight-line artifact with `changed` of its lines rewritten.
///
/// The line count is the fixture's mass knob, and it has to be a knob: ED-01
/// measures a normalized LINE diff, so any single-line rewrite is a total
/// replacement and saturates at `d_norm == 1`. Eight lines give
/// `d_norm == changed / 8`, which is enough resolution to place a scope above
/// AND below its peers.
fn artifact(changed: usize) -> (String, String) {
    let before: Vec<String> = (0..ARTIFACT_LINES)
        .map(|line| format!("line {line}"))
        .collect();
    let after: Vec<String> = before
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index < changed {
                format!("{line} amended")
            } else {
                line.clone()
            }
        })
        .collect();
    (before.join("\n"), after.join("\n"))
}

/// One amendment to fold: how much of the artifact moved, and why.
struct Amendment<'a> {
    receipt: &'a str,
    task_class: &'a str,
    changed: usize,
    cause: AmendmentCause,
}

impl<'a> Amendment<'a> {
    /// A SOUND amendment — the decider wanted it otherwise, so nothing was
    /// wrong with the proposal.
    const fn sound(receipt: &'a str, task_class: &'a str, changed: usize) -> Self {
        Self {
            receipt,
            task_class,
            changed,
            cause: AmendmentCause::DeciderPreference,
        }
    }
}

/// Drives the whole ED-01 → ED-03 → ED-07 path for one amendment and returns
/// the edit mass it contributed. Nothing here hands the projection a number:
/// the mass is measured, the class is judged, and the fold reads both back.
fn fold(vault: &Vault, actor: EntityId, amendment: &Amendment<'_>) -> Result<f64> {
    let d_norm = judge(vault, actor, amendment)?;
    record_judged_amendment(vault, amendment.receipt)?;
    Ok(d_norm)
}

/// [`fold`] stopping short of the routing fold — a judged receipt this module
/// has not folded yet.
fn judge(vault: &Vault, actor: EntityId, amendment: &Amendment<'_>) -> Result<f64> {
    let (before, after) = artifact(amendment.changed);
    let record = ProposalArtifactRef::mint();
    let delta = delta_from_reconstructed(
        MeasuredEnd {
            at: EndpointRef::imported_proposed(record),
            content: before.as_str(),
        },
        MeasuredEnd {
            at: EndpointRef::imported_final(record),
            content: after.as_str(),
        },
    );
    let d_norm = delta.d_norm;
    vault.with_write_txn(|wtxn| {
        put_amendment_delta_in_txn(vault, wtxn, amendment.receipt, &delta)?;
        Ok(())
    })?;
    let mut evidence = AmendmentEvidence::new(amendment.receipt, actor, amendment.task_class)
        .at(10)
        .with_cause(amendment.cause)
        .with_executor(serving_model_version(vault)?);
    if amendment.cause == AmendmentCause::ProposalWrong {
        evidence = evidence.with_routing_facts(false, true);
    }
    record_amendment_evidence(vault, &evidence)?;
    judge_amendment(vault, amendment.receipt)?.expect("fixture amendment judges");
    Ok(f64::from(d_norm))
}

fn stats_for(vault: &Vault, executor: &str, task_class: &str) -> Result<Option<RoutingScopeStats>> {
    Ok(routing_data_bar(vault)?
        .into_iter()
        .find(|row| row.key.executor == executor && row.key.task_class == task_class))
}

fn close_to(left: f32, right: f32) -> bool {
    (left - right).abs() < 1e-5
}

// ─── the swap hard-reset (oracle NEG) ───────────────────────────────────

#[test]
fn a_model_swap_starts_a_fresh_aggregate_and_never_blends() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    set_serving_model(&vault, &model(STACK_V1_MODEL))?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    fold(&vault, actor, &Amendment::sound("r2", "prose", 2))?;

    set_serving_model(&vault, &model(STACK_V2_MODEL))?;
    fold(&vault, actor, &Amendment::sound("r3", "prose", 2))?;

    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;
    let old = stats_for(&vault, STACK_V1_MODEL, "prose")?.expect("old generation retained");
    let new = stats_for(&vault, STACK_V2_MODEL, "prose")?.expect("new generation opened");

    assert_eq!(
        old.hint.runs, 2,
        "the old row keeps exactly the runs it earned"
    );
    assert_eq!(new.hint.runs, 1, "the new generation starts from nothing");
    // NEG: no row anywhere holds the merged history.
    assert!(
        routing_data_bar(&vault)?
            .iter()
            .all(|row| row.hint.runs < 3),
        "a swap must never fold two generations into one row"
    );
    assert!(
        old.hint
            .sound_share
            .is_some_and(|share| close_to(share, 1.0))
            && new
                .hint
                .sound_share
                .is_some_and(|share| close_to(share, 1.0)),
        "each row scores from its own runs"
    );
    Ok(())
}

#[test]
fn a_receipt_folds_once_even_across_a_swap() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    set_serving_model(&vault, &model(STACK_V1_MODEL))?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;

    // The same run, re-offered under a different generation, is still one run.
    record_judged_amendment(&vault, "r1")?;
    set_serving_model(&vault, &model(STACK_V2_MODEL))?;
    record_judged_amendment(&vault, "r1")?;

    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;
    let rows = routing_data_bar(&vault)?;
    assert_eq!(rows.len(), 1, "one run, one scope");
    assert_eq!(rows[0].hint.runs, 1);
    assert_eq!(rows[0].key.executor, STACK_V1_MODEL);
    Ok(())
}

#[test]
fn concurrent_folds_of_one_receipt_still_count_one_run() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    judge(&vault, actor, &Amendment::sound("r1", "prose", 2))?;

    // Both folds reach their binding read while this transaction holds the
    // writer lock, so neither can see the other's write yet — the interleaving
    // a first-fold check outside the write transaction cannot survive.
    // Releasing the lock lets them through one at a time.
    let gate = vault.store.env.write_txn()?;
    std::thread::scope(|scope| -> Result<()> {
        let folds: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| record_judged_amendment(&vault, "r1")))
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(100));
        drop(gate);
        for handle in folds {
            handle.join().expect("fold thread")?;
        }
        Ok(())
    })?;

    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;
    let row = stats_for(&vault, &serving_model_version(&vault)?, "prose")?.expect("scope folded");
    assert_eq!(row.hint.runs, 1, "one receipt is one run, whoever folds it");
    Ok(())
}

#[test]
fn an_unjudged_receipt_is_refused() {
    let (_tmp, vault) = temp_vault();
    assert!(matches!(
        record_judged_amendment(&vault, "never-judged"),
        Err(Error::InvalidClaimBody(_))
    ));
}

// ─── the rollout ladder ─────────────────────────────────────────────────

#[test]
fn the_ladder_gates_visibility_then_routing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    let key = RoutingScopeKey::new(serving_model_version(&vault)?, "prose");

    assert_eq!(rollout_rung(&vault, "prose")?, RolloutRung::Shadow);
    assert!(
        routing_weight_hint(&vault, &key)?.is_none(),
        "shadow reaches nothing"
    );
    assert!(
        routing_data_bar(&vault)?.is_empty(),
        "shadow is not even visible"
    );

    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;
    assert_eq!(routing_data_bar(&vault)?.len(), 1, "the data bar shows it");
    assert!(
        routing_weight_hint(&vault, &key)?.is_none(),
        "visible is not graduated"
    );

    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;
    assert!(routing_weight_hint(&vault, &key)?.is_some());
    assert_eq!(
        routing_data_bar(&vault)?.len(),
        1,
        "a graduated scope stays visible"
    );

    // A rung is a dial, not a ratchet.
    set_rollout_rung(&vault, "prose", RolloutRung::Shadow)?;
    assert!(routing_weight_hint(&vault, &key)?.is_none());
    Ok(())
}
