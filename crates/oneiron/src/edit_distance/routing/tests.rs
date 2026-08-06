use super::*;

use crate::config::VaultConfig;
use crate::edit_distance::attribution::{
    AmendmentCause, AmendmentEvidence, judge_amendment, record_amendment_evidence,
};
use crate::edit_distance::delta::{delta_from_reconstructed, put_amendment_delta_in_txn};
use crate::entity_id::EntityId;
use crate::llm::RoleModelDefaults;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

// ─── fixtures ───────────────────────────────────────────────────────────

/// The two compiled generations, by the role this projection measures. The
/// swap fixtures use REGISTERED models on purpose: it is the `ModelStack`
/// reverse resolution under test, not the unregistered fallback.
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

    /// An UNSOUND amendment: the proposal was wrong on its own terms, which
    /// the deterministic judge routes to an execution lapse.
    const fn unsound(receipt: &'a str, task_class: &'a str, changed: usize) -> Self {
        Self {
            receipt,
            task_class,
            changed,
            cause: AmendmentCause::ProposalWrong,
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
    let delta = delta_from_reconstructed(&before, &after);
    let d_norm = delta.d_norm;
    vault.with_write_txn(|wtxn| {
        put_amendment_delta_in_txn(vault, wtxn, amendment.receipt, &delta)?;
        Ok(())
    })?;
    let mut evidence = AmendmentEvidence::new(amendment.receipt, actor, amendment.task_class)
        .at(10)
        .with_cause(amendment.cause);
    if amendment.cause == AmendmentCause::ProposalWrong {
        evidence = evidence.with_routing_facts(false, true);
    }
    record_amendment_evidence(vault, &evidence)?;
    judge_amendment(vault, amendment.receipt)?.expect("fixture amendment judges");
    Ok(f64::from(d_norm))
}

fn stats_for(vault: &Vault, version: &str, task_class: &str) -> Result<Option<RoutingScopeStats>> {
    Ok(routing_data_bar(vault)?
        .into_iter()
        .find(|row| row.key.model_version == version && row.key.task_class == task_class))
}

fn close_to(left: f32, right: f32) -> bool {
    (left - right).abs() < 1e-5
}

// ─── model version identity ─────────────────────────────────────────────

#[test]
fn a_registered_model_takes_its_stacks_identity() {
    assert_eq!(
        RoutingScopeKey::for_model(&model(STACK_V2_MODEL), "prose").model_version,
        "stack:default-v2"
    );
    assert_eq!(
        RoutingScopeKey::for_model(&model(STACK_V1_MODEL), "prose").model_version,
        "stack:default-v1"
    );
}

#[test]
fn an_unregistered_model_gets_its_own_generation() {
    // The two namespaces cannot collide, so an unknown model aggregates on its
    // own rather than quietly sharing a stack's row.
    let key = RoutingScopeKey::for_model(&model("openai/gpt-4.1@2026-07-02"), "prose");
    assert_eq!(key.model_version, "model:openai/gpt-4.1@2026-07-02");
}

#[test]
fn an_unconfigured_vault_records_where_the_router_reads() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let router = RoutingScopeKey::for_model(
        &RoleModelDefaults::default().resolve(DRAFTING_ROLE),
        "prose",
    );
    assert_eq!(serving_model_version(&vault)?, router.model_version);
    Ok(())
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
    let old = stats_for(&vault, "stack:default-v1", "prose")?.expect("old generation retained");
    let new = stats_for(&vault, "stack:default-v2", "prose")?.expect("new generation opened");

    assert_eq!(old.runs, 2, "the old row keeps exactly the runs it earned");
    assert_eq!(new.runs, 1, "the new generation starts from nothing");
    // NEG: no row anywhere holds the merged history.
    assert!(
        routing_data_bar(&vault)?.iter().all(|row| row.runs < 3),
        "a swap must never fold two generations into one row"
    );
    assert!(
        close_to(old.hint.outcome_score, 1.0) && close_to(new.hint.outcome_score, 1.0),
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
    assert_eq!(rows[0].runs, 1);
    assert_eq!(rows[0].key.model_version, "stack:default-v1");
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
    assert_eq!(row.runs, 1, "one receipt is one run, whoever folds it");
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

// ─── PGR-style relativity ───────────────────────────────────────────────

#[test]
fn the_same_absolute_cost_scores_against_its_own_task_class() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    // One generation does identically-sized work in two task classes...
    set_serving_model(&vault, &model(STACK_V2_MODEL))?;
    let mine_prose = fold(&vault, actor, &Amendment::sound("p1", "prose", 2))?;
    let mine_calendar = fold(&vault, actor, &Amendment::sound("c1", "calendar", 2))?;
    assert!(close_to(mine_prose as f32, mine_calendar as f32));

    // ...against peers who are expensive in one class and cheap in the other.
    set_serving_model(&vault, &model(STACK_V1_MODEL))?;
    let peer_prose = fold(&vault, actor, &Amendment::sound("p2", "prose", 6))?;
    let peer_calendar = fold(&vault, actor, &Amendment::sound("c2", "calendar", 1))?;
    assert!(peer_prose > mine_prose, "fixture peer edits prose harder");
    assert!(
        peer_calendar < mine_calendar,
        "fixture peer edits calendar lighter"
    );

    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;
    set_rollout_rung(&vault, "calendar", RolloutRung::Graduated)?;
    let prose = routing_weight_hint(&vault, &RoutingScopeKey::new("stack:default-v2", "prose"))?
        .expect("graduated scope answers");
    let calendar = routing_weight_hint(
        &vault,
        &RoutingScopeKey::new("stack:default-v2", "calendar"),
    )?
    .expect("graduated scope answers");

    assert!(
        prose.relative_edit_cost < 1.0,
        "cheaper than its prose peers"
    );
    assert!(
        calendar.relative_edit_cost > 1.0,
        "dearer than its calendar peers"
    );

    // The score is this generation's mean over the task class's whole
    // distribution — the same absolute mass, two different answers.
    assert!(close_to(
        prose.relative_edit_cost,
        (mine_prose / ((mine_prose + peer_prose) / 2.0)) as f32
    ));
    assert!(close_to(
        calendar.relative_edit_cost,
        (mine_calendar / ((mine_calendar + peer_calendar) / 2.0)) as f32
    ));
    Ok(())
}

#[test]
fn a_generation_with_no_peers_sits_at_par() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;

    let key = RoutingScopeKey::new(serving_model_version(&vault)?, "prose");
    let hint = routing_weight_hint(&vault, &key)?.expect("graduated scope answers");
    assert!(
        close_to(hint.relative_edit_cost, 1.0),
        "compared to nothing is compared to itself"
    );
    Ok(())
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

#[test]
fn the_ladder_is_per_task_class() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("p1", "prose", 2))?;
    fold(&vault, actor, &Amendment::sound("c1", "calendar", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;

    let version = serving_model_version(&vault)?;
    assert!(routing_weight_hint(&vault, &RoutingScopeKey::new(&version, "prose"))?.is_some());
    assert!(
        routing_weight_hint(&vault, &RoutingScopeKey::new(&version, "calendar"))?.is_none(),
        "promoting one task class promotes only that one"
    );
    Ok(())
}

// ─── the Goodhart pairing ───────────────────────────────────────────────

#[test]
fn the_hint_always_carries_the_paired_outcome() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    // Two amendments of the SAME mass in the same scope: one because the
    // decider wanted it otherwise, one because the proposal was wrong.
    let sound = fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    let unsound = fold(&vault, actor, &Amendment::unsound("r2", "prose", 2))?;
    assert!(close_to(sound as f32, unsound as f32), "same edit mass");

    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;
    let key = RoutingScopeKey::new(serving_model_version(&vault)?, "prose");
    let hint = routing_weight_hint(&vault, &key)?.expect("graduated scope answers");

    // Cost alone cannot tell these two apart — which is exactly why it is
    // never readable alone.
    assert!(close_to(hint.relative_edit_cost, 1.0));
    assert!(
        close_to(hint.outcome_score, 0.5),
        "half of this scope's amendments were the proposal being wrong"
    );
    Ok(())
}

#[test]
fn an_all_sound_scope_scores_a_perfect_outcome() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    fold(&vault, actor, &Amendment::sound("r2", "prose", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;

    let key = RoutingScopeKey::new(serving_model_version(&vault)?, "prose");
    let hint = routing_weight_hint(&vault, &key)?.expect("graduated scope answers");
    assert!(close_to(hint.outcome_score, 1.0));
    Ok(())
}

// ─── rebuild (CID-7) ────────────────────────────────────────────────────

#[test]
fn rebuild_reproduces_the_incremental_fold() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    set_serving_model(&vault, &model(STACK_V1_MODEL))?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    fold(&vault, actor, &Amendment::unsound("r2", "prose", 2))?;
    set_serving_model(&vault, &model(STACK_V2_MODEL))?;
    fold(&vault, actor, &Amendment::sound("r3", "calendar", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;
    set_rollout_rung(&vault, "calendar", RolloutRung::DataBar)?;

    let before = routing_data_bar(&vault)?;
    assert_eq!(before.len(), 2, "the fixture built two scopes");
    rebuild_routing_projection(&vault)?;
    assert_eq!(before, routing_data_bar(&vault)?, "rebuild is an identity");

    // And it is idempotent, not merely correct once.
    rebuild_routing_projection(&vault)?;
    assert_eq!(before, routing_data_bar(&vault)?);
    Ok(())
}

#[test]
fn rebuild_drops_a_run_whose_judgment_was_withdrawn() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    fold(&vault, actor, &Amendment::sound("r2", "prose", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;
    let version = serving_model_version(&vault)?;
    assert_eq!(
        stats_for(&vault, &version, "prose")?
            .expect("scope folded")
            .runs,
        2
    );

    // The judge abstains on re-judging: ED-03 withdraws the row, and the run
    // must stop weighing on the generation.
    record_amendment_evidence(&vault, &AmendmentEvidence::new("r2", actor, "prose").at(10))?;
    assert!(judge_amendment(&vault, "r2")?.is_none());
    rebuild_routing_projection(&vault)?;

    let row = stats_for(&vault, &version, "prose")?.expect("scope survives");
    assert_eq!(row.runs, 1, "a verdict nobody stands behind stops counting");

    // The binding went with it, so nothing keeps a withdrawn run bound to a
    // generation it can no longer be judged into.
    assert!(matches!(
        record_judged_amendment(&vault, "r2"),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

#[test]
fn rebuild_picks_up_a_rejudged_class() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;
    let key = RoutingScopeKey::new(serving_model_version(&vault)?, "prose");
    assert!(close_to(
        routing_weight_hint(&vault, &key)?
            .expect("graduated scope answers")
            .outcome_score,
        1.0
    ));

    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new("r1", actor, "prose")
            .at(10)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(false, true),
    )?;
    judge_amendment(&vault, "r1")?.expect("re-judges");
    rebuild_routing_projection(&vault)?;

    assert!(
        close_to(
            routing_weight_hint(&vault, &key)?
                .expect("graduated scope answers")
                .outcome_score,
            0.0
        ),
        "the correction reaches the projection"
    );
    Ok(())
}

// ─── the router call site ───────────────────────────────────────────────

#[test]
fn the_router_door_is_shadow_defaulted_and_never_swaps_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let defaults = RoleModelDefaults::default();
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;

    let (shadowed, hint) = defaults.resolve_with_routing_hint(&vault, DRAFTING_ROLE, "prose")?;
    assert_eq!(shadowed, defaults.resolve(DRAFTING_ROLE));
    assert!(hint.is_none(), "shadow is the default rung");

    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;
    let (graduated, hint) = defaults.resolve_with_routing_hint(&vault, DRAFTING_ROLE, "prose")?;
    assert_eq!(
        graduated,
        defaults.resolve(DRAFTING_ROLE),
        "a hint informs a weight; it never changes the model"
    );
    assert!(hint.is_some(), "a graduated scope reaches the router");
    Ok(())
}

// ─── key hygiene ────────────────────────────────────────────────────────

#[test]
fn an_unusable_scope_is_refused_rather_than_keyed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    for task_class in ["", "   ", "a\0b"] {
        assert!(matches!(
            rollout_rung(&vault, task_class),
            Err(Error::InvalidClaimBody(_))
        ));
        assert!(matches!(
            routing_weight_hint(
                &vault,
                &RoutingScopeKey::new("stack:default-v2", task_class)
            ),
            Err(Error::InvalidClaimBody(_))
        ));
    }

    // The rung gate runs first, so an unusable MODEL version is only reached
    // once the task class has graduated — a shadow scope does no key work at
    // all.
    let empty_version = RoutingScopeKey::new("", "prose");
    assert!(routing_weight_hint(&vault, &empty_version)?.is_none());
    set_rollout_rung(&vault, "prose", RolloutRung::Graduated)?;
    assert!(matches!(
        routing_weight_hint(&vault, &empty_version),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

#[test]
fn a_stored_scope_key_round_trips_both_halves() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    fold(&vault, actor, &Amendment::sound("r1", "prose", 2))?;
    set_rollout_rung(&vault, "prose", RolloutRung::DataBar)?;

    let row = routing_data_bar(&vault)?.pop().expect("one scope");
    assert_eq!(row.key.task_class, "prose");
    assert_eq!(row.key.model_version, serving_model_version(&vault)?);
    Ok(())
}
