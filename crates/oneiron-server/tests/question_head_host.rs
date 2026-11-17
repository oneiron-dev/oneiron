#![cfg(oneiron_test_support)]
//! The host's question heads (FIX 23586, 23587; FIX 3864). The Local slot
//! answers a yes/no question the owner bound a head to, when the call
//! carries the head's input, with that head; every other call reaches the
//! seat the slot fronts. A head that cannot load abstains, so the next rung
//! answers. An unbound head leaves the slot when the owner's door prunes it,
//! or at the slot's next call once a minute has passed. A head's trial reads
//! the host's current answerer twice per held-out row, records the first
//! read's pin, cost and wall clock, and records an abstaining answerer's row
//! as unknown. The trainer is a local fake that returns a tiny head whose
//! encoder is all zero, so its raw logits are its bias and every probability
//! below is exact; custody, every run write and the head's load are real.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test question_head_host`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/question_head_fixture.rs"]
mod question_head_fixture;

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionClass, DecisionImage, DecisionPack,
    DecisionProvider, DecisionQuestion, DecisionQuestionInput, DecisionRung, EvidenceVersion,
    ProviderDecision, ProviderPin,
};
use oneiron::llm::image::ImageBytes;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::store::GateDecisionId;
use oneiron::training_pack::{QuestionHeadBinding, SwapChoice};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::question_heads;
use serde_json::{Value, json};

use engine_stack::on_engine_stack;
use question_head_fixture::{
    HeadTrainer, TEMPERATURE, TestSeat, big_rung_question, scored_question_run,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The bound head's bias: raw logits [no, yes] = [0, 2].
const HEAD_BIAS: [f32; 2] = [0.0, 2.0];
/// The seats' P(yes): outside the default band, so a ladder takes it.
const LOCAL_SEAT_YES: f64 = 0.2;
const BIG_SEAT_YES: f64 = 0.9;
const BIG_SEAT_COST: f64 = 0.25;
/// The trial's held-out rows, one family each.
const HELD_OUT_ROWS: usize = 2;

/// The head's P(yes) at the fitted temperature: sigmoid(margin / T).
fn head_yes() -> f64 {
    let margin = f64::from(HEAD_BIAS[1] - HEAD_BIAS[0]) / TEMPERATURE;
    1.0 / (1.0 + (-margin).exp())
}

fn assert_close(found: Option<f64>, expected: f64) {
    let found = found.expect("a number");
    assert!(
        (found - expected).abs() < 1e-12,
        "found {found}, expected {expected}"
    );
}

/// A vault and its authenticated owner, the owner's actor beside it.
fn owner_vault() -> TestResult<(tempfile::TempDir, Arc<Vault>, AuthenticatedOwner, EntityId)> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default())?);
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())?;
    Ok((dir, vault, owner, actor))
}

fn bind(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    run: &EntityId,
    question: EntityId,
) -> TestResult<QuestionHeadBinding> {
    let choice = SwapChoice::ExplicitOverride {
        reason: "owner tried the head".to_owned(),
    };
    Ok(vault.approve_training_question_head(owner, run, question, 1, choice, &[])?)
}

/// A server over `vault` with `seat` in its Local slot and the owner's
/// question heads in front of it, as a server attached with a `[models]`
/// config holds them.
fn local_host(vault: &Arc<Vault>, seat: &Arc<TestSeat>) -> TestResult<SyncServer> {
    let server = SyncServer::new(Arc::clone(vault), SyncServerConfig::default())?;
    let server = question_heads::with_seat(server, DecisionRung::Local, seat.clone())?;
    Ok(question_heads::with_question_heads(server))
}

fn local_slot(server: &SyncServer) -> Arc<dyn DecisionProvider> {
    Arc::clone(
        server
            .decision_ladder()
            .local
            .as_ref()
            .expect("the Local slot"),
    )
}

fn question(id: EntityId, contract: AnswerContract) -> DecisionQuestion {
    DecisionQuestionInput {
        text: "Does this target ask for help?".to_owned(),
        class: DecisionClass::Judgment,
        contract,
        accept_type: false,
    }
    .with_identity(id, 1)
}

/// A state that is the head's input: a target and its context.
fn head_input() -> Value {
    json!({"target": "Can someone explain chart 0?", "context": []})
}

fn ask(
    slot: &dyn DecisionProvider,
    question: &DecisionQuestion,
    state: &Value,
    images: &[DecisionImage],
) -> oneiron::Result<ProviderDecision> {
    let deadline = RetrievalDeadline::hard(Instant::now(), Duration::from_secs(60));
    slot.decide(&DecisionCall {
        question,
        evidence: &[],
        images,
        audio: &[],
        state,
        deadline: &deadline,
        run: None,
        labels: None,
    })
}

fn ask_pack(
    slot: &dyn DecisionProvider,
    questions: &[&DecisionQuestion],
) -> oneiron::Result<Vec<ProviderDecision>> {
    let deadline = RetrievalDeadline::hard(Instant::now(), Duration::from_secs(60));
    let state = head_input();
    slot.decide_pack(&DecisionPack {
        questions,
        evidence: &[],
        images: &[],
        audio: &[],
        state: &state,
        deadline: &deadline,
        run: None,
        labels: None,
    })
}

/// The head's answer: its P(yes) at the bound temperature, named by its
/// checkpoint's load-set hash under the slot's rung and version.
fn assert_head_answered(decision: &ProviderDecision, binding: &QuestionHeadBinding) -> TestResult {
    let checkpoint = blake3::Hash::from(binding.checkpoint.content_hash()?).to_hex();
    assert_eq!(binding.temperature, TEMPERATURE);
    assert_eq!(decision.answer, DecisionAnswer::Noul(head_yes() >= 0.5));
    assert_close(decision.probability, head_yes());
    assert_eq!(
        decision.served,
        Some(ProviderPin {
            rung: DecisionRung::Local,
            model: format!("oneiron/question-head.{checkpoint}"),
            version: "v1".to_owned(),
        })
    );
    assert_eq!(decision.cost_per_thousand, None, "the provider's rate");
    Ok(())
}

/// The Local seat's answer, as the seat gave it.
fn assert_seat_answered(decision: &ProviderDecision, answer: DecisionAnswer) {
    assert_eq!(decision.answer, answer);
    assert_close(decision.probability, LOCAL_SEAT_YES);
    assert_eq!(decision.served, None);
}

#[test]
fn a_bound_head_answers_its_yes_no_question_and_every_other_call_reaches_the_seat() -> TestResult {
    on_engine_stack(bound_head_and_seat_reads)
}

async fn bound_head_and_seat_reads() -> TestResult {
    let (_dir, vault, owner, _) = owner_vault()?;
    let trainer = HeadTrainer {
        bias: HEAD_BIAS,
        without: None,
    };
    let run = scored_question_run(&vault, &owner, 1, &trainer).await?.id;
    let bound = EntityId::now();
    let binding = bind(&vault, &owner, &run, bound)?;
    let seat = Arc::new(TestSeat::new(
        DecisionRung::Local,
        "fixture/local-seat",
        LOCAL_SEAT_YES,
        None,
    ));
    let server = local_host(&vault, &seat)?;
    let local = local_slot(&server);
    assert_eq!(local.pin(), seat.pin(), "the slot names the seat it fronts");

    let noul = question(bound, AnswerContract::Noul);
    assert_head_answered(&ask(&*local, &noul, &head_input(), &[])?, &binding)?;
    assert_eq!(seat.calls(), 0, "the head answered; the seat was not asked");
    assert_eq!(
        question_heads::loaded_question_heads(&server),
        vec![(bound, 1)]
    );

    let no = DecisionAnswer::Noul(false);
    let unbound = question(EntityId::now(), AnswerContract::Noul);
    assert_seat_answered(&ask(&*local, &unbound, &head_input(), &[])?, no.clone());
    let choice = question(
        bound,
        AnswerContract::Choice {
            options: vec!["help".to_owned(), "none".to_owned()],
        },
    );
    let help = DecisionAnswer::Choice("help".to_owned());
    assert_seat_answered(&ask(&*local, &choice, &head_input(), &[])?, help);
    let score = question(bound, AnswerContract::Score { min: 0.0, max: 1.0 });
    let lowest = DecisionAnswer::Score(0.0);
    assert_seat_answered(&ask(&*local, &score, &head_input(), &[])?, lowest);
    let image = DecisionImage {
        name: "camera".to_owned(),
        evidence: EvidenceVersion {
            id: EntityId::now(),
            body_hash: [7; 32],
        },
        image: ImageBytes {
            bytes: b"\x89PNG\r\n\x1a\n".to_vec(),
            media_type: "image/png".to_owned(),
        },
        frame: None,
    };
    let with_image = ask(&*local, &noul, &head_input(), std::slice::from_ref(&image))?;
    assert_seat_answered(&with_image, no.clone());
    let no_context = json!({"target": "Can someone explain chart 0?"});
    assert_seat_answered(&ask(&*local, &noul, &no_context, &[])?, no.clone());
    assert_eq!(seat.calls(), 5, "each of the five reached the seat once");

    // A pack in which no question has a bound head goes to the seat whole.
    let whole = ask_pack(&*local, &[&unbound, &choice])?;
    assert_eq!((seat.packs(), seat.calls()), (1, 5));
    assert_seat_answered(&whole[0], no.clone());
    // Otherwise the head answers its question and the seat each other one, alone.
    let mixed = ask_pack(&*local, &[&noul, &unbound])?;
    assert_eq!((seat.packs(), seat.calls()), (1, 6));
    assert_head_answered(&mixed[0], &binding)?;
    assert_seat_answered(&mixed[1], no);
    assert_eq!(
        question_heads::loaded_question_heads(&server),
        vec![(bound, 1)]
    );
    Ok(())
}

#[test]
fn an_unbound_head_leaves_the_slot_on_the_owners_prune_or_within_a_minute() -> TestResult {
    on_engine_stack(unbound_head_prunes)
}

async fn unbound_head_prunes() -> TestResult {
    let (_dir, vault, owner, _) = owner_vault()?;
    let trainer = HeadTrainer {
        bias: HEAD_BIAS,
        without: None,
    };
    let run = scored_question_run(&vault, &owner, 1, &trainer).await?.id;
    let bound = EntityId::now();
    let seat = Arc::new(TestSeat::new(
        DecisionRung::Local,
        "fixture/local-seat",
        LOCAL_SEAT_YES,
        None,
    ));
    let server = local_host(&vault, &seat)?;
    let local = local_slot(&server);
    let noul = question(bound, AnswerContract::Noul);
    let unbound = question(EntityId::now(), AnswerContract::Noul);

    // The owner's unbind door prunes the slot once the binding is gone.
    let binding = bind(&vault, &owner, &run, bound)?;
    assert_head_answered(&ask(&*local, &noul, &head_input(), &[])?, &binding)?;
    assert_eq!(
        question_heads::loaded_question_heads(&server),
        vec![(bound, 1)]
    );
    assert!(
        vault
            .unbind_training_question_head(&owner, bound, 1)?
            .is_some()
    );
    assert_eq!(
        question_heads::loaded_question_heads(&server),
        vec![(bound, 1)],
        "an unbind alone leaves the loaded head until a prune"
    );
    question_heads::forget_unbound_question_heads(&server);
    assert!(question_heads::loaded_question_heads(&server).is_empty());
    let after = ask(&*local, &noul, &head_input(), &[])?;
    assert_seat_answered(&after, DecisionAnswer::Noul(false));
    assert!(question_heads::loaded_question_heads(&server).is_empty());

    // With no door prune, the slot's next call once a minute has passed drops it.
    let binding = bind(&vault, &owner, &run, bound)?;
    assert_head_answered(&ask(&*local, &noul, &head_input(), &[])?, &binding)?;
    assert!(
        vault
            .unbind_training_question_head(&owner, bound, 1)?
            .is_some()
    );
    ask(&*local, &unbound, &head_input(), &[])?;
    assert_eq!(
        question_heads::loaded_question_heads(&server),
        vec![(bound, 1)],
        "within the minute no call prunes"
    );
    question_heads::backdate_question_head_prune(&server, Duration::from_secs(61));
    ask(&*local, &unbound, &head_input(), &[])?;
    assert!(question_heads::loaded_question_heads(&server).is_empty());
    Ok(())
}

#[test]
fn a_bound_head_whose_load_set_lacks_a_file_abstains_and_the_seat_is_not_asked() -> TestResult {
    on_engine_stack(short_load_set_abstains)
}

async fn short_load_set_abstains() -> TestResult {
    let (_dir, vault, owner, _) = owner_vault()?;
    let trainer = HeadTrainer {
        bias: HEAD_BIAS,
        without: Some("head.safetensors"),
    };
    let run = scored_question_run(&vault, &owner, 1, &trainer).await?.id;
    let bound = EntityId::now();
    let binding = bind(&vault, &owner, &run, bound)?;
    assert_eq!(
        binding.checkpoint.files.len(),
        4,
        "custody kept the short set"
    );
    let seat = Arc::new(TestSeat::new(
        DecisionRung::Local,
        "fixture/local-seat",
        LOCAL_SEAT_YES,
        None,
    ));
    let server = local_host(&vault, &seat)?;
    let local = local_slot(&server);

    let decision = ask(
        &*local,
        &question(bound, AnswerContract::Noul),
        &head_input(),
        &[],
    )?;
    assert_eq!(
        decision.answer,
        DecisionAnswer::Abstain,
        "the next rung answers"
    );
    assert_eq!((decision.probability, decision.served), (None, None));
    assert_eq!(seat.calls(), 0, "a bound question never falls to the seat");
    assert!(question_heads::loaded_question_heads(&server).is_empty());
    Ok(())
}

#[test]
fn a_trial_reads_the_current_answerer_twice_per_row_and_records_its_numbers() -> TestResult {
    on_engine_stack(trial_reads_and_records)
}

async fn trial_reads_and_records() -> TestResult {
    let (_dir, vault, owner, actor) = owner_vault()?;
    let trainer = HeadTrainer {
        bias: HEAD_BIAS,
        without: None,
    };
    let run = scored_question_run(&vault, &owner, HELD_OUT_ROWS, &trainer)
        .await?
        .id;
    let question = big_rung_question(&vault, actor)?;
    let seat = Arc::new(
        TestSeat::new(
            DecisionRung::Big,
            "fixture/big-seat",
            BIG_SEAT_YES,
            Some(BIG_SEAT_COST),
        )
        .reading_for(Duration::from_millis(5)),
    );
    let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default())?;
    let server = question_heads::with_seat(server, DecisionRung::Big, seat.clone())?;
    let answerer = question_heads::answerer_pins(&server);
    assert!(answerer.contains(&seat.pin()), "{answerer:?}");

    let trial = question_heads::run_question_head_trial(&server, &owner, &run, question, 1)?;
    assert_eq!(seat.calls(), 2 * HELD_OUT_ROWS, "two reads of each row");
    assert_eq!((trial.question, trial.question_version), (question, 1));
    assert_eq!(trial.answerer, answerer);
    let measured = trial.measured.clone().expect("recorded");
    assert_eq!(measured.cases, HELD_OUT_ROWS as u64);
    assert_eq!(measured.families, HELD_OUT_ROWS as u64);
    assert_eq!(measured.unknown_cases, 0);
    assert_eq!(measured.incumbent, vec![seat.pin()], "the first read's pin");
    assert_eq!(measured.incumbent_cost_per_thousand, Some(BIG_SEAT_COST));
    assert_eq!(measured.head_cost_per_thousand, 0.0);
    assert!(measured.incumbent_latency_ms >= 5.0, "{measured:?}");
    // Every held-out row is a yes: agreement is 1 - (1 - P(yes))^2.
    let agreement = |yes: f64| 1.0 - (1.0 - yes).powi(2);
    assert_close(
        measured.delta,
        agreement(head_yes()) - agreement(BIG_SEAT_YES),
    );
    assert_eq!(measured.noise, Some(0.0), "the retest read agreed");
    assert_eq!(vault.training_question_trial(&run)?, Some(trial));

    // An answerer that abstains leaves each row unknown; the trial still records.
    seat.abstain_from_now();
    let trial = question_heads::run_question_head_trial(&server, &owner, &run, question, 1)?;
    assert_eq!(seat.calls(), 4 * HELD_OUT_ROWS);
    let measured = trial.measured.clone().expect("recorded");
    assert_eq!(measured.unknown_cases, HELD_OUT_ROWS as u64);
    assert!(measured.incumbent.is_empty());
    assert_eq!(measured.incumbent_cost_per_thousand, None);
    assert_eq!((measured.delta, measured.noise), (None, None));
    assert!(!trial.wins());
    Ok(())
}
