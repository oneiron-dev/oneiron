//! Done means for provider cooldowns and call-time fallback (OF-305,
//! ONEIRON-FALLBACK = A): an offer refused for a quota or a limit hands the
//! same call to the next offer, rests until its reset (across a restart) and
//! is back with no action; a request error passes through; work kept on the
//! device stays there; and the receipt says why another model answered.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use oneiron::store::ports::ManualClock;
use oneiron::{
    EntityId, FatalLlmError, LlmError, LlmRequest, LlmResponse, LlmResult, LlmStreamEvent,
    RetryableLlmError, Vault, VaultConfig,
};
use serde_json::{Value, json};

use super::tests::{config, request, test_run, text_of};
use super::*;
use crate::fake_llm::{FakeLlm, Reply};

/// 2026-10-15T00:00:00Z.
pub(super) const T0: u64 = 1_792_022_400;
/// 2026-10-19T00:00:00Z.
const OCT_19: u64 = 1_792_368_000;
/// The shipped `provider_cooldown_default_seconds` row.
const DEFAULT_REST: u64 = 600;

pub(super) fn clocked_vault(dir: &Path, clock: &Arc<ManualClock>) -> Arc<Vault> {
    let mut vault_config = VaultConfig::device();
    vault_config.store_clock = clock.bundle();
    Arc::new(Vault::open(dir, vault_config).unwrap())
}

/// A checker seat: `first` on the vault's own server, then `second` in a
/// provider's cloud. `extra` lands in the seat's table.
pub(super) fn two_offers(first: &FakeLlm, second: &FakeLlm, extra: &str) -> ModelsConfig {
    config(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
{extra}
"#,
        first.base_url, second.base_url
    ))
}

/// A runtime whose rests are kept in `vault`, on `clock`.
pub(super) fn kept(
    config: &ModelsConfig,
    vault: &Arc<Vault>,
    clock: &Arc<ManualClock>,
) -> ModelRuntime {
    ModelRuntime::build_hosted(
        Some(config),
        None,
        OfferCooldowns::in_vault_on(Arc::clone(vault), Arc::clone(clock)),
    )
}

pub(super) fn refusal(status: u16, headers: &[(&str, &str)], body: Value) -> Reply {
    Reply::Error {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body,
    }
}

async fn ask(seat: &Seat) -> LlmResult<LlmResponse> {
    seat.ladder
        .generate(&test_run(), request(&seat.model, "check this"), None)
        .await
}

/// A world this vault holds, at its default settings: readable everywhere.
pub(super) fn portable_world(vault: &Vault) -> EntityId {
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    world
}

/// A world the world settings keep on this machine.
pub(super) fn private_world(vault: &Vault) -> EntityId {
    let world = portable_world(vault);
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .unwrap();
    world
}

/// A call to `seat` about `world`.
pub(super) fn about(seat: &Seat, world: EntityId) -> LlmRequest {
    let mut call = request(&seat.model, "about the world");
    call.envelope.scope.world = Some(world);
    call
}

/// The typed outcome of a call kept on the device, back at `back` when an
/// offer it may use rests.
pub(super) fn kept_here(back: Option<(u64, u64)>) -> LlmError {
    let (retry_after, resets_at) =
        back.map_or((None, Vec::new()), |(wait, at)| (Some(wait), vec![at]));
    RetryableLlmError::KeptOnDevice {
        retry_after,
        resets_at,
    }
    .into()
}

/// The text a seat streams for one call, which must answer.
async fn streamed(seat: &Seat) -> String {
    let mut events = seat
        .ladder
        .stream(&test_run(), request(&seat.model, "stream this"), None)
        .expect("a stream");
    let mut text = String::new();
    while let Some(event) = events.next().await {
        if let LlmStreamEvent::TextDelta { text: delta, .. } = event.expect("an answer") {
            text.push_str(&delta);
        }
    }
    text
}

fn limited(retry_after: u64, back: u64) -> LlmError {
    RetryableLlmError::RateLimited {
        retry_after: Some(retry_after),
        resets_at: vec![back],
    }
    .into()
}

/// Done means: a 429 on offer A answers from offer B in the same call; A is
/// skipped until its reset, then used again with no action; the receipt
/// names the answering offer, the refused offer and the cooldown end.
#[tokio::test]
async fn a_quota_refusal_answers_from_the_next_offer_which_serves_until_the_reset() {
    let first = FakeLlm::start(
        vec![refusal(
            429,
            &[],
            json!({"error": {
                "message": "Subscription quota exhausted, resets at 2026-10-15T00:15:00Z",
                "type": "rate_limit_error",
            }}),
        )],
        Some(Reply::text("first is back")),
    )
    .await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from second"))).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&two_offers(&first, &second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");

    let answer = ask(seat)
        .await
        .expect("the next offer answers the same call");
    assert_eq!(text_of(&answer.message), "from second");
    let receipt = &answer.usage.raw_provider;
    assert_eq!(receipt["provider"], json!("second"));
    assert_eq!(receipt["requested_model"], json!("big"));
    assert_eq!(receipt["failed_rungs"], json!(1));
    assert_eq!(
        receipt["passed_over"],
        json!([{
            "rung": 0, "provider": "first", "model": "small",
            "passed": "refused", "class": "rate_limited",
            "cooldown_until": T0 + 900, "reset": "error_time",
        }])
    );
    assert_eq!(first.seen().len(), 1);

    // Until its reset, the call goes straight to the next offer.
    clock.set(T0 + 899);
    let answer = ask(seat).await.expect("the next offer answers");
    assert_eq!(text_of(&answer.message), "from second");
    assert_eq!(
        answer.usage.raw_provider["passed_over"],
        json!([{
            "rung": 0, "provider": "first", "model": "small",
            "passed": "cooling_down", "cooldown_until": T0 + 900,
        }])
    );
    assert_eq!(answer.usage.raw_provider["failed_rungs"], json!(0));
    assert_eq!(first.seen().len(), 1, "a resting offer is never sent");

    // At its reset it is back in rotation, with no action.
    clock.set(T0 + 900);
    let answer = ask(seat).await.expect("the first offer is back");
    assert_eq!(text_of(&answer.message), "first is back");
    assert_eq!(answer.usage.raw_provider.get("passed_over"), None);
    assert_eq!((first.seen().len(), second.seen().len()), (2, 2));
}

/// Done means: a cooldown survives a restart.
#[tokio::test]
async fn a_rest_survives_a_restart_and_ends_by_itself() {
    let first = FakeLlm::start(
        vec![refusal(
            429,
            &[("retry-after", "300")],
            json!({"error": {"message": "rate limit"}}),
        )],
        Some(Reply::text("first is back")),
    )
    .await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from second"))).await;
    let models = two_offers(&first, &second, "");
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    {
        let vault = clocked_vault(dir.path(), &clock);
        let runtime = kept(&models, &vault, &clock);
        let seat = runtime.seat(ModelRole::Checker).expect("seat");
        let answer = ask(seat).await.expect("the next offer answers");
        assert_eq!(text_of(&answer.message), "from second");
    }
    // A new process: the vault reopens and the runtime is built afresh.
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&models, &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    clock.set(T0 + 299);
    let answer = ask(seat).await.expect("the next offer answers");
    assert_eq!(text_of(&answer.message), "from second");
    assert_eq!(
        answer.usage.raw_provider["passed_over"][0],
        json!({
            "rung": 0, "provider": "first", "model": "small",
            "passed": "cooling_down", "cooldown_until": T0 + 300,
        })
    );
    assert_eq!(first.seen().len(), 1, "the rest outlived the restart");
    clock.set(T0 + 300);
    let answer = ask(seat).await.expect("the first offer is back");
    assert_eq!(text_of(&answer.message), "first is back");
}

/// Done means: a 400 passes through unchanged, with no cooldown, even when
/// its body speaks of a quota.
#[tokio::test]
async fn a_bad_request_passes_through_unchanged_and_rests_nothing() {
    let first = FakeLlm::start(
        vec![],
        Some(refusal(
            400,
            &[],
            json!({"error": {
                "message": "max_tokens is past this model's output quota",
                "type": "invalid_request_error",
            }}),
        )),
    )
    .await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from second"))).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&two_offers(&first, &second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    for _ in 0..2 {
        let error = ask(seat).await.expect_err("a request error ends the call");
        assert_eq!(error, LlmError::Fatal(FatalLlmError::InvalidRequest));
    }
    let mut events = seat
        .ladder
        .stream(&test_run(), request(&seat.model, "stream this"), None)
        .expect("a stream");
    let error = events
        .next()
        .await
        .expect("an event")
        .expect_err("a request error ends the stream");
    assert_eq!(error, LlmError::Fatal(FatalLlmError::InvalidRequest));
    assert_eq!(
        first.seen().len(),
        3,
        "nothing rested: each call reached it"
    );
    assert!(second.seen().is_empty(), "a request error never falls back");

    // Review repro (Sol R1): a request error a provider sends inside an open
    // stream, and an Anthropic 400 whose body names a rate-limit type, are
    // request errors too. Review repro (Bugbot #1460): so is one an
    // OpenAI-compatible provider names by its `code` alone.
    let in_stream = json!({"error": {
        "type": "invalid_request_error",
        "message": "max_tokens is past this model's output quota",
    }});
    let by_code = json!({"error": {
        "code": "invalid_request_error",
        "message": "max_tokens is past this model's output quota",
    }});
    let streamed = FakeLlm::start(
        vec![Reply::Raw(format!("data: {in_stream}\n\n"))],
        Some(Reply::Raw(format!("data: {by_code}\n\n"))),
    )
    .await;
    let anthropic = FakeLlm::start(
        vec![],
        Some(refusal(
            400,
            &[],
            json!({"type": "error", "error": {"type": "rate_limit_error", "message": "bad limit field"}}),
        )),
    )
    .await;
    let models = config(&format!(
        r#"
[providers.streamed]
kind = "local-openai-compat"
base_url = "{}"
[providers.anthropic]
kind = "anthropic-compat"
base_url = "{}"
key_env = "HOME"
[providers.second]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [{{ model = "streamed:small" }}, {{ model = "second:big" }}]
[roles.generative_reasoner]
rungs = [{{ model = "anthropic:small" }}, {{ model = "second:big" }}]
"#,
        streamed.base_url, anthropic.base_url, second.base_url
    ));
    let runtime = kept(&models, &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    for _ in 0..2 {
        let mut events = seat
            .ladder
            .stream(&test_run(), request(&seat.model, "stream this"), None)
            .expect("a stream");
        let error = events
            .next()
            .await
            .expect("an event")
            .expect_err("an in-stream request error ends the stream");
        assert_eq!(error, LlmError::Fatal(FatalLlmError::InvalidRequest));
    }
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    let error = ask(seat).await.expect_err("an Anthropic 400 ends the call");
    assert_eq!(error, LlmError::Fatal(FatalLlmError::InvalidRequest));
    assert!(second.seen().is_empty(), "a request error never falls back");
}

/// Done means: an on-device seat never falls back to an off-device offer:
/// neither a seat set to stay on the device nor a call whose world the
/// world settings keep on it. Each refuses with when its offer is back.
#[tokio::test]
async fn work_kept_on_the_device_never_falls_back_off_it() {
    let limit = || {
        refusal(
            429,
            &[("retry-after", "120")],
            json!({"error": {"message": "rate limit"}}),
        )
    };
    let first = FakeLlm::start(vec![], Some(limit())).await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);

    // A seat whose work never leaves the device has no rung off it.
    let runtime = kept(
        &two_offers(&first, &second, "leave_device = \"never\""),
        &vault,
        &clock,
    );
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    assert_eq!(seat.locality, ModelLocality::OwnServer);
    let error = ask(seat).await.expect_err("nothing on the device is left");
    assert_eq!(error, limited(120, T0 + 120));
    assert!(second.seen().is_empty(), "the seat stays on the device");

    // A seat that may leave, called for a world kept on this machine.
    let world = private_world(&vault);
    let portable = portable_world(&vault);
    let (other_first, other_second) = (
        FakeLlm::start(vec![limit()], None).await,
        FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await,
    );
    let runtime = kept(&two_offers(&other_first, &other_second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let private = about(seat, world);
    let error = seat
        .ladder
        .generate(&test_run(), private.clone(), None)
        .await
        .expect_err("the world stays on the device");
    assert_eq!(error, kept_here(Some((120, T0 + 120))));
    let refused = seat
        .ladder
        .stream(&test_run(), private, None)
        .err()
        .expect("refused before the stream starts");
    assert_eq!(refused, kept_here(Some((120, T0 + 120))));
    assert!(
        other_second.seen().is_empty(),
        "the world's text stayed here"
    );
    // A call about a world that may leave still falls back.
    let answer = seat
        .ladder
        .generate(&test_run(), about(seat, portable), None)
        .await
        .expect("the cloud offer answers");
    assert_eq!(text_of(&answer.message), "from the cloud");
    assert_eq!(
        answer.usage.raw_provider["passed_over"][0]["passed"],
        json!("cooling_down")
    );

    // Review repro (Sol R1 P1): a cloud offer resting for a moment is never
    // one a device-only world's call waits for. A portable call leaves the
    // local offer resting an hour and the cloud one two seconds.
    let wait = |seconds: &str| {
        refusal(
            429,
            &[("retry-after", seconds)],
            json!({"error": {"message": "rate limit"}}),
        )
    };
    let (local, cloud) = (
        FakeLlm::start(vec![wait("3600")], None).await,
        FakeLlm::start(vec![wait("2"), wait("2")], None).await,
    );
    let runtime = kept(&two_offers(&local, &cloud, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let error = seat
        .ladder
        .generate(&test_run(), about(seat, portable), None)
        .await
        .expect_err("both offers refused");
    // It waited two seconds; the cloud offer's second refusal rests it two more.
    assert_eq!(error, limited(2, T0 + 4));
    assert_eq!(cloud.seen().len(), 2, "the portable call waited for it");
    let private = about(seat, world);
    let error = seat
        .ladder
        .generate(&test_run(), private.clone(), None)
        .await
        .expect_err("the private call waits for nothing it may not use");
    assert_eq!(error, kept_here(Some((3598, T0 + 3600))));
    let refused = seat
        .ladder
        .stream(&test_run(), private, None)
        .err()
        .expect("refused before the stream starts");
    assert_eq!(refused, kept_here(Some((3598, T0 + 3600))));
    assert_eq!(cloud.seen().len(), 2, "the world's text never went out");
}

/// Review repro (Sol R1 P1): a role whose work never leaves the device, left
/// with no rung, is refused rather than served by another role's cloud seat.
#[tokio::test]
async fn a_role_kept_on_the_device_never_borrows_a_cloud_seat() {
    let cloud = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let models = config(&format!(
        r#"
[providers.cloud]
kind = "openai-compat"
base_url = "{}"
[roles.generative_reasoner]
model = "cloud:big"
[roles.checker]
model = "cloud:big"
leave_device = "never"
"#,
        cloud.base_url
    ));
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&models, &vault, &clock);
    assert!(runtime.seat(ModelRole::Checker).is_none());
    let borrowed = runtime
        .seat(ModelRole::GenerativeReasoner)
        .expect("a cloud seat");
    assert!(matches!(
        runtime.route_role(&vault, ModelRole::Checker, borrowed),
        Err(RoleRefusal::NoSeat)
    ));
    assert!(
        runtime
            .route_role(&vault, ModelRole::GenerativeReasoner, borrowed)
            .is_ok()
    );
}

/// Review repro (CodeRabbit #1460): a call waiting for its first offer back
/// still asks whether it may go out, so a turn stopped mid-wait ends within
/// a slice of the wait, not when the offer is back.
#[tokio::test]
async fn a_call_stopped_while_it_waits_for_an_offer_back_ends_within_a_slice() {
    let limit = || {
        refusal(
            429,
            &[("retry-after", "30")],
            json!({"error": {"message": "rate limit"}}),
        )
    };
    let first = FakeLlm::start(vec![], Some(limit())).await;
    let second = FakeLlm::start(vec![], Some(limit())).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&two_offers(&first, &second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let (run, stopped) = (test_run(), AtomicBool::new(false));
    let may_send = || !stopped.load(Ordering::SeqCst);
    let call =
        seat.ladder
            .generate_while(&run, request(&seat.model, "wait for this"), None, &may_send);
    // Both offers refuse, so the call waits half a minute for the first back.
    let stop = async {
        while second.seen().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        stopped.store(true, Ordering::SeqCst);
        Instant::now()
    };
    let (answer, stopped_at) =
        tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(call, stop) })
            .await
            .expect("the stopped call ended before its offer was back");
    assert!(stopped_at.elapsed() <= 2 * cooldown::WAIT_SLICE);
    assert_eq!(answer.expect_err("nothing answered"), limited(30, T0 + 30));
    assert_eq!((first.seen().len(), second.seen().len()), (1, 1));
}

/// Review repro (Sol R2 P1): a seat whose first offer cannot be built still
/// treats its cloud offer as a fallback, so a call for a world kept on this
/// machine never goes there.
#[tokio::test]
async fn a_cloud_fallback_stays_a_fallback_when_the_first_offer_is_unavailable() {
    let cloud = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let models = config(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:9"
key_env = "ONEIRON_TEST_KEY_THAT_IS_NEVER_SET"
[providers.second]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
"#,
        cloud.base_url
    ));
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let (world, portable) = (private_world(&vault), portable_world(&vault));
    let runtime = kept(&models, &vault, &clock);
    let seat = runtime
        .seat(ModelRole::Checker)
        .expect("the cloud offer serves");
    let private = about(seat, world);
    let refused = kept_here(None);
    let error = seat
        .ladder
        .generate(&test_run(), private.clone(), None)
        .await
        .expect_err("the world stays on the device");
    assert_eq!(error, refused);
    let error = seat
        .ladder
        .stream(&test_run(), private, None)
        .err()
        .expect("refused before the stream starts");
    assert_eq!(error, refused);
    assert!(cloud.seen().is_empty(), "the world's text stayed here");
    let answer = seat
        .ladder
        .generate(&test_run(), about(seat, portable), None)
        .await
        .expect("a portable call goes to the cloud");
    assert_eq!(answer.usage.raw_provider["rung"], json!(1));
}

