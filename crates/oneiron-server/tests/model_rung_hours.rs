//! A role's rung may keep daily hours, such as a GPU box the owner runs
//! batch models on at night (UNBUILT-14; Engine RULING 15 Nov 21:46,
//! UNBUILT14-BATCH-MODEL-PICK = A). `[models.roles.<role>]` rungs take
//! `hours = { start, end, utc_offset | iana_timezone }`, the same type and
//! checks as `[[gpu.pods]] hours`.
//!
//! - Inside its hours the seat's walk tries that rung before the ladder's
//!   other rungs, wherever the owner listed it.
//! - Outside them the walk passes it at once, with no wait for the hours to
//!   open, and the next rung answers; the receipt names the rung passed as
//!   `outside_hours`.
//! - A model the owner's manifest pins is served at any hour: the pin is the
//!   owner's own pick of one model, never a ladder walk.
//! - A run's live compaction fork is bound to the rung that answered it only
//!   while the walk would take that rung: never outside its hours.
//! - A ladder whose every rung keeps hours is refused, so a call outside
//!   them always has a rung; `hours` on a role's single `model` is refused.
//!
//! Hours here are UTC and set around the current minute, an hour on each
//! side, so no run sits near a boundary.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! model_rung_hours`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fake_llm::{FakeLlm, Reply};
use futures_util::StreamExt;
use oneiron::llm::manifest::ModelRole;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, LlmStreamEvent, LlmUsage, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{ModelRuntime, OfferLadder};
use oneiron_server::test_doors::live_fork_rung::binds_live_fork_to_rung;
use oneiron_server::test_doors::replay_admission::{
    pin_every_role, runtime_keeping_owner_choices, seat_models,
};
use serde_json::{Value, json};

const MINUTES_PER_DAY: u64 = 24 * 60;
/// The longest a call here may take. A walk that waited for a rung's hours
/// to open would take an hour.
const CALL_LIMIT: Duration = Duration::from_secs(60);

/// `"HH:MM"` for `minute` after midnight.
fn clock(minute: u64) -> String {
    let minute = minute % MINUTES_PER_DAY;
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// The UTC minute of the day now.
fn utc_minute_now() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    secs / 60 % MINUTES_PER_DAY
}

/// A rung's `hours` in UTC from `from` to `to` minutes after now.
fn utc_hours(from: u64, to: u64) -> String {
    let now = utc_minute_now() + MINUTES_PER_DAY;
    format!(
        r#"{{ start = "{}", end = "{}", utc_offset = "+00:00" }}"#,
        clock(now + from),
        clock(now + to)
    )
}

/// Hours that hold now: from an hour ago to an hour from now.
fn hours_holding_now() -> String {
    utc_hours(MINUTES_PER_DAY - 60, 60)
}

/// Hours that open an hour from now and close an hour after that.
fn hours_after_now() -> String {
    utc_hours(60, 120)
}

/// Two owner servers: `gpubox`, the GPU box, and `daybox`, the server that
/// answers at any hour. Each answers every call with its own name.
struct Servers {
    gpubox: FakeLlm,
    daybox: FakeLlm,
}

impl Servers {
    async fn start() -> Self {
        Self {
            gpubox: FakeLlm::start(Vec::new(), Some(Reply::text("gpubox"))).await,
            daybox: FakeLlm::start(Vec::new(), Some(Reply::text("daybox"))).await,
        }
    }

    /// The models config: both servers as providers, and
    /// `generative_reasoner`'s `rungs` (the TOML array's items).
    fn models(&self, rungs: &str) -> String {
        format!(
            r#"
[providers.gpubox]
kind = "local-openai-compat"
base_url = "{gpubox}"
[providers.daybox]
kind = "local-openai-compat"
base_url = "{daybox}"
[roles.generative_reasoner]
rungs = [
{rungs}
]
"#,
            gpubox = self.gpubox.base_url,
            daybox = self.daybox.base_url,
        )
    }

    fn runtime(&self, rungs: &str) -> ModelRuntime {
        let config = ModelsConfig::from_toml(&self.models(rungs), None)
            .expect("a rung with hours is a valid models config");
        ModelRuntime::build(Some(&config), oneiron::HostingPrivacyPosture::SelfHostLocal)
    }
}

fn request(model: &ModelId) -> LlmRequest {
    LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "summarise the week".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

fn budget() -> BudgetGuard {
    BudgetGuard::new("rung-hours", 100_000, BudgetExhaustionPolicy::Suspend)
}

/// One call on `ladder`, answered within [`CALL_LIMIT`]: its receipt.
async fn generate(runtime: &ModelRuntime, ladder: &OfferLadder, model: &ModelId) -> LlmUsage {
    let run = runtime.undeclared_run("rung-hours", budget());
    tokio::time::timeout(CALL_LIMIT, ladder.generate(&run, request(model), None))
        .await
        .expect("the call ends at once, with no wait for a rung's hours")
        .expect("a rung answers the call")
        .usage
}

/// One streamed call on `ladder`, answered within [`CALL_LIMIT`]: its
/// receipt.
async fn stream(runtime: &ModelRuntime, ladder: &Arc<OfferLadder>, model: &ModelId) -> LlmUsage {
    let run = runtime.undeclared_run("rung-hours", budget());
    let mut events = ladder
        .stream(&run, request(model), None)
        .expect("a rung opens the stream");
    let done = async {
        while let Some(event) = events.next().await {
            if let LlmStreamEvent::Done { usage, .. } = event.expect("the stream answers") {
                return usage;
            }
        }
        panic!("the stream ended without Done");
    };
    tokio::time::timeout(CALL_LIMIT, done)
        .await
        .expect("the stream ends at once, with no wait for a rung's hours")
}

/// The receipt's answering rung: its place in the configured ladder and its
/// provider.
fn answered_by(usage: &LlmUsage) -> (Value, Value) {
    (
        usage.raw_provider["rung"].clone(),
        usage.raw_provider[LlmUsage::SERVED_PROVIDER_KEY].clone(),
    )
}

/// Inside its hours, the GPU box's rung is tried first although the owner
/// listed it second, and answers; the day server is never called.
#[tokio::test]
async fn a_rung_inside_its_hours_is_tried_before_the_ladders_other_rungs() {
    let servers = Servers::start().await;
    let runtime = servers.runtime(&format!(
        r#"{{ model = "daybox:day-model" }},
{{ model = "gpubox:night-model", hours = {} }},"#,
        hours_holding_now()
    ));
    let seat = runtime
        .seat(ModelRole::GenerativeReasoner)
        .expect("the reasoner's seat");

    let usage = generate(&runtime, &seat.ladder, &seat.model).await;
    assert_eq!(answered_by(&usage), (json!(1), json!("gpubox")));
    assert_eq!(
        usage.raw_provider.get("passed_over"),
        None,
        "no rung was passed: the GPU box's was tried first"
    );

    let usage = stream(&runtime, &seat.ladder, &seat.model).await;
    assert_eq!(answered_by(&usage), (json!(1), json!("gpubox")));

    assert_eq!(
        servers.gpubox.seen().len(),
        2,
        "the GPU box took both calls"
    );
    assert!(
        servers.daybox.seen().is_empty(),
        "the day server was never called inside the GPU box's hours"
    );
}

/// Outside its hours, the GPU box's rung is passed at once, with no wait for
/// them to open, and the next rung answers. The receipt names the rung it
/// passed and why.
#[tokio::test]
async fn a_rung_outside_its_hours_is_passed_at_once_for_the_next_rung() {
    let servers = Servers::start().await;
    let runtime = servers.runtime(&format!(
        r#"{{ model = "gpubox:night-model", hours = {} }},
{{ model = "daybox:day-model" }},"#,
        hours_after_now()
    ));
    let seat = runtime
        .seat(ModelRole::GenerativeReasoner)
        .expect("the reasoner's seat");

    let usage = generate(&runtime, &seat.ladder, &seat.model).await;
    assert_eq!(answered_by(&usage), (json!(1), json!("daybox")));
    assert_eq!(
        usage.raw_provider["passed_over"],
        json!([{
            "rung": 0,
            "provider": "gpubox",
            "model": "night-model",
            "passed": "outside_hours",
        }]),
        "the receipt names the rung passed outside its hours"
    );

    let usage = stream(&runtime, &seat.ladder, &seat.model).await;
    assert_eq!(answered_by(&usage), (json!(1), json!("daybox")));

    assert!(
        servers.gpubox.seen().is_empty(),
        "no call reached the GPU box outside its hours"
    );
    assert_eq!(
        servers.daybox.seen().len(),
        2,
        "the day server took both calls"
    );
}

/// A model the owner's manifest pins for the role is served on its own rung
/// at any hour: the pin is the owner's pick of that one model, not a walk
/// of the ladder.
#[tokio::test]
async fn a_model_the_owners_manifest_pins_is_served_outside_its_rungs_hours() {
    let servers = Servers::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let runtime = runtime_keeping_owner_choices(
        &servers.models(&format!(
            r#"{{ model = "gpubox:night-model", hours = {} }},
{{ model = "daybox:day-model" }},"#,
            hours_after_now()
        )),
        Arc::clone(&vault),
    )
    .expect("a rung with hours is a valid models config");
    let models = seat_models(&runtime, ModelRole::GenerativeReasoner);
    let [night, _day] = models.as_slice() else {
        panic!("the reasoner's seat has two rungs, found {models:?}");
    };
    pin_every_role(&vault, night, ModelLocality::OwnServer).expect("the owner's manifest pin");
    let seat = runtime
        .seat(ModelRole::GenerativeReasoner)
        .expect("the reasoner's seat");
    let route = runtime
        .route_role(&vault, ModelRole::GenerativeReasoner, seat)
        .expect("the pinned route");
    assert_eq!(&route.model, night, "the route is the pinned model");

    let usage = generate(&runtime, &route.ladder, &route.model).await;
    assert_eq!(answered_by(&usage), (json!(0), json!("gpubox")));
    assert_eq!(servers.gpubox.seen().len(), 1);
    assert!(servers.daybox.seen().is_empty());
}

/// A run's live compaction fork is bound to its answering rung only while
/// the walk would take that rung now: inside the GPU box's hours its rung
/// binds the fork, outside them it binds none, and the day server's rung,
/// which keeps no hours, binds it at any hour.
#[tokio::test]
async fn a_live_fork_is_never_bound_to_a_rung_outside_its_hours() {
    let servers = Servers::start().await;
    for (hours, gpubox_binds) in [(hours_holding_now(), true), (hours_after_now(), false)] {
        let runtime = servers.runtime(&format!(
            r#"{{ model = "gpubox:night-model", hours = {hours} }},
{{ model = "daybox:day-model" }},"#
        ));
        let seat = runtime
            .seat(ModelRole::GenerativeReasoner)
            .expect("the reasoner's seat");
        let live = request(&seat.model);
        assert_eq!(
            binds_live_fork_to_rung(&seat.ladder, 0, &live),
            gpubox_binds,
            "the GPU box's rung binds a live fork only inside its hours {hours}"
        );
        assert!(
            binds_live_fork_to_rung(&seat.ladder, 1, &live),
            "the day server's rung binds a live fork at any hour"
        );
    }
    assert!(servers.gpubox.seen().is_empty());
    assert!(servers.daybox.seen().is_empty());
}

/// The reason a models config with `rungs` is refused, or `None` when it is
/// accepted.
fn refusal(rungs: &str) -> Option<String> {
    let text = format!(
        r#"
[providers.gpubox]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:9"
[providers.daybox]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:9"
[roles.generative_reasoner]
{rungs}
"#
    );
    ModelsConfig::from_toml(&text, None)
        .err()
        .map(|error| format!("{error:#}"))
}

/// A rung's hours take the checks `[[gpu.pods]] hours` take, and a ladder
/// keeps one rung without hours. `hours` belongs to a rung of `rungs`.
#[test]
fn rung_hours_take_the_gpu_pod_hours_checks_and_leave_a_rung_without_hours() {
    let day = r#"{ model = "daybox:day-model" }"#;
    let ladder = |hours: &str| {
        format!(r#"rungs = [{{ model = "gpubox:night-model", hours = {hours} }}, {day}]"#)
    };
    for accepted in [
        r#"{ start = "22:00", end = "07:00", utc_offset = "+09:00" }"#,
        r#"{ start = "22:00", end = "07:00", iana_timezone = "Europe/Berlin" }"#,
    ] {
        assert_eq!(refusal(&ladder(accepted)), None, "{accepted}");
    }
    for (refused, reason) in [
        (
            r#"{ start = "22:00", end = "22:00", utc_offset = "+09:00" }"#,
            "start and end must differ",
        ),
        (
            r#"{ start = "24:00", end = "07:00", utc_offset = "+09:00" }"#,
            "start must be a time of day",
        ),
        (
            r#"{ start = "22:00", end = "07:00" }"#,
            "hours need a utc_offset or an iana_timezone",
        ),
        (
            r#"{ start = "22:00", end = "07:00", utc_offset = "+09:00", iana_timezone = "Asia/Tokyo" }"#,
            "set utc_offset or iana_timezone, not both",
        ),
        (
            r#"{ start = "22:00", end = "07:00", utc_offset = "+15:00" }"#,
            "utc_offset must be",
        ),
        (
            r#"{ start = "22:00", end = "07:00", iana_timezone = "Mars/Olympus" }"#,
            "iana_timezone must name an IANA zone",
        ),
    ] {
        let error = refusal(&ladder(refused)).unwrap_or_else(|| panic!("accepted {refused}"));
        assert!(
            error.contains("models.roles.generative_reasoner.rungs[0].hours"),
            "{refused}: the error names the rung: {error}"
        );
        assert!(error.contains(reason), "{refused}: {error}");
    }

    let every_rung = refusal(
        r#"rungs = [
  { model = "gpubox:night-model", hours = { start = "22:00", end = "07:00", utc_offset = "+09:00" } },
  { model = "daybox:day-model", hours = { start = "07:00", end = "22:00", utc_offset = "+09:00" } },
]"#,
    )
    .expect("a ladder whose every rung keeps hours is refused");
    assert!(
        every_rung.contains("leave one rung without hours"),
        "{every_rung}"
    );

    let single_model = refusal(
        r#"model = "gpubox:night-model"
hours = { start = "22:00", end = "07:00", utc_offset = "+09:00" }"#,
    )
    .expect("hours on a role's single model are refused");
    assert!(single_model.contains("hours"), "{single_model}");
}
