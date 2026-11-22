//! A role whose work never leaves the device (`leave_device = "never"`)
//! keeps that rule on every ladder its route hands out, the owner's quota
//! fallback included (FIX-LIST ROLE-LEAVE-DEVICE-LOST-ON-BARE-LADDER-FALLBACK).
//!
//! The role's own seat carries the rule. Its route may hand out a ladder
//! scoped for no role instead: the bare ladder of a model the owner's
//! manifest pins and the role's seat lacks, or the seat of another role
//! that the call comes with. When the offer on that ladder parks on a
//! limit and the owner's standing fallback (`use_fallback`) for it names a
//! model in a provider's cloud, the call is held: the cloud is never sent
//! it, and the widest route the call may take stays the owner's server.
//! A role that may leave the device takes the same fallback, as before.
//! #7309 closed the replay half of this row; this is the live walk.
//!
//! Reaches the owner's fallback and the route's bound through
//! `oneiron_server::test_doors::replay_admission`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! role_kept_on_device_fallback`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeMap;
use std::sync::Arc;

use fake_llm::{FakeLlm, Reply};
use oneiron::llm::manifest::ModelRole;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::replay_admission::{
    keep_owner_fallback, pin_every_role, route_locality_bound, runtime_keeping_owner_choices,
    seat_models,
};
use serde_json::json;

/// What the cloud answers.
const FROM_THE_CLOUD: &str = "from the cloud";

/// `own` is the owner's server, `cloud` a provider's cloud. The checker's
/// seat is one model on the owner's server. The generative reasoner's seat
/// is another model there, and its work never leaves the device. The
/// Dreamer's seat is a cloud model, so the runtime serves it as a model a
/// parked offer's calls may fall back to once the owner names it.
fn models(own: &FakeLlm, cloud: &FakeLlm) -> String {
    format!(
        r#"
[providers.own]
kind = "local-openai-compat"
base_url = "{}"
[providers.cloud]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [{{ model = "own:small" }}]
[roles.generative_reasoner]
model = "own:mid"
leave_device = "never"
[roles.dreamer_current]
model = "cloud:big"
"#,
        own.base_url, cloud.base_url
    )
}

/// A limit refusal that rests its offer an hour, past the vault's longest
/// wait, so a call parks on it at once.
fn limit() -> Reply {
    Reply::Error {
        status: 429,
        headers: vec![("retry-after".to_owned(), "3600".to_owned())],
        body: json!({"error": {"message": "rate limit"}}),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    runtime: ModelRuntime,
    /// The owner's server: every call it is sent meets the limit.
    own: FakeLlm,
    /// The provider's cloud: it answers every call it is sent.
    cloud: FakeLlm,
    /// The checker seat's model, on the owner's server.
    small: ModelId,
}

fn only(models: Vec<ModelId>, role: &str) -> ModelId {
    let [model] = models.as_slice() else {
        panic!("{role}: one rung, found {models:?}");
    };
    model.clone()
}

/// The runtime over both servers, its rests and the owner's choices kept
/// in a fresh vault, and the owner's fallback for the checker's offer: the
/// Dreamer's cloud model.
async fn fixture() -> Fixture {
    let own = FakeLlm::start(vec![], Some(limit())).await;
    let cloud = FakeLlm::start(vec![], Some(Reply::text(FROM_THE_CLOUD))).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let runtime = runtime_keeping_owner_choices(&models(&own, &cloud), Arc::clone(&vault))
        .expect("the models config");
    let small = only(seat_models(&runtime, ModelRole::Checker), "checker");
    let reasoner = only(
        seat_models(&runtime, ModelRole::GenerativeReasoner),
        "generative_reasoner",
    );
    assert_ne!(
        reasoner, small,
        "the reasoner's seat lacks the checker's model"
    );
    let big = only(
        seat_models(&runtime, ModelRole::DreamerCurrent),
        "dreamer_current",
    );
    for role in [ModelRole::Checker, ModelRole::GenerativeReasoner] {
        assert_eq!(
            runtime.seat(role).expect("seat").locality,
            ModelLocality::OwnServer,
            "{role:?}'s seat stays on the owner's server"
        );
    }
    let offers = keep_owner_fallback(&runtime, ModelRole::Checker, &big)
        .expect("the owner's use_fallback answer is kept");
    assert_eq!(offers, 1, "the checker's seat has one offer");
    Fixture {
        _dir: dir,
        vault,
        runtime,
        own,
        cloud,
        small,
    }
}

/// A chat call on `model` at `locality`, as a role's caller sends it.
fn request(model: &ModelId, locality: ModelLocality) -> LlmRequest {
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
            locality,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "the question".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

impl Fixture {
    /// One call of `role` that comes with `seat_role`'s seat, sent down the
    /// ladder the role's route hands out: the answer's text, else the
    /// error's.
    async fn call(&self, role: ModelRole, seat_role: ModelRole) -> Result<String, String> {
        let seat = self.runtime.seat(seat_role).expect("seat");
        let route = self
            .runtime
            .route_role(&self.vault, role, seat)
            .map_err(|refusal| refusal.to_string())?;
        let run = self.runtime.undeclared_run(
            "role-kept-test",
            BudgetGuard::new("role-kept-test", 100_000, BudgetExhaustionPolicy::Suspend),
        );
        let answer = route
            .ladder
            .generate(&run, request(&route.model, route.locality), None)
            .await
            .map_err(|error| format!("{error:?}"))?;
        Ok(answer
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect())
    }

    /// The widest route a call of `role` with `seat_role`'s seat may take,
    /// the owner's fallbacks included.
    fn bound(&self, role: ModelRole, seat_role: ModelRole) -> ModelLocality {
        route_locality_bound(&self.runtime, &self.vault, role, seat_role).expect("a route")
    }
}

/// The owner's manifest pins every role to the checker's model, which no
/// rung of the reasoner's seat has, so the reasoner's route is that model's
/// bare ladder.
#[tokio::test]
async fn a_manifest_pin_off_the_seat_keeps_a_staying_roles_call_on_the_device() {
    let fixture = fixture().await;
    pin_every_role(&fixture.vault, &fixture.small, ModelLocality::OwnServer)
        .expect("the owner's manifest pin");
    let reasoner = ModelRole::GenerativeReasoner;

    let held = fixture.call(reasoner, reasoner).await;
    assert!(
        fixture.cloud.seen().is_empty(),
        "the reasoner's call never reaches the cloud: {held:?}"
    );
    held.expect_err("the pinned offer rests and no fallback on the device is left");
    assert!(
        !fixture.own.seen().is_empty(),
        "the call went to the pinned model on the owner's server"
    );
    assert_eq!(
        fixture.bound(reasoner, reasoner),
        ModelLocality::OwnServer,
        "no fallback the owner may name takes the reasoner's call off the device"
    );

    // The checker may leave the device: on the same pin its call takes the
    // owner's fallback, as before.
    let checker = ModelRole::Checker;
    let answer = fixture
        .call(checker, checker)
        .await
        .expect("the owner's fallback answers the checker");
    assert_eq!(answer, FROM_THE_CLOUD);
    assert_eq!(fixture.bound(checker, checker), ModelLocality::ThirdParty);
}

/// With no manifest, the reasoner's call comes with the checker's seat (as
/// the Dreamer's teacher calls on its seat): the route is the checker's
/// ladder, which is scoped for the checker.
#[tokio::test]
async fn a_staying_role_on_another_roles_seat_keeps_its_call_on_the_device() {
    let fixture = fixture().await;
    let (reasoner, checker) = (ModelRole::GenerativeReasoner, ModelRole::Checker);

    let held = fixture.call(reasoner, checker).await;
    assert!(
        fixture.cloud.seen().is_empty(),
        "the reasoner's call never reaches the cloud: {held:?}"
    );
    held.expect_err("the checker's offer rests and no fallback on the device is left");
    assert!(
        !fixture.own.seen().is_empty(),
        "the call went to the checker's model on the owner's server"
    );
    assert_eq!(
        fixture.bound(reasoner, checker),
        ModelLocality::OwnServer,
        "no fallback the owner may name takes the reasoner's call off the device"
    );

    let answer = fixture
        .call(checker, checker)
        .await
        .expect("the owner's fallback answers the checker on its own seat");
    assert_eq!(answer, FROM_THE_CLOUD);
    assert_eq!(fixture.bound(checker, checker), ModelLocality::ThirdParty);
}
