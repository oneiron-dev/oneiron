//! An exact replay of a call the owner's quota fallback answered (FIX-LIST
//! REPLAY-REFUSED-FOR-WIDER-FALLBACK-RUNG; Engine ruling 13 Nov 02:2x).
//!
//! A role's seat runs on the owner's own server. When its offer parks on
//! spent quota the owner answers `use_fallback` with a model in a provider's
//! cloud, and that model answers the call: wider than every rung of the
//! seat. The replay of that call re-reads the owner's choice at replay time.
//! It is admitted while the owner's fallback for the seat's offers still
//! names that model there, since it then stays inside the owner's own
//! standing choice and widens nothing. It is refused for its own reason,
//! "fallback no longer allowed", once the owner names no fallback there or
//! has named another.
//!
//! Reaches the replay admission through `oneiron_server::test_doors`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! replay_owner_fallback`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use oneiron::{ModelId, ModelLocality, Vault, VaultConfig};
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::replay_admission::{
    admit_replay, keep_owner_fallback, runtime_keeping_owner_choices, seat_models,
};

/// The checker's seat is one model on the owner's own server. Two models in
/// a provider's cloud serve other roles, so each is a model a parked offer's
/// calls may fall back to once the owner names it. No call is sent: the
/// addresses are never dialled.
const MODELS: &str = r#"
[providers.own]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:9"
[providers.cloud]
kind = "openai-compat"
base_url = "http://127.0.0.1:9"
[roles.checker]
rungs = [{ model = "own:small" }]
[roles.generative_reasoner]
model = "cloud:big"
[roles.dreamer_current]
model = "cloud:other"
"#;

/// The text a replay refused for the owner's fallback reads with.
const FALLBACK_NO_LONGER_ALLOWED: &str = "fallback no longer allowed";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    runtime: ModelRuntime,
    /// The checker seat's own model, on the owner's server.
    own: ModelId,
    /// The cloud model the owner first names as the checker's fallback.
    big: ModelId,
    /// Another cloud model.
    other: ModelId,
}

fn only(models: Vec<ModelId>, role: &str) -> ModelId {
    let [model] = models.as_slice() else {
        panic!("{role}: one rung, found {models:?}");
    };
    model.clone()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let runtime =
        runtime_keeping_owner_choices(MODELS, Arc::clone(&vault)).expect("the models config");
    let own = only(seat_models(&runtime, ModelRole::Checker), "checker");
    let big = only(
        seat_models(&runtime, ModelRole::GenerativeReasoner),
        "generative_reasoner",
    );
    let other = only(
        seat_models(&runtime, ModelRole::DreamerCurrent),
        "dreamer_current",
    );
    assert_eq!(
        runtime.seat(ModelRole::Checker).expect("seat").locality,
        ModelLocality::OwnServer,
        "the checker's seat stays on the owner's server"
    );
    Fixture {
        _dir: dir,
        vault,
        runtime,
        own,
        big,
        other,
    }
}

impl Fixture {
    fn replay(&self, model: &ModelId, locality: ModelLocality) -> Result<(), String> {
        admit_replay(
            &self.runtime,
            &self.vault,
            ModelRole::Checker,
            model,
            locality,
        )
    }

    fn owner_names_fallback(&self, model: &ModelId) {
        let offers = keep_owner_fallback(&self.runtime, ModelRole::Checker, model)
            .expect("the owner's use_fallback answer is kept");
        assert_eq!(offers, 1, "the checker's seat has one offer");
    }
}

#[test]
fn a_replay_on_the_seats_own_route_is_admitted() {
    let fixture = fixture();
    fixture
        .replay(&fixture.own, ModelLocality::OwnServer)
        .expect("the seat's own rung serves its replay");
}

#[test]
fn a_replay_the_owners_standing_fallback_answered_is_admitted() {
    let fixture = fixture();
    fixture.owner_names_fallback(&fixture.big);
    fixture
        .replay(&fixture.big, ModelLocality::ThirdParty)
        .expect("the owner's standing fallback still names this model for the seat");
}

#[test]
fn a_replay_past_the_seat_with_no_owner_fallback_is_refused_for_its_own_reason() {
    let fixture = fixture();
    let refused = fixture
        .replay(&fixture.big, ModelLocality::ThirdParty)
        .expect_err("no owner's fallback lets the checker's calls leave its route");
    assert!(
        refused.contains(FALLBACK_NO_LONGER_ALLOWED),
        "refused for its own reason: {refused}"
    );
}

#[test]
fn a_replay_of_a_fallback_the_owner_narrowed_since_is_refused_for_its_own_reason() {
    let fixture = fixture();
    fixture.owner_names_fallback(&fixture.big);
    fixture
        .replay(&fixture.big, ModelLocality::ThirdParty)
        .expect("admitted while the owner's fallback names it");
    // The owner answers the next quota question with another model.
    fixture.owner_names_fallback(&fixture.other);
    let refused = fixture
        .replay(&fixture.big, ModelLocality::ThirdParty)
        .expect_err("the owner's fallback no longer names this model");
    assert!(
        refused.contains(FALLBACK_NO_LONGER_ALLOWED),
        "refused for its own reason: {refused}"
    );
    fixture
        .replay(&fixture.other, ModelLocality::ThirdParty)
        .expect("the owner's new fallback serves its own replay");
}
