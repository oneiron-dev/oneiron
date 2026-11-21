//! The task-brief composer's model call never reaches a model its prompt may
//! not go to (census L8-07; review #7821 round 1, P1 x2; Engine RULING
//! STACK-7819-FIX-LAYER, 14 Nov 17:11: each egress fix has a named red test
//! at the point the prompt would leave).
//!
//! The `[models.roles.local_reasoner]` seat is one model on the owner's own
//! server, a local-openai-compat fake; a model in a provider's cloud serves
//! another role. Each case sends the composer's call through
//! `oneiron_server::test_doors::task_brief_send`, the send the vault's
//! task-brief model makes once the role is admitted.
//!
//! - The seat's offer parks on a limit, and the owner has named the cloud
//!   model as its quota fallback: the call is refused, and the cloud model
//!   receives nothing. On a tree whose call takes the owner's fallback, the
//!   cloud model gets the prompt, and only its answer is dropped.
//! - A lens NOTE sits in a world the owner keeps on this machine: the owner's
//!   server is another machine, so the call is refused there too, and the
//!   seat's model receives nothing. While the world goes everywhere, the
//!   same call is drafted there. On a tree that never admits a lens row for
//!   the model's destination, the seat's model gets the prompt.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! task_brief_egress`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;

use fake_llm::{FakeLlm, Reply};
use oneiron::federation::record_scope::BirthPosition;
use oneiron::llm::manifest::ModelRole;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, ModelLocality, Vault, VaultConfig};
use oneiron_server::models::ModelRuntime;
use oneiron_server::test_doors::replay_admission::{
    keep_owner_fallback, runtime_keeping_owner_choices, seat_models,
};
use oneiron_server::test_doors::task_brief_send::send_brief_call;
use serde_json::json;

/// The lens NOTE's words.
const LENS_TEXT: &str = "Harbour survey: the dawn gauge sits beside the outfall pipe.";
/// The request the composer's prompt opens with.
const REQUEST: &str = "Request: Find out why the dawn tide readings run high";

/// The local reasoner's seat on the owner's server at `own`; the
/// generative reasoner's in a provider's cloud at `cloud`.
fn models(own: &FakeLlm, cloud: &FakeLlm) -> String {
    format!(
        r#"
[providers.own]
kind = "local-openai-compat"
base_url = "{}"
[providers.cloud]
kind = "openai-compat"
base_url = "{}"
[roles.local_reasoner]
model = "own:small"
[roles.generative_reasoner]
model = "cloud:big"
"#,
        own.base_url, cloud.base_url
    )
}

/// The runtime `models` builds, its rests and the owner's quota choices
/// kept in `vault`; its local reasoner seat is on the owner's server.
fn runtime(vault: &Arc<Vault>, own: &FakeLlm, cloud: &FakeLlm) -> ModelRuntime {
    let runtime = runtime_keeping_owner_choices(&models(own, cloud), Arc::clone(vault))
        .expect("the models config");
    assert_eq!(
        runtime
            .seat(ModelRole::LocalReasoner)
            .expect("the local reasoner seat")
            .locality,
        ModelLocality::OwnServer,
        "precondition: the local reasoner's seat is on the owner's server"
    );
    runtime
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// Review #7821 P1 (ai_host/task_brief.rs:155): the seat's own offer parks
/// on a rate limit, and the owner's standing `use_fallback` choice for it
/// names a model in a provider's cloud. The composer's call keeps to the
/// owner's own models: it is refused, and the cloud model never receives
/// the prompt.
#[tokio::test]
async fn a_parked_local_reasoner_never_falls_back_to_a_third_party() {
    let limit = Reply::Error {
        status: 429,
        headers: vec![("retry-after".to_owned(), "600".to_owned())],
        body: json!({ "error": { "message": "rate limit" } }),
    };
    let own = FakeLlm::start(vec![limit], None).await;
    let cloud = FakeLlm::start(Vec::new(), Some(Reply::text("a cloud draft"))).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let runtime = runtime(&vault, &own, &cloud);
    let cloud_models = seat_models(&runtime, ModelRole::GenerativeReasoner);
    let [big] = cloud_models.as_slice() else {
        panic!("the cloud seat is one model: {cloud_models:?}");
    };
    let offers = keep_owner_fallback(&runtime, ModelRole::LocalReasoner, big)
        .expect("the owner's use_fallback answer is kept");
    assert_eq!(offers, 1, "precondition: the seat's one offer");

    let sent = send_brief_call(&runtime, &vault, REQUEST, &[]).await;
    assert_eq!(
        own.seen().len(),
        1,
        "precondition: the seat's own offer was asked and parked: {sent:?}"
    );
    assert!(
        cloud.seen().is_empty(),
        "the owner's cloud fallback received the composer's prompt: {sent:?}"
    );
    assert!(sent.is_err(), "no local model drafted: {sent:?}");
}

/// Review #7821 P1 (task_verb/compose.rs:424): the lens NOTE's world is kept
/// on this machine, and the seat's model runs on the owner's server,
/// another machine. The composer's call carrying the NOTE's words is
/// refused before it is sent, and the seat's model never receives them.
/// While the world goes everywhere, the same call is drafted there.
#[tokio::test]
async fn a_lens_row_kept_on_this_machine_never_reaches_the_owner_server_model() {
    let own = FakeLlm::start(Vec::new(), Some(Reply::text("a local draft"))).await;
    let cloud = FakeLlm::start(Vec::new(), None).await;
    let dir = tempfile::tempdir().expect("tempdir");
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Arc::new(Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault"));
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let world = vault
        .create_world(&owner_proof, "harbour survey", now_secs())
        .expect("the lens world");
    let note = vault
        .memory(owner_id, EdgeActorClass::Human)
        .with_birth_position(BirthPosition {
            world: Some(world),
            facet: None,
        })
        .create_note("research", LENS_TEXT)
        .expect("the owner's NOTE in the lens world");
    let lens = EntityId::from_hex(&note.id_hex).expect("the NOTE's id");
    let runtime = runtime(&vault, &own, &cloud);
    let input = format!(
        "{REQUEST}\n\nContext rows:\n[1] NOTE {}:\n{LENS_TEXT}\n",
        note.id_hex
    );

    let drafted = send_brief_call(&runtime, &vault, &input, &[lens]).await;
    assert_eq!(
        drafted.as_deref(),
        Ok("a local draft"),
        "precondition: while the world goes everywhere, the owner's server drafts"
    );
    assert_eq!(own.seen().len(), 1, "precondition: one call drafted");

    vault
        .keep_world_on_this_machine_for_test(world, true)
        .expect("the owner keeps the lens world on this machine");
    let kept = send_brief_call(&runtime, &vault, &input, &[lens]).await;
    assert_eq!(
        own.seen().len(),
        1,
        "a lens row kept on this machine reached the owner's server model: {kept:?}"
    );
    assert!(kept.is_err(), "nothing drafted the kept call: {kept:?}");
    assert!(cloud.seen().is_empty(), "no cloud model was asked");
}
