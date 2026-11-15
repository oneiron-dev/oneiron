//! Restriction wave 8 (owner 16 Nov 00:44, "optional freedom with good defaults everywhere"):
//! three fixed bounds become owner keys on the Setting primitive, each defaulting to today's
//! value, so nothing changes until the owner moves one.
//! - `receipt.action.max_input_entities` (default 64): an action naming more entities states no
//!   input digest; the owner may raise the cap.
//! - `derive.batch.max_items` (default 256, never below it): a larger derivation batch is
//!   malformed; the owner may raise the cap.
//! - `note.birth.agent_min_chars` (default 16): an agent's NOTE born shorter is refused; the
//!   owner may lower the floor.
//!
//! For each key, a moved value lets the formerly refused act stand, and the default refuses it
//! exactly as before.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test restriction_wave_8`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{Claim, Committed, Named, commit_claims};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const INPUT_ENTITIES_KEY: &str = "receipt.action.max_input_entities";
const BATCH_ITEMS_KEY: &str = "derive.batch.max_items";
const AGENT_NOTE_KEY: &str = "note.birth.agent_min_chars";

/// The owner's change of `key` at the vault scope, as the Setting door answers it.
fn owner_sets(vault: &Vault, key: &str, value: Value) -> oneiron::Result<SetSettingOutcome> {
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    vault.set_setting(
        SettingCaller::Owner(&owner),
        SetSetting::vault_value(key, value),
    )
}

/// The owner moves `key` to `value`, and the change applies.
fn owner_moves(vault: &Vault, key: &str, value: Value) {
    let outcome = owner_sets(vault, key, value).expect("the owner's change");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's change did not apply: {outcome:?}"
    );
}

fn plain_vault(dir: &tempfile::TempDir) -> Vault {
    Vault::open(dir.path(), VaultConfig::default()).expect("open vault")
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn named_entities(count: usize) -> BTreeSet<EntityId> {
    let mut named = BTreeSet::new();
    while named.len() < count {
        named.insert(EntityId::now());
    }
    named
}

// receipt.action.max_input_entities

#[test]
fn an_owner_raised_input_entity_cap_versions_a_wider_action() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    owner_moves(&vault, INPUT_ENTITIES_KEY, json!(65));
    let named = named_entities(65);
    let inputs = vault
        .action_inputs(&named)
        .expect("the capture reads")
        .expect("65 named entities fit the owner's cap of 65");
    let text = format!("{inputs:?}");
    for id in &named {
        assert!(
            text.contains(&format!("entity:{}", id.to_hex())),
            "every named entity is versioned: {text}"
        );
    }
}

#[test]
fn an_action_naming_more_than_64_entities_states_no_input_digest_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    assert!(
        vault
            .action_inputs(&named_entities(65))
            .expect("the capture reads")
            .is_none(),
        "65 named entities pass the default cap of 64: no input digest"
    );
    assert!(
        vault
            .action_inputs(&named_entities(64))
            .expect("the capture reads")
            .is_some(),
        "64 named entities are versioned under the default"
    );
}

// derive.batch.max_items

/// `count` claims about one person, each citing nothing: each is judged alone (and refused by
/// the evidence floor); the batch itself commits when its size is admitted.
fn claims_about(person: EntityId, count: usize) -> Vec<Claim> {
    (0..count)
        .map(|index| Claim {
            local: Box::leak(format!("claim-{index}").into_boxed_str()),
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!(format!("cup {index}")),
            evidence: Vec::new(),
        })
        .collect()
}

fn commit_batch_of(vault: &Vault, count: usize) -> oneiron::Result<Committed> {
    let person = put(vault, ENTITY_TYPE_PERSON, b"someone");
    let actor = dreamer(vault).expect("the Dreamer");
    commit_claims(
        vault,
        actor,
        EdgeActorClass::System,
        "run-batch-cap",
        &claims_about(person, count),
    )
}

#[test]
fn an_owner_raised_batch_cap_commits_a_larger_derivation_batch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    owner_moves(&vault, BATCH_ITEMS_KEY, json!(257));
    let committed = commit_batch_of(&vault, 257).expect("257 items fit the owner's cap of 257");
    assert_eq!(committed.items.len(), 257, "every item has its outcome");
}

#[test]
fn a_derivation_batch_over_256_items_is_malformed_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let refused = commit_batch_of(&vault, 257).expect_err("257 items pass the default cap");
    assert!(
        format!("{refused:?}").contains("derive.batch.max_items"),
        "the batch is malformed by its size: {refused:?}"
    );
    let committed = commit_batch_of(&vault, 256).expect("256 items fit the default cap");
    assert_eq!(committed.items.len(), 256);
}

#[test]
fn a_batch_cap_below_256_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
    let refused = owner_sets(&vault, BATCH_ITEMS_KEY, json!(255))
        .expect_err("the engine's own jobs fill 256-item batches");
    assert!(
        format!("{refused:?}").contains("at least 256"),
        "the cap's own check refuses it: {refused:?}"
    );
    owner_moves(&vault, BATCH_ITEMS_KEY, json!(256));
}

// note.birth.agent_min_chars

fn agent(vault: &Vault) -> EntityId {
    put(vault, ENTITY_TYPE_PERSON, b"agent")
}

const SHORT_NOTE: &str = "Low tide.";
const SIXTEEN_CHARS: &str = "Low tide at six.";

#[test]
fn an_owner_lowered_agent_note_floor_lets_a_short_agent_note_land() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    let agent = agent(&vault);
    owner_moves(&vault, AGENT_NOTE_KEY, json!(8));
    vault
        .memory(agent, EdgeActorClass::Agent)
        .create_note("research", SHORT_NOTE)
        .expect("a 9-character agent NOTE meets the owner's floor of 8");
}

#[test]
fn an_agent_note_under_16_chars_is_refused_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = plain_vault(&dir);
    let agent = agent(&vault);
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    let refused = memory
        .create_note("research", SHORT_NOTE)
        .expect_err("a 9-character agent NOTE is under the default floor of 16");
    assert!(
        format!("{refused:?}").contains("under the minimum length"),
        "the birth floor refuses it: {refused:?}"
    );
    assert_eq!(SIXTEEN_CHARS.chars().count(), 16);
    memory
        .create_note("research", SIXTEEN_CHARS)
        .expect("a 16-character agent NOTE meets the default floor");
}
