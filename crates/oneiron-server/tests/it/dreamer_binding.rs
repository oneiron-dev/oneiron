// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! A correction a later pass hears binds to the claim an earlier pass wrote
//! (dogfood gate 3, the binding slice of map gap 7). The shipped binary runs
//! two passes on a model that follows the extraction prompt: it reuses a
//! listed entity's id and names a listed claim when a turn corrects it.
//! Before the extraction input listed the known entities, the second pass saw
//! only its own turn, minted a new subject, and nothing bound.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_consolidation::{
    enqueue_partition_attempts, read_watermark, scan_dirty_turns,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use oneiron::{DreamerConsolidationScope, EntityId, TimeRange, Vault};
use serde_json::{Value, json};

use crate::ai_serve::{
    free_port, models_section, oneiron, serve, stop, vault_config, wait_for, write_config,
};
use crate::fake_llm::{FakeLlm, Reply};

/// The id the model gives the person it meets in the first pass.
const PERSON: &str = "0c0ffee0000000000000000000000001";

/// One user turn in `conversation`, queued for the Dreamer while the server
/// is stopped. A new conversation row comes with the first turn.
fn witness(vault_path: &Path, conversation: EntityId, text: &str, new: bool, run: &str) {
    let vault = Vault::open_owned(vault_path, vault_config()).unwrap();
    let turn = EntityId::now();
    let at = vault.now_recorded_at();
    let when = TimeRange { start: at, end: at };
    let encode = |body: Value| rmp_serde::to_vec_named(&body).unwrap();
    let mut batch = vault.batch();
    if new {
        batch = batch.put(
            &conversation,
            ENTITY_TYPE_CONVERSATION,
            when,
            at,
            &encode(json!({"title": "binding"})),
        );
    }
    batch
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            when,
            at,
            &encode(json!({"txt": text, "spkr": "user", "at": at})),
        )
        .edge_checked(&turn, &conversation, 1.0)
        .commit()
        .unwrap();
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope).unwrap();
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 16).unwrap();
    assert!(!dirty.is_empty(), "the new turn is dirty");
    enqueue_partition_attempts(&vault, scope, &dirty, &watermark, run, 1).unwrap();
}

fn text(message: &Value) -> &str {
    message["content"].as_str().unwrap_or_default()
}

/// A model that does what the extraction prompt asks. It names a listed
/// `profile.name` claim when one is shown, and otherwise meets the person.
/// Asked for a verdict, it takes the newer value.
fn follows_the_prompt() -> Reply {
    Reply::Computed(Arc::new(|request: &Value| {
        let messages = request["messages"].as_array().unwrap();
        if !text(&messages[0]).starts_with("Extract durable memory claims") {
            return json!({"resolution": "supersede", "value": "Alex"}).to_string();
        }
        let input = text(messages.last().unwrap());
        let turn = input
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix('['))
            .and_then(|line| line.split_whitespace().next())
            .unwrap()
            .to_owned();
        let mut subject = None;
        let mut listed = None;
        for line in input.lines() {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some("entity"), Some(id), _) => subject = Some(id.to_owned()),
                (Some("claim"), Some(id), Some("profile.name")) => {
                    listed = subject.clone().map(|subject| (subject, id.to_owned()));
                }
                _ => {}
            }
        }
        let evidence = json!([{"source_id": turn, "byte_range": [0, 4]}]);
        match listed {
            Some((subject, claim)) => json!({"candidates": [{
                "subject": subject, "predicate": "profile.name", "value": "Alex",
                "corrects": claim, "confidence": 0.9, "evidence_refs": evidence,
            }]}),
            None => json!({
                "persons": [{"id": PERSON, "name": "Oleksii", "evidence_turn_refs": [turn]}],
                "candidates": [{
                    "subject": PERSON, "predicate": "profile.name", "value": "Oleksii",
                    "confidence": 0.9, "evidence_refs": evidence,
                }],
            }),
        }
        .to_string()
    }))
}

/// Serves until the model has heard `calls` requests and then a quiet spell,
/// then stops gracefully.
async fn serve_until(config: &Path, fake: &FakeLlm, calls: usize) {
    let child = serve(config);
    assert!(
        wait_for(Duration::from_secs(90), || fake.seen().len() >= calls).await,
        "the server made {} model calls, not {calls}",
        fake.seen().len()
    );
    let mut heard = fake.seen().len();
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let now = fake.seen().len();
        if now == heard {
            break;
        }
        heard = now;
    }
    stop(child);
}

fn names(vault: &Vault, person: EntityId) -> Vec<(EntityId, oneiron::ClaimBody)> {
    vault
        .claims_for_subject(&person)
        .unwrap()
        .into_iter()
        .filter_map(|id| Some((id, vault.get_claim(&id).ok().flatten()?)))
        .filter(|(_, body)| body.predicate == "profile.name")
        .collect()
}

/// Whether `replacement` binds to `prior`: granted (it supersedes it) or held
/// in the owner's review with the supersession deferred.
fn binds(vault: &Vault, replacement: EntityId, prior: EntityId) -> bool {
    vault.pending_claim_supersession(&replacement).unwrap() == Some(prior)
        || vault
            .edges_out(&replacement)
            .unwrap()
            .iter()
            .any(|edge| edge.kind == oneiron::edge::EdgeKind::Supersedes && edge.target == prior)
}

#[tokio::test]
async fn a_later_pass_binds_a_correction_to_the_claim_an_earlier_pass_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    let conversation = EntityId::now();
    witness(
        &vault_path,
        conversation,
        "call me Oleksii",
        true,
        "binding-1",
    );
    let fake = FakeLlm::start(Vec::new(), Some(follows_the_prompt())).await;
    let config = write_config(
        dir.path(),
        &vault_path,
        free_port(),
        &models_section(&fake.base_url),
    );
    let granted = oneiron(
        &config,
        &["dreamer", "grant", "--extraction-route", "own_server"],
    )
    .output()
    .unwrap();
    assert!(
        granted.status.success(),
        "grant: {}",
        String::from_utf8_lossy(&granted.stderr)
    );

    serve_until(&config, &fake, 1).await;
    let person = EntityId::from_hex(PERSON).unwrap();
    let first = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        let [(first, _)] = names(&vault, person)[..] else {
            panic!("the first pass wrote one name: {:?}", names(&vault, person));
        };
        first
    };

    witness(
        &vault_path,
        conversation,
        "Not Oleksii any more, call me Alex.",
        false,
        "binding-2",
    );
    let before = fake.seen().len();
    serve_until(&config, &fake, before + 1).await;
    let seen = fake.seen();
    let listing = text(
        seen[before].body["messages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
    );
    assert!(
        listing.contains(&format!("entity {PERSON}"))
            && listing.contains(&format!("claim {}", first.to_hex())),
        "the second pass's input lists the person and the first pass's claim: {listing}"
    );

    let held = |vault: &Vault| {
        let names = names(vault, person);
        assert_eq!(names.len(), 2, "one correction, no duplicate: {names:?}");
        let bound: Vec<_> = names
            .iter()
            .filter(|(id, _)| *id != first && binds(vault, *id, first))
            .collect();
        assert_eq!(bound.len(), 1, "the correction binds once: {names:?}");
        assert_eq!(bound[0].1.value, rmpv::Value::from("Alex"));
    };
    held(&Vault::open_owned(&vault_path, vault_config()).unwrap());

    // Started again, nothing is left to run and nothing binds twice.
    let calls = fake.seen().len();
    let child = serve(&config);
    tokio::time::sleep(Duration::from_secs(5)).await;
    stop(child);
    assert_eq!(fake.seen().len(), calls, "a finished pass makes no call");
    held(&Vault::open_owned(&vault_path, vault_config()).unwrap());
}
