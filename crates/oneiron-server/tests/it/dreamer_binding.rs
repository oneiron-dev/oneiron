// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! A correction a later pass hears binds to the claim an earlier pass wrote
//! (dogfood gate 3, the binding slice of map gap 7). The shipped binary runs
//! two passes on a model that follows the extraction prompt: it reuses a
//! listed entity's id and names a listed claim when a turn corrects it.
//! Before the extraction input listed the known entities, the second pass saw
//! only its own turn, minted a new subject, and nothing bound.
//!
//! Where it binds follows the seeded policy (Engine ruling 2026-10-13): a
//! correction on a predicate no rule names lands with its grant, and one on a
//! class canon declares critical is held for the owner, in a fresh vault and
//! in one seeded before those classes shipped.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_consolidation::{
    enqueue_partition_attempts, read_watermark, scan_dirty_turns,
};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
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

/// What a scenario says about the person, and where its correction binds.
struct Case {
    predicate: &'static str,
    /// The first turn, and the value on `predicate` it holds.
    first: (&'static str, &'static str),
    /// Who holds that value: the first pass, as its own unvetted claim, or
    /// the owner, as an observed claim stated in person once the first pass
    /// has met the person (a Dreamer claim in a critical class lands Proposed
    /// and is never listed).
    owner_states_first: bool,
    second: (&'static str, &'static str),
    seeded_before_critical_classes: bool,
    granted: bool,
}

/// A model that does what the extraction prompt asks. It names a listed
/// claim on the case's predicate when one is shown, and otherwise meets the
/// person. Asked for a verdict, it takes the newer value.
fn follows_the_prompt(case: &Case) -> Reply {
    let (predicate, second) = (case.predicate, case.second.1);
    let (met, first) = if case.owner_states_first {
        ("profile.name", "Oleksii")
    } else {
        (predicate, case.first.1)
    };
    Reply::Computed(Arc::new(move |request: &Value| {
        let messages = request["messages"].as_array().unwrap();
        if !text(&messages[0]).starts_with("Extract durable memory claims") {
            return json!({"resolution": "supersede", "value": second}).to_string();
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
                (Some("claim"), Some(id), Some(named)) if named == predicate => {
                    listed = subject.clone().map(|subject| (subject, id.to_owned()));
                }
                _ => {}
            }
        }
        let evidence = json!([{"source_id": turn, "byte_range": [0, 4]}]);
        match listed {
            Some((subject, claim)) => json!({"candidates": [{
                "subject": subject, "predicate": predicate, "value": second,
                "corrects": claim, "confidence": 0.9, "evidence_refs": evidence,
            }]}),
            None => json!({
                "persons": [{"id": PERSON, "name": "Oleksii", "evidence_turn_refs": [turn]}],
                "candidates": [{
                    "subject": PERSON, "predicate": met, "value": first,
                    "confidence": 0.9, "evidence_refs": evidence,
                }],
            }),
        }
        .to_string()
    }))
}

/// Stops the server gracefully off this test's runtime thread: the fake
/// model runs on that thread, and a call a pass makes after the signal is
/// answered while the pass finishes. Blocking the thread in [`stop`] left
/// that call unanswered and the server waiting for it.
async fn stop_serving(child: std::process::Child) {
    tokio::task::spawn_blocking(move || stop(child))
        .await
        .unwrap();
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
    stop_serving(child).await;
}

fn claims_on(
    vault: &Vault,
    person: EntityId,
    predicate: &str,
) -> Vec<(EntityId, oneiron::ClaimBody)> {
    vault
        .claims_for_subject(&person)
        .unwrap()
        .into_iter()
        .filter_map(|id| Some((id, vault.get_claim(&id).ok().flatten()?)))
        .filter(|(_, body)| body.predicate == predicate)
        .collect()
}

/// Whether `replacement` binds to `prior` the way `granted` says: it closed
/// it with its grant, or it is held in the owner's review with the closure
/// deferred and the prior still Active.
fn binds(vault: &Vault, replacement: EntityId, prior: EntityId, granted: bool) -> bool {
    let closes = vault
        .edges_out(&replacement)
        .unwrap()
        .iter()
        .any(|edge| edge.kind == oneiron::edge::EdgeKind::Supersedes && edge.target == prior);
    let body = vault.get_claim(&replacement).unwrap().unwrap();
    let prior = vault.get_claim(&prior).unwrap().unwrap();
    if granted {
        closes
            && body.approval == oneiron::ClaimApprovalStatus::Auto
            && prior.lifecycle == oneiron::ClaimLifecycleStatus::Superseded
    } else {
        !closes
            && vault
                .pending_claim_supersession(&replacement)
                .unwrap()
                .is_some()
            && body.approval == oneiron::ClaimApprovalStatus::Proposed
            && prior.lifecycle == oneiron::ClaimLifecycleStatus::Active
    }
}

async fn binds_once(case: Case) {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    if case.seeded_before_critical_classes {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        vault
            .install_seeded_policy_manifest_for_test(
                Vault::policy_manifest_before_critical_classes_for_test().unwrap(),
            )
            .unwrap();
    }
    let conversation = EntityId::now();
    witness(&vault_path, conversation, case.first.0, true, "binding-1");
    let fake = FakeLlm::start(Vec::new(), Some(follows_the_prompt(&case))).await;
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
        if case.owner_states_first {
            let owner = vault.ensure_embedded_owner_actor().unwrap();
            let input = serde_json::from_value(json!({
                "predicate": case.predicate, "subject_ref": PERSON, "value": case.first.1,
                "confidence": 1.0, "source": "observed",
            }))
            .unwrap();
            // The owner states it in person, so the critical claim carries
            // its own confirmation and the next pass may list it.
            let authenticated = vault
                .authenticate_owner(
                    owner,
                    &owner.to_hex(),
                    true,
                    oneiron::store::GateDecisionId::now(),
                )
                .unwrap();
            vault
                .memory(owner, EdgeActorClass::Human)
                .with_owner_authorship(&authenticated)
                .claim_upsert(&input)
                .unwrap();
        }
        let written = claims_on(&vault, person, case.predicate);
        let [(first, _)] = written[..] else {
            panic!("the first pass wrote one claim: {written:?}");
        };
        first
    };

    witness(&vault_path, conversation, case.second.0, false, "binding-2");
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
        let claims = claims_on(vault, person, case.predicate);
        assert_eq!(claims.len(), 2, "one correction, no duplicate: {claims:?}");
        let bound: Vec<_> = claims
            .iter()
            .filter(|(id, _)| *id != first && binds(vault, *id, first, case.granted))
            .collect();
        assert_eq!(
            bound.len(),
            1,
            "the correction binds once, granted = {}: {claims:?}",
            case.granted
        );
        assert_eq!(bound[0].1.value, rmpv::Value::from(case.second.1));
    };
    held(&Vault::open_owned(&vault_path, vault_config()).unwrap());

    // Started again, nothing is left to run and nothing binds twice.
    let calls = fake.seen().len();
    let child = serve(&config);
    tokio::time::sleep(Duration::from_secs(5)).await;
    stop_serving(child).await;
    assert_eq!(fake.seen().len(), calls, "a finished pass makes no call");
    held(&Vault::open_owned(&vault_path, vault_config()).unwrap());
}

/// A predicate no rule names: the correction lands with its grant.
#[tokio::test]
async fn a_later_pass_binds_a_correction_to_the_claim_an_earlier_pass_wrote() {
    binds_once(Case {
        predicate: "residence.city",
        first: ("I'm Oleksii and I live in Lisbon.", "Lisbon"),
        owner_states_first: false,
        second: (
            "Oleksii again: I moved, I live in Porto now, not Lisbon.",
            "Porto",
        ),
        seeded_before_critical_classes: false,
        granted: true,
    })
    .await;
}

/// A class canon declares critical: the correction is held for the owner.
#[tokio::test]
async fn a_correction_on_a_critical_class_is_held_for_the_owner() {
    binds_once(Case {
        predicate: "health.allergy",
        first: ("I'm Oleksii and I am allergic to peanuts.", "peanuts"),
        owner_states_first: true,
        second: (
            "Oleksii again: not peanuts after all, I am allergic to shellfish.",
            "shellfish",
        ),
        seeded_before_critical_classes: false,
        granted: false,
    })
    .await;
}

/// A vault seeded before those classes shipped takes them on its first open
/// by the new build, and holds the same correction. Before the upgrade it
/// granted it: the class was unregistered there.
#[tokio::test]
async fn a_vault_seeded_before_the_critical_classes_holds_that_correction_too() {
    binds_once(Case {
        predicate: "health.allergy",
        first: ("I'm Oleksii and I am allergic to peanuts.", "peanuts"),
        owner_states_first: true,
        second: (
            "Oleksii again: not peanuts after all, I am allergic to shellfish.",
            "shellfish",
        ),
        seeded_before_critical_classes: true,
        granted: false,
    })
    .await;
}

/// DREAMER-SEAT (owner ruling A, 2026-10-14; Engine notes): the extraction
/// call carries no schema on any provider, whether the provider is set to
/// `response_format = "none"` or left at the default, and the engine's own
/// check still refuses an answer that breaks the extraction contract: the
/// pass writes the same claims in both arms, none from that answer. The
/// answer holds a writable Lisbon candidate beside a stray item the decoder
/// would skip, so only the contract check refuses it: without the stray
/// item, the same answer lands Lisbon. The vault configures no reasoning
/// level, so every extraction call to this local server names `medium`, in
/// the effort field and in the chat template's arguments, with a 4,096-token
/// thinking budget.
#[tokio::test]
async fn an_off_contract_answer_is_refused_with_no_schema_on_any_wire() {
    let none = "response_format = \"none\"\n";
    let mut written = Vec::new();
    for (line, stray) in [("", true), (none, true), ("", false)] {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault");
        std::fs::create_dir_all(&vault_path).unwrap();
        witness(
            &vault_path,
            EntityId::now(),
            "I'm Oleksii and I live in Lisbon.",
            true,
            "schema-1",
        );
        let Reply::Computed(answer) = follows_the_prompt(&Case {
            predicate: "residence.city",
            first: ("I'm Oleksii and I live in Lisbon.", "Lisbon"),
            owner_states_first: false,
            second: ("", ""),
            seeded_before_critical_classes: false,
            granted: false,
        }) else {
            unreachable!("the prompt-following model computes its answer")
        };
        let fake = FakeLlm::start(
            Vec::new(),
            Some(Reply::Computed(Arc::new(move |request: &Value| {
                let mut reply: Value = serde_json::from_str(&answer(request)).unwrap();
                if stray
                    && let Some(items) = reply.get_mut("candidates").and_then(Value::as_array_mut)
                {
                    items.push(json!("stray"));
                }
                reply.to_string()
            }))),
        )
        .await;
        let config = write_config(
            dir.path(),
            &vault_path,
            free_port(),
            &format!("{}{line}", models_section(&fake.base_url)),
        );
        let granted = oneiron(
            &config,
            &["dreamer", "grant", "--extraction-route", "own_server"],
        )
        .output()
        .unwrap();
        assert!(granted.status.success());
        serve_until(&config, &fake, 1).await;
        let seen = fake.seen();
        let extraction: Vec<_> = seen
            .iter()
            .filter(|call| {
                text(&call.body["messages"][0]).starts_with("Extract durable memory claims")
            })
            .collect();
        assert!(!extraction.is_empty(), "the pass called the model");
        for call in extraction {
            let body = &call.body;
            assert_eq!(body.get("response_format"), None, "{body}");
            assert_eq!(body["reasoning_effort"], "medium", "{body}");
            assert_eq!(
                body["chat_template_kwargs"],
                json!({"reasoning_effort": "medium"}),
                "{body}"
            );
            assert_eq!(body["reasoning_budget_tokens"], 4_096, "{body}");
        }
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        let person = EntityId::from_hex(PERSON).unwrap();
        assert_eq!(
            claims_on(&vault, person, "residence.city").len(),
            usize::from(!stray),
            "the off-contract answer wrote nothing; the same answer within it lands"
        );
        let predicates: std::collections::BTreeSet<String> = vault
            .entities_by_type(ENTITY_TYPE_CLAIM)
            .unwrap()
            .iter()
            .filter_map(|id| vault.get_claim(id).ok().flatten())
            .map(|claim| claim.predicate)
            .collect();
        written.push(predicates);
    }
    assert_eq!(written[0], written[1], "both arms refuse it the same way");
}
