// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! Claims from imported history wait for the owner's review (ARCH-0027 trust
//! tier: "imported material never auto-approves ... the person approves the
//! batch"), through the shipped binary. `oneiron import` lands a Claude Code
//! project and a ChatGPT export, `serve` with a model runs the Dreamer over
//! them, and every claim it extracts is `imported`, Proposed and grouped in
//! its import's one review. `oneiron runs approve` admits all of one import's
//! claims with a receipt; `runs decline` admits none of the other's. The
//! prompts a delegating agent gave its subagents never reach the model.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{ClaimApprovalStatus, ClaimBody, ClaimSource, EntityId, TimeRange, Vault};
use serde_json::{Value, json};

use crate::ai_serve::{
    free_port, models_section, oneiron, serve, stop, vault_config, wait_for, write_config,
};
use crate::fake_llm::{FakeLlm, Reply};

/// What the owner said in the imported Claude Code session and ChatGPT chat.
const OWNER_SAID: [&str; 2] = ["Add a watering schedule", "Kyoto"];

/// Each delegating agent's prompt in the Claude Code fixture: an inline
/// sidechain, a subagent, a workflow agent and an older agent log.
const DELEGATED: [&str; 4] = [
    "Find every place the planner reads watering intervals",
    "Check that the planner's tests pass",
    "Draft release notes for the watering schedule",
    "Summarize the planner's open issues",
];

/// What each of those subagents answered; their words still reach the model.
const SUBAGENTS_SAID: [&str; 4] = [
    "Two places read intervals",
    "All fourteen tests pass",
    "Release notes: per-plant",
    "Two open issues",
];

fn fixture(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/history")
        .join(path)
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    id
}

/// The transcript's turns, as `(turn id, text)`.
fn turns(request: &Value) -> Vec<(String, String)> {
    let transcript = request["messages"]
        .as_array()
        .and_then(|messages| messages.last())
        .and_then(|message| message["content"].as_str())
        .unwrap_or_default();
    transcript
        .lines()
        .filter_map(|line| {
            let (head, text) = line.strip_prefix('[')?.split_once("] ")?;
            Some((head.split_whitespace().next()?.to_owned(), text.to_owned()))
        })
        .collect()
}

fn candidate(subject: EntityId, value: &str, turn: &str) -> Value {
    json!({
        "subject": subject.to_hex(),
        "predicate": "profile.name",
        "value": value,
        "confidence": 0.9,
        "evidence_refs": [{"source_id": turn, "byte_range": [0, 4]}],
    })
}

/// A model that extracts from the turn where the owner said something: two
/// claims from the Claude Code session, one from the ChatGPT chat, none from
/// anything else.
fn extractor(code: [EntityId; 2], chat: EntityId) -> Reply {
    Reply::Computed(Arc::new(move |request: &Value| {
        let mut candidates = Vec::new();
        for (turn, text) in turns(request) {
            if text.contains(OWNER_SAID[0]) {
                candidates.push(candidate(code[0], "Ana", &turn));
                candidates.push(candidate(code[1], "Garden planner", &turn));
            } else if text.contains(OWNER_SAID[1]) {
                candidates.push(candidate(chat, "Ana", &turn));
            }
        }
        json!({ "candidates": candidates }).to_string()
    }))
}

fn run_json(config: &Path, args: &[&str]) -> Value {
    let output = oneiron(config, args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn claims_about(vault: &Vault, subject: &EntityId) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).ok().flatten())
        .filter(|body| body.predicate == "profile.name")
        .collect()
}

/// The entities a Dreamer claim's evidence names.
fn evidence_refs(body: &ClaimBody) -> Vec<EntityId> {
    let Some(rmpv::Value::Map(entries)) = &body.evidence else {
        return Vec::new();
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .and_then(|(_, value)| {
            oneiron::dreamer_consolidation::decode_consolidation_evidence(value)
                .ok()
                .flatten()
        })
        .map(|evidence| evidence.refs)
        .unwrap_or_default()
}

/// Whether `id` is a TURN the history import landed (its body carries the
/// import stamp).
fn imported_turn(vault: &Vault, id: &EntityId) -> bool {
    if vault.get_entity_type(id).unwrap() != Some(ENTITY_TYPE_TURN) {
        return false;
    }
    let body = vault.get(id).unwrap().unwrap_or_default();
    matches!(
        rmpv::decode::read_value(&mut body.as_slice()),
        Ok(rmpv::Value::Map(fields))
            if fields.iter().any(|(key, _)| key.as_str() == Some("import_source"))
    )
}

#[tokio::test]
async fn imported_claims_wait_in_one_review_per_import_which_the_owner_approves_or_declines_whole()
{
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault");
    std::fs::create_dir_all(&vault_path).unwrap();
    let (code, chat) = {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        ([person(&vault), person(&vault)], person(&vault))
    };
    let fake = FakeLlm::start(vec![], Some(extractor(code, chat))).await;
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

    // Each import names the one review its claims will wait in.
    let mut reviews = Vec::new();
    for (source, path) in [
        (
            "claude-code",
            "claude-code/projects/-Users-ana-code-garden-planner",
        ),
        ("chatgpt", "chatgpt/export-1"),
    ] {
        let path = fixture(path);
        let report = run_json(&config, &["import", source, path.to_str().unwrap()]);
        let review = &report["review"];
        assert!(
            review["dreamer_attempts"].as_u64().unwrap() > 0,
            "{report:#}"
        );
        reviews.push(review["run_id"].as_str().unwrap().to_owned());
    }
    assert!(reviews[0].starts_with("import:claude-code:"), "{reviews:?}");
    assert!(reviews[1].starts_with("import:chatgpt:"), "{reviews:?}");

    // The Dreamer runs on what the imports queued, with no sitting to end.
    let server = serve(&config);
    let seen = || {
        fake.seen()
            .iter()
            .map(|request| request.body.to_string())
            .collect::<Vec<_>>()
    };
    let every_thread_read = wait_for(Duration::from_secs(120), || {
        let seen = seen();
        OWNER_SAID
            .iter()
            .chain(&SUBAGENTS_SAID)
            .all(|said| seen.iter().any(|request| request.contains(said)))
    })
    .await;
    // Give the last pass time to land, then stop gracefully.
    tokio::time::sleep(Duration::from_secs(3)).await;
    stop(server);
    let seen = seen();
    assert!(every_thread_read, "{} model calls: {seen:#?}", seen.len());
    // A delegating agent's prompt is not the owner speaking: the model never
    // reads it, so it cannot become a claim about the owner.
    for prompt in DELEGATED {
        assert!(
            seen.iter().all(|request| !request.contains(prompt)),
            "the model read {prompt:?}"
        );
    }

    {
        let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
        let unfinished: Vec<_> = oneiron::attempt_queue::AttemptQueue::new(&vault)
            .list()
            .unwrap()
            .into_iter()
            .filter(|row| {
                matches!(
                    row.state,
                    oneiron::attempt_queue::AttemptState::Leased
                        | oneiron::attempt_queue::AttemptState::Queued
                )
            })
            .collect();
        assert!(unfinished.is_empty(), "{unfinished:?}");
        // Every claim is imported and Proposed, never Auto, on the imported TURN.
        for subject in code.iter().chain([&chat]) {
            let claims = claims_about(&vault, subject);
            assert_eq!(claims.len(), 1, "{claims:?}");
            assert_eq!(claims[0].source, Some(ClaimSource::Imported));
            assert_eq!(claims[0].approval, ClaimApprovalStatus::Proposed);
            let refs = evidence_refs(&claims[0]);
            assert!(!refs.is_empty());
            assert!(
                refs.iter().all(|turn| imported_turn(&vault, turn)),
                "{refs:?}"
            );
        }
    }

    // One review per import, holding exactly that import's claims.
    let pending = run_json(&config, &["runs", "pending"]);
    let waiting = |run: &str| {
        pending
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["run_id"] == json!(run))
            .map(|row| row["pending"].as_u64().unwrap())
    };
    assert_eq!(waiting(&reviews[0]), Some(2), "{pending:#}");
    assert_eq!(waiting(&reviews[1]), Some(1), "{pending:#}");

    // Approve the Claude Code import whole: both claims are admitted, with
    // the review's one receipt.
    let review = run_json(&config, &["runs", "show", &reviews[0]]);
    assert_eq!(
        review["proposals"].as_array().unwrap().len(),
        2,
        "{review:#}"
    );
    let approved = run_json(
        &config,
        &[
            "runs",
            "approve",
            &reviews[0],
            "--bundle",
            review["bundle_id"].as_str().unwrap(),
        ],
    );
    assert_eq!(approved["action"], json!("approve"), "{approved:#}");
    assert_eq!(approved["claim_ids"].as_array().unwrap().len(), 2);
    assert!(!approved["receipt_id"].as_str().unwrap().is_empty());

    // Decline the ChatGPT import whole: nothing of it is admitted.
    let review = run_json(&config, &["runs", "show", &reviews[1]]);
    let declined = run_json(
        &config,
        &[
            "runs",
            "decline",
            &reviews[1],
            "--bundle",
            review["bundle_id"].as_str().unwrap(),
        ],
    );
    assert_eq!(declined["action"], json!("decline"), "{declined:#}");
    assert!(!declined["receipt_id"].as_str().unwrap().is_empty());

    let vault = Vault::open_owned(&vault_path, vault_config()).unwrap();
    for subject in &code {
        let claims = claims_about(&vault, subject);
        assert_eq!(
            claims[0].approval,
            ClaimApprovalStatus::Approved,
            "{claims:?}"
        );
    }
    let claims = claims_about(&vault, &chat);
    assert_eq!(
        claims[0].approval,
        ClaimApprovalStatus::Rejected,
        "{claims:?}"
    );
    drop(vault);
    let pending = run_json(&config, &["runs", "pending"]);
    assert_eq!(pending, json!([]), "{pending:#}");
}
