//! A strength attempt's job client (untangle 6.9c PR 3, RULING S69C-DESIGN
//! item 5): `OneironClient::for_dreamer_attempt` over the binding the engine
//! mints from the admitted attempt. The client reads the observations page
//! and commits Archive items as the Dreamer, and each call proves the
//! attempt's lease (owner and generation) and the Dreamer's live Steward
//! reach and MACHINE binding again, so a call refuses, and writes nothing,
//! once the generation moves, the reach or binding is revoked, or the lease
//! ends.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-remote
//! --features oneiron/test-support --test dreamer_attempt_binding` (the
//! oneiron features of its `--all-features` build added).
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::dreamer_runner::{
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerAdmittedAttempt,
    DreamerRunnerStore,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_LEASE_REQUIRED, MemoryError};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{derive_item_receipts, row_live};
use oneiron::test_doors::dreamer_attempt_binding::{
    ObservedStrengthClaim, STRENGTH_LEASE_OWNER, STRENGTH_RUN, admit_strength_attempt,
    enqueue_strength_attempt, observe_strength_claim,
};
use oneiron::test_doors::run_lifecycle::release_lease;
use oneiron::test_doors::steward::{
    STEWARD_VERBS, archive_every_quiet_claim, dreamer, mark_steward_opt_out,
    revoke_base_agent_bindings, stand_steward_grant,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_remote::OneironClient;
use serde_json::{Value, json};

type BindingTestResult<T> = Result<T, Box<dyn std::error::Error>>;

const PAGE: &str = "vault.consolidation.strength.observations.page";
const COMMIT: &str = "vault.derive.commit";
/// The queue clock every admission and release here runs at, in seconds.
const QUEUE_NOW: u64 = 1_000;

/// One admitted strength attempt over one quiet, weak, observed claim, and
/// the job client the engine minted for it.
struct BoundStrength {
    vault: Arc<Vault>,
    dreamer: EntityId,
    observed: ObservedStrengthClaim,
    admitted: DreamerAdmittedAttempt,
    client: OneironClient,
}

/// What a refused call must leave as it found: the Dreamer's batches, the
/// claim's liveness, its strength snapshots and its derive receipts.
#[derive(Debug, PartialEq, Eq)]
struct Written {
    batches: usize,
    claim_live: bool,
    snapshots: usize,
    receipts: usize,
}

fn written(bound: &BoundStrength) -> BindingTestResult<Written> {
    let claim = bound.observed.claim;
    Ok(Written {
        batches: bound.vault.derive_batches_of(bound.dreamer)?.len(),
        claim_live: row_live(&bound.vault, claim)?,
        snapshots: bound.vault.consolidation_strength_snapshots(&claim)?.len(),
        receipts: derive_item_receipts(&bound.vault, &claim)?.len(),
    })
}

/// A Dreamer with a full live Steward grant and a MACHINE binding, one
/// observed claim that is quiet and weak under the policy, its strength
/// attempt admitted, and the client bound to that attempt.
fn bound_strength(dir: &tempfile::TempDir) -> BindingTestResult<BoundStrength> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;
    let observed = observe_strength_claim(&vault)?;
    archive_every_quiet_claim(&vault)?;
    // The observation is recorded one second ahead of the clock; it is
    // quiet once the clock passes it.
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let admitted = enqueue_strength_attempt(&vault, observed.seed, QUEUE_NOW)?;
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    Ok(BoundStrength {
        vault,
        dreamer,
        observed,
        admitted,
        client,
    })
}

/// The bound client's page, and the Archive batch for the observed claim at
/// the pins that page served.
fn page_and_archive(bound: &BoundStrength) -> BindingTestResult<Value> {
    let page = bound.client.agent_verb(PAGE, json!({}))?;
    let page = &page["value"];
    let claim = bound.observed.claim;
    let served = page["claims"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves claims: {page}"))
        .iter()
        .find(|served| served["claim"] == claim.to_hex())
        .unwrap_or_else(|| panic!("the page serves the observed claim: {page}"));
    assert_eq!(served["status"], "current", "{served}");
    Ok(json!({
        "items": [archive_item(claim, served, page)],
        "sources": [],
    }))
}

fn archive_item(claim: EntityId, served: &Value, page: &Value) -> Value {
    json!({
        "kind": "archive",
        "spec": {
            "local": "weak",
            "claim": {"stored": claim},
            "signals": {"type_prior": 0.1, "frequency": 0.1, "recency": 0.1, "diversity": 0.1},
            "score": 0.1,
            "observation_pin": served["pin"],
            "policy_pin": page["policy_pin"],
            "config_pin": page["config_pin"],
        },
    })
}

/// `call` refuses with `code`, its message naming `about`.
fn refused(call: Result<Value, MemoryError>, code: &str, about: &str) {
    let refusal = call.expect_err(about);
    assert_eq!(refusal.code, code, "{about}: {refusal:?}");
    assert!(refusal.message.contains(about), "{about}: {refusal:?}");
}

/// Both of the bound client's calls refuse with `code` and `about`, and
/// neither writes a batch, a receipt, a snapshot or an archive.
fn both_calls_refuse(
    bound: &BoundStrength,
    archive: &Value,
    code: &str,
    about: &str,
) -> BindingTestResult<()> {
    let before = written(bound)?;
    refused(bound.client.agent_verb(PAGE, json!({})), code, about);
    refused(
        bound.client.agent_verb(COMMIT, archive.clone()),
        code,
        about,
    );
    assert_eq!(written(bound)?, before, "{about}: the refused calls wrote");
    assert!(before.claim_live, "the claim stays live");
    Ok(())
}

#[test]
fn bound_strength_client_reads_page_and_commits_archive_as_dreamer() -> BindingTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_strength(&dir)?;
    let archive = page_and_archive(&bound)?;
    let claim = bound.observed.claim;

    // The facet admits these two verbs and Archive items only, and the
    // handle acts as nobody else.
    let mut mixed = archive.clone();
    mixed["items"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("the batch has items"))
        .insert(
            0,
            json!({"kind": "claim", "spec": {
                "local": "other",
                "predicate": "profile.drink",
                "subject": {"stored": bound.observed.source},
                "value": "tea",
                "confidence": 0.9,
                "evidence": [{"stored": bound.observed.source}],
            }}),
        );
    let before = written(&bound)?;
    let facet = "the Dreamer strength facet does not admit this operation";
    refused(
        bound.client.agent_verb(COMMIT, mixed),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    refused(
        bound
            .client
            .agent_verb("vault.derive.revert", json!({"batch": EntityId::now()})),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    assert_eq!(written(&bound)?, before, "a refused operation wrote");
    let rebind = bound
        .client
        .as_actor(&format!("system:{}", bound.dreamer.to_hex()))
        .expect_err("a bound handle cannot rebind");
    assert_eq!(rebind.code, MEMORY_CODE_FORBIDDEN, "{rebind:?}");
    assert_eq!(
        bound.client.actor_ref(),
        Some(bound.dreamer.to_hex()),
        "the handle acts as the Dreamer"
    );

    let view = bound.client.agent_verb(COMMIT, archive)?;
    assert_eq!(view["items"][0]["landed"], true, "{view}");
    let batches = bound.vault.derive_batches_of(bound.dreamer)?;
    assert_eq!(batches.len(), before.batches + 1, "one batch lands");
    let batch: EntityId = serde_json::from_value(view["batch"].clone())?;
    assert_eq!(batches.last(), Some(&batch));
    let record = bound
        .vault
        .derive_batch(batch)?
        .unwrap_or_else(|| panic!("the batch is recorded"));
    assert_eq!(record.actor, bound.dreamer, "the Dreamer commits it");
    assert_eq!(record.actor_class, "system");
    assert_eq!(record.run.as_deref(), Some(STRENGTH_RUN));
    assert_eq!(record.items.len(), 1);
    assert_eq!(record.items[0].kind, "archive");
    assert_eq!(record.items[0].rows, vec![claim]);
    assert!(!row_live(&bound.vault, claim)?, "the claim is archived");
    let snapshots = bound.vault.consolidation_strength_snapshots(&claim)?;
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        snapshots[0].attempt, bound.admitted.status.attempt.id,
        "the archive names the strength attempt"
    );
    assert_ne!(snapshots[0].attempt, bound.observed.seed);
    Ok(())
}

#[test]
fn stale_strength_lease_generation_refuses_mid_job() -> BindingTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_strength(&dir)?;
    let archive = page_and_archive(&bound)?;
    let attempt = &bound.admitted.status.attempt;

    // The same try is released and taken again by the same owner: only the
    // lease generation moves.
    assert!(release_lease(
        &bound.vault,
        attempt.id,
        STRENGTH_LEASE_OWNER,
        QUEUE_NOW
    )?);
    let again = admit_strength_attempt(&bound.vault, QUEUE_NOW)?;
    assert_eq!(again.status.attempt.id, attempt.id);
    assert_eq!(
        again.status.attempt.lease_owner.as_deref(),
        Some(STRENGTH_LEASE_OWNER)
    );
    assert_eq!(
        again.status.attempt.attempt_count,
        attempt.attempt_count + 1
    );

    both_calls_refuse(
        &bound,
        &archive,
        MEMORY_CODE_LEASE_REQUIRED,
        "the Dreamer attempt lease no longer holds",
    )?;
    // The binding of the generation that holds the lease now reads.
    let current = OneironClient::for_dreamer_attempt(bound.vault.bind_dreamer_attempt(&again)?);
    current.agent_verb(PAGE, json!({}))?;
    Ok(())
}

#[test]
fn revoked_steward_reach_refuses_mid_job() -> BindingTestResult<()> {
    // The Steward grant is opted out; the lease and the MACHINE binding
    // stand.
    let dir = tempfile::tempdir()?;
    let bound = bound_strength(&dir)?;
    let archive = page_and_archive(&bound)?;
    mark_steward_opt_out(&bound.vault, bound.dreamer)?;
    both_calls_refuse(
        &bound,
        &archive,
        MEMORY_CODE_FORBIDDEN,
        "the Dreamer attempt no longer has live Steward read reach",
    )?;

    // The MACHINE binding is revoked; the lease and the Steward grant stand.
    let dir = tempfile::tempdir()?;
    let bound = bound_strength(&dir)?;
    let archive = page_and_archive(&bound)?;
    assert!(revoke_base_agent_bindings(&bound.vault, bound.dreamer)? > 0);
    both_calls_refuse(
        &bound,
        &archive,
        MEMORY_CODE_FORBIDDEN,
        "the Dreamer attempt MACHINE binding is no longer live",
    )
}

#[test]
fn ended_strength_attempt_lease_refuses_calls() -> BindingTestResult<()> {
    // The lease is released and no worker takes the try again.
    let dir = tempfile::tempdir()?;
    let bound = bound_strength(&dir)?;
    let archive = page_and_archive(&bound)?;
    let attempt = &bound.admitted.status.attempt;
    assert!(release_lease(
        &bound.vault,
        attempt.id,
        STRENGTH_LEASE_OWNER,
        QUEUE_NOW
    )?);
    both_calls_refuse(
        &bound,
        &archive,
        MEMORY_CODE_LEASE_REQUIRED,
        "the Dreamer attempt lease no longer holds",
    )?;

    // The attempt completes.
    let dir = tempfile::tempdir()?;
    let bound = bound_strength(&dir)?;
    let archive = page_and_archive(&bound)?;
    let attempt = &bound.admitted.status.attempt;
    let completed = DreamerRunnerStore::new(&bound.vault).complete(CompleteDreamerAttempt {
        id: attempt.id,
        lease_owner: STRENGTH_LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        now: QUEUE_NOW,
    })?;
    assert!(
        matches!(completed, CompleteDreamerAttemptOutcome::Completed(_)),
        "{completed:?}"
    );
    both_calls_refuse(
        &bound,
        &archive,
        MEMORY_CODE_LEASE_REQUIRED,
        "the Dreamer attempt lease no longer holds",
    )
}
