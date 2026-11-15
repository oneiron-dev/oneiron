//! RESTRICTION-WAVE-10 part B (owner principle, 16 Nov 00:44: a restriction that is no correctness
//! fix ships as a good default plus an owner opt-out; RULING RESTRICTION-WAVE-10-CANON, 16 Nov
//! 03:35: agents only, no member arm): two owner Setting keys of `vault_cleanup`, each defaulting
//! to the behaviour before it.
//! - `vault_cleanup.attempt_delete.owner_or_admin_only` (census C44): only the owner or a live
//!   vault Admin previews and deletes a cleanup-archived completed attempt, unless the owner turns
//!   the key off; then an agent whose live owner Grant names
//!   `vault.archive.attempt.delete.confirm` does too.
//! - `vault_cleanup.decide.owner_only` (census C43): only the owner decides an open cleanup
//!   proposal, unless the owner turns the key off; then an agent whose live owner Grant names
//!   `vault.cleanup.decide` decides too.
//!
//! Each agent calls the verb in process, through the row's own call line. The fixture ages one
//! completed attempt past the 90-day retention, and a propose-first cleanup run proposes it.
//!
//! Red on the base (the Setting primitive with neither key): each test that turns a key off fails
//! at its `set_setting`, which names no such key. Guards (green on both): at the default an agent
//! holding the Grant is refused as before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! vault_cleanup_setting_keys`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::vault_cleanup::{
    CleanupKind, CleanupPosture, accept_cleanup_proposal, cleanup_proposals, run_vault_cleanup,
    set_cleanup_posture,
};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// When the attempt completed; the cleanup run comes 91 days later.
const T0: u64 = 1_780_000_000;

const ATTEMPT_DELETE_KEY: &str = "vault_cleanup.attempt_delete.owner_or_admin_only";
const DECIDE_KEY: &str = "vault_cleanup.decide.owner_only";
const PREVIEW: &str = "vault.archive.attempt.delete.preview";
const CONFIRM: &str = "vault.archive.attempt.delete.confirm";
const DECIDE: &str = "vault.cleanup.decide";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    proof: AuthenticatedOwner,
    /// The completed attempt the open proposal names.
    attempt: AttemptId,
    /// The run's proposal, open unless the fixture accepted it.
    proposal: EntityId,
    /// How many slots the proposal holds.
    slots: usize,
}

impl Fixture {
    /// A vault whose one completed attempt is 91 days old, with an open propose-first cleanup
    /// proposal naming it, then the owner.
    fn proposed() -> Self {
        Self::open(false)
    }

    /// [`Self::proposed`] with the proof-free accept before the owner is set up: the attempt is
    /// cleanup-archived.
    fn archived() -> Self {
        let fx = Self::open(true);
        assert!(
            fx.vault.archived_attempt(fx.attempt).expect("archive read"),
            "the accept archives the attempt"
        );
        fx
    }

    /// The cleanup runs before any owner or agent row exists, so its proposal names the aged
    /// attempt and nothing the setup writes.
    fn open(accept: bool) -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
        let queue = AttemptQueue::new(&vault);
        queue
            .enqueue(EnqueueAttempt {
                kind: "test.retained".into(),
                payload: vec![1, 2, 3],
                dedupe_key: None,
                run_id: None,
                now: T0,
            })
            .expect("enqueue");
        let ClaimOutcome::Claimed(record) = queue
            .claim(ClaimAttempt {
                lease_owner: "test".into(),
                now: T0,
            })
            .expect("claim")
        else {
            panic!("the attempt is claimed");
        };
        queue
            .complete(CompleteAttempt {
                id: record.id,
                lease_owner: "test".into(),
                attempt_count: record.attempt_count,
                now: T0,
            })
            .expect("complete");
        clock.set(T0 + 91 * 86_400);
        vault
            .set_task_retention_days(Some(90))
            .expect("90-day retention");
        set_cleanup_posture(&vault, CleanupPosture::ProposeFirst).expect("propose first");
        let report = run_vault_cleanup(&vault, &AttemptId::now()).expect("cleanup run");
        let proposal = report.proposal.expect("the run proposes the aged attempt");
        assert!(
            report
                .candidates
                .iter()
                .flatten()
                .any(|candidate| candidate.kind == CleanupKind::CompletedAttempt),
            "the proposal names the completed attempt: {report:?}"
        );
        assert!(
            !vault.archived_attempt(record.id).expect("archive read"),
            "a proposal archives nothing"
        );
        if accept {
            accept_cleanup_proposal(&vault, &proposal).expect("the proof-free accept");
        }

        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // The owner's agent Grant act is carried by this install's live machine profile.
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let (_, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            _dir: dir,
            vault,
            proof,
            attempt: record.id,
            proposal,
            slots: report.candidates.len(),
        }
    }

    fn set_key(&self, key: &str, value: Value) {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.proof),
                SetSetting::vault_value(key, value),
            )
            .unwrap_or_else(|error| panic!("the owner sets {key}: {error}"));
    }

    /// An enabled agent the owner creates and gives one Grant naming `verbs`.
    fn agent_with_grant(&self, agent_id: &str, verbs: &[&str]) -> EntityId {
        let agent = EntityId::now();
        create_agent_definition_as(
            &self.vault,
            &self.proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": agent_id,
                    "desc": "Vault cleanup key test agent",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("typed agent definition"),
            },
        )
        .expect("owner creates an enabled, active agent definition");
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("owner mints the agent a Grant");
        assert!(minted.grant.confers, "{agent_id}: the Grant confers");
        agent
    }

    /// `agent` calls `verb` in process.
    fn call(&self, agent: EntityId, verb: &str, input: Value) -> Result<Value, MemoryError> {
        invoke(
            &self.vault.memory(agent, EdgeActorClass::Agent),
            verb,
            input,
        )
    }

    fn attempt_hex(&self) -> String {
        self.attempt
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// One complete verdict accepting every slot of the proposal.
    fn accept_all(&self) -> Value {
        let choices: Vec<Value> = (0..self.slots)
            .map(|slot| json!({ "slot": slot, "decision": "accept" }))
            .collect();
        json!({ "proposal": self.proposal.to_hex(), "choices": choices })
    }

    fn proposal_is_open(&self) -> bool {
        cleanup_proposals(&self.vault)
            .expect("proposals")
            .iter()
            .any(|proposal| proposal.id == self.proposal)
    }
}

fn refused_with(error: &MemoryError, reason: &str) {
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert_eq!(error.message, reason, "{error:?}");
}

#[test]
fn an_agent_deletes_a_cleanup_archived_attempt_once_the_owner_turns_the_admin_rule_off() {
    let fx = Fixture::archived();
    fx.set_key(ATTEMPT_DELETE_KEY, json!(false));
    let granted = fx.agent_with_grant("attempt_deleter", &["read", CONFIRM]);
    let read_only = fx.agent_with_grant("read_only_agent", &["read"]);

    let refusal = fx
        .call(read_only, PREVIEW, json!({ "attempt": fx.attempt_hex() }))
        .expect_err("an agent whose Grant does not name the confirm verb is refused");
    refused_with(&refusal, "attempt_delete_no_standing");

    let preview = fx
        .call(granted, PREVIEW, json!({ "attempt": fx.attempt_hex() }))
        .unwrap_or_else(|error| panic!("the granted agent previews: {error:?}"));
    let receipt = fx
        .call(
            granted,
            CONFIRM,
            json!({ "attempt": fx.attempt_hex(), "expected": preview["expected"] }),
        )
        .unwrap_or_else(|error| panic!("the granted agent deletes: {error:?}"));
    assert_eq!(receipt["role"], "agent", "{receipt}");
    assert_eq!(receipt["deleted_by"], granted.to_hex(), "{receipt}");
    assert!(receipt["grant_ref"].is_string(), "{receipt}");
    assert!(
        !fx.vault.archived_attempt(fx.attempt).expect("archive read"),
        "the archived attempt is gone"
    );
}

#[test]
fn an_agent_with_the_grant_cannot_delete_a_cleanup_archived_attempt_by_default() {
    let fx = Fixture::archived();
    let granted = fx.agent_with_grant("attempt_deleter", &["read", CONFIRM]);
    let refusal = fx
        .call(granted, PREVIEW, json!({ "attempt": fx.attempt_hex() }))
        .expect_err("an agent has no standing while the key is on");
    refused_with(&refusal, "attempt_delete_no_standing");
    assert!(
        fx.vault.archived_attempt(fx.attempt).expect("archive read"),
        "the archived attempt stays"
    );
}

#[test]
fn an_agent_decides_a_cleanup_proposal_once_the_owner_turns_owner_only_off() {
    let fx = Fixture::proposed();
    fx.set_key(DECIDE_KEY, json!(false));
    let granted = fx.agent_with_grant("cleanup_decider", &["read", DECIDE]);
    let read_only = fx.agent_with_grant("read_only_agent", &["read"]);

    let refusal = fx
        .call(read_only, DECIDE, fx.accept_all())
        .expect_err("an agent whose Grant does not name the verb is refused");
    refused_with(&refusal, "vault.cleanup.decide is the vault owner's");
    assert!(fx.proposal_is_open(), "the refused verdict changes nothing");

    let decided = fx
        .call(granted, DECIDE, fx.accept_all())
        .unwrap_or_else(|error| panic!("the granted agent decides: {error:?}"));
    assert!(
        decided["digest"].is_string(),
        "an accept records a digest: {decided}"
    );
    assert!(!fx.proposal_is_open(), "the proposal is decided");
    assert!(
        fx.vault.archived_attempt(fx.attempt).expect("archive read"),
        "the accepted attempt is archived"
    );
}

#[test]
fn an_agent_with_the_grant_cannot_decide_a_cleanup_proposal_by_default() {
    let fx = Fixture::proposed();
    let granted = fx.agent_with_grant("cleanup_decider", &["read", DECIDE]);
    let refusal = fx
        .call(granted, DECIDE, fx.accept_all())
        .expect_err("the decide is the owner's while the key is on");
    refused_with(&refusal, "vault.cleanup.decide is the vault owner's");
    assert!(fx.proposal_is_open(), "the proposal stays open");
    assert!(
        !fx.vault.archived_attempt(fx.attempt).expect("archive read"),
        "nothing is archived"
    );
}
