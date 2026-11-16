#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! REVIEW2-8651 P2-1 (OPUS-REVIEW2-MONEY, 16 Nov 23:52) on RESTRICTION-WAVE-10 C43: the server's
//! `vault.cleanup.decide` door judges an agent's presented credential as the in-process row does.
//! The owner's `vault_cleanup.decide.owner_only` is off and the agent's live owner Grant names the
//! verb. Then a credential of the agent's that is bound to a channel, or to named records, decides
//! no proposal over HTTP, and the agent's own unbounded credential decides.
//!
//! Red at 4743562442 (the door decided as the bare agent, so the credential was never asked):
//! both bounded credentials decide. Guard (green on both): the unbounded credential decides.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test cleanup_decide_served_credential`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use engine_stack::on_engine_stack;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
};
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::setting::set_setting_as_engine;
use oneiron::vault_cleanup::{CleanupPosture, cleanup_proposals, run_vault_cleanup};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DAY: u64 = 86_400;
const DECIDE_KEY: &str = "vault_cleanup.decide.owner_only";
const DECIDE: &str = "vault.cleanup.decide";

/// Sets one cleanup key (`cleanup.task_retention_days`, `cleanup.posture`) through the engine's
/// own change, before any owner row exists: SETTING-PLAIN PLAIN-2 deleted the cleanup tables
/// and their setters.
fn set_cleanup_key(vault: &Vault, key: &str, value: Value) -> TestResult {
    let outcome = set_setting_as_engine(vault, None, SetSetting::vault_value(key, value))?;
    if !matches!(outcome, SetSettingOutcome::Applied { .. }) {
        return Err(format!("{key} does not apply: {outcome:?}").into());
    }
    Ok(())
}

/// What a test credential of the agent's is bound to besides its holder.
#[derive(Clone, Copy, Debug)]
enum Bound {
    Nothing,
    Channel,
    Records,
}

/// The key every agent credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6E; 32])
}

/// A served vault with one open propose-first cleanup proposal, the owner's
/// `vault_cleanup.decide.owner_only` off, and an agent whose live owner Grant
/// names `vault.cleanup.decide`. The vault closes before its directory goes.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    agent: EntityId,
    proposal: EntityId,
    /// How many slots the proposal holds.
    slots: usize,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// One completed attempt, 91 days old by a recording clock that ends at the wall clock's
    /// now (a holder proof is judged on the recording clock), proposed by a propose-first
    /// cleanup run before any owner or agent row exists.
    fn new() -> TestResult<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let completed_at = now - 91 * DAY;
        let clock = ManualClock::new(completed_at);
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        let queue = AttemptQueue::new(&vault);
        queue.enqueue(EnqueueAttempt {
            kind: "test.retained".into(),
            payload: vec![1, 2, 3],
            dedupe_key: None,
            run_id: None,
            now: completed_at,
        })?;
        let ClaimOutcome::Claimed(record) = queue.claim(ClaimAttempt {
            lease_owner: "test".into(),
            now: completed_at,
        })?
        else {
            return Err("the attempt is claimed".into());
        };
        queue.complete(CompleteAttempt {
            id: record.id,
            lease_owner: "test".into(),
            attempt_count: record.attempt_count,
            now: completed_at,
        })?;
        clock.set(now);
        set_cleanup_key(&vault, "cleanup.task_retention_days", json!(90))?;
        set_cleanup_key(
            &vault,
            "cleanup.posture",
            serde_json::to_value(CleanupPosture::ProposeFirst)?,
        )?;
        let report = run_vault_cleanup(&vault, &AttemptId::now())?;
        let proposal = report.proposal.ok_or("the run proposes the aged attempt")?;

        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // The owner's agent Grant act is carried by this install's live machine profile.
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_, owner) = embedded_owner(&vault)?;
        vault.set_setting(
            SettingCaller::Owner(&owner),
            SetSetting::vault_value(DECIDE_KEY, json!(false)),
        )?;
        let agent = EntityId::now();
        create_agent_definition_as(
            &vault,
            &owner,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "served_cleanup_decider",
                    "desc": "Served cleanup decide credential test agent",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))?,
            },
        )?;
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some(["read", DECIDE].into_iter().map(str::to_owned).collect());
        let minted = mint_agent_grant_as(
            &vault,
            &owner,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: std::collections::BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )?;
        assert!(minted.grant.confers, "the agent's Grant confers");
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("cleanup-decide-served-credential".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            agent,
            proposal,
            slots: report.candidates.len(),
            _clock: clock,
            _dir: dir,
        })
    }

    /// A credential this host mints the agent, bound to `bound` as well.
    fn credential(&self, slip_id: u8, bound: Bound) -> TestResult<CapabilitySlip> {
        let mut claims = self.vault.ensure_host_root_slip(&self.issuer)?.claims;
        claims.slip_id = [slip_id; 32];
        claims.parent_id = None;
        claims.holder_ref = self.agent.to_hex();
        claims.actor_class = Some("agent".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        match bound {
            Bound::Nothing => {}
            Bound::Channel => {
                claims.channels.insert("cleanup-test-channel".to_owned());
            }
            Bound::Records => {
                claims.records.insert(EntityId::now().to_hex());
            }
        }
        Ok(self.vault.mint_capability_slip(&self.issuer, claims)?)
    }

    /// `slip` posts one complete verdict accepting every slot of the proposal to the facade's
    /// `vault.cleanup.decide`: the status and the body.
    async fn decide(&self, slip: &CapabilitySlip) -> TestResult<(StatusCode, Value)> {
        let binding = holder_proof(slip, &holder_key(), self.vault.now_recorded_at())?;
        let choices: Vec<Value> = (0..self.slots)
            .map(|slot| json!({ "slot": slot, "decision": "accept" }))
            .collect();
        let request = Request::post(format!("/v1/core/facade/{DECIDE}"))
            .header("authorization", format!("Bearer {}", slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "proposal": self.proposal.to_hex(), "choices": choices }).to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }

    fn proposal_is_open(&self) -> TestResult<bool> {
        Ok(cleanup_proposals(&self.vault)?
            .iter()
            .any(|proposal| proposal.id == self.proposal))
    }
}

/// The agent's credential bound to `bound` decides nothing: the door refuses it and the
/// proposal stays open.
async fn a_bounded_credential_decides_nothing(bound: Bound) -> TestResult {
    let fx = Fixture::new()?;
    let slip = fx.credential(0x41, bound)?;
    let (status, body) = fx.decide(&slip).await?;
    assert!(
        status.is_client_error(),
        "a {bound:?}-bound credential is refused, not {status}: {body}"
    );
    assert!(
        fx.proposal_is_open()?,
        "the proposal stays open after the {bound:?}-bound credential's call: {body}"
    );
    Ok(())
}

#[test]
fn a_channel_bound_agent_credential_decides_no_cleanup_over_the_server() -> TestResult {
    on_engine_stack(|| a_bounded_credential_decides_nothing(Bound::Channel))
}

#[test]
fn a_record_bound_agent_credential_decides_no_cleanup_over_the_server() -> TestResult {
    on_engine_stack(|| a_bounded_credential_decides_nothing(Bound::Records))
}

#[test]
fn an_agents_own_credential_decides_a_cleanup_proposal_over_the_server() -> TestResult {
    on_engine_stack(|| async {
        let fx = Fixture::new()?;
        let slip = fx.credential(0x42, Bound::Nothing)?;
        let (status, body) = fx.decide(&slip).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the agent's own credential decides: {body}"
        );
        assert!(
            !fx.proposal_is_open()?,
            "the decided proposal is no longer open: {body}"
        );
        Ok(())
    })
}
