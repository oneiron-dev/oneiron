#![cfg(oneiron_test_support)]
//! USAGE-EVENTS-BODY-SCOPE-UNCHECKED: `POST /v1/usage/events` on a server
//! whose meter is bound to one vault records a posted event only in that
//! vault. An event whose body names another vault is refused
//! `400 BAD_REQUEST` on `vaultId` and records nothing; an event for the
//! bound vault records as before, under the bound billing owner and under
//! another billing owner in the same vault alike (a room-paid payer's
//! account, FIX 7035).
//!
//! Red on main: the handler passes the body's owner and vault strings to
//! the ledger unchecked, so the other-vault post answers 200 with
//! `recorded: true` and the first status assertion fails.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test usage_events_body_scope`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::usage::UsageLedger;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The billing owner the fixture's meter is bound for.
const BILLING_OWNER: &str = "billing-owner";
/// A billing owner in the bound vault other than the meter's own.
const PAYER_OWNER: &str = "room-payer-account";
/// A vault the fixture's meter is not bound to.
const OTHER_VAULT: &str = "another-vault";

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    /// The vault id the server's meter is bound to: the authority log's.
    bound_vault: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A rooted server with its usage meter bound, as `serve` builds one:
    /// the auth secret roots the vault in `SyncServer::new`, so its
    /// authority log names the vault the meter then binds to.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("usage-events-body-scope".into()),
                ..Default::default()
            },
        )?
        .with_usage_metering(BILLING_OWNER)?;
        let usage = server.vault_usage().ok_or("the server meters its usage")?;
        assert_eq!(usage.owner(), BILLING_OWNER);
        let bound_vault = usage.vault_id().to_owned();
        drop(usage);
        let issuer = vault.load_host_slip_issuer()?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        Ok(Self {
            app: build_app(Arc::new(server)),
            vault,
            issuer,
            root,
            bound_vault,
            _dir: dir,
        })
    }

    /// Posts `event` to `/v1/usage/events` as the vault's owner, on the
    /// host root slip with its holder.
    async fn post(&self, event: Value) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self.issuer.binding_proof(&self.root, &challenge)?;
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post("/v1/usage/events")
            .header("authorization", format!("Bearer {}", self.root.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(event.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }

    /// The recorded event count of `owner` in `vault_id`, by the ledger's
    /// own rollup read; `None` before its first recorded event.
    fn event_count(&self, owner: &str, vault_id: &str) -> TestResult<Option<u64>> {
        Ok(UsageLedger::new(Arc::clone(&self.vault))
            .vault_rollup(owner, vault_id)?
            .map(|rollup| rollup.counters.event_count))
    }
}

/// One priced inference event like the handler's own billing fixtures
/// post, under `owner` in `vault_id`, keyed once by `key`.
fn usage_event(owner: &str, vault_id: &str, key: &str) -> Value {
    json!({
        "owner": owner,
        "vaultId": vault_id,
        "idempotencyKey": key,
        "eventType": "inference",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": { "currency": "USD", "priceTableSnapshot": "fixture",
            "inputPerMillion": 2000000000,
            "outputPerMillion": 4000000000_u64,
            "cacheReadPerMillion": 0,
            "cacheWritePerMillion": 0
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_posted_usage_event_must_name_the_bound_metering_vault() -> TestResult {
    on_engine_stack(posted_usage_event_scope)
}

async fn posted_usage_event_scope() -> TestResult {
    let fixture = Fixture::new()?;
    let bound = fixture.bound_vault.clone();

    let (status, body) = fixture
        .post(usage_event(BILLING_OWNER, OTHER_VAULT, "wrong-vault"))
        .await?;
    assert_eq!(
        status, 400,
        "a post naming a vault the meter is not bound to is refused: {body}"
    );
    assert_eq!(body["code"], Value::from("BAD_REQUEST"), "{body}");
    assert_eq!(body["details"]["field"], Value::from("vaultId"), "{body}");
    assert_eq!(
        fixture.event_count(BILLING_OWNER, OTHER_VAULT)?,
        None,
        "the refused post records nothing under the other vault"
    );
    assert_eq!(
        fixture.event_count(BILLING_OWNER, &bound)?,
        None,
        "the refused post records nothing under the bound vault either"
    );

    let (status, body) = fixture
        .post(usage_event(BILLING_OWNER, &bound, "bound-vault"))
        .await?;
    assert_eq!(status, 200, "a post naming the bound vault records: {body}");
    assert_eq!(body["recorded"], Value::from(true), "{body}");
    assert_eq!(fixture.event_count(BILLING_OWNER, &bound)?, Some(1));

    let (status, body) = fixture
        .post(usage_event(PAYER_OWNER, &bound, "payer-in-bound-vault"))
        .await?;
    assert_eq!(
        status, 200,
        "another billing owner in the bound vault still records: {body}"
    );
    assert_eq!(body["recorded"], Value::from(true), "{body}");
    assert_eq!(fixture.event_count(PAYER_OWNER, &bound)?, Some(1));
    Ok(())
}
