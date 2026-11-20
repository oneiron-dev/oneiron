#![cfg(oneiron_test_support)]
//! The HTTP facade refuses a facet-narrowed credential the agent slot doors
//! (`vault.lenses.activate_as`, `vault.lenses.deactivate_as`) at their
//! generated record-scope guard, before the input, the actor or any lens is
//! read: the engine door judges no lane, so a narrowed credential is no
//! narrower there (fix 6a77952d, FIX W9-LENS-RUN-LINEAGE-REGRESSION-TESTS (2)).
//! An unnarrowed credential passes the guard and meets the engine's own
//! refusal.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test lens_slot_agent_doors_record_scope`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SCOPE_REFUSAL: &str = "request does not have the required scope";
const ACTIVATE_AS: &str = "vault.lenses.activate_as";
const DEACTIVATE_AS: &str = "vault.lenses.deactivate_as";

struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    plain: Credential,
    narrow: Credential,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// The seeded default agent holding two read-and-write credentials: one
    /// of top scope, and one narrowed to a single facet.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or("the default agent is seeded")?;
        let work = EntityId::now();
        vault.put_entity(
            &work,
            oneiron::registry::ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"work",
        )?;

        // HTTP trusts the logged issuer of each mint, not auth_secret. Root
        // this fixture explicitly; the app needs no retained signing key.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-lens-slot-agent-doors")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let key = SigningKey::from_bytes(&[0x6b; 32]);
        let mut claims = root.claims;
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        // Both core scopes the slot doors' guards ask for: a refusal is then
        // about the narrowing alone.
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        claims.slip_id = [0x6b; 32];
        let plain = Credential {
            slip: vault.mint_capability_slip(&issuer, claims.clone())?,
            key: key.clone(),
        };
        claims.slip_id = [0x6c; 32];
        claims.scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(work)]));
        let narrow = Credential {
            slip: vault.mint_capability_slip(&issuer, claims)?,
            key,
        };
        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            plain,
            narrow,
            _dir: dir,
        })
    }

    async fn facade(
        &self,
        credential: &Credential,
        verb: &str,
        input: Value,
    ) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = credential
            .key
            .sign(&credential.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header(
                "authorization",
                format!("Bearer {}", credential.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_narrowed_credential_is_refused_the_agent_slot_doors() -> TestResult {
    on_engine_stack(narrowed_credential_and_the_agent_slot_doors)
}

async fn narrowed_credential_and_the_agent_slot_doors() -> TestResult {
    let fixture = Fixture::new()?;
    let lens_ref = EntityId::now().to_hex();
    let select = json!({ "lens_ref": lens_ref, "compiled_hash": "00".repeat(32) });
    let clear = json!({
        "slot": { "pack_name": "oneiron.weave", "skill_id": EntityId::now().to_hex() },
        "expected_active_ref": lens_ref,
    });
    for (verb, input) in [(ACTIVATE_AS, select), (DEACTIVATE_AS, clear)] {
        let (status, body) = fixture.facade(&fixture.plain, verb, input.clone()).await?;
        assert_ne!(
            body["error"]["message"], SCOPE_REFUSAL,
            "{verb}: the unnarrowed credential passes the record-scope guard: status={status}, body={body}"
        );

        let (status, body) = fixture.facade(&fixture.narrow, verb, input).await?;
        assert_eq!(
            status, 403,
            "{verb}: expected a record-scope refusal: status={status}, body={body}"
        );
        assert_eq!(
            body["error"]["code"], "FORBIDDEN",
            "{verb}: status={status}, body={body}"
        );
        // The facade drops ApiError.details but keeps this guard's exact
        // words, which no engine door refusal carries.
        assert_eq!(
            body["error"]["message"], SCOPE_REFUSAL,
            "{verb}: status={status}, body={body}"
        );
    }
    Ok(())
}
