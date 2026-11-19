#![cfg(oneiron_test_support)]
//! FIX-LIST 25102 (T0I-MCP-RUN-CLAIM-ROW-IDENTITY-KEY): over `/mcp` a code
//! run's `vault.claims.put` and `vault.claims.supersede` check the records
//! they name on the connector's credential lane, as the run's
//! `vault.edges.put`, search, consult and workflow rows do. Before the fix
//! the door admitted the claim rows with no key, so the check fell back to
//! the writer's own key and a vault-wide Write connector with no core:read
//! grant got INVENTED_REFERENCE on a run's claim about a record its
//! credential reads.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test mcp_run_claim_row_identity_key`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::code_run::SelfEffect;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::mcp_run_claim_lane::run_call_reads_on_credential_lane;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-run-claim-row-identity-key".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            server,
            vault,
            issuer,
            _dir: dir,
        })
    }

    /// A vault-wide Write connector's slip for a grantless agent, minted
    /// under the vault's logged issuer as pairing mints one: read and write
    /// verbs, no narrower axis, and the holder's signing key.
    fn mint_connector(&self) -> TestResult<(CapabilitySlip, SigningKey)> {
        let agent = EntityId::now();
        self.vault.put_entity(
            &agent,
            oneiron::registry::ENTITY_TYPE_MACHINE,
            TimeRange { start: 1, end: 1 },
            1,
            b"a grantless connector agent",
        )?;
        let root = self.vault.ensure_host_root_slip(&self.issuer)?;
        let key = SigningKey::from_bytes(&[0x62; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x62; 32];
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        Ok((slip, key))
    }

    /// A fresh holder proof for `slip`: the timestamp, nonce and hex
    /// signature the door verifies, as the MCP ingress verifies them.
    fn holder_proof(
        &self,
        slip: &CapabilitySlip,
        key: &SigningKey,
    ) -> TestResult<(u64, String, String)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(&key.sign(&slip.binding_transcript(&challenge)?).to_bytes());
        Ok((timestamp, nonce, signature))
    }

    /// Whether the run's call to `effect` reads on the connector's
    /// credential lane. A refusal at the gate fails the test: the wanted
    /// answer is a lane, keyed or keyless, never a refusal.
    fn reads_on_credential_lane(
        &self,
        slip: &CapabilitySlip,
        key: &SigningKey,
        effect: SelfEffect,
    ) -> bool {
        let (timestamp, nonce, signature) =
            self.holder_proof(slip, key).expect("sign the holder proof");
        let token = slip.to_token().expect("render the slip");
        run_call_reads_on_credential_lane(
            &self.server,
            &token,
            timestamp,
            &nonce,
            &signature,
            effect,
        )
        .unwrap_or_else(|error| {
            panic!(
                "the {} call is refused at the gate: {error}",
                effect.as_str()
            )
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_runs_claim_rows_read_their_records_on_the_connectors_credential_lane() -> TestResult {
    on_engine_stack(run_claim_rows_read_on_credential_lane)
}

async fn run_claim_rows_read_on_credential_lane() -> TestResult {
    let fixture = Fixture::new()?;
    let (slip, key) = fixture.mint_connector()?;

    // Control: the run's edge row already reads on the credential lane.
    assert!(
        fixture.reads_on_credential_lane(&slip, &key, SelfEffect::MemoryPutEdge),
        "control: the run's edge row reads on the credential lane"
    );
    // The defect: the claim rows were admitted with no key, so their
    // record check fell back to the writer's own key.
    assert!(
        fixture.reads_on_credential_lane(&slip, &key, SelfEffect::MemoryPutClaim),
        "a run's claim put checks its subject on the credential lane"
    );
    assert!(
        fixture.reads_on_credential_lane(&slip, &key, SelfEffect::MemorySupersedeClaim),
        "a run's supersede checks its claims on the credential lane"
    );
    Ok(())
}
