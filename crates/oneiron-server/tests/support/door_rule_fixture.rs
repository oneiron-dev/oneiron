//! The callers of the host-door row check tests (UC-01 PRs 0a and 0b): an
//! in-process vault and server, deterministic (no HTTP, no models), and three
//! callers, each on its own slip with its holder proof:
//! - `owner`: this install's host root, a self-hosted vault's owner;
//! - `agent`: a registered agent principal on its own slip (actor class
//!   `agent`, read, propose and write), holding no Grant;
//! - `unbound`: a slip naming a principal the vault does not know, with no
//!   actor class.
//!
//! [`admits`] judges one caller for one verb as the facade and the MCP
//! dispatch judge it before the row's pre hooks (`row_door_admits`, FIX 1763).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::door_rule_admission::row_door_admits;
use serde_json::json;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// How a slip's holder proves possession of it.
enum Holder {
    /// The host root: the issuer signs its binding proof.
    Root,
    /// A minted slip: its holder's own key signs the binding transcript.
    Key(SigningKey),
}

/// A slip and the proof of its holder.
pub(crate) struct Credential {
    slip: CapabilitySlip,
    holder: Holder,
}

/// The vault, its server and the three callers.
pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    issuer: HostSlipIssuer,
    pub(crate) owner: Credential,
    pub(crate) agent: Credential,
    pub(crate) unbound: Credential,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A slip minted under `root`'s issuer for `holder_ref`, with `actor_class`,
/// read, propose and write (never owner grade), held by the key `seed`.
fn mint(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder_ref: String,
    actor_class: Option<&str>,
    seed: u8,
) -> TestResult<Credential> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = root.claims.clone();
    claims.parent_id = None;
    claims.holder_ref = holder_ref;
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = actor_class.map(str::to_owned);
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "propose".to_owned(),
        "write".to_owned(),
    ]));
    claims.slip_id = [seed; 32];
    Ok(Credential {
        slip: vault.mint_capability_slip(issuer, claims)?,
        holder: Holder::Key(key),
    })
}

/// A device vault with a device keystore, served with an auth secret, and
/// its three callers.
pub(crate) fn setup() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("door-rule-admission".into()),
            ..Default::default()
        },
    )?);
    let issuer = vault.load_host_slip_issuer()?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let agent_ref = vault.ensure_agent_principal("door-rule-admission-agent")?;
    let agent = mint(
        &vault,
        &issuer,
        &root,
        agent_ref.to_hex(),
        Some("agent"),
        0x71,
    )?;
    let unbound = mint(&vault, &issuer, &root, EntityId::now().to_hex(), None, 0x72)?;
    Ok(Fixture {
        _dir: dir,
        vault,
        server,
        issuer,
        owner: Credential {
            slip: root,
            holder: Holder::Root,
        },
        agent,
        unbound,
    })
}

/// The request headers `credential` presents: its token and a fresh holder
/// proof.
fn headers(fixture: &Fixture, credential: &Credential) -> TestResult<HeaderMap> {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = match &credential.holder {
        Holder::Root => hex(&fixture
            .issuer
            .binding_proof(&credential.slip, challenge.as_bytes())?),
        Holder::Key(key) => {
            let transcript = credential.slip.binding_transcript(challenge.as_bytes())?;
            hex(&key.sign(&transcript).to_bytes())
        }
    };
    let binding = json!({"timestamp": timestamp, "nonce": nonce, "signature": signature});
    let mut map = HeaderMap::new();
    map.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", credential.slip.to_token()?))?,
    );
    map.insert(
        "x-oneiron-binding",
        HeaderValue::from_str(&binding.to_string())?,
    );
    Ok(map)
}

/// Whether the check `verb`'s row runs before its pre hooks admits
/// `credential`: `Ok` when it does, else the refusal as `<code>: <message>`.
pub(crate) fn admits(
    fixture: &Fixture,
    credential: &Credential,
    verb: &str,
) -> TestResult<Result<(), String>> {
    Ok(row_door_admits(
        &fixture.server,
        &headers(fixture, credential)?,
        verb,
    ))
}
