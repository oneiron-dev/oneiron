//! A paired `oneiron_remote::OneironClient` against the real router.
//!
//! Pairing is the only enrollment, and every slip request carries a fresh
//! holder proof signed with the connection key the pairing chose. Every call
//! here goes through the SDK client, so what passes is what a developer's
//! program does.

// Integration-test helpers (non-`#[test]` fns) are not covered by
// allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use oneiron::authority::{CapabilitySlip, HostSlipIssuer, PairingPrincipal, format_pairing_link};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{ClaimInput, MemoryError, RecallScope, WitnessTurn};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_remote::OneironClient;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;

const SECRET: &str = "remote-pairing-host-root";
const READ_WRITE: &[&str] = &["core:read", "core:write"];

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    origin: String,
    person: String,
}

impl Fixture {
    /// A served vault with one PERSON, the principal every owner link names.
    async fn serve() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).unwrap());
        let person = vault.ensure_embedded_owner_actor().unwrap().to_hex();
        let config = SyncServerConfig {
            auth_secret: Some(SECRET.to_owned()),
            ..Default::default()
        };
        let server = Arc::new(SyncServer::new(vault.clone(), config).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, build_app(server)).await.unwrap();
        });
        Self {
            _dir: dir,
            vault,
            origin,
            person,
        }
    }

    /// A link the owner created on the shared vault, and its expiry.
    fn link(&self, verbs: &[&str], holder: &str, class: Option<&str>) -> (String, u64) {
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        let link = self
            .vault
            .issue_pairing_link_for_principal(
                &issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(holder.to_owned()),
                    actor_class: class.map(str::to_owned),
                    org_ref: None,
                },
            )
            .unwrap();
        (
            format_pairing_link(&self.origin, &link.code, holder),
            link.expires_at,
        )
    }

    fn owner_link(&self) -> String {
        self.link(READ_WRITE, &self.person, Some("human")).0
    }
}

/// The SDK client is blocking; it runs off the runtime that serves it.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

fn paired(link: &str) -> OneironClient {
    let (url, credential) = OneironClient::pair(link).unwrap();
    OneironClient::connect(&url, &credential).unwrap()
}

/// The slip a credential carries, without its connection key.
fn bare_slip(credential: &str) -> String {
    let (slip, _seed) = credential
        .strip_prefix("v2.cred.")
        .unwrap()
        .rsplit_once('.')
        .unwrap();
    format!("v2.slip.{slip}")
}

fn code(result: Result<impl Sized, MemoryError>) -> String {
    result.err().unwrap().code
}

fn turn() -> WitnessTurn {
    serde_json::from_value(serde_json::json!({
        "conversation_ref": "55555555555555555555555555555555",
        "turn_ref": null,
        "messages": [{
            "id": null, "author": "user", "message_type": "dialogue",
            "content": "I prefer a window seat when I fly.", "metadata": null,
            "is_visible": true, "order": 0,
        }],
        "occurred_at": oneiron_remote::unix_seconds_now(),
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_client_witnesses_claims_recalls_and_reads_its_receipts() {
    let fixture = Fixture::serve().await;
    let link = fixture.owner_link();
    let found = blocking(move || {
        let client = paired(&link);
        let witnessed = client.witness(&turn()).unwrap();
        let claim: ClaimInput = serde_json::from_value(serde_json::json!({
            "predicate": "preference.travel.seat",
            "subject_ref": witnessed.turn_short_id,
            "value": {"seat": "window"}, "confidence": 1.0, "source": "user_stated",
        }))
        .unwrap();
        let claimed = client.claim_upsert(&claim).unwrap();
        let effort = oneiron_remote::parse_effort("medium").unwrap();
        client
            .recall("window seat", effort, &RecallScope::default(), 10, None)
            .unwrap();
        let receipts = client.receipts(100).unwrap();
        receipts
            .iter()
            .any(|receipt| receipt.receipt_ref == claimed.receipt_ref)
    })
    .await;
    assert!(found);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn back_to_back_calls_each_spend_a_fresh_nonce() {
    let fixture = Fixture::serve().await;
    let link = fixture.owner_link();
    let (first, second) = blocking(move || {
        let client = paired(&link);
        (client.receipts(10), client.receipts(10))
    })
    .await;
    assert!(first.is_ok() && second.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bare_slip_without_its_key_is_unauthorized() {
    let fixture = Fixture::serve().await;
    let link = fixture.owner_link();
    let refused = blocking(move || {
        let (url, credential) = OneironClient::pair(&link).unwrap();
        let client = OneironClient::connect(&url, &bare_slip(&credential)).unwrap();
        code(client.receipts(10))
    })
    .await;
    assert_eq!(refused, "UNAUTHORIZED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slip_with_the_wrong_key_is_unauthorized() {
    let fixture = Fixture::serve().await;
    let link = fixture.owner_link();
    let refused = blocking(move || {
        let (url, credential) = OneironClient::pair(&link).unwrap();
        let (slip, _seed) = credential.rsplit_once('.').unwrap();
        let wrong = format!("{slip}.{}", "11".repeat(32));
        let client = OneironClient::connect(&url, &wrong).unwrap();
        code(client.receipts(10))
    })
    .await;
    assert_eq!(refused, "UNAUTHORIZED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeeming_a_link_twice_is_unauthorized_at_pair() {
    let fixture = Fixture::serve().await;
    let link = fixture.owner_link();
    let refused = blocking(move || {
        OneironClient::pair(&link).unwrap();
        code(OneironClient::pair(&link))
    })
    .await;
    assert_eq!(refused, "UNAUTHORIZED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_link_is_unauthorized_at_pair() {
    let fixture = Fixture::serve().await;
    let (link, expires_at) = fixture.link(READ_WRITE, &fixture.person, Some("human"));
    fixture
        .vault
        .sync_state_put("authlog:first_seen:clock_floor", &expires_at.to_be_bytes())
        .unwrap();
    let refused = blocking(move || code(OneironClient::pair(&link))).await;
    assert_eq!(refused, "UNAUTHORIZED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_for_a_holder_that_is_not_an_entity_is_unauthorized_at_pair() {
    let fixture = Fixture::serve().await;
    let (link, _) = fixture.link(READ_WRITE, &EntityId::now().to_hex(), Some("human"));
    let refused = blocking(move || code(OneironClient::pair(&link))).await;
    assert_eq!(refused, "UNAUTHORIZED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slip_with_no_actor_class_is_forbidden_at_the_verb() {
    let fixture = Fixture::serve().await;
    let (link, _) = fixture.link(READ_WRITE, &fixture.person, None);
    let refused = blocking(move || code(paired(&link).receipts(10))).await;
    assert_eq!(refused, "FORBIDDEN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_slip_is_forbidden_to_write() {
    let fixture = Fixture::serve().await;
    let (link, _) = fixture.link(&["core:read"], &fixture.person, Some("human"));
    let refused = blocking(move || code(paired(&link).witness(&turn()))).await;
    assert_eq!(refused, "FORBIDDEN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_slip_is_unauthorized_on_its_next_call() {
    let fixture = Fixture::serve().await;
    let link = fixture.owner_link();
    let vault = fixture.vault.clone();
    let refused = blocking(move || {
        let (url, credential) = OneironClient::pair(&link).unwrap();
        let client = OneironClient::connect(&url, &credential).unwrap();
        client.receipts(10).unwrap();
        let slip = CapabilitySlip::from_token(&bare_slip(&credential)).unwrap();
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        vault
            .revoke_capability_slip(&issuer, slip.claims.slip_id)
            .unwrap();
        code(client.receipts(10))
    })
    .await;
    assert_eq!(refused, "UNAUTHORIZED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_secret_crosses_with_no_proof_and_is_authenticated() {
    let fixture = Fixture::serve().await;
    let origin = fixture.origin.clone();
    let refused = blocking(move || {
        let client = OneironClient::connect(&origin, SECRET).unwrap();
        code(client.receipts(10))
    })
    .await;
    // Authenticated, then refused at the facade: a secret names no principal.
    assert_eq!(refused, "FORBIDDEN");
}
