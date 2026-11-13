//! GENUI-STATE-PERSIST at the served door: a card's `$state` lasts for the
//! card's life on the server that holds it, so a reload does not reset it.
//! `GET /v1/core/lens-frames/{card_id}` answers the held card's current
//! `$state`, as its events left it, to the credential that rendered the
//! card; another credential, and a card the server does not hold, get the
//! re-render refusal.
//!
//! The card is the owner's default lens, rendered through
//! `vault.lenses.default`, which holds its frame. That card carries no local
//! action, so the test door `move_held_state` moves its held `$state` as an
//! accepted local event does.
//!
//! Red on main (main with this file and the door): the path routes DELETE
//! only, so every GET answers 405.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! lens_frame_state_door`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::lens::GeneratedUiStateSnapshot;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::lens_frames::move_held_state;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5A; 32])
}

/// A rooted server on its own device keystore, its owner, and one other
/// person of the vault.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    other: EntityId,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("lens-frame-state-door".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let other = EntityId::now();
    vault
        .put_entity(
            &other,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        owner,
        other,
    }
}

impl Served {
    /// The owner's own slip, narrowed by its holder to `read` and `write`.
    fn owner_credential(&self) -> CapabilitySlip {
        let mut slip = self.slip(self.owner, false);
        let mut narrowed = Scope::top();
        narrowed.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(narrowed),
                ..Default::default()
            },
            &holder_key(),
        )
        .expect("the owner narrows its own slip");
        slip
    }

    /// A credential this host mints the other person, holding `read` and
    /// `write`.
    fn other_credential(&self) -> CapabilitySlip {
        self.slip(self.other, true)
    }

    /// A slip for `holder`, cut from the host root slip's claims; with
    /// `narrow`, its verbs are `read` and `write` alone.
    fn slip(&self, holder: EntityId, narrow: bool) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        if narrow {
            claims.scope.verbs =
                ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        }
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a slip")
    }

    /// `slip` sends `method` to `uri` with `body`: the status and the body.
    async fn send(
        &self,
        slip: &CapabilitySlip,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let token = slip.to_token().expect("token");
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding.to_string())
            .header("Content-Type", "application/json")
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .expect("request");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(request)
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1_048_576)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `slip` renders the default lens over the other person's row: the
    /// card id the server holds its frame under.
    async fn render(&self, slip: &CapabilitySlip) -> String {
        let (status, body) = self
            .send(
                slip,
                "POST",
                "/v1/core/facade/vault.lenses.default",
                Some(json!({ "title": "People", "ledger": [self.other.to_hex()] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "vault.lenses.default: {body}");
        card_id(&body).unwrap_or_else(|| panic!("the answer names its card: {body}"))
    }

    /// `slip` reads the card's state back.
    async fn card_state(&self, slip: &CapabilitySlip, card: &str) -> (StatusCode, Value) {
        self.send(slip, "GET", &format!("/v1/core/lens-frames/{card}"), None)
            .await
    }
}

/// The first card id in `value`, at any depth: the card's `card_id`, or its
/// render's `cardId`.
fn card_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map
            .get("card_id")
            .or_else(|| map.get("cardId"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| map.values().find_map(card_id)),
        Value::Array(items) => items.iter().find_map(card_id),
        _ => None,
    }
}

fn picked() -> GeneratedUiStateSnapshot {
    serde_json::from_value(json!({
        "north": { "type": "bool", "value": true },
        "note": { "type": "text", "value": "after lunch" },
    }))
    .expect("a state snapshot")
}

/// Runs `case` on a thread with the stack `oneiron serve` runs its doors
/// on: a generated dispatch frame is larger than a libtest thread's stack
/// in a dev build (FIX 16372).
fn on_engine_stack<F>(case: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(case());
        })
        .expect("engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn the_renderer_reads_the_state_its_cards_events_left() {
    on_engine_stack(|| async {
        let fx = served();
        let owner = fx.owner_credential();
        let card = fx.render(&owner).await;

        let (status, body) = fx.card_state(&owner, &card).await;
        assert_eq!(status, StatusCode::OK, "an untouched card: {body}");
        assert_eq!(body["cardId"], json!(card), "{body}");
        assert_eq!(body["$state"], json!({}), "the render's own state: {body}");

        assert!(
            move_held_state(&fx.server, &card, picked()).await,
            "the server holds the card"
        );
        let (status, body) = fx.card_state(&owner, &card).await;
        assert_eq!(status, StatusCode::OK, "a moved card: {body}");
        assert_eq!(
            body["$state"],
            serde_json::to_value(picked()).expect("state JSON"),
            "a reload draws the state the card's events left: {body}"
        );
        assert!(
            body.get("render").is_none() && body.get("nodes").is_none(),
            "the answer is the state alone: {body}"
        );
    });
}

#[test]
fn another_credential_is_refused_the_cards_state() {
    on_engine_stack(|| async {
        let fx = served();
        let card = fx.render(&fx.owner_credential()).await;
        assert!(move_held_state(&fx.server, &card, picked()).await);
        let (status, body) = fx.card_state(&fx.other_credential(), &card).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "only the renderer reads its card's state: {body}"
        );
        assert!(
            body.to_string().contains("re-render"),
            "the refusal says to re-render: {body}"
        );
    });
}

#[test]
fn a_card_the_server_does_not_hold_is_refused() {
    on_engine_stack(|| async {
        let fx = served();
        let owner = fx.owner_credential();
        let (status, body) = fx.card_state(&owner, "default-vault-unknown").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let card = fx.render(&owner).await;
        let (status, closed) = fx
            .send(
                &owner,
                "DELETE",
                &format!("/v1/core/lens-frames/{card}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{closed}");
        assert_eq!(closed["closed"], true, "{closed}");
        let (status, body) = fx.card_state(&owner, &card).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a closed card: {body}");
    });
}
