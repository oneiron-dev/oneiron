//! GENUI-STATE-PERSIST at the served door: a card's `$state` lasts for the
//! card's life on the server that holds it, so a reload does not reset it.
//! `GET /v1/core/lens-frames/{card_id}` hands the held card back to the
//! credential that rendered it, its render carrying the current `$state` its
//! events left, after every row it binds is proved again on that read.
//! Another credential, and a card the server does not hold, get the
//! re-render refusal; a card whose row moved since the render is refused.
//!
//! The card is the owner's default lens, rendered through
//! `vault.lenses.default`, which holds its frame. That card carries no local
//! action, so the test door `move_held_state` moves its held `$state` as an
//! accepted local event does.
//!
//! Red on main (main with this file and the door): the path routes DELETE
//! only, so every GET answers 405.
//!
//! A run's live re-render of the same subscription carries the replaced
//! card's `$state` key by key (Engine ruling 14 Nov 05:40, item 2), and an
//! event on the replaced card finds it closed. No lens a run renders today
//! declares `$state`, so the test holds a walk-planner card through the
//! door `replace_run_card`, as the run's re-render holds it, and reads the
//! held state back through `held_state`. Red on the base (#7709's head with
//! these tests and a door that holds the card without carrying): every
//! re-render starts from its own initial state.
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
use oneiron::lens::{
    CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier,
    GeneratedUiCard, GeneratedUiRender, GeneratedUiStateSnapshot, LensAtom, LensAtomId, LensNode,
    LensRenderId, LensText, SegmentedControl, SelfUiAction, SelfUiActionId, SelfUiBindableProperty,
    SelfUiBinding, SelfUiControl, SelfUiControlId, SelfUiOption, SelfUiOptionValue, SelfUiStateKey,
    SelfUiStateValue,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::lens_frames::{held_state, move_held_state, replace_run_card};
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
        assert_eq!(body["render"]["cardId"], json!(card), "{body}");
        assert_eq!(
            body["render"]["$state"],
            json!({}),
            "the render's own state: {body}"
        );

        assert!(
            move_held_state(&fx.server, &card, picked()).await,
            "the server holds the card"
        );
        let (status, body) = fx.card_state(&owner, &card).await;
        assert_eq!(status, StatusCode::OK, "a moved card: {body}");
        assert_eq!(
            body["render"]["$state"],
            serde_json::to_value(picked()).expect("state JSON"),
            "a reload draws the state the card's events left: {body}"
        );
    });
}

#[test]
fn a_card_whose_row_moved_since_its_render_is_refused() {
    on_engine_stack(|| async {
        let fx = served();
        let owner = fx.owner_credential();
        let card = fx.render(&owner).await;
        let (status, body) = fx.card_state(&owner, &card).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let bound = body["render"]["nodes"].as_array().is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node["bindings"]
                    .as_array()
                    .is_some_and(|bindings| !bindings.is_empty())
            })
        });
        assert!(bound, "the card binds the person's row: {body}");

        // The row changes after the render: the card's backing ref is stale.
        fx.vault
            .put_entity(
                &fx.other,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                2,
                b"human, renamed",
            )
            .expect("the person's row moves");
        let (status, body) = fx.card_state(&owner, &card).await;
        assert!(
            status.is_client_error(),
            "a row that moved since the render refuses: {status} {body}"
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

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn walk_state(pace: &str, note: &str) -> GeneratedUiStateSnapshot {
    [
        (
            SelfUiStateKey::new("pace").expect("state key"),
            SelfUiStateValue::Token(SelfUiOptionValue::new(pace).expect("option value")),
        ),
        (
            SelfUiStateKey::new("note").expect("state key"),
            SelfUiStateValue::Text(text(note)),
        ),
    ]
    .into_iter()
    .collect()
}

fn pace_action() -> SelfUiAction {
    SelfUiAction {
        command: SelfUiActionId::new("pace.set").expect("action id"),
        args: Vec::new(),
    }
}

/// The walk-planner card `card_id`: a segmented control offering `paces`,
/// its selection bound to the `pace` key, and a `note`; it starts at the
/// first pace with no note.
fn planner(card_id: &str, paces: &[&str]) -> GeneratedUiRender {
    let mut pace = LensNode::with_fallback_text(
        LensAtomId::new("pace").expect("atom id"),
        LensAtom::SelfUi(SelfUiControl::Segmented(SegmentedControl {
            id: SelfUiControlId::new("pace").expect("control id"),
            label: text("Pace"),
            options: paces
                .iter()
                .map(|value| SelfUiOption {
                    value: SelfUiOptionValue::new(*value).expect("option value"),
                    label: text(value),
                })
                .collect(),
            selected: None,
            action: pace_action(),
        })),
        text("Pace"),
    );
    pace.state_bindings = vec![SelfUiBinding {
        state_key: SelfUiStateKey::new("pace").expect("state key"),
        property: SelfUiBindableProperty::Selected,
    }];
    let mut root = LensNode::with_fallback_text(
        LensAtomId::new("root").expect("atom id"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Walk"),
            rows: Vec::new(),
        }),
        text("Walk"),
    );
    root.children = vec![pace];
    GeneratedUiCard::interactive(
        LensRenderId::new(card_id).expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        vec![GeneratedUiActionDeclaration {
            element_id: LensAtomId::new("pace").expect("atom id"),
            action_id: SelfUiActionId::new("pace.set").expect("action id"),
            tier: GeneratedUiActionTier::Local,
            action: pace_action(),
        }],
        walk_state(paces[0], "none yet"),
    )
    .expect("a planner card")
    .render()
    .expect("render")
}

#[test]
fn a_live_re_render_carries_the_replaced_cards_state() {
    on_engine_stack(|| async {
        let fx = served();
        let run = EntityId::now();
        let first = replace_run_card(
            &fx.server,
            run,
            "walk",
            planner("walk-1", &["easy", "brisk"]),
        )
        .await
        .expect("the first card");
        assert_eq!(first.state, walk_state("easy", "none yet"));
        let picked = walk_state("brisk", "after lunch");
        assert!(
            move_held_state(&fx.server, "walk-1", picked.clone()).await,
            "the server holds the first card"
        );

        let second = replace_run_card(
            &fx.server,
            run,
            "walk",
            planner("walk-2", &["easy", "brisk"]),
        )
        .await
        .expect("the re-render");
        assert_eq!(
            second.state, picked,
            "the re-render answers the state the person left"
        );
        assert_eq!(held_state(&fx.server, "walk-2").await, Some(picked));
        assert_eq!(
            held_state(&fx.server, "walk-1").await,
            None,
            "the replaced card is closed: an event on it answers re-render"
        );

        // A re-render whose control no longer offers the picked pace keeps
        // its own pace, and still carries the note.
        let third = replace_run_card(
            &fx.server,
            run,
            "walk",
            planner("walk-3", &["easy", "steady"]),
        )
        .await
        .expect("the second re-render");
        let kept = walk_state("easy", "after lunch");
        assert_eq!(third.state, kept);
        assert_eq!(held_state(&fx.server, "walk-3").await, Some(kept));
    });
}

#[test]
fn another_runs_or_subscriptions_card_carries_nothing() {
    on_engine_stack(|| async {
        let fx = served();
        let run = EntityId::now();
        replace_run_card(
            &fx.server,
            run,
            "walk",
            planner("walk-1", &["easy", "brisk"]),
        )
        .await
        .expect("the first card");
        let picked = walk_state("brisk", "after lunch");
        assert!(move_held_state(&fx.server, "walk-1", picked.clone()).await);

        let other_run = replace_run_card(
            &fx.server,
            EntityId::now(),
            "walk",
            planner("walk-other-run", &["easy", "brisk"]),
        )
        .await
        .expect("another run's card");
        assert_eq!(other_run.state, walk_state("easy", "none yet"));

        let other_subscription = replace_run_card(
            &fx.server,
            run,
            "swim",
            planner("swim-1", &["easy", "brisk"]),
        )
        .await
        .expect("another subscription's card");
        assert_eq!(other_subscription.state, walk_state("easy", "none yet"));
        assert_eq!(
            held_state(&fx.server, "walk-1").await,
            Some(picked),
            "neither replaces the first card"
        );
    });
}
