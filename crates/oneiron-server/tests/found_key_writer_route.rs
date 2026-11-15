//! L6-03-WRITER-MARK-PERSON-ROUTE (Engine RULING NEXT-ROW-13 = A, 14 Nov):
//! the person who wrote a value that mask on write lifted reaches their two
//! answers to its found key, not a secret and kept as text, over HTTP on
//! their own verified human slip, at the owner's two routes
//! (`POST /v1/owner/secrets/found/not-a-secret` and `/keep-as-text`). The
//! engine judges the writer (L6-03-WRITER-MARK = B); another person's own
//! slip gets the owner door's 403, and the key stays open.
//!
//! The record is written through the engine in the person's own name, as
//! the writer is recorded only inside an actor content transaction; the
//! answer is the served call under test.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test found_key_writer_route`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{HostSlipIssuer, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::ScopeAxis;
use oneiron::memory::StructuralPutInput;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::FoundKeySettled;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A rooted server on its own device keystore, its host issuer, and the
/// vault owner's proof (for the owner's found-key list only).
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("FIXTURE: a vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: a vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("FIXTURE: install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("found-key-writer-route".to_owned()),
                ..Default::default()
            },
        )
        .expect("FIXTURE: a server"),
    );
    let issuer = vault
        .bootstrap_host_slip_issuer()
        .expect("FIXTURE: the host issuer");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let owner = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        owner,
    }
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5A; 32])
}

impl Served {
    /// A live PERSON who does not own the vault.
    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("FIXTURE: a live person");
        id
    }

    /// An EVENT `writer` writes in their own name, whose notes hold the
    /// token.
    fn write_event(&self, writer: EntityId) -> EntityId {
        let receipt = self
            .vault
            .memory(writer, EdgeActorClass::Human)
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "EVENT".to_owned(),
                body: json!({
                    "name": "release",
                    "notes": format!("deploy with token={TOKEN}"),
                }),
                text_fields: None,
                edges: None,
                occurred_at: 1,
                learned_at: None,
            })
            .unwrap_or_else(|error| panic!("FIXTURE: the person writes an EVENT: {error:?}"));
        EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the EVENT's id")
    }

    /// A NOTE `writer` writes in their own name, holding the token.
    fn write_note(&self, writer: EntityId) -> EntityId {
        self.vault
            .create_note(
                "research",
                &format!("Release notes: deploy with token={TOKEN}."),
                WriteActor::new(writer, EdgeActorClass::Human),
            )
            .unwrap_or_else(|error| panic!("FIXTURE: the person writes a NOTE: {error:?}"))
    }

    /// Whether the stored body of `id` holds the token as written.
    fn holds_token(&self, id: &EntityId) -> bool {
        self.vault
            .get(id)
            .expect("FIXTURE: a body read")
            .expect("FIXTURE: a stored body")
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes())
    }

    /// The handle of the key the mask lifted out of `record`, from the
    /// owner's found-key list.
    fn found_handle(&self, record: &EntityId) -> String {
        self.vault
            .found_keys(&self.owner, true, 10)
            .expect("FIXTURE: the owner's found-key list")
            .into_iter()
            .find(|notice| notice.record == *record)
            .and_then(|notice| notice.keys.into_iter().next())
            .map(|key| key.handle)
            .expect("FIXTURE: the mask lifted the token into a found key")
    }

    /// How `record`'s key is settled, as the owner's found-key list reads it.
    fn settled(&self, record: &EntityId) -> Option<FoundKeySettled> {
        self.vault
            .found_keys(&self.owner, false, 10)
            .expect("FIXTURE: the owner's found-key list")
            .into_iter()
            .find(|notice| notice.record == *record)
            .and_then(|notice| notice.keys.into_iter().next())
            .and_then(|key| key.settled)
    }

    /// `who`'s own verified human slip from this host, holding `read` and
    /// `write`: not owner-grade.
    fn human_slip(&self, who: EntityId) -> oneiron::authority::CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("FIXTURE: the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("FIXTURE: the person's own slip")
    }

    /// `POST /v1/owner/secrets/found/<route>` of `handle` on `who`'s own
    /// slip, with its holder proof: the status and the JSON answer.
    async fn answer(&self, who: EntityId, route: &str, handle: &str) -> (StatusCode, Value) {
        let slip = self.human_slip(who);
        let binding = holder_proof(&slip, &holder_key(), self.vault.now_recorded_at())
            .expect("FIXTURE: a holder proof");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/owner/secrets/found/{route}"))
                    .header(
                        "Authorization",
                        format!("Bearer {}", slip.to_token().expect("FIXTURE: a token")),
                    )
                    .header("x-oneiron-binding", binding.to_string())
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({ "handle": handle }).to_string()))
                    .expect("FIXTURE: a request"),
            )
            .await
            .expect("a response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("a response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

#[test]
fn the_writer_rules_their_key_not_a_secret_on_their_own_slip() {
    run_on_engine_stack("writer-not-a-secret", writer_rules_not_a_secret);
}

async fn writer_rules_not_a_secret() {
    let served = served();
    let writer = served.person();
    let record = served.write_event(writer);
    assert!(
        !served.holds_token(&record),
        "FIXTURE: the mask on write lifts the token out of the stored body"
    );
    let handle = served.found_handle(&record);

    let (status, body) = served.answer(writer, "not-a-secret", &handle).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the writer's own slip reaches their answer: {body}"
    );
    assert_eq!(body["action"], "not_a_secret", "{body}");
    assert_eq!(
        body["by"],
        writer.to_hex(),
        "the settled answer names the writer"
    );
    assert!(
        served.holds_token(&record),
        "the record reads the value as written again"
    );
    assert_eq!(
        served.settled(&record).and_then(|settled| settled.by),
        Some(writer),
        "the owner's list shows the key settled by its writer"
    );
}

#[test]
fn the_writer_keeps_their_key_as_text_on_their_own_slip() {
    run_on_engine_stack("writer-keep-as-text", writer_keeps_as_text);
}

async fn writer_keeps_as_text() {
    let served = served();
    let writer = served.person();
    let note = served.write_note(writer);
    let handle = served.found_handle(&note);

    let (status, body) = served.answer(writer, "keep-as-text", &handle).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the writer's own slip reaches their answer: {body}"
    );
    assert_eq!(body["action"], "kept_as_text", "{body}");
    assert_eq!(
        body["by"],
        writer.to_hex(),
        "the settled answer names the writer"
    );
}

#[test]
fn another_person_on_their_own_slip_may_not_answer_the_key() {
    run_on_engine_stack("another-person-refused", another_person_refused);
}

async fn another_person_refused() {
    let served = served();
    let writer = served.person();
    let other = served.person();
    let record = served.write_event(writer);
    let handle = served.found_handle(&record);

    for route in ["not-a-secret", "keep-as-text"] {
        let (status, body) = served.answer(other, route, &handle).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{route}: a person who did not write the key gets the owner door's refusal: {body}"
        );
    }
    assert!(served.settled(&record).is_none(), "the key stays open");
    assert!(
        !served.holds_token(&record),
        "the record still holds the handle, not the value"
    );
}
