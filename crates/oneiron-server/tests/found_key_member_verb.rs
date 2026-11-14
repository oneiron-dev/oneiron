//! L6-03-WRITER-MARK-MANAGED-MEMBER (Engine RULING 08:35 C, 14 Nov): the
//! person who wrote a value that mask on write lifted answers its found key,
//! not a secret or kept as text, at the two facade verbs
//! `vault.secrets.found.not_a_secret` and `vault.secrets.found.keep_as_text`,
//! which take a live person's own proof (`shared_act_doors::person`). A
//! managed member, who carries no slip of his own, reaches them on the
//! person action his supervisor signed for the one request
//! (`ManagedPersonAction`, `auth::MANAGED_PERSON_DOORS`); a person on a
//! self-hosted install reaches them on their own verified human slip. The
//! engine judges the writer: another managed member is refused, an agent's
//! slip is refused at the verb even when it names the writer, and the key
//! stays open.
//!
//! The record is written through the engine in the person's own name, as
//! the writer is recorded only inside an actor content transaction; the
//! answer is the served call under test. The managed server is the plain
//! server behind managed ingress (`build_managed_app`), with the managed
//! issuer managed boot installs (`test_doors::managed_issuer`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test found_key_member_verb`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::ScopeAxis;
use oneiron::memory::StructuralPutInput;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::FoundKeySettled;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_server::managed::{ManagedState, WakeLedger, build_managed_app};
use oneiron_server::test_doors::managed_issuer::with_managed_issuer;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use oneiron_vault_contract::{
    DEK_LEN, MANAGED_PERSON_ACTION_HEADER, ManagedOwnerRequest, ManagedPersonAction, TOKEN_LEN,
    TokenHex, read_credentials, write_credentials,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// The verb that rules a found key no secret.
const NOT_A_SECRET: &str = "vault.secrets.found.not_a_secret";

/// The verb that keeps a found key's value as text.
const KEEP_AS_TEXT: &str = "vault.secrets.found.keep_as_text";

/// The managed vault's name, as its supervisor and its wake ledger know it.
const VAULT_NAME: &str = "found-key-member";

/// The per-spawn secret the supervisor signs person actions with.
const SPAWN_TOKEN: [u8; TOKEN_LEN] = [0x62; TOKEN_LEN];

/// A rooted server on its own device keystore, its host issuer, the vault
/// owner's proof (for the owner's found-key list only), and the app a
/// request reaches: the plain one, or the plain one behind managed ingress.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    app: Router,
}

/// A served vault: behind managed ingress when `managed`, so a person action
/// its supervisor signed names the request's person; else served plain.
fn served(managed: bool) -> Served {
    let dir = tempfile::tempdir().expect("FIXTURE: a vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: a vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("FIXTURE: install signing");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("found-key-member-verb".to_owned()),
            ..Default::default()
        },
    )
    .expect("FIXTURE: a server");
    let issuer = vault
        .bootstrap_host_slip_issuer()
        .expect("FIXTURE: the host issuer");
    let app = if managed {
        let managed_issuer = vault
            .bootstrap_host_slip_issuer()
            .expect("FIXTURE: the managed issuer");
        let server = Arc::new(with_managed_issuer(server, managed_issuer));
        let mut frame = Vec::new();
        write_credentials(&mut frame, &[0x71; DEK_LEN], &SPAWN_TOKEN)
            .expect("FIXTURE: a credentials frame");
        let credentials = read_credentials(&frame[..]).expect("FIXTURE: the spawn credentials");
        let ledger = WakeLedger::load(
            Arc::clone(&vault),
            VAULT_NAME.to_owned(),
            dir.path().join("supervisor.sock"),
            &credentials,
        )
        .expect("FIXTURE: the wake ledger");
        let state = Arc::new(ManagedState::new(
            VAULT_NAME.to_owned(),
            Arc::clone(&server),
            ledger,
        ));
        build_managed_app(server, state)
    } else {
        build_app(Arc::new(server))
    };
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let owner = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    Served {
        _dir: dir,
        vault,
        issuer,
        owner,
        app,
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

/// The facade path of `verb`.
fn facade_path(verb: &str) -> String {
    format!("/v1/core/facade/{verb}")
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

    /// `holder`'s own slip from this host as an `actor_class` caller,
    /// holding `read` and `write`: not owner-grade.
    fn slip(&self, holder: EntityId, actor_class: &str) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("FIXTURE: the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.actor_class = Some(actor_class.to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("FIXTURE: the caller's own slip")
    }

    /// `request` served: the status and the JSON answer.
    async fn serve(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.expect("a response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("a response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `verb` of `handle` at the facade, on the person action the managed
    /// vault's supervisor signed for `who` over this exact request, with no
    /// slip: the status and the JSON answer.
    async fn as_managed_person(
        &self,
        who: EntityId,
        verb: &str,
        handle: &str,
    ) -> (StatusCode, Value) {
        // The vault is rooted, as managed boot leaves a provisioned one.
        self.vault
            .ensure_host_root_slip(&self.issuer)
            .expect("FIXTURE: the host root slip");
        let path = facade_path(verb);
        let body = json!({ "handle": handle }).to_string();
        let action = ManagedPersonAction::sign_after_account_auth(
            &TokenHex::from_token(&SPAWN_TOKEN),
            VAULT_NAME,
            &who.to_hex(),
            &ManagedOwnerRequest {
                method: "POST",
                path: &path,
                query: "",
                headers: ["", "", ""],
                body: body.as_bytes(),
            },
        );
        self.serve(
            Request::builder()
                .method("POST")
                .uri(&path)
                .header("Content-Type", "application/json")
                .header(
                    MANAGED_PERSON_ACTION_HEADER,
                    serde_json::to_string(&action).expect("FIXTURE: the person action"),
                )
                .body(Body::from(body))
                .expect("FIXTURE: a request"),
        )
        .await
    }

    /// `verb` of `handle` at the facade on `holder`'s own `actor_class`
    /// slip, with its holder proof: the status and the JSON answer.
    async fn on_own_slip(
        &self,
        holder: EntityId,
        actor_class: &str,
        verb: &str,
        handle: &str,
    ) -> (StatusCode, Value) {
        let slip = self.slip(holder, actor_class);
        let binding = holder_proof(&slip, &holder_key(), self.vault.now_recorded_at())
            .expect("FIXTURE: a holder proof");
        self.serve(
            Request::builder()
                .method("POST")
                .uri(facade_path(verb))
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
    }
}

#[test]
fn a_managed_member_rules_their_key_not_a_secret_at_the_facade_verb() {
    run_on_engine_stack("managed-not-a-secret", managed_member_rules_not_a_secret);
}

async fn managed_member_rules_not_a_secret() {
    let served = served(true);
    let writer = served.person();
    let record = served.write_event(writer);
    assert!(
        !served.holds_token(&record),
        "FIXTURE: the mask on write lifts the token out of the stored body"
    );
    let handle = served.found_handle(&record);

    let (status, body) = served
        .as_managed_person(writer, NOT_A_SECRET, &handle)
        .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the managed member's person action reaches their answer: {body}"
    );
    assert_eq!(body["action"], "not_a_secret", "{body}");
    assert_eq!(
        body["by"],
        writer.to_hex(),
        "the settled answer names the writer: {body}"
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
fn a_managed_member_keeps_their_key_as_text_at_the_facade_verb() {
    run_on_engine_stack("managed-keep-as-text", managed_member_keeps_as_text);
}

async fn managed_member_keeps_as_text() {
    let served = served(true);
    let writer = served.person();
    let note = served.write_note(writer);
    let handle = served.found_handle(&note);

    let (status, body) = served
        .as_managed_person(writer, KEEP_AS_TEXT, &handle)
        .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the managed member's person action reaches their answer: {body}"
    );
    assert_eq!(body["action"], "kept_as_text", "{body}");
    assert_eq!(
        body["by"],
        writer.to_hex(),
        "the settled answer names the writer: {body}"
    );
    assert_eq!(
        served.settled(&note).and_then(|settled| settled.by),
        Some(writer),
        "the owner's list shows the key settled by its writer"
    );
}

#[test]
fn another_managed_member_may_not_answer_the_key() {
    run_on_engine_stack("managed-other-refused", another_managed_member_refused);
}

async fn another_managed_member_refused() {
    let served = served(true);
    let writer = served.person();
    let other = served.person();
    let record = served.write_event(writer);
    let handle = served.found_handle(&record);

    for verb in [NOT_A_SECRET, KEEP_AS_TEXT] {
        let (status, body) = served.as_managed_person(other, verb, &handle).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{verb}: a member who did not write the key is refused as a non-owner is: {body}"
        );
    }
    assert!(served.settled(&record).is_none(), "the key stays open");
    assert!(
        !served.holds_token(&record),
        "the record still holds the handle, not the value"
    );
}

#[test]
fn the_writer_on_their_own_slip_rules_their_key_at_the_facade_verb() {
    run_on_engine_stack("slip-not-a-secret", writer_on_own_slip_rules_not_a_secret);
}

async fn writer_on_own_slip_rules_not_a_secret() {
    let served = served(false);
    let writer = served.person();
    let record = served.write_event(writer);
    let handle = served.found_handle(&record);

    let (status, body) = served
        .on_own_slip(writer, "human", NOT_A_SECRET, &handle)
        .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the writer's own human slip reaches their answer: {body}"
    );
    assert_eq!(body["action"], "not_a_secret", "{body}");
    assert_eq!(
        body["by"],
        writer.to_hex(),
        "the settled answer names the writer: {body}"
    );
    assert!(
        served.holds_token(&record),
        "the record reads the value as written again"
    );
}

#[test]
fn an_agent_slip_is_refused_at_both_verbs() {
    run_on_engine_stack("agent-slip-refused", agent_slip_refused);
}

async fn agent_slip_refused() {
    let served = served(false);
    let writer = served.person();
    let record = served.write_event(writer);
    let handle = served.found_handle(&record);

    for verb in [NOT_A_SECRET, KEEP_AS_TEXT] {
        let (status, body) = served.on_own_slip(writer, "agent", verb, &handle).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{verb}: an agent's slip, even one naming the writer, is refused at the verb: {body}"
        );
    }
    assert!(served.settled(&record).is_none(), "the key stays open");
    assert!(
        !served.holds_token(&record),
        "the record still holds the handle, not the value"
    );
}
