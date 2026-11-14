//! L6-03-WRITER-FOUND-KEY-LIST PR 2 (Engine RULING 14 Nov 11:39,
//! PLAN-L6-03-WRITER-FOUND-KEY-LIST = A): the facade verb
//! `vault.secrets.found.list` lists the found keys a caller may answer,
//! under a live person's own proof (`shared_act_doors::person`). The owner
//! reads every key, record by record, on the owner's card; any other person
//! reads only the keys whose values they wrote, on value-free cards, a
//! record named only while they can still read it. A managed member, who
//! carries no slip of his own, reaches it on the person action his
//! supervisor signed for the one request (`auth::MANAGED_PERSON_DOORS`); a
//! person on a self-hosted install on their own verified human slip. An
//! agent's slip is refused at the verb even when it names the writer.
//!
//! The records are written through the engine in each person's own name, as
//! the writer is recorded only inside an actor content transaction; the
//! list is the served call under test. The managed server is the plain
//! server behind managed ingress (`build_managed_app`), with the managed
//! issuer managed boot installs (`test_doors::managed_issuer`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test found_key_list_verb`.

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
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{FoundKeyListRequest, UNREADABLE_PLACE, list_found_keys_as};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::managed::{ManagedState, WakeLedger, build_managed_app};
use oneiron_server::test_doors::managed_issuer::with_managed_issuer;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use oneiron_vault_contract::{
    DEK_LEN, MANAGED_PERSON_ACTION_HEADER, ManagedOwnerRequest, ManagedPersonAction, TOKEN_LEN,
    TokenHex, read_credentials, write_credentials,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// GitHub tokens the door's text rules place by their span, one per
/// record: a value custody already holds comes back under its old handle
/// and is lifted into no new key (OF-560 C).
const TOKENS: [&str; 2] = [
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "ghp_1123456789abcdefghijklmnopqrstuvwxyz",
];

/// The verb that lists the found keys a caller may answer.
const LIST: &str = "vault.secrets.found.list";

/// The managed vault's name, as its supervisor and its wake ledger know it.
const VAULT_NAME: &str = "found-key-list";

/// The per-spawn secret the supervisor signs person actions with.
const SPAWN_TOKEN: [u8; TOKEN_LEN] = [0x62; TOKEN_LEN];

/// A rooted server on its own device keystore, its host issuer, the vault
/// owner's proof, and the app a request reaches: the plain one, or the
/// plain one behind managed ingress.
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
            auth_secret: Some("found-key-list-verb".to_owned()),
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

    /// An EVENT `writer` writes in their own name, whose notes hold
    /// `token`.
    fn write_event(&self, writer: EntityId, token: &str) -> EntityId {
        let receipt = self
            .vault
            .memory(writer, EdgeActorClass::Human)
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "EVENT".to_owned(),
                body: json!({
                    "name": "release",
                    "notes": format!("deploy with token={token}"),
                }),
                text_fields: None,
                edges: None,
                occurred_at: 1,
                learned_at: None,
            })
            .unwrap_or_else(|error| panic!("FIXTURE: the person writes an EVENT: {error:?}"));
        EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the EVENT's id")
    }

    /// The handle of the key the mask lifted out of `record`, from the
    /// owner's found-key list.
    fn found_handle(&self, record: &EntityId) -> String {
        self.vault
            .found_keys(&self.owner, true, 50)
            .expect("FIXTURE: the owner's found-key list")
            .into_iter()
            .find(|notice| notice.record == *record)
            .and_then(|notice| notice.keys.into_iter().next())
            .map(|key| key.handle)
            .expect("FIXTURE: the mask lifted the token into a found key")
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

    /// `verb` with `input` at the facade, on the person action the managed
    /// vault's supervisor signed for `who` over this exact request, with no
    /// slip: the status and the JSON answer.
    async fn as_managed_person(
        &self,
        who: EntityId,
        verb: &str,
        input: Value,
    ) -> (StatusCode, Value) {
        // The vault is rooted, as managed boot leaves a provisioned one.
        self.vault
            .ensure_host_root_slip(&self.issuer)
            .expect("FIXTURE: the host root slip");
        let path = facade_path(verb);
        let body = input.to_string();
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

    /// `verb` with `input` at the facade on `holder`'s own `actor_class`
    /// slip, with its holder proof: the status and the JSON answer.
    async fn on_own_slip(
        &self,
        holder: EntityId,
        actor_class: &str,
        verb: &str,
        input: Value,
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
                .body(Body::from(input.to_string()))
                .expect("FIXTURE: a request"),
        )
        .await
    }
}

/// The handles of a writer's list answer, after checking its shape: the
/// writer's view, value-free cards, and the two answers still open.
fn writer_handles(body: &Value) -> Vec<String> {
    assert_eq!(body["view"], "writer", "{body}");
    assert_eq!(
        body["notices"],
        json!([]),
        "a writer reads no owner notice: {body}"
    );
    let keys = body["keys"].as_array().expect("the writer's keys");
    for key in keys {
        assert!(
            key.get("name").is_none() && key.get("label").is_none(),
            "a writer's card names no custody record or label: {key}"
        );
        if key["record"].is_null() {
            assert_eq!(key["place"], UNREADABLE_PLACE, "{key}");
        }
        assert_eq!(
            key["actions"],
            json!(["not_a_secret", "kept_as_text"]),
            "{key}"
        );
    }
    keys.iter()
        .map(|key| key["handle"].as_str().expect("a handle").to_owned())
        .collect()
}

#[test]
fn a_managed_member_lists_the_keys_they_wrote_at_the_facade_verb() {
    run_on_engine_stack("managed-list", managed_member_lists_their_keys);
}

async fn managed_member_lists_their_keys() {
    let served = served(true);
    let writer = served.person();
    let other = served.person();
    let mine = served.write_event(writer, TOKENS[0]);
    let theirs = served.write_event(other, TOKENS[1]);
    let mine = served.found_handle(&mine);
    let theirs = served.found_handle(&theirs);

    let (status, body) = served.as_managed_person(writer, LIST, json!({})).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the managed member's person action reaches the list: {body}"
    );
    assert_eq!(
        writer_handles(&body),
        vec![mine],
        "the member lists their own key and not another writer's"
    );
    assert_eq!(body["done"], true, "{body}");
    let (status, body) = served.as_managed_person(other, LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        writer_handles(&body),
        vec![theirs],
        "the other member lists theirs"
    );
}

#[test]
fn the_writer_on_their_own_slip_lists_their_keys_at_the_facade_verb() {
    run_on_engine_stack("slip-list", writer_on_own_slip_lists_their_keys);
}

async fn writer_on_own_slip_lists_their_keys() {
    let served = served(false);
    let writer = served.person();
    let stranger = served.person();
    let record = served.write_event(writer, TOKENS[0]);
    let handle = served.found_handle(&record);

    let (status, body) = served
        .on_own_slip(writer, "human", LIST, json!({ "open_only": true }))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the writer's own human slip reaches the list: {body}"
    );
    assert_eq!(writer_handles(&body), vec![handle]);

    let (status, body) = served.on_own_slip(stranger, "human", LIST, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        writer_handles(&body).is_empty(),
        "a person who wrote no key lists none: {body}"
    );
}

#[test]
fn an_agent_slip_is_refused_at_the_list() {
    run_on_engine_stack("agent-list-refused", agent_slip_refused_at_the_list);
}

async fn agent_slip_refused_at_the_list() {
    let served = served(false);
    let writer = served.person();
    served.write_event(writer, TOKENS[0]);

    let (status, body) = served.on_own_slip(writer, "agent", LIST, json!({})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent's slip, even one naming the writer, is refused at the verb: {body}"
    );
    assert!(body.get("keys").is_none(), "and lists nothing: {body}");
}

#[test]
fn the_owner_lists_every_key_on_the_owner_card() {
    run_on_engine_stack("owner-list", owner_lists_every_key);
}

async fn owner_lists_every_key() {
    let served = served(false);
    let writer = served.person();
    let other = served.person();
    let mine = served.write_event(writer, TOKENS[0]);
    let theirs = served.write_event(other, TOKENS[1]);

    let page = list_found_keys_as(&served.vault, &served.owner, FoundKeyListRequest::default())
        .expect("the owner's list");
    assert_eq!(page.view, "owner");
    assert!(
        page.keys.is_empty(),
        "the owner reads notices, not writer cards"
    );
    let records: Vec<EntityId> = page.notices.iter().map(|notice| notice.record).collect();
    assert!(
        records.contains(&mine) && records.contains(&theirs),
        "the owner lists every writer's record: {records:?}"
    );
    let card = &page.notices[0].keys[0];
    assert!(
        !card.name.is_empty(),
        "the owner's card names the custody record the rotate door takes"
    );
    assert!(
        card.actions.iter().any(|action| action == "rotate"),
        "and offers the owner's own answers: {:?}",
        card.actions
    );
    assert_eq!(page.named_records().len(), 2, "the page names both records");
}
