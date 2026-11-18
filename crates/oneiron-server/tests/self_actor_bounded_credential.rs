//! `self.actor` answers a bounded credential (leg A1, E2E HOOKS-03 cause 1).
//!
//! Every case drives the real facade route in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/self.actor` on a credential the owner minted. Each
//! case owns its vault. No sleeps, no models.
//!
//! - a bounded support slip (worlds/facets/audience named, records empty,
//!   verbs `read` + `write`) reaches `self.actor` and learns its own actor
//!   ref; red on main (403 `record-scope`), green after the lane fix;
//! - a credential with a channel caveat is still refused (403), on main and
//!   after the fix.
//!
//! Fixture modeled on `crates/oneiron-server/tests/vault_support_grants_doors.rs`
//! (support mint + facade `post` with a holder-signed binding); channel mint
//! modeled on `crates/oneiron-server/tests/cleanup_decide_served_credential.rs`
//! (direct `mint_capability_slip` with `claims.channels`).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! self_actor_bounded_credential`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
//!
//! Never compiled or run in this leg (lane rules forbid cargo); E2E HOOKS-03
//! (`tests/e2e/hooks.test.ts:497-540`) is the proof until the fleet runs this.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const MINT: &str = "vault.support_grants.mint";
const SELF_ACTOR: &str = "self.actor";

/// One credential a test holds: its slip, its holder key and its token.
struct Holder {
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential, the owner's own
/// PERSON, and a live support PERSON who owns nothing here.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: EntityId,
    support_person: EntityId,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The owner on the host root credential.
    Owner,
    /// The support party on a minted grant (or, for the channel case, on a
    /// directly minted channel-bound slip with the same holder).
    Support(&'a Holder),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// A self-hosted served vault on the wall clock.
async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("self-actor-bounded-credential".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let owner_person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner's PERSON");
    let support_person = EntityId::now();
    vault
        .put_entity(
            &support_person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"our support person",
        )
        .expect("a live support PERSON");
    let app = build_app(server);
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner_person,
        support_person,
    }
}

/// The HOOKS-03 ceiling: one named world, facet and audience, every band,
/// the top sensitivity, records empty, and the classes `verbs` (the support
/// mint adds `read`).
fn bounded_scope(world: ScopeId, facet: ScopeId, project: ScopeId, verbs: &[&str]) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([world]));
    scope.facets = ScopeAxis::Some(BTreeSet::from([facet]));
    scope.audience = ScopeAxis::Some(BTreeSet::from([project]));
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    scope
}

impl Served {
    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller<'_>) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let held = |holder: &Holder| {
            let transcript = holder
                .slip
                .binding_transcript(challenge.as_bytes())
                .expect("holder binding transcript");
            hex(&holder.key.sign(&transcript).to_bytes())
        };
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Support(holder) => held(holder),
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn token<'a>(&'a self, caller: Caller<'a>) -> &'a str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Support(holder) => holder.token.as_str(),
        }
    }

    /// `caller` posts `verb` with `input` to its facade door: the status and
    /// the body.
    async fn post(&self, caller: Caller<'_>, verb: &str, input: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("facade response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The mint input for the support PERSON, its key `key`, bounds
    /// `scope` and lifetime `ttl_secs`. Records omitted: empty, every
    /// record inside `scope` (`crates/oneiron-verb-wire/src/verbs/support_grant.rs`).
    fn mint_input(&self, key: &SigningKey, scope: &Scope, ttl_secs: u64) -> Value {
        json!({
            "holder": self.support_person.to_hex(),
            "holder_class": "human",
            "holder_key": hex(&key.verifying_key().to_bytes()),
            "scope": serde_json::to_value(scope).expect("scope JSON"),
            "ttl_secs": ttl_secs,
            "purpose": "HOOKS-03: learn our own actor ref under a bounded grant",
            "ticket_ref": "SELF-ACTOR-BOUNDED",
        })
    }

    /// The owner mints a grant to the support party's key from `seed`:
    /// asserts the 200 and answers the support credential and the answer.
    async fn mint(&self, seed: u8, scope: &Scope, ttl_secs: u64) -> (Holder, Value) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let (status, minted) = self
            .post(Caller::Owner, MINT, self.mint_input(&key, scope, ttl_secs))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner mints a grant: {minted}");
        let token = minted["slip"]
            .as_str()
            .expect("the mint answers the support credential")
            .to_owned();
        let slip = CapabilitySlip::from_token(&token).expect("the support slip");
        (Holder { key, slip, token }, minted)
    }

    /// A directly minted credential for the support PERSON with the narrowed
    /// `scope` and one channel caveat. Support grants never carry channels
    /// (`support_scope_admissible`), so the channel case mints directly, as
    /// `cleanup_decide_served_credential.rs` does.
    fn channel_holder(&self, key_seed: u8, slip_seed: u8, scope: &Scope) -> Holder {
        let key = SigningKey::from_bytes(&[key_seed; 32]);
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("host root claims")
            .claims;
        claims.slip_id = [slip_seed; 32];
        claims.parent_id = None;
        claims.holder_ref = self.support_person.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = key.verifying_key().to_bytes();
        claims.scope = scope.clone();
        claims.records = BTreeSet::new();
        claims.channels = BTreeSet::from(["self-actor-channel-test".to_owned()]);
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a channel-bound slip");
        let token = slip.to_token().expect("a channel-bound token");
        Holder { key, slip, token }
    }
}

/// A bounded support slip reaches `self.actor`: 200 with its own actor ref.
/// Red on main: the row's `unrestricted_record_scope` guard
/// (`crates/oneiron-server/src/auth/slips.rs:require_unrestricted_record_scope`)
/// refuses the named worlds/facets/audience with 403 `record-scope`; green
/// after the `lane_record_scope` fix, which refuses only a channel caveat.
#[test]
fn a_bounded_support_slip_reaches_self_actor() {
    run_on_engine_stack("self-actor-bounded", || async {
        let served = served().await;
        let scope = bounded_scope(
            ScopeId(EntityId::now()),
            ScopeId(EntityId::now()),
            ScopeId(EntityId::now()),
            &["write"],
        );
        let (support, minted) = served.mint(0xA1, &scope, 3600).await;

        assert!(
            support.token.starts_with("v2.slip."),
            "the support credential is a slip: {minted}"
        );
        assert_ne!(
            served.owner_person.to_hex(),
            served.support_person.to_hex(),
            "support owns nothing here"
        );
        assert_eq!(
            support.slip.claims.holder_ref,
            served.support_person.to_hex(),
            "the slip's holder is the support PERSON"
        );
        assert!(
            support.slip.claims.records.is_empty(),
            "records empty, as HOOKS-03 mints: {:?}",
            support.slip.claims.records
        );
        assert!(
            support.slip.claims.channels.is_empty(),
            "no channel caveat on the support slip"
        );
        let verbs = match &support.slip.claims.scope.verbs {
            ScopeAxis::Some(verbs) => verbs.clone(),
            _ => BTreeSet::new(),
        };
        assert!(
            verbs.contains("read") && verbs.contains("write"),
            "the mint adds read to the requested write, as HOOKS-03 expects: {verbs:?}"
        );

        let (status, actor) = served
            .post(Caller::Support(&support), SELF_ACTOR, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a bounded support slip reaches self.actor: {actor}"
        );
        assert_eq!(
            actor["actor_ref"],
            served.support_person.to_hex(),
            "its own actor ref: {actor}"
        );
        assert_eq!(actor["actor_class"], "human", "{actor}");
        assert_eq!(
            actor["person_ref"],
            served.support_person.to_hex(),
            "a human acts for itself: {actor}"
        );
    });
}

/// A channel caveat is still refused at `self.actor`, even under the same
/// narrowed ceiling. Green on main too (`unrestricted` also refuses
/// channels): it pins the lane's one refusal, not the fix.
#[test]
fn a_channel_caveat_is_still_refused_at_self_actor() {
    run_on_engine_stack("self-actor-channel", || async {
        let served = served().await;
        // A direct mint adds no class; name both, as the support mint answers.
        let scope = bounded_scope(
            ScopeId(EntityId::now()),
            ScopeId(EntityId::now()),
            ScopeId(EntityId::now()),
            &["read", "write"],
        );
        let bound = served.channel_holder(0xC2, 0xC1, &scope);
        assert!(
            !bound.slip.claims.channels.is_empty(),
            "the fixture carries a channel caveat"
        );

        let (status, body) = served
            .post(Caller::Support(&bound), SELF_ACTOR, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a channel-bound credential is refused: {body}"
        );
        assert_eq!(
            error_code(&body),
            Some("FORBIDDEN"),
            "a channel-bound credential is refused: {body}"
        );
    });
}
