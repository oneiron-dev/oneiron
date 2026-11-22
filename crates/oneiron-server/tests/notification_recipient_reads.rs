//! FIX RECIPIENT-NOTICE-READ-BY-ANY-READER (Engine TASK 21 Nov 06:27, the
//! non-owner half): a NOTIFICATION addressed to one person reads by id
//! (`vault.get`) only to that person and to the owner, whichever producer
//! wrote it. The inbox list already kept each caller to the notices
//! delivered to it; `vault.get` served another person's notice to any reader
//! of the band.
//!
//! Callers: the owner on the host root credential, and two live persons,
//! each on their own human slip (core read and write) minted on the host
//! issuer. The notices are Asks of an ordinary producer (`mail.reply`), one
//! addressed to the first person and one to no one. Red on main: the second
//! person reads the first person's Ask by id.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! notification_recipient_reads`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::inbox::{
    NotificationBody, NotificationKind, NotificationSource, encode_notification_body,
};
use oneiron::registry::{ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// An ordinary notice producer: a mailbox's reply Ask, which main addresses
/// to the mailbox's own person (`mail_pack/reply_ask.rs`).
const ASK_PRODUCER: &str = "mail.reply";

/// A live person's own credential: their PERSON, slip, holder key and token.
struct Holder {
    person: EntityId,
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// Who sends a request.
enum Caller<'a> {
    /// The owner on the host root credential.
    Owner,
    /// A person on their own slip.
    Holder(&'a Holder),
}

/// A self-hosted served vault with its owner's host root credential.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("notification-recipient-reads".into()),
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
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner's PERSON");
    Served {
        _dir: dir,
        vault,
        app: build_app(server),
        issuer,
        owner_slip,
        owner_token,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Served {
    /// A fresh live PERSON holding one ordinary human slip with core read
    /// and write, minted on the host issuer.
    fn person_with_slip(&self, slip_id: [u8; 32]) -> Holder {
        let person = EntityId::now();
        self.vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"a member",
            )
            .expect("a live PERSON");
        let key = SigningKey::from_bytes(&slip_id);
        let mut claims = self.owner_slip.claims.clone();
        claims.parent_id = None;
        claims.slip_id = slip_id;
        claims.holder_ref = person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the minted slip");
        let token = slip.to_token().expect("slip token");
        Holder {
            person,
            key,
            slip,
            token,
        }
    }

    /// Stores an Ask of [`ASK_PRODUCER`] addressed to `recipient`, or to no
    /// one, as a fresh NOTIFICATION row: its id.
    fn ask(&self, event: &str, recipient: Option<EntityId>) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let body = NotificationBody {
            kind: NotificationKind::Ask,
            source: NotificationSource {
                producer: ASK_PRODUCER.to_owned(),
                event: event.to_owned(),
                result: Some(EntityId::now().to_hex()),
                ..NotificationSource::default()
            },
            subject_refs: Vec::new(),
            recipient: recipient.map(|person| person.to_hex()),
            created_at: now,
            origin_conversation: None,
            seen_by: BTreeMap::new(),
            acked_by: BTreeMap::new(),
        };
        let bytes = encode_notification_body(&body).expect("the notice body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_NOTIFICATION,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &bytes,
            )
            .expect("the notice row");
        id
    }

    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: &Caller<'_>) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Holder(holder) => {
                let transcript = holder
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("holder binding transcript");
                hex(&holder.key.sign(&transcript).to_bytes())
            }
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// `caller` reads `id` through the facade's `vault.get`: the status and
    /// the body.
    async fn get(&self, caller: &Caller<'_>, id: EntityId) -> (StatusCode, Value) {
        let token = match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Holder(holder) => holder.token.as_str(),
        };
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/facade/vault.get")
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(json!({"entity_ref": id.to_hex()}).to_string()))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

/// A notice addressed to one person reads by id to that person and to the
/// owner, and to no other member; a notice addressed to no one reads to
/// every member as before. Red on main: the second member's `vault.get` of
/// the first member's Ask serves it.
#[test]
fn a_notice_addressed_to_a_person_reads_by_id_only_to_them_and_the_owner() {
    run_on_engine_stack("notification-recipient-reads", || async {
        let served = served();
        let recipient = served.person_with_slip([0x61; 32]);
        let other = served.person_with_slip([0x62; 32]);
        let addressed = served.ask("recipient-ask", Some(recipient.person));
        let unaddressed = served.ask("everyone-ask", None);

        let (status, body) = served.get(&Caller::Holder(&recipient), addressed).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["value"]["id_hex"],
            addressed.to_hex(),
            "setup: the recipient reads their own notice by id: {body}"
        );
        let (status, body) = served.get(&Caller::Holder(&other), unaddressed).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["value"]["id_hex"],
            unaddressed.to_hex(),
            "setup: a notice addressed to no one reads to every member: {body}"
        );

        let (status, body) = served.get(&Caller::Holder(&other), addressed).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["value"].is_null(),
            "another member reads nothing of a notice addressed to someone else: {body}"
        );

        let (status, body) = served.get(&Caller::Owner, addressed).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["value"]["id_hex"],
            addressed.to_hex(),
            "the owner still reads a member's notice by id (the owner half waits on the \
             source floor): {body}"
        );
    });
}
