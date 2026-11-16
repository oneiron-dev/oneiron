//! The person's own client signs their opt back in (row
//! PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF; ruling
//! PERSONKEY-PR2-STATEMENT-SOURCE = A).
//!
//! Over the in-process wire: `GET /v1/owner/conversation-learning/me`
//! names `vault_id` and the caller's own `slip`, and the client's
//! `set_own_conversation_training(false)` signs them with `leave_out` and
//! the revision as `seen` under that slip's binding key, so the opt back
//! in lands through a carrier that is not the owner's. The vault owner
//! proves with an owner key instead, so their reply names no slip.
//!
//! The vault is a hosted vault as a managed host serves it, rooted by the
//! server's own bootstrap (see `served_host`); the tests need the
//! test-support build: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --features oneiron/test-support --test
//! own_conversation_training_client`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{HeaderName, HeaderValue, Request};
use ed25519_dalek::SigningKey;
use oneiron::authority::{ActAuthority, ActSurface, HostSlipIssuer, MachineRole};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_remote::{
    InProcessReply, InProcessRequest, InProcessStream, InProcessTransport, OneironClient,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use tower::ServiceExt;

/// The member's slip key seed, as `person_choice_proof.rs` seeds it.
const MEMBER_SLIP_SEED: u8 = 69;
/// The owner's slip key seed: no other seed in this file.
const OWNER_SLIP_SEED: u8 = 0x6B;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let first = EntityId::now();
    let second = EntityId::now();
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(first.as_bytes());
    id[16..].copy_from_slice(second.as_bytes());
    id
}

/// The in-process wire: `build_app`'s router on its own multi-thread
/// runtime, because the routes run `spawn_blocking`. Each exchange builds
/// the HTTP request from the client's method, path, headers and body, and
/// answers the whole reply.
struct RouterTransport {
    app: axum::Router,
    runtime: tokio::runtime::Runtime,
}

impl RouterTransport {
    fn round_trip(&self, request: InProcessRequest) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
        let method: axum::http::Method = request.method.parse().expect("the client's method");
        let uri: axum::http::Uri = request.path.parse().expect("the client's path");
        let mut http = Request::builder()
            .method(method)
            .uri(uri)
            .body(axum::body::Body::from(request.body))
            .expect("the client's request");
        for (name, value) in &request.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value),
            ) {
                http.headers_mut().append(name, value);
            }
        }
        let response = self
            .runtime
            .block_on(self.app.clone().oneshot(http))
            .expect("the server's response");
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect();
        let body = self
            .runtime
            .block_on(to_bytes(response.into_body(), 64 * 1024 * 1024))
            .expect("the server's body")
            .to_vec();
        (status, headers, body)
    }
}

impl InProcessTransport for RouterTransport {
    fn exchange(
        &self,
        request: InProcessRequest,
    ) -> Result<InProcessReply, oneiron::memory::MemoryError> {
        let (status, headers, body) = self.round_trip(request);
        Ok(InProcessReply {
            status,
            headers,
            body,
        })
    }

    fn exchange_streamed(
        &self,
        request: InProcessRequest,
    ) -> Result<InProcessStream, oneiron::memory::MemoryError> {
        let (status, headers, body) = self.round_trip(request);
        Ok(InProcessStream {
            status,
            headers,
            body: Box::new(std::io::Cursor::new(body)),
        })
    }
}

/// One vault as a managed host serves it: the Hosted posture, rooted by the
/// server's own bootstrap, this install profiled `Unanswered`, the owner
/// letting people opt out with their owner key held on another install, and
/// a member with their own human slip. The transport and the vault drop
/// before their directory.
struct ServedHost {
    transport: Arc<RouterTransport>,
    vault: Arc<Vault>,
    member: EntityId,
    member_slip: [u8; 32],
    member_credential: String,
    owner_credential: String,
    _dir: tempfile::TempDir,
}

/// The member's own human slip, narrowed to read and write, and the
/// `v2.cred` credential bound to its key: the slip's id and the credential.
fn member_credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    member: EntityId,
) -> ([u8; 32], String) {
    let slip_key = SigningKey::from_bytes(&[MEMBER_SLIP_SEED; 32]);
    let root = vault.ensure_host_root_slip(issuer).expect("host root");
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.parent_id = None;
    claims.holder_ref = member.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = slip_key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("the member's own slip");
    let token = slip.to_token().expect("the member's token");
    let credential = format!(
        "v2.cred.{}.{}",
        token.strip_prefix("v2.slip.").expect("a v2 slip"),
        hex(slip_key.as_bytes())
    );
    (slip.claims.slip_id, credential)
}

/// The owner's own full human slip, unattenuated, for the owner door, and
/// the `v2.cred` credential bound to its key.
fn owner_credential(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> String {
    let owner_key = SigningKey::from_bytes(&[OWNER_SLIP_SEED; 32]);
    let root = vault.ensure_host_root_slip(issuer).expect("host root");
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = owner_key.verifying_key().to_bytes();
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("the owner's own slip");
    let token = slip.to_token().expect("the owner's token");
    format!(
        "v2.cred.{}.{}",
        token.strip_prefix("v2.slip.").expect("a v2 slip"),
        hex(owner_key.as_bytes())
    )
}

fn served_host() -> ServedHost {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("hosted vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    // The server roots the vault: on hosted, `SyncServer::new` bootstraps
    // the host issuer and refuses to serve without one, so the test issuer
    // that roots PR 1's unstopped vault cannot root this one. The server's
    // slip verifier trusts the fold's logged mint signer, so the slips below
    // are minted by the loaded bootstrap issuer, this vault's host.
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("own-conversation-training-client".to_owned()),
                ..Default::default()
            },
        )
        .expect("server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("bind the owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    vault
        .set_conversation_learning(&owner_proof, ActSurface::ThisInstall, true, true, None)
        .expect("the setting that lets people opt out lands");
    vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            &issuer,
        )
        .expect("the owner enrols this install's owner signing key");
    oneiron::test_doors::owner_key_release::release_owner_keys(&vault);

    let member = EntityId::now();
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )
        .expect("the member PERSON");
    let (member_slip, member_credential) = member_credential(&vault, &issuer, member);
    let owner_credential = owner_credential(&vault, &issuer, owner);

    let transport = Arc::new(RouterTransport {
        app: build_app(server),
        runtime: tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("the transport runtime"),
    });
    ServedHost {
        transport,
        vault,
        member,
        member_slip,
        member_credential,
        owner_credential,
        _dir: dir,
    }
}

impl ServedHost {
    /// A client bound to `credential` over this host's transport.
    fn connect(&self, credential: &str) -> OneironClient {
        OneironClient::connect_in_process(
            Arc::clone(&self.transport) as Arc<dyn InProcessTransport>,
            credential,
        )
        .expect("connect")
    }
}

/// Ruling PERSONKEY-PR2-STATEMENT-SOURCE = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: the member's client proves
/// their opt back in through a carrier that is not the owner's. The
/// opt-out lands, the opt back in lands on the client's own slip-key
/// proof, and the vault's own fold agrees the member is let back in.
#[test]
fn a_members_client_proves_their_opt_back_in_through_a_not_mine_carrier() {
    let host = served_host();
    let client = host.connect(&host.member_credential);
    let out = client
        .set_own_conversation_training(true)
        .expect("the opt-out lands");
    assert!(out.leave_out, "the member is left out");
    let back_in = client
        .set_own_conversation_training(false)
        .expect("the proven opt back in lands");
    assert!(!back_in.leave_out, "the member is let back in");
    let fold = host.vault.authority_fold().expect("authority fold");
    assert!(
        !oneiron::test_doors::conversation_training_fold::leaves_out(&fold, host.member),
        "the vault's own fold lets the member back in"
    );
}

/// Ruling PERSONKEY-PR2-STATEMENT-SOURCE = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: the member's reply names this
/// vault's id, their own slip and their person: the fields their client
/// signs an opt back in over.
#[test]
fn the_members_reply_names_the_vault_and_their_own_slip() {
    let host = served_host();
    let client = host.connect(&host.member_credential);
    let reply = client
        .own_conversation_training()
        .expect("the member's GET");
    let vault_id = host
        .vault
        .authority_vault_id()
        .expect("the vault id")
        .expect("the vault is rooted");
    assert_eq!(
        reply.vault_id,
        Some(hex(&vault_id)),
        "the reply names this vault's id"
    );
    assert_eq!(
        reply.slip,
        Some(hex(&host.member_slip)),
        "the reply names the member's own slip"
    );
    assert_eq!(
        reply.person,
        host.member.to_hex(),
        "the reply names the member"
    );
}

/// Ruling PERSONKEY-PR2-STATEMENT-SOURCE = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: the vault owner proves with an
/// owner key, never a slip key, so the owner's reply names no vault and no
/// slip. The owner reaches the owner door on their own full human slip: a
/// bare host secret acts as nobody on a hosted vault.
#[test]
fn the_owners_reply_names_no_slip() {
    let host = served_host();
    let client = host.connect(&host.owner_credential);
    let reply = client.own_conversation_training().expect("the owner's GET");
    assert_eq!(reply.vault_id, None, "the owner proves with no vault field");
    assert_eq!(reply.slip, None, "the owner proves with no slip");
}
