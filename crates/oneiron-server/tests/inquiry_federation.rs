//! INQUIRE-1 PR 5 (federation.md #inquiry; Engine ruling INQUIRE-SHAPE Q2,
//! Q4, Q7 = A): the inquiry verbs and the member host's inquiry route, over
//! real HTTP between two hosts.
//!
//! Two served vaults on loopback: the member's, whose router listens on a
//! TCP port, and the company's, whose router the test calls in process.
//! - the member mints an inquiry edge (`vault.inquiry.edge.mint`) and the
//!   company Owner its reciprocal grant
//!   (`vault.inquiry.reciprocal_grant.mint`); the Connect pact over them
//!   goes Active through the existing owner routes; the member's vault
//!   mints the company host's slip on the edge, and the company Owner opens
//!   the route with it (`vault.inquiry.route.open`);
//! - a paired company agent sends an inquiry for its open TASK
//!   (`vault.inquire`): the company host POSTs it to the member host's
//!   `/v1/federation/inquiry` under that slip with its own signature, and
//!   the member's vault answers `pending` (the production judgment is
//!   unsure, so the member is asked);
//! - the member reads it in "Asked about you" (`vault.inquiry.list`) and
//!   answers (`vault.inquiry.answer`); the agent's re-send of the same id
//!   then answers with the member's word, which the company holds with
//!   the task, and the word is filed in the edge's opened scope
//!   (`vault.inquiry.scope.list`);
//! - once the member revokes the edge (`vault.inquiry.edge.revoke`), a new
//!   inquiry answers `unavailable`;
//! - the member route refuses a call with no slip, the owner's own root
//!   slip (no edge grant), and a body that is no inquiry, and logs none;
//! - the member route refuses the edge's slip once its holder narrowed it
//!   (no world, or one record), even for an inquiry the member answered,
//!   and the slip as minted still gets the member's word (review round 1
//!   of #7603);
//! - the company host reads a member host's answer only up to its cap: an
//!   answer that runs past it is refused at the cap, not read to its end
//!   (review round 1 of #7603);
//! - a `vault.inquire` call's answer is not kept for its invocation: the
//!   same invocation, sent again once the task ended, runs again and is
//!   refused, and never gets the held answer back (review round 2 of
//!   #7603);
//! - the member opens, lists and closes a statement on an edge
//!   (`vault.inquiry.scope.open` / `.list` / `.close`).
//!
//! Red on main: none of the ten verbs and no inquiry route exists, so the
//! facade answers 404 at the first call. Fleet command:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! inquiry_federation`.
#![cfg(all(unix, oneiron_test_support))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat,
    pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, Scope, ScopeAxis};
use oneiron::inquiry::{
    Inquiry, InquiryAsker, InquiryKeep, InquiryTask, InquiryTransport, InquiryTransportError,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::inquiry_delivery::HttpInquiryTransport;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The company's shared vault the member holds a seat in.
const SHARED: u64 = 42;
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const QUESTION: &str = "Is owen in the office on Thursday?";
const PURPOSE: &str = "find a time for the review";
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";
/// A company vault no fixture opens: an edge needs no live peer to mint.
const UNOPENED_COMPANY: AuthorityVaultId = [0xbd; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One served, rooted vault: its router, its host's slip issuer and root
/// slip, its owner bound under that root, and the owner's engine proof.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root_slip: CapabilitySlip,
    root_token: String,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

impl Host {
    fn open(name: &str) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault =
            Arc::new(Vault::open(&dir.path().join(name), VaultConfig::device()).expect("vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(format!("inquiry-federation-{name}")),
                    ..Default::default()
                },
            )
            .expect("server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let root_slip = vault.ensure_host_root_slip(&issuer).expect("host root");
        let root_token = root_slip.to_token().expect("root slip token");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let vault_id = vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("a rooted vault has an id");
        Self {
            _dir: dir,
            vault,
            app: build_app(server),
            issuer,
            root_slip,
            root_token,
            owner,
            proof,
            vault_id,
        }
    }

    /// The owner's holder proof for one call under the host root slip.
    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = hex(&self
            .issuer
            .binding_proof(&self.root_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    async fn raw(
        &self,
        path: &str,
        token: Option<&str>,
        binding: Option<String>,
        body: Vec<u8>,
    ) -> (StatusCode, Vec<u8>) {
        self.raw_with(path, token, binding, None, body).await
    }

    /// [`Self::raw`] naming the client's `invocation` id, when given.
    async fn raw_with(
        &self,
        path: &str,
        token: Option<&str>,
        binding: Option<String>,
        invocation: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, Vec<u8>) {
        let mut request = Request::post(path).header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(binding) = binding {
            request = request.header("x-oneiron-binding", binding);
        }
        if let Some(invocation) = invocation {
            request = request.header("x-oneiron-invocation", invocation);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        (status, bytes.to_vec())
    }

    /// One call as the vault's owner.
    async fn owner_call(&self, path: &str, input: Value) -> (StatusCode, Value) {
        let (status, bytes) = self
            .raw(
                path,
                Some(&self.root_token),
                Some(self.owner_binding()),
                input.to_string().into_bytes(),
            )
            .await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn owner_ok(&self, path: &str, input: Value) -> Value {
        let (status, body) = self.owner_call(path, input).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }

    async fn verb(&self, verb: &str, input: Value) -> Value {
        self.owner_ok(&format!("/v1/core/facade/{verb}"), input)
            .await
    }
}

/// One paired agent credential on a host.
struct Agent {
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

impl Agent {
    /// Pairs one agent the way `token agent` does: a registered named
    /// PERSON principal, a principal-bound link at `core:read` and
    /// `core:write`, redeemed over the real pairing route.
    async fn pair(host: &Host, name: &str, seed: [u8; 32]) -> Self {
        let principal = host
            .vault
            .ensure_agent_principal(name)
            .expect("agent principal");
        let holder = SigningKey::from_bytes(&seed);
        let binding_key = holder.verifying_key().to_bytes();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let link = host
            .vault
            .issue_pairing_link_for_principal(
                &host.issuer,
                scope,
                3600,
                PairingPrincipal {
                    holder_ref: Some(principal.to_hex()),
                    actor_class: Some("agent".to_owned()),
                    org_ref: None,
                    write_facet: None,
                    ..Default::default()
                },
            )
            .expect("pairing link");
        let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
            .expect("pairing transcript");
        let redeem = json!({
            "code": link.code,
            "holder_ref": principal.to_hex(),
            "binding_key": hex(&binding_key),
            "signature": hex(&holder.sign(&transcript).to_bytes()),
        });
        let (status, bytes) = host
            .raw(
                "/v1/core/pairing/redeem",
                None,
                None,
                redeem.to_string().into_bytes(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "pairing redeem");
        let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
        let token = body["token"].as_str().expect("paired token").to_owned();
        let slip = CapabilitySlip::from_token(&token).expect("paired slip");
        Self {
            holder,
            slip,
            token,
        }
    }

    async fn verb(&self, host: &Host, verb: &str, input: Value) -> (StatusCode, Value) {
        self.call(host, verb, None, input).await
    }

    /// One call of `verb` with a fresh holder proof, naming `invocation`
    /// when given.
    async fn call(
        &self,
        host: &Host,
        verb: &str,
        invocation: Option<&str>,
        input: Value,
    ) -> (StatusCode, Value) {
        let timestamp = host.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = self
            .slip
            .binding_transcript(challenge.as_bytes())
            .expect("agent binding transcript");
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&self.holder.sign(&transcript).to_bytes()),
        })
        .to_string();
        let (status, bytes) = host
            .raw_with(
                &format!("/v1/core/facade/{verb}"),
                Some(&self.token),
                Some(binding),
                invocation,
                input.to_string().into_bytes(),
            )
            .await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

/// The member's host, listening on loopback, and the company's, with the
/// member's seat, the edge Active over its Connect pact, the route the
/// company Owner opened, a paired company agent and its open TASK.
struct Thursday {
    member: Host,
    company: Host,
    member_listener: tokio::task::JoinHandle<()>,
    edge_grant: String,
    /// The slip the member's vault minted for the company host on the edge.
    edge_slip: String,
    seat: EntityId,
    agent: Agent,
    task: EntityId,
}

async fn thursday() -> Thursday {
    let member = Host::open("member");
    let company = Host::open("company");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("member host listener");
    let member_host = format!("http://{}", listener.local_addr().expect("member address"));
    let member_app = member.app.clone();
    let member_listener = tokio::spawn(async move {
        axum::serve(listener, member_app)
            .await
            .expect("member host serves");
    });

    let edge = member
        .verb(
            "vault.inquiry.edge.mint",
            json!({"company_vault": hex(&company.vault_id), "company_name": COMPANY}),
        )
        .await;
    assert_eq!(edge["check_in_mode"], "auto", "{edge}");
    assert_eq!(edge["keep_allowed"], "task", "{edge}");
    let edge_grant = edge["grant"].as_str().expect("edge grant").to_owned();
    let reciprocal = company
        .verb(
            "vault.inquiry.reciprocal_grant.mint",
            json!({"member_vault": hex(&member.vault_id), "member_name": MEMBER}),
        )
        .await;
    let reciprocal_grant = reciprocal["grant"].as_str().expect("reciprocal grant");

    let offer = member
        .owner_ok(
            "/v1/owner/federation/connect/offer",
            json!({
                "peer_vault": hex(&company.vault_id), "grant": edge_grant,
                "outbound": edge["pact_direction"], "inbound": reciprocal["pact_direction"],
            }),
        )
        .await;
    let accepted = company
        .owner_ok(
            "/v1/owner/federation/connect/accept",
            json!({"grant": reciprocal_grant, "offer": offer}),
        )
        .await;
    let joined = member
        .owner_ok(
            "/v1/owner/federation/connect/accept",
            json!({"grant": edge_grant, "offer": accepted["counter"]}),
        )
        .await;
    assert_eq!(joined["status"], "Active", "{joined}");

    let slip = member
        .verb(
            "vault.guests.mint_slip",
            json!({
                "grant_ref": edge_grant,
                "holder_key": hex(&company.issuer.binding_key()),
                "expires_at": member.vault.now_recorded_at() + 3_600,
            }),
        )
        .await;

    company
        .vault
        .initialize_shared_vault(
            &company.proof,
            SHARED,
            None,
            &[],
            company.vault.now_recorded_at(),
        )
        .expect("the company's shared vault");
    let seat = person(&company.vault, EntityId::now());
    stand_member_grant(&company.vault, seat, SHARED, FederationGrantRole::Member)
        .expect("the member's seat");
    let route = company
        .verb(
            "vault.inquiry.route.open",
            json!({
                "shared_vault_id": SHARED,
                "member": seat,
                "member_vault": hex(&member.vault_id),
                "member_host": member_host,
                "slip": slip["slip"],
            }),
        )
        .await;
    assert_eq!(route["edge_grant"], edge_grant, "{route}");
    assert!(
        route.get("slip").is_none(),
        "the route's answer carries no slip: {route}"
    );

    let agent = Agent::pair(&company, "scheduling-agent", [0x51; 32]).await;
    // The company's owner opens the TASK: on a rooted vault only a bound
    // writer creates one, and the inquiry asks only that it is an open TASK
    // of this vault.
    let task = company
        .vault
        .memory(company.owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("plan the Thursday review"),
            None,
            Some(company.owner),
            None,
        ))
        .expect("the TASK")
        .task_ref
        .expect("the TASK is minted");
    let edge_slip = slip["slip"].as_str().expect("edge slip").to_owned();
    Thursday {
        member,
        company,
        member_listener,
        edge_grant,
        edge_slip,
        seat,
        agent,
        task,
    }
}

fn person(vault: &Vault, id: EntityId) -> EntityId {
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person of the company",
        )
        .expect("person");
    id
}

impl Thursday {
    async fn inquire(&self, inquiry_id: Option<&Value>) -> Value {
        let input = self.inquiry_input(inquiry_id);
        let (status, body) = self.agent.verb(&self.company, "vault.inquire", input).await;
        assert_eq!(status, StatusCode::OK, "vault.inquire: {body}");
        body
    }

    /// The agent's `vault.inquire` input for its TASK, re-sending
    /// `inquiry_id` when given.
    fn inquiry_input(&self, inquiry_id: Option<&Value>) -> Value {
        let mut input = json!({
            "shared_vault_id": SHARED,
            "member": self.seat,
            "question": QUESTION,
            "task": self.task,
            "purpose": PURPOSE,
            "expires_at": self.company.vault.now_recorded_at() + 600,
        });
        if let Some(id) = inquiry_id {
            input["inquiry_id"] = id.clone();
        }
        input
    }
}

#[test]
fn an_inquiry_over_the_member_route_reaches_the_member_and_the_members_word_answers_it() {
    run_on_engine_stack("inquiry-federation-thursday", || async {
        let fixture = thursday().await;

        let sent = fixture.inquire(None).await;
        assert_eq!(sent["outcome"], "pending", "the member is asked: {sent}");
        assert_eq!(sent["statements"], json!([]), "{sent}");
        assert_eq!(sent["held"], false, "{sent}");
        let inquiry_id = sent["inquiry_id"].clone();

        let log = fixture.member.verb("vault.inquiry.list", json!({})).await;
        let entries = log["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 1, "{log}");
        let entry = &entries[0];
        assert_eq!(entry["inquiry_id"], inquiry_id, "{entry}");
        assert_eq!(entry["edge"], fixture.edge_grant.as_str(), "{entry}");
        assert_eq!(entry["question"], QUESTION, "{entry}");
        assert_eq!(entry["purpose"], PURPOSE, "{entry}");
        assert_eq!(entry["asker_role"], "agent", "{entry}");
        assert_eq!(
            entry["asking_vault"],
            hex(&fixture.company.vault_id),
            "{entry}"
        );
        assert_eq!(entry["answer"]["outcome"], "pending", "{entry}");

        let answered = fixture
            .member
            .verb(
                "vault.inquiry.answer",
                json!({"grant": fixture.edge_grant, "inquiry_id": inquiry_id, "words": OUT_THURSDAY}),
            )
            .await;
        assert_eq!(answered["outcome"], "answered", "{answered}");

        let resent = fixture.inquire(Some(&inquiry_id)).await;
        assert_eq!(resent["inquiry_id"], inquiry_id, "{resent}");
        assert_eq!(resent["outcome"], "answered", "{resent}");
        assert_eq!(
            resent["statements"],
            json!([{"text": OUT_THURSDAY, "source": "member_word"}]),
            "{resent}"
        );
        assert_eq!(
            resent["held"], true,
            "the company holds it with the task: {resent}"
        );

        let scope = fixture
            .member
            .verb(
                "vault.inquiry.scope.list",
                json!({"grant": fixture.edge_grant}),
            )
            .await;
        let statements: Vec<&str> = scope["items"]
            .as_array()
            .expect("items")
            .iter()
            .filter_map(|item| item["statement"].as_str())
            .collect();
        assert_eq!(statements, [OUT_THURSDAY], "filed for next time: {scope}");

        let revoked = fixture
            .member
            .verb(
                "vault.inquiry.edge.revoke",
                json!({"grant": fixture.edge_grant}),
            )
            .await;
        assert_eq!(
            revoked["grant_ref"],
            fixture.edge_grant.as_str(),
            "{revoked}"
        );
        let after = fixture.inquire(None).await;
        assert_eq!(after["outcome"], "unavailable", "the edge is gone: {after}");
        let log = fixture.member.verb("vault.inquiry.list", json!({})).await;
        assert!(
            log["entries"]
                .as_array()
                .expect("entries")
                .iter()
                .all(|entry| entry["inquiry_id"] != after["inquiry_id"]),
            "a refused inquiry is not logged: {log}"
        );
        fixture.member_listener.abort();
    });
}

#[test]
fn the_member_route_admits_only_the_edges_slip_with_its_hosts_proof() {
    run_on_engine_stack("inquiry-federation-route", || async {
        let fixture = thursday().await;
        let path = oneiron::inquiry::INQUIRY_PEER_PATH;
        let not_an_inquiry = json!({"not": "an inquiry"}).to_string().into_bytes();
        let edge_slip = CapabilitySlip::from_token(&fixture.edge_slip).expect("edge slip");

        let (status, _) = fixture
            .member
            .raw(path, None, None, not_an_inquiry.clone())
            .await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "no slip: {status}"
        );
        let (status, _) = fixture
            .member
            .raw(
                path,
                Some(&fixture.member.root_token),
                Some(fixture.member.owner_binding()),
                not_an_inquiry.clone(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the owner's root slip names no edge"
        );
        let (status, _) = fixture
            .member
            .raw(
                path,
                Some(&fixture.edge_slip),
                Some(binding(&fixture.member, &fixture.member.issuer, &edge_slip)),
                not_an_inquiry.clone(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the edge's slip signed by a key it is not bound to"
        );
        let (status, _) = fixture
            .member
            .raw(
                path,
                Some(&fixture.edge_slip),
                Some(binding(
                    &fixture.member,
                    &fixture.company.issuer,
                    &edge_slip,
                )),
                not_an_inquiry,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the edge's credential, but no inquiry"
        );

        let log = fixture.member.verb("vault.inquiry.list", json!({})).await;
        assert_eq!(log["entries"], json!([]), "nothing is logged: {log}");
        fixture.member_listener.abort();
    });
}

/// A holder proof for one call to `host` under `slip`, signed by `signer`.
fn binding(host: &Host, signer: &HostSlipIssuer, slip: &CapabilitySlip) -> String {
    let timestamp = host.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = hex(&signer
        .binding_proof(slip, challenge.as_bytes())
        .expect("holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

impl Thursday {
    /// One inquiry from the company's agent for its TASK, as the company
    /// host puts it on the wire.
    fn wire_inquiry(&self) -> Inquiry {
        Inquiry {
            id: EntityId::now(),
            from: InquiryAsker {
                vault: hex(&self.company.vault_id),
                actor: EntityId::now(),
                role: "agent".to_owned(),
            },
            task: InquiryTask {
                id: self.task,
                purpose: PURPOSE.to_owned(),
            },
            question: QUESTION.to_owned(),
            keep: InquiryKeep::Task,
            expires_at: self.member.vault.now_recorded_at() + 600,
        }
    }

    /// The edge's slip as the company host narrows it with `caveat`, under
    /// its own key: verification accepts it.
    fn narrowed_edge_slip(&self, caveat: SlipCaveat) -> CapabilitySlip {
        let mut slip = CapabilitySlip::from_token(&self.edge_slip).expect("edge slip");
        self.company
            .issuer
            .attenuate(&mut slip, caveat)
            .expect("the company host narrows its own slip");
        slip
    }

    /// One POST of `wire` to the member route under `slip`, with the
    /// company host's holder proof.
    async fn post_inquiry(&self, slip: &CapabilitySlip, wire: &[u8]) -> (StatusCode, Value) {
        let token = slip.to_token().expect("slip token");
        let (status, bytes) = self
            .member
            .raw(
                oneiron::inquiry::INQUIRY_PEER_PATH,
                Some(&token),
                Some(binding(&self.member, &self.company.issuer, slip)),
                wire.to_vec(),
            )
            .await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

#[test]
fn the_member_route_refuses_the_edges_slip_narrowed_by_its_holder() {
    run_on_engine_stack("inquiry-federation-narrowed", || async {
        let fixture = thursday().await;
        let minted = CapabilitySlip::from_token(&fixture.edge_slip).expect("edge slip");
        let inquiry = fixture.wire_inquiry();
        let wire = inquiry.encode_wire().expect("inquiry wire");

        let (status, sent) = fixture.post_inquiry(&minted, &wire).await;
        assert_eq!(status, StatusCode::OK, "the slip as minted: {sent}");
        assert_eq!(sent["outcome"], "pending", "the member is asked: {sent}");
        let answered = fixture
            .member
            .verb(
                "vault.inquiry.answer",
                json!({"grant": fixture.edge_grant, "inquiry_id": inquiry.id.to_hex(), "words": OUT_THURSDAY}),
            )
            .await;
        assert_eq!(answered["outcome"], "answered", "{answered}");

        let mut no_world = Scope::top();
        no_world.worlds = ScopeAxis::Bottom;
        let narrowed = [
            (
                "no world, the verb kept",
                fixture.narrowed_edge_slip(SlipCaveat {
                    scope: Some(no_world),
                    ..Default::default()
                }),
            ),
            (
                "one record",
                fixture.narrowed_edge_slip(SlipCaveat {
                    records: Some(BTreeSet::from([inquiry.id.to_hex()])),
                    ..Default::default()
                }),
            ),
        ];
        for (narrowing, slip) in &narrowed {
            let (status, body) = fixture.post_inquiry(slip, &wire).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "the answered inquiry under a slip narrowed to {narrowing}: {body}"
            );
            let fresh = fixture.wire_inquiry().encode_wire().expect("inquiry wire");
            let (status, body) = fixture.post_inquiry(slip, &fresh).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a new inquiry under a slip narrowed to {narrowing}: {body}"
            );
        }
        let log = fixture.member.verb("vault.inquiry.list", json!({})).await;
        assert_eq!(
            log["entries"].as_array().map(Vec::len),
            Some(1),
            "only the inquiry sent under the slip as minted is logged: {log}"
        );

        let (status, resent) = fixture.post_inquiry(&minted, &wire).await;
        assert_eq!(status, StatusCode::OK, "the slip as minted: {resent}");
        assert_eq!(resent["outcome"], "answered", "{resent}");
        assert_eq!(
            resent["statements"],
            json!([{"text": OUT_THURSDAY, "source": "member_word"}]),
            "{resent}"
        );
        fixture.member_listener.abort();
    });
}

/// A member host that answers 200 with more than the company host reads
/// and never ends its answer: 1 MiB with no length, then the connection
/// held open until the company host drops it.
fn endless_answer_host() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("answer host listener");
    let origin = format!(
        "http://{}",
        listener.local_addr().expect("answer host address")
    );
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = vec![0_u8; 64 * 1024];
        let _ = stream.read(&mut request);
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n")
            .is_err()
        {
            return;
        }
        let chunk = vec![b' '; 16 * 1024];
        for _ in 0..64 {
            if stream.write_all(&chunk).is_err() {
                return;
            }
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(90)));
        let _ = stream.read(&mut request);
    });
    origin
}

#[test]
fn the_company_host_reads_no_answer_past_its_cap() {
    run_on_engine_stack("inquiry-federation-answer-cap", || async {
        let company = Host::open("company");
        let member_host = endless_answer_host();
        let wire = json!({"an": "inquiry"}).to_string().into_bytes();
        let transport = HttpInquiryTransport::new(&company.issuer);
        let exchanged = std::thread::scope(|scope| {
            scope
                .spawn(|| transport.exchange(&member_host, &[0xcd; 32], &company.root_token, &wire))
                .join()
                .expect("the exchange thread")
        });
        assert!(
            matches!(&exchanged, Err(InquiryTransportError::Refused(why)) if why.contains("too large")),
            "an answer past the cap is refused at the cap: {exchanged:?}"
        );
    });
}

#[test]
fn a_held_answer_is_not_sent_again_for_its_invocation_once_its_task_ended() {
    run_on_engine_stack("inquiry-federation-invocation", || async {
        let fixture = thursday().await;
        let sent = fixture.inquire(None).await;
        let inquiry_id = sent["inquiry_id"].clone();
        let answered = fixture
            .member
            .verb(
                "vault.inquiry.answer",
                json!({"grant": fixture.edge_grant, "inquiry_id": inquiry_id, "words": OUT_THURSDAY}),
            )
            .await;
        assert_eq!(answered["outcome"], "answered", "{answered}");

        // One invocation, one input: the second request is the same call.
        let invocation = EntityId::now().to_hex();
        let input = fixture.inquiry_input(Some(&inquiry_id));
        let (status, held) = fixture
            .agent
            .call(
                &fixture.company,
                "vault.inquire",
                Some(&invocation),
                input.clone(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "vault.inquire: {held}");
        assert_eq!(
            held["statements"],
            json!([{"text": OUT_THURSDAY, "source": "member_word"}]),
            "{held}"
        );
        assert_eq!(held["held"], true, "held with the task: {held}");

        oneiron::test_doors::inquiry::cancel_task(
            &fixture.company.vault,
            fixture.task,
            fixture.company.owner,
        )
        .expect("the task ends");

        let (status, again) = fixture
            .agent
            .call(&fixture.company, "vault.inquire", Some(&invocation), input)
            .await;
        assert!(
            !again.to_string().contains(OUT_THURSDAY),
            "the ended task's answer is not sent again for its invocation: {status} {again}"
        );
        assert_ne!(
            status,
            StatusCode::OK,
            "the call runs again and finds its task ended: {again}"
        );
        fixture.member_listener.abort();
    });
}

#[test]
fn the_member_opens_lists_and_closes_a_statement_on_an_edge() {
    run_on_engine_stack("inquiry-federation-scope", || async {
        let member = Host::open("member");
        let edge = member
            .verb(
                "vault.inquiry.edge.mint",
                json!({
                    "company_vault": hex(&UNOPENED_COMPANY),
                    "company_name": COMPANY,
                    "check_in_mode": "manual",
                }),
            )
            .await;
        assert_eq!(edge["check_in_mode"], "manual", "{edge}");
        let grant = edge["grant"].clone();

        let empty = member
            .verb("vault.inquiry.scope.list", json!({"grant": grant}))
            .await;
        assert_eq!(empty["items"], json!([]), "the scope starts empty: {empty}");

        let opened = member
            .verb(
                "vault.inquiry.scope.open",
                json!({"grant": grant, "statement": OUT_THURSDAY}),
            )
            .await;
        assert_eq!(opened["statement"], OUT_THURSDAY, "{opened}");
        let listed = member
            .verb("vault.inquiry.scope.list", json!({"grant": grant}))
            .await;
        assert_eq!(listed["items"], json!([opened.clone()]), "{listed}");

        let closed = member
            .verb(
                "vault.inquiry.scope.close",
                json!({"grant": grant, "claim": opened["claim"]}),
            )
            .await;
        assert_eq!(closed["claim"], opened["claim"], "{closed}");
        let after = member
            .verb("vault.inquiry.scope.list", json!({"grant": grant}))
            .await;
        assert_eq!(after["items"], json!([]), "{after}");

        let (status, refusal) = member
            .owner_call(
                "/v1/core/facade/vault.inquiry.edge.mint",
                json!({"company_vault": "not-hex", "company_name": COMPANY}),
            )
            .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a bad company vault is refused: {refusal}"
        );
    });
}
