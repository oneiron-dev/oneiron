//! Promise tests for the `vault.disclosure.*` doors, entered at
//! `POST /v1/core/facade/<verb>`. Canon: ONE-1592
//! (oneiron/gate/one-1592-ildf2-consent-channel.md) and DEC-0006
//! (oneiron/decisions/oneiron-dec-0006-unified-consent-mode.md).
//!
//! - ONE-1592 consent channel :81 "An offer is not an authorization. The
//!   confirm still lands on the authenticated surface.": an agent's
//!   `vault.disclosure.offer` files a frozen offer and clears nothing; neither
//!   the agent nor another person settles it.
//! - ONE-1592 consent channel :8 "Granting clearance to a *new* party is
//!   *the* widening op, and it costs the owner exactly one authenticated
//!   confirm": the owner's one standing confirm writes the offered clearance,
//!   and the settled offer takes no second answer.
//! - DEC-0006 :112 "The agent never raises its own ceiling.": every owner door
//!   of the family (ceilings, home clearances, reveal asks and answers)
//!   refuses an agent and a person who is not the owner, and their attempt
//!   changes no dial.
//! - DEC-0006 :102 "A record above the connection's ceiling reaches the model
//!   as its bare handle": the owner's ceiling on a model connection turns a
//!   classed value in that connection's context pack into its handle, and
//!   the owner's clear brings the value back.
//! - DEC-0006 :112 "`reveal` hydrates inside a grant, or it asks; the guard
//!   offers and never grants": an agent's secret reveal waits on the owner,
//!   the owner's answer must name the ask's digest, and an answered ask
//!   takes no second answer. No listing carries the value.
//!
//! Where the offer is settled: `POST /v1/owner/disclosure/confirm` is the
//! owner's authenticated surface (`owner_routes/disclosure_routes.rs`), not a
//! facade row; the tests enter it as the owner's half of the offer promise.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::disclosure::DisclosureScopeStatus;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The owner's frozen view of one offer (`disclosure_routes.rs` `offer`).
const OWNER_OFFER: &str = "/v1/owner/disclosure/offer";

/// The owner's answer to one offer (`disclosure_routes.rs` `confirm`).
const OWNER_CONFIRM: &str = "/v1/owner/disclosure/confirm";

/// The context-pack route, where a model connection's ceiling shows.
const CONTEXT_PACK: &str = "/v1/core/context-pack";

/// Another vault's authority id, as a home clearance names it.
const OTHER_HOME: [u8; 32] = [0x42; 32];

/// The offer's purpose, which the standing clearance keeps.
const PURPOSE: &str = "share the reading group's notes";

/// The verbs every caller slip carries.
const CORE: &[&str] = &["core:read", "core:write"];

/// The verbs the offering agent's slip carries: the offer needs
/// `propose_disclosure_widen` (`consent/contact_clearance.rs`).
const OFFERING: &[&str] = &["core:read", "core:write", "propose_disclosure_widen"];

/// The one word the classed claim's text index holds.
const SHARED_WORD: &str = "lanternwick";

/// The classed claim's value, which only its own row holds.
const NAME_VALUE: &str = "Marisol Quenby";

/// A names-class predicate (`disclosure/model_channel.rs` `claim_data_class`).
const NAME_PREDICATE: &str = "profile.given_name";

/// The registered secret's value, which no answer may carry.
const SECRET_VALUE: &str = "reading-room-door-code-5521";

/// One served vault, called by its owner on the host root.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    owner: EntityId,
}

/// A caller on its own slip, signed by its own key.
struct Principal {
    id: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The host root slip: on a self-hosted vault it acts as the owner.
    Root,
    As(&'a Principal),
}

/// One reply: its status and its JSON.
struct Reply {
    status: StatusCode,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
    }

    /// Asserts a 403 `FORBIDDEN` whose message holds `words`.
    fn forbidden(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::FORBIDDEN,
            "{call} answered {}",
            self.body
        );
        assert_eq!(self.body["error"]["code"], "FORBIDDEN", "{call}");
        assert!(
            self.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(words)),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    /// Asserts a 400 whose reply holds `words`.
    fn bad_request(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::BAD_REQUEST,
            "{call} answered {}",
            self.body
        );
        assert!(
            self.body.to_string().contains(words),
            "{call} must name `{words}`: {}",
            self.body
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The rows of a list answer: a bare array, or an `items` array.
fn rows(body: &Value) -> Vec<Value> {
    body.as_array()
        .or_else(|| body["items"].as_array())
        .cloned()
        .unwrap_or_else(|| panic!("a list answer holds no rows: {body}"))
}

/// The ids of a context pack's result rows.
fn result_ids(pack: &Value) -> Vec<String> {
    pack["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temporary vault directory");
        let vault =
            Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("this install's signing keys");
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("vault-disclosure-doors".into()),
                    ..Default::default()
                },
            )
            .expect("create the vault's server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        Self {
            _dir: dir,
            vault,
            app: build_app(server),
            issuer,
            slip,
            token,
            owner,
        }
    }

    /// `caller`'s `method` request to `path`, with `body` as its JSON.
    async fn send(
        &self,
        caller: Caller<'_>,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (token, signature) = match caller {
            Caller::Root => (
                self.token.clone(),
                hex(&self
                    .issuer
                    .binding_proof(&self.slip, &challenge)
                    .expect("owner holder proof")),
            ),
            Caller::As(principal) => (
                principal.slip.to_token().expect("caller slip token"),
                hex(&principal
                    .key
                    .sign(
                        &principal
                            .slip
                            .binding_transcript(&challenge)
                            .expect("caller binding transcript"),
                    )
                    .to_bytes()),
            ),
        };
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            );
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(request.body(body).expect("the request"))
            .await
            .expect("the app's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{path} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply { status, body }
    }

    /// `caller`'s call to `verb` at its facade route.
    async fn facade(&self, caller: Caller<'_>, verb: &str, input: &Value) -> Reply {
        self.send(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// The owner's call to `verb`, which must answer 200.
    async fn owner_ok(&self, verb: &str, input: Value) -> Value {
        self.facade(Caller::Root, verb, &input).await.ok(verb)
    }

    /// The owner's own context pack for `query`.
    async fn owner_pack(&self, query: &str) -> Value {
        self.send(
            Caller::Root,
            Method::POST,
            CONTEXT_PACK,
            Some(&json!({"query": query, "limit": 10})),
        )
        .await
        .ok(CONTEXT_PACK)
    }

    /// The owner's verified proof, for engine-side setup.
    fn owner_proof(&self) -> oneiron::consent::AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// A PERSON row named `name`.
    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
        )
        .expect("the person's PERSON body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the person's PERSON row");
        id
    }

    /// `holder`'s own slip as a `class` caller holding `verbs`, signed by the
    /// key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8, verbs: &[&str]) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the caller's slip");
        Principal {
            id: holder,
            slip,
            key,
        }
    }

    /// The vault's own agent `name`, bound with full access, on its own slip
    /// holding `verbs`.
    fn agent(&self, name: &str, seed: u8, verbs: &[&str]) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &self.owner_proof(),
                agent,
                AgentTier::FullAccess.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed, verbs)
    }

    /// A new, active contact of a new PERSON: a party nobody cleared.
    fn contact(&self, address: &str) -> EntityId {
        let person = self.person(address);
        let contact = EntityId::now();
        self.vault
            .create_counterparty_contact(
                &contact,
                &CounterpartyContactRecord::public(person, address, self.vault.now_recorded_at())
                    .expect("the contact's record"),
            )
            .expect("the contact's row");
        contact
    }

    /// The contact's stored clearance, read at the engine.
    fn clearance(&self, contact: &EntityId) -> Option<oneiron::disclosure::DisclosureScope> {
        self.vault
            .counterparty_disclosure_scope(contact)
            .expect("read the contact's clearance")
    }

    /// An offer of the whole scope for `contact`, lapsing in ten minutes of
    /// vault time and addressed to this vault's owner.
    fn offer_input(&self, contact: &EntityId) -> Value {
        json!({
            "contact": contact.to_hex(),
            "scope": serde_json::to_value(Scope::top()).expect("the scope's wire form"),
            "purpose": PURPOSE,
            "channel": "room:reading-group",
            "beneficiary": contact.to_hex(),
            "ask": null,
            "owner_ref": self.owner.to_hex(),
            "expires_at": self.vault.now_recorded_at() + 600,
        })
    }

    /// `agent`'s offer for `contact`, which must be filed; its proposal ref.
    async fn offer(&self, agent: &Principal, contact: &EntityId) -> String {
        let offered = self
            .facade(
                Caller::As(agent),
                "vault.disclosure.offer",
                &self.offer_input(contact),
            )
            .await
            .ok("vault.disclosure.offer");
        let proposal = offered["proposal_ref"]
            .as_str()
            .unwrap_or_else(|| panic!("the offer names no proposal: {offered}"))
            .to_owned();
        assert_eq!(
            proposal.len(),
            64,
            "a widen proposal ref is 64 hex: {offered}"
        );
        assert_eq!(
            offered["owner_ref"],
            self.owner.to_hex(),
            "the offer is addressed to this vault's owner: {offered}"
        );
        proposal
    }

    /// The owner's frozen view of `proposal`.
    async fn offer_view(&self, proposal: &str) -> Value {
        self.send(
            Caller::Root,
            Method::GET,
            &format!("{OWNER_OFFER}?proposal_ref={proposal}"),
            None,
        )
        .await
        .ok(OWNER_OFFER)
    }

    /// `caller`'s standing answer to `proposal`, against `delta`.
    async fn confirm(&self, caller: Caller<'_>, proposal: &str, delta: &str) -> Reply {
        self.send(
            caller,
            Method::POST,
            OWNER_CONFIRM,
            Some(&json!({
                "proposal_ref": proposal,
                "expected_delta": delta,
                "outcome": "standing",
            })),
        )
        .await
    }

    /// One claim about a new PERSON, of the names class, stamped `private`,
    /// holding [`NAME_VALUE`] and indexed under [`SHARED_WORD`] only.
    fn seed_name_claim(&self) -> EntityId {
        let subject = self.person("pack subject");
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            NAME_PREDICATE,
            ClaimSubject::Entity(subject),
            rmpv::Value::from(NAME_VALUE),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("the classed claim's body");
        body.source = Some(ClaimSource::UserStated);
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from("private"),
        )]));
        let now = self.vault.now_recorded_at();
        self.vault
            .put_claim(
                &id,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .expect("the classed claim");
        self.vault
            .batch()
            .text(&id, &[("body", SHARED_WORD)])
            .commit()
            .expect("index the classed claim");
        id
    }

    /// The owner registers one model-revealable secret; its handle, found by
    /// `asker`'s `reveal.describe` (no public read names a short handle).
    async fn secret_handle(&self, asker: &Principal) -> String {
        self.vault
            .register_secret_as_owner(
                &self.owner_proof(),
                &OwnerSecretRegistration {
                    name: "reading-room.door",
                    class: CustodyClass::CustodyPortable,
                    device_only: false,
                    rung: CustodyTier::T1Leased,
                    bindings: vec![RequestedBinding {
                        effector: "connector:microsoft365".to_owned(),
                        tier_ceiling: None,
                        scopes: vec!["read".to_owned()],
                    }],
                    manifest: None,
                    value: SECRET_VALUE.as_bytes(),
                },
                self.vault.now_recorded_at(),
            )
            .expect("the owner's secret");
        for n in 1..=16 {
            let handle = format!("sc{n}");
            let card = self
                .facade(
                    Caller::As(asker),
                    "reveal.describe",
                    &json!({"handle": handle}),
                )
                .await;
            if card.status == StatusCode::OK {
                assert!(
                    !card.body.to_string().contains(SECRET_VALUE),
                    "reveal.describe never carries the value: {}",
                    card.body
                );
                return handle;
            }
        }
        panic!("no custody handle sc1..sc16 names the registered secret");
    }
}

/// ONE-1592 consent channel :81: "An offer is not an authorization. The
/// confirm still lands on the authenticated surface." The agent's offer is
/// filed and frozen for the owner, and the contact stays uncleared; neither
/// the offering agent nor a person who is not the owner can confirm it.
#[test]
fn an_agents_offer_is_not_an_authorization_and_only_the_owner_confirms_it() {
    run_on_engine_stack("disclosure-doors-offer", || async {
        let host = Host::new();
        let agent = host.agent("disclosure-offerer", 0x71, OFFERING);
        let person = host.principal(host.person("Olu"), "human", 0x72, CORE);
        let contact = host.contact("reader@example.com");
        assert!(
            host.clearance(&contact).is_none(),
            "a new party starts with no clearance"
        );
        let proposal = host.offer(&agent, &contact).await;
        assert!(
            host.clearance(&contact).is_none(),
            "an offer is not an authorization: the contact stays uncleared after it"
        );
        let view = host.offer_view(&proposal).await;
        assert_eq!(view["proposal_ref"], proposal, "{view}");
        assert_eq!(view["contact"], contact.to_hex(), "{view}");
        assert_eq!(view["proposer"], agent.id.to_hex(), "{view}");
        assert_eq!(view["purpose"], PURPOSE, "{view}");
        let delta = view["canonical_delta"]
            .as_str()
            .unwrap_or_else(|| panic!("the owner's view names no delta: {view}"))
            .to_owned();
        for (who, caller) in [
            ("the offering agent", Caller::As(&agent)),
            ("a person who is not the owner", Caller::As(&person)),
        ] {
            let reply = host.confirm(caller, &proposal, &delta).await;
            assert_eq!(
                reply.status,
                StatusCode::FORBIDDEN,
                "{who} confirms nothing: {}",
                reply.body
            );
            assert!(
                host.clearance(&contact).is_none(),
                "{who}'s confirm leaves the contact uncleared"
            );
        }
    });
}

/// ONE-1592 consent channel :8: granting clearance to a new party "costs the
/// owner exactly one authenticated confirm". The owner's standing confirm
/// writes the offered scope and purpose as the contact's active clearance,
/// and the settled offer takes no second confirm.
#[test]
fn one_owner_confirm_clears_a_new_party_and_settles_its_offer_once() {
    run_on_engine_stack("disclosure-doors-confirm", || async {
        let host = Host::new();
        let agent = host.agent("disclosure-offerer", 0x73, OFFERING);
        let contact = host.contact("reader@example.com");
        let proposal = host.offer(&agent, &contact).await;
        let view = host.offer_view(&proposal).await;
        let delta = view["canonical_delta"]
            .as_str()
            .unwrap_or_else(|| panic!("the owner's view names no delta: {view}"))
            .to_owned();
        host.confirm(Caller::Root, &proposal, &delta)
            .await
            .ok(OWNER_CONFIRM);
        let clearance = host
            .clearance(&contact)
            .expect("the owner's confirm clears the contact");
        assert_eq!(clearance.status, DisclosureScopeStatus::Active);
        assert_eq!(
            clearance.scope,
            Scope::top(),
            "the clearance is the offered scope"
        );
        assert_eq!(
            clearance.purpose, PURPOSE,
            "the clearance keeps the offer's purpose"
        );
        host.confirm(Caller::Root, &proposal, &delta)
            .await
            .bad_request("a second confirm", "stale, changed, or resolved");
        assert_eq!(
            host.clearance(&contact),
            Some(clearance),
            "a refused second confirm changes nothing"
        );
    });
}

/// DEC-0006 :112: "The agent never raises its own ceiling." Each owner door
/// of the family refuses the vault's own full-access agent and a person who
/// is not the owner with the owner refusal, and their attempts change no
/// dial the owner set.
#[test]
fn no_disclosure_dial_or_reveal_answer_opens_for_anyone_but_the_owner() {
    run_on_engine_stack("disclosure-doors-owner-only", || async {
        let host = Host::new();
        let agent = host.agent("disclosure-agent", 0x74, CORE);
        let person = host.principal(host.person("Mina"), "human", 0x75, CORE);
        let connection = format!("agent:{}", agent.id.to_hex());
        let home = hex(&OTHER_HOME);
        let set = host
            .owner_ok(
                "vault.disclosure.ceiling.set",
                json!({"connection": connection, "class": "names", "ceiling": "public"}),
            )
            .await;
        assert_eq!(set["ceiling"], "public", "{set}");
        let doors = [
            (
                "vault.disclosure.ceiling.get",
                json!({"connection": connection, "class": "names"}),
            ),
            (
                "vault.disclosure.ceiling.set",
                json!({"connection": connection, "class": "names", "ceiling": "restricted"}),
            ),
            (
                "vault.disclosure.ceiling.clear",
                json!({"connection": connection, "class": "names"}),
            ),
            ("vault.disclosure.home.get", json!({"home_vault_id": home})),
            (
                "vault.disclosure.home.set",
                json!({"home_vault_id": home, "band": "sensitive"}),
            ),
            (
                "vault.disclosure.home.clear",
                json!({"home_vault_id": home}),
            ),
            ("vault.disclosure.reveals", json!({"pending": true})),
            (
                "vault.disclosure.reveals.answer",
                json!({
                    "reveal": hex(&[0x11; 16]),
                    "expected_digest": hex(&[0x22; 32]),
                    "outcome": "once",
                }),
            ),
        ];
        for (who, caller) in [
            ("the full-access agent", Caller::As(&agent)),
            ("a person who is not the owner", Caller::As(&person)),
        ] {
            for (verb, input) in &doors {
                host.facade(caller, verb, input).await.forbidden(
                    &format!("{who} at {verb}"),
                    &format!("{verb} is the vault owner's"),
                );
            }
        }
        let ceiling = host
            .owner_ok(
                "vault.disclosure.ceiling.get",
                json!({"connection": connection, "class": "names"}),
            )
            .await;
        assert_eq!(
            ceiling["ceiling"], "public",
            "the refused callers moved no ceiling: {ceiling}"
        );
        let home_band = host
            .owner_ok("vault.disclosure.home.get", json!({"home_vault_id": home}))
            .await;
        assert!(
            home_band["band"].is_null(),
            "the refused callers set no home clearance: {home_band}"
        );
    });
}

/// DEC-0006 :102: "A record above the connection's ceiling reaches the model
/// as its bare handle". The owner's own model connection reads a private
/// names-class value in full; under the owner's `public` ceiling for names the
/// row stays in the pack with its value withheld, and the owner's clear
/// brings the value back.
#[test]
fn a_model_connection_sees_a_bare_handle_above_its_ceiling_until_the_owner_clears_it() {
    run_on_engine_stack("disclosure-doors-ceiling", || async {
        let host = Host::new();
        let claim = host.seed_name_claim().to_hex();
        let connection = format!("owner:{}", host.owner.to_hex());
        let dial = json!({"connection": connection, "class": "names"});
        let pack = host.owner_pack(SHARED_WORD).await;
        assert!(
            result_ids(&pack).contains(&claim),
            "the owner's pack finds the classed claim: {pack}"
        );
        assert!(
            pack.to_string().contains(NAME_VALUE),
            "with no ceiling the owner's connection reads the value: {pack}"
        );
        let unset = host
            .owner_ok("vault.disclosure.ceiling.get", dial.clone())
            .await;
        assert!(unset["ceiling"].is_null(), "no ceiling is set yet: {unset}");
        let set = host
            .owner_ok(
                "vault.disclosure.ceiling.set",
                json!({"connection": connection, "class": "names", "ceiling": "public"}),
            )
            .await;
        assert_eq!(set["connection"], connection, "{set}");
        assert_eq!(set["class"], "names", "{set}");
        assert_eq!(set["ceiling"], "public", "{set}");
        let read = host
            .owner_ok("vault.disclosure.ceiling.get", dial.clone())
            .await;
        assert_eq!(read["ceiling"], "public", "{read}");
        let pack = host.owner_pack(SHARED_WORD).await;
        assert!(
            result_ids(&pack).contains(&claim),
            "above the ceiling the row stays, as its handle: {pack}"
        );
        assert!(
            !pack.to_string().contains(NAME_VALUE),
            "above the ceiling the model reads the handle, never the value: {pack}"
        );
        let cleared = host
            .owner_ok("vault.disclosure.ceiling.clear", dial.clone())
            .await;
        assert!(
            cleared["ceiling"].is_null(),
            "the clear removes the ceiling: {cleared}"
        );
        let pack = host.owner_pack(SHARED_WORD).await;
        assert!(
            pack.to_string().contains(NAME_VALUE),
            "after the clear the owner's connection reads the value again: {pack}"
        );
    });
}

/// DEC-0006 :112: "`reveal` hydrates inside a grant, or it asks; the guard
/// offers and never grants." An agent's reveal of a secret with no standing
/// grant waits on the owner; the owner's open asks name it with its digest
/// and never the value; an answer naming another digest is refused; the
/// owner's one answer settles it, and the answered ask takes no second one.
#[test]
fn a_secret_ask_waits_for_the_owners_one_answer_naming_its_digest() {
    run_on_engine_stack("disclosure-doors-reveal", || async {
        let host = Host::new();
        let agent = host.agent("reveal-asker", 0x76, CORE);
        let handle = host.secret_handle(&agent).await;
        let pending = host
            .facade(
                Caller::As(&agent),
                "reveal",
                &json!({"handle": handle, "why": "to open the reading room"}),
            )
            .await
            .ok("reveal");
        let reveal = pending["reveal"]
            .as_str()
            .unwrap_or_else(|| panic!("the reveal names no id: {pending}"))
            .to_owned();
        let waiting = host
            .facade(
                Caller::As(&agent),
                "reveal.wait",
                &json!({"reveal": reveal}),
            )
            .await
            .ok("reveal.wait");
        assert_eq!(
            waiting["decision"], "pending",
            "the ask waits on the owner: {waiting}"
        );
        assert!(
            !waiting.to_string().contains(SECRET_VALUE),
            "a waiting reveal carries no value: {waiting}"
        );
        let asks = host
            .owner_ok("vault.disclosure.reveals", json!({"pending": true}))
            .await;
        assert!(
            !asks.to_string().contains(SECRET_VALUE),
            "the owner's asks never carry the value: {asks}"
        );
        let ask = rows(&asks)
            .into_iter()
            .find(|row| row["receipt"]["reveal"] == reveal)
            .unwrap_or_else(|| panic!("the open asks name the agent's reveal: {asks}"));
        assert_eq!(ask["receipt"]["handle"], handle, "{ask}");
        let digest = ask["expected_digest"]
            .as_str()
            .unwrap_or_else(|| panic!("an open ask names its digest: {ask}"))
            .to_owned();
        assert_eq!(digest.len(), 64, "{ask}");
        let other = hex(&[0x33; 32]);
        assert_ne!(other, digest, "the test's other digest is another ask's");
        host.facade(
            Caller::Root,
            "vault.disclosure.reveals.answer",
            &json!({"reveal": reveal, "expected_digest": other, "outcome": "deny"}),
        )
        .await
        .bad_request(
            "an answer naming another digest",
            "the answer names another ask than this reveal's",
        );
        let answered = host
            .owner_ok(
                "vault.disclosure.reveals.answer",
                json!({"reveal": reveal, "expected_digest": digest, "outcome": "deny"}),
            )
            .await;
        assert_eq!(answered["reveal"], reveal, "{answered}");
        assert_eq!(answered["outcome"], "deny", "{answered}");
        assert!(
            answered["receipt_ref"]
                .as_str()
                .is_some_and(|receipt| receipt.starts_with("gate:")),
            "the answer is a Gate act: {answered}"
        );
        host.facade(
            Caller::Root,
            "vault.disclosure.reveals.answer",
            &json!({"reveal": reveal, "expected_digest": digest, "outcome": "once"}),
        )
        .await
        .bad_request("a second answer", "this reveal is not waiting on an answer");
        let settled = host
            .facade(
                Caller::As(&agent),
                "reveal.wait",
                &json!({"reveal": reveal}),
            )
            .await
            .ok("reveal.wait");
        assert_ne!(
            settled["decision"], "pending",
            "the answered ask no longer waits: {settled}"
        );
        assert!(
            !settled.to_string().contains(SECRET_VALUE),
            "a denied reveal carries no value: {settled}"
        );
        let open = host
            .owner_ok("vault.disclosure.reveals", json!({"pending": true}))
            .await;
        assert!(
            rows(&open)
                .iter()
                .all(|row| row["receipt"]["reveal"] != reveal),
            "the answered ask leaves the open asks: {open}"
        );
    });
}
