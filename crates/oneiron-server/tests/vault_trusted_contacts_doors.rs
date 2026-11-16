//! Promise tests for the `vault.trusted_contacts.*` doors, entered at
//! `POST /v1/core/facade/<verb>`. Canon: EIRI-FEAT-0009
//! (eiri/features/eiri-feat-0009-trusted-contact.md); the doors' own module
//! doc (`api/facade/trusted_contact_doors.rs` :1-27) states the same
//! promises for the host.
//!
//! - :58 "Consent is two-sided. You agree, and your contact agrees." and :59
//!   "The contact is an adult.": a person names a contact, and the naming is
//!   not live until the contact consents, as an adult, under its own person
//!   proof. The namer, the owner, a third person and an agent are refused;
//!   until the consent a crisis asks nobody and stages nothing.
//! - :60 "You can revoke it at any time. So can your contact.": either side
//!   lists and revokes the relation under its own proof; a third person lists
//!   nothing and revokes nothing, and a revoked relation never fires.
//! - :36 "Concern | She asks you first. You say yes or no. | Only if you say
//!   yes." and :43 "Only the fact of concern crosses ... It never carries a
//!   transcript, a quote or a topic.": a crisis the owner's gate routes to
//!   help raises an ask; a yes stages the notice and does not deliver it;
//!   only the notice's stored sender takes it up, and no answer quotes the
//!   message. :30 "The notify fires only on RouteToHelp.": a message no row
//!   decides proposes nothing.
//! - :37 "Imminent | She calls your contact now." and :56 "Just call | She
//!   calls on the imminent tier without asking.": on the owner's imminent
//!   row a just-call naming is notified at once, and the dial change keeps
//!   the contact's consent.
//! - The tier is the owner's (doors.rs :4-5 "a policy row's tier stays under
//!   the owner's proof"): a person or an agent is refused, and its attempt
//!   leaves the row a concern.
//! - :36 again, per person (doors.rs :3-4 "reads and answers their own
//!   concern asks"): another person, the contact, the owner and an agent
//!   neither read nor answer a person's ask.
//!
//! The gate: the owner adds a RouteToHelp row, then turns owner policy on
//! with one deciding pattern for it (`vault.policy.owner.row.change`, then
//! `.configure`, in the order of tests/e2e/secrets.test.ts SECRETS-07: a
//! pattern must name a row that exists). This host serves no safeguard model,
//! so a message no pattern decides is refused, not routed (:30).
//!
//! The notice goes out on `email`, which a seeded vault refuses until its
//! built-in pack is installed Active with its connection checked (OF-519).
//! The pack is not what these tests cover, so the vault drops its seed
//! marker through a test door, as tests/booking_feed_move_held.rs does; the
//! file therefore builds only under `--cfg oneiron_test_support`.

#![cfg(all(unix, oneiron_test_support))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const NAME: &str = "vault.trusted_contacts.name";
const LIST: &str = "vault.trusted_contacts.list";
const CONSENT: &str = "vault.trusted_contacts.consent";
const REVOKE: &str = "vault.trusted_contacts.revoke";
const DIAL: &str = "vault.trusted_contacts.dial.set";
const TIER: &str = "vault.trusted_contacts.tier.set";
const ASKS: &str = "vault.trusted_contacts.concern.asks";
const AUTHORIZE: &str = "vault.trusted_contacts.concern.authorize";
const PROPOSE: &str = "vault.trusted_contacts.concern.propose";
const DELIVER: &str = "vault.trusted_contacts.concern.deliver";

/// The owner's RouteToHelp row; its deciding pattern routes `crisis-marker`.
const CRISIS_ROW: &str = "owner:crisis";

/// A turn the owner's gate routes to help. Every word past the marker is
/// private, and no answer may quote it.
const PRIVATE_TURN: &str = "crisis-marker: the rail bridge at Halvard Street, my sister's pills";

/// The private words of [`PRIVATE_TURN`].
const PRIVATE_WORDS: [&str; 4] = ["Halvard", "bridge", "pills", "sister"];

/// A turn no pattern decides.
const CALM_TURN: &str = "the reading group meets on Thursday";

/// The contact's address: the reach holds it, and no receipt carries it.
const CONTACT_ADDRESS: &str = "contact@example.com";

/// The scopes every person and agent slip here holds.
const CORE: &[&str] = &["core:read", "core:write"];

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

/// Ana names, Ben is named, Cleo is a third person, and the courier is the
/// vault's own agent: the sender every naming stores, and the agent caller
/// every person door refuses.
struct Cast {
    ana: Principal,
    ben: Principal,
    cleo: Principal,
    courier: Principal,
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

    /// Asserts a 200 whose answer is `null`: nothing for this caller.
    fn nothing(self, call: &str) {
        let body = self.ok(call);
        assert!(body.is_null(), "{call} must answer null, answered {body}");
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

/// Asserts `answer` quotes no private word of [`PRIVATE_TURN`].
fn assert_quotes_nothing(call: &str, answer: &Value) {
    let text = answer.to_string();
    for word in PRIVATE_WORDS {
        assert!(
            !text.contains(word),
            "{call} quotes the private word `{word}`: {text}"
        );
    }
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temporary vault directory");
        let vault =
            Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        // Without this the sender's deliver answers 400 "the channel's
        // built-in pack is not installed" before any gate or sink runs.
        oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&vault)
            .expect("remove the built-in pack seed marker");
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("vault-trusted-contacts-doors".into()),
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

    /// `caller`'s call to `verb` at its facade route, with `input` as its JSON.
    async fn call(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
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
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("the request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{verb} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply { status, body }
    }

    /// The owner's call to `verb`, which must answer 200.
    async fn owner_ok(&self, verb: &str, input: Value) -> Value {
        self.call(Caller::Root, verb, input).await.ok(verb)
    }

    /// The owner's verified proof, for binding the vault's own agent.
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

    /// A row of `kind` whose MessagePack body is the one-field map
    /// `field: value`.
    fn row(&self, kind: u8, field: &str, value: &str) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from(field), rmpv::Value::from(value))]),
        )
        .expect("the row's body");
        self.vault
            .put_entity(
                &id,
                kind,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the row");
        id
    }

    /// `holder`'s own slip as a `class` caller holding [`CORE`], signed by
    /// the key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(CORE.iter().map(|verb| (*verb).to_owned()).collect());
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

    /// A live PERSON named `name`, on a human slip of its own.
    fn person(&self, name: &str, seed: u8) -> Principal {
        let id = self.row(ENTITY_TYPE_PERSON, "name", name);
        self.principal(id, "human", seed)
    }

    /// The vault's own agent `name`, bound with full access, on its own slip.
    fn agent(&self, name: &str, seed: u8) -> Principal {
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
        self.principal(agent, "agent", seed)
    }

    fn cast(&self) -> Cast {
        Cast {
            ana: self.person("Ana Okonkwo-Reyes", 0x71),
            ben: self.person("Ben Vasquez-Lund", 0x72),
            cleo: self.person("Cleo Marchetti", 0x73),
            courier: self.agent("trusted-contact-courier", 0x74),
        }
    }

    /// The owner's gate: a RouteToHelp row, then owner policy on with one
    /// deciding pattern for it.
    async fn install_crisis_gate(&self) {
        self.owner_ok(
            "vault.policy.owner.row.change",
            json!({"change": {"Add": {
                "row_ref": CRISIS_ROW,
                "text": "Route a self-harm crisis to help.",
                "action": "route_to_help",
                "scope": "Vault",
            }}}),
        )
        .await;
        let current = self.owner_ok("vault.policy.owner.get", json!({})).await;
        self.owner_ok(
            "vault.policy.owner.configure",
            json!({
                "expected_body_hash": current["body_hash"],
                "configuration": {
                    "owner_policy_enabled": true,
                    "owner_policy_patterns": [{
                        "id": "owner.crisis",
                        "pattern": "(?i)crisis-marker",
                        "category": CRISIS_ROW,
                        "role": "decide",
                    }],
                },
            }),
        )
        .await;
        let enabled = self.owner_ok("vault.policy.owner.get", json!({})).await;
        assert_eq!(enabled["enabled"], true, "owner policy on: {enabled}");
    }

    /// A conversation MESSAGE whose content is `text`; its ref.
    fn message(&self, text: &str) -> String {
        self.row(ENTITY_TYPE_MESSAGE, "content", text).to_hex()
    }

    /// `namer` names `contact`, reached through `sender`'s email, at `dial`.
    async fn name(
        &self,
        namer: &Principal,
        contact: &Principal,
        sender: &Principal,
        dial: &str,
    ) -> Value {
        self.call(
            Caller::As(namer),
            NAME,
            json!({
                "contact_ref": contact.id.to_hex(),
                "reach": {
                    "sender": sender.id.to_hex(),
                    "channel": "email",
                    "verb": "send",
                    "target": CONTACT_ADDRESS,
                },
                "dial": dial,
            }),
        )
        .await
        .ok(NAME)
    }

    /// `contact` consents, as an adult, to `namer`'s naming at `version`.
    async fn consent(&self, contact: &Principal, namer: &Principal, version: u64) -> Value {
        self.call(
            Caller::As(contact),
            CONSENT,
            json!({"person_ref": namer.id.to_hex(), "version": version, "adult": true}),
        )
        .await
        .ok(CONSENT)
    }

    /// `ana` names `ben` at `dial`, through the courier, and `ben` consents.
    async fn live_naming(&self, cast: &Cast, dial: &str) {
        let named = self.name(&cast.ana, &cast.ben, &cast.courier, dial).await;
        let version = named["version"].as_u64().expect("the naming's version");
        self.consent(&cast.ben, &cast.ana, version).await;
    }

    /// `person` proposes a fresh message holding `text`.
    async fn propose(&self, person: &Principal, text: &str) -> Reply {
        let content_ref = self.message(text);
        self.call(
            Caller::As(person),
            PROPOSE,
            json!({"content_ref": content_ref}),
        )
        .await
    }

    /// `caller`'s open asks.
    async fn asks(&self, caller: Caller<'_>) -> Vec<Value> {
        rows(&self.call(caller, ASKS, json!({})).await.ok(ASKS))
    }

    /// `caller`'s relations.
    async fn listed(&self, caller: Caller<'_>) -> Vec<Value> {
        rows(&self.call(caller, LIST, json!({})).await.ok(LIST))
    }

    /// `caller`'s deliver call.
    async fn deliver(&self, caller: Caller<'_>) -> Reply {
        self.call(caller, DELIVER, json!({})).await
    }
}

/// Asserts the stored sender's deliver call took up the one staged notice:
/// a receipt of the fact alone, for `person`'s naming of `contact`, under
/// `authorization`. The served sink of a bare test vault holds no mail
/// connection and the sender holds no send grant, so the dispatch's outcome
/// may be held or failed; what the receipt carries is the promise. A refused dispatch must quote nothing either.
fn assert_sender_takes_the_fact(
    reply: Reply,
    person: &Principal,
    contact: &Principal,
    authorization: &Value,
) {
    let call = "the stored sender's deliver";
    if reply.status != StatusCode::OK {
        assert_quotes_nothing(call, &reply.body);
        assert!(
            !reply.body.to_string().contains(CONTACT_ADDRESS),
            "{call} names the contact's address: {}",
            reply.body
        );
        panic!(
            "{call} answered {} {}; the staged notice is the sender's to take",
            reply.status, reply.body
        );
    }
    let receipt = reply.body;
    assert!(
        !receipt.is_null(),
        "{call} found no notice: the staged one is its own"
    );
    assert_eq!(receipt["fact"], "fact_of_concern", "{call}: {receipt}");
    assert_eq!(receipt["person_ref"], person.id.to_hex(), "{call}");
    assert_eq!(receipt["contact_ref"], contact.id.to_hex(), "{call}");
    assert_eq!(receipt["version"], 1, "{call}");
    assert_eq!(receipt["channel"], "email", "{call}");
    assert_eq!(receipt["verb"], "send", "{call}");
    assert_eq!(&receipt["authorization"], authorization, "{call}");
    assert_quotes_nothing(call, &receipt);
    assert!(
        !receipt.to_string().contains(CONTACT_ADDRESS),
        "{call} names the contact's address: {receipt}"
    );
}

/// :58-59: the naming waits for the contact's own adult consent. Nobody else
/// gives it, and until it is given a crisis reaches no one.
#[test]
fn a_named_contact_hears_nothing_until_they_consent_as_an_adult_under_their_own_proof() {
    run_on_engine_stack(
        "a_named_contact_hears_nothing_until_they_consent_as_an_adult_under_their_own_proof",
        || async {
            let host = Host::new();
            let cast = host.cast();

            // A fresh vault's owner policy is off: no gate settles a RouteToHelp.
            let off = host.propose(&cast.ana, PRIVATE_TURN).await;
            assert_eq!(
                off.status,
                StatusCode::CONFLICT,
                "a propose with owner policy off answered {}",
                off.body
            );
            assert!(
                off.body.to_string().contains("owner policy is off"),
                "{}",
                off.body
            );
            host.install_crisis_gate().await;

            let named = host
                .name(&cast.ana, &cast.ben, &cast.courier, "ask_first")
                .await;
            assert_eq!(named["version"], 1, "{named}");
            assert_eq!(named["person"], cast.ana.id.to_hex(), "{named}");
            assert_eq!(named["contact"], cast.ben.id.to_hex(), "{named}");
            assert_eq!(named["dial"], "ask_first", "{named}");
            assert_eq!(named["reach"]["target"], CONTACT_ADDRESS, "{named}");
            assert!(named["accepted"].is_null(), "{named}");
            assert!(named["revoked"].is_null(), "{named}");

            // The contact sees the naming it is asked to accept, unaccepted.
            let seen = host.listed(Caller::As(&cast.ben)).await;
            assert_eq!(seen.len(), 1, "the contact's list: {seen:?}");
            assert_eq!(seen[0]["person"], cast.ana.id.to_hex());
            assert!(seen[0]["accepted"].is_null(), "{:?}", seen[0]);

            // Until it consents, a crisis asks nobody and stages nothing.
            let proposal = host
                .propose(&cast.ana, PRIVATE_TURN)
                .await
                .ok("a crisis before the consent");
            assert_eq!(proposal["action"], "route_to_help", "{proposal}");
            assert_eq!(proposal["fact"], "fact_of_concern", "{proposal}");
            assert_eq!(
                proposal["open_asks"],
                json!([]),
                "an unaccepted naming is asked about: {proposal}"
            );
            assert_quotes_nothing("the proposal", &proposal);
            assert!(host.asks(Caller::As(&cast.ana)).await.is_empty());
            host.deliver(Caller::As(&cast.courier))
                .await
                .nothing("the courier's deliver before the consent");

            // Nobody consents for the contact.
            let for_ben = json!({"person_ref": cast.ana.id.to_hex(), "version": 1, "adult": true});
            host.call(Caller::As(&cast.ana), CONSENT, for_ben.clone())
                .await
                .forbidden(
                    "the namer consenting for the contact",
                    "no one named this person a trusted contact",
                );
            host.call(Caller::As(&cast.cleo), CONSENT, for_ben.clone())
                .await
                .forbidden(
                    "a third person consenting for the contact",
                    "no one named this person a trusted contact",
                );
            host.call(Caller::Root, CONSENT, for_ben.clone())
                .await
                .forbidden(
                    "the owner consenting for the contact",
                    "consent owner not authenticated",
                );
            host.call(Caller::As(&cast.courier), CONSENT, for_ben)
                .await
                .forbidden(
                    "an agent consenting for the contact",
                    "vault.trusted_contacts.consent is a live person's own act",
                );

            // The contact itself consents only as an adult, to the naming it
            // was shown.
            host.call(
                Caller::As(&cast.ben),
                CONSENT,
                json!({"person_ref": cast.ana.id.to_hex(), "version": 1, "adult": false}),
            )
            .await
            .bad_request(
                "a consent that is not an adult's",
                "a trusted contact is an adult",
            );
            host.call(
                Caller::As(&cast.ben),
                CONSENT,
                json!({"person_ref": cast.ana.id.to_hex(), "version": 2, "adult": true}),
            )
            .await
            .bad_request(
                "a consent to a naming never shown",
                "this is not the naming the contact was shown",
            );
            let still = host.listed(Caller::As(&cast.ana)).await;
            assert_eq!(still.len(), 1, "{still:?}");
            assert!(
                still[0]["accepted"].is_null(),
                "a refused consent accepted the naming: {:?}",
                still[0]
            );

            let accepted = host.consent(&cast.ben, &cast.ana, 1).await;
            assert_eq!(accepted["accepted"]["adult"], true, "{accepted}");
            assert!(accepted["revoked"].is_null(), "{accepted}");
        },
    );
}

/// :60: either side lists and revokes the relation; a third person sees
/// nothing and ends nothing, and a revoked relation never fires.
#[test]
fn either_side_lists_and_revokes_and_a_third_person_sees_nothing() {
    run_on_engine_stack(
        "either_side_lists_and_revokes_and_a_third_person_sees_nothing",
        || async {
            let host = Host::new();
            let cast = host.cast();
            host.install_crisis_gate().await;
            host.live_naming(&cast, "ask_first").await;

            for (side, principal) in [("the person", &cast.ana), ("the contact", &cast.ben)] {
                let listed = host.listed(Caller::As(principal)).await;
                assert_eq!(listed.len(), 1, "{side}'s list: {listed:?}");
                assert_eq!(listed[0]["person"], cast.ana.id.to_hex(), "{side}");
                assert_eq!(listed[0]["contact"], cast.ben.id.to_hex(), "{side}");
                assert_eq!(listed[0]["accepted"]["adult"], true, "{side}");
                assert!(listed[0]["revoked"].is_null(), "{side}");
            }
            assert!(
                host.listed(Caller::As(&cast.cleo)).await.is_empty(),
                "a third person lists another person's contact"
            );

            let ends =
                json!({"person_ref": cast.ana.id.to_hex(), "contact_ref": cast.ben.id.to_hex()});
            host.call(Caller::As(&cast.cleo), REVOKE, ends.clone())
                .await
                .forbidden(
                    "a third person revoking",
                    "only the person or their contact revokes",
                );
            host.call(Caller::Root, REVOKE, ends.clone())
                .await
                .forbidden("the owner revoking", "consent owner not authenticated");
            host.call(Caller::As(&cast.courier), REVOKE, ends.clone())
                .await
                .forbidden(
                    "an agent revoking",
                    "vault.trusted_contacts.revoke is a live person's own act",
                );
            let standing = host.listed(Caller::As(&cast.ana)).await;
            assert!(
                standing[0]["revoked"].is_null(),
                "a refused revoke ended the relation: {standing:?}"
            );

            // The contact revokes; the revocation stays on both sides' record.
            let revoked = host
                .call(Caller::As(&cast.ben), REVOKE, ends)
                .await
                .ok("the contact's revoke");
            assert_eq!(revoked["revoked"]["by"], "contact", "{revoked}");
            for (side, principal) in [("the person", &cast.ana), ("the contact", &cast.ben)] {
                let listed = host.listed(Caller::As(principal)).await;
                assert_eq!(listed.len(), 1, "{side}'s list: {listed:?}");
                assert_eq!(listed[0]["revoked"]["by"], "contact", "{side}");
            }
            assert!(host.listed(Caller::As(&cast.cleo)).await.is_empty());

            // A revoked relation never fires.
            let proposal = host
                .propose(&cast.ana, PRIVATE_TURN)
                .await
                .ok("a crisis after the revoke");
            assert_eq!(proposal["fact"], "fact_of_concern", "{proposal}");
            assert_eq!(
                proposal["open_asks"],
                json!([]),
                "a revoked relation is asked about: {proposal}"
            );
            host.deliver(Caller::As(&cast.courier))
                .await
                .nothing("the courier's deliver after the revoke");

            // The person revokes a relation of their own.
            host.name(&cast.ana, &cast.cleo, &cast.courier, "ask_first")
                .await;
            host.consent(&cast.cleo, &cast.ana, 1).await;
            let ended = host
                .call(
                    Caller::As(&cast.ana),
                    REVOKE,
                    json!({"person_ref": cast.ana.id.to_hex(), "contact_ref": cast.cleo.id.to_hex()}),
                )
                .await
                .ok("the person's revoke");
            assert_eq!(ended["revoked"]["by"], "person", "{ended}");
            let bens = host.listed(Caller::As(&cast.ben)).await;
            assert_eq!(bens.len(), 1, "the contact lists only its own: {bens:?}");
            assert_eq!(bens[0]["contact"], cast.ben.id.to_hex());
        },
    );
}

/// :36, :43, :30: on the concern tier a crisis raises the person's ask; a yes
/// stages the fact and delivers nothing; only the notice's stored sender
/// takes it up; and no answer quotes the message. A message no row decides
/// proposes nothing.
#[test]
fn an_ask_first_yes_stages_the_notice_and_only_its_sender_delivers_the_fact() {
    run_on_engine_stack(
        "an_ask_first_yes_stages_the_notice_and_only_its_sender_delivers_the_fact",
        || async {
            let host = Host::new();
            let cast = host.cast();
            host.install_crisis_gate().await;
            host.live_naming(&cast, "ask_first").await;

            // A message no row decides: no verdict is made up, nothing is asked.
            let calm = host.propose(&cast.ana, CALM_TURN).await;
            assert_eq!(
                calm.status,
                StatusCode::SERVICE_UNAVAILABLE,
                "a message no pattern decides answered {}",
                calm.body
            );
            assert!(
                calm.body.to_string().contains("nothing was proposed"),
                "{}",
                calm.body
            );
            assert!(host.asks(Caller::As(&cast.ana)).await.is_empty());

            let proposal = host.propose(&cast.ana, PRIVATE_TURN).await.ok("the crisis");
            assert_eq!(proposal["action"], "route_to_help", "{proposal}");
            assert_eq!(proposal["fact"], "fact_of_concern", "{proposal}");
            assert!(
                proposal["gate_receipt_ref"].is_string(),
                "the gate's receipt: {proposal}"
            );
            let open = proposal["open_asks"]
                .as_array()
                .expect("the proposal's open asks");
            assert_eq!(open.len(), 1, "one ask for the one live naming: {proposal}");
            let ask = open[0].clone();
            assert_eq!(ask["person"], cast.ana.id.to_hex(), "{ask}");
            assert_eq!(ask["contact"], cast.ben.id.to_hex(), "{ask}");
            assert_eq!(ask["tier"], "concern", "{ask}");
            assert!(ask["answer"].is_null(), "{ask}");
            assert!(
                proposal["system_notices"]
                    .as_array()
                    .is_some_and(|notices| !notices.is_empty()),
                "the person is told of the ask: {proposal}"
            );
            assert_quotes_nothing("the proposal", &proposal);
            let ask_ref = ask["ask"].as_str().expect("the ask's ref").to_owned();
            let asks = host.asks(Caller::As(&cast.ana)).await;
            assert_eq!(asks.len(), 1, "{asks:?}");
            assert_eq!(asks[0]["ask"], ask_ref.as_str());
            assert_quotes_nothing("the person's asks", &json!(asks));

            // Asked first: nothing is staged before the answer.
            host.deliver(Caller::As(&cast.courier))
                .await
                .nothing("the courier's deliver before the yes");

            let yes = json!({"ask_ref": ask_ref, "yes": true});
            let staged = host
                .call(Caller::As(&cast.ana), AUTHORIZE, yes.clone())
                .await
                .ok("the person's yes");
            assert_eq!(staged["outcome"], "staged", "{staged}");
            assert_eq!(staged["yes"], true, "{staged}");
            assert!(
                staged["system_notices"]
                    .as_array()
                    .is_some_and(|notices| !notices.is_empty()),
                "the person is told the notice goes: {staged}"
            );
            assert_quotes_nothing("the yes", &staged);
            host.call(Caller::As(&cast.ana), AUTHORIZE, yes)
                .await
                .bad_request("a second answer", "this ask is already answered");
            assert!(host.asks(Caller::As(&cast.ana)).await.is_empty());

            // The staged notice is the courier's alone: the person, the
            // contact, a third person and the owner take nothing.
            for (who, caller) in [
                ("the person", Caller::As(&cast.ana)),
                ("the contact", Caller::As(&cast.ben)),
                ("a third person", Caller::As(&cast.cleo)),
                ("the owner", Caller::Root),
            ] {
                host.deliver(caller)
                    .await
                    .nothing(&format!("{who}'s deliver of the courier's notice"));
            }
            assert_sender_takes_the_fact(
                host.deliver(Caller::As(&cast.courier)).await,
                &cast.ana,
                &cast.ben,
                &json!({"origin": "ask", "ask_ref": ask_ref}),
            );
        },
    );
}

/// :37, :56: on the owner's imminent row a just-call naming is notified at
/// once, with no ask, and the dial change keeps the contact's consent.
#[test]
fn just_call_on_an_imminent_row_notifies_at_once_and_keeps_the_consent() {
    run_on_engine_stack(
        "just_call_on_an_imminent_row_notifies_at_once_and_keeps_the_consent",
        || async {
            let host = Host::new();
            let cast = host.cast();
            host.install_crisis_gate().await;
            host.live_naming(&cast, "ask_first").await;

            let tier = host
                .owner_ok(TIER, json!({"row_ref": CRISIS_ROW, "tier": "imminent"}))
                .await;
            assert_eq!(tier, json!({"row_ref": CRISIS_ROW, "tier": "imminent"}));
            let dialed = host
                .call(
                    Caller::As(&cast.ana),
                    DIAL,
                    json!({"contact_ref": cast.ben.id.to_hex(), "dial": "just_call"}),
                )
                .await
                .ok("the person's dial");
            assert_eq!(dialed["dial"], "just_call", "{dialed}");
            assert_eq!(dialed["version"], 1, "{dialed}");
            assert_eq!(
                dialed["accepted"]["adult"], true,
                "the dial change dropped the consent: {dialed}"
            );

            let proposal = host
                .propose(&cast.ana, PRIVATE_TURN)
                .await
                .ok("the imminent crisis");
            assert_eq!(proposal["fact"], "fact_of_concern", "{proposal}");
            assert_eq!(
                proposal["open_asks"],
                json!([]),
                "a just-call naming on the imminent tier is asked: {proposal}"
            );
            assert!(
                proposal["system_notices"]
                    .as_array()
                    .is_some_and(|notices| !notices.is_empty()),
                "the person is told the contact is called: {proposal}"
            );
            assert_quotes_nothing("the proposal", &proposal);
            assert!(host.asks(Caller::As(&cast.ana)).await.is_empty());

            for (who, caller) in [
                ("the person", Caller::As(&cast.ana)),
                ("the contact", Caller::As(&cast.ben)),
            ] {
                host.deliver(caller)
                    .await
                    .nothing(&format!("{who}'s deliver of the courier's notice"));
            }
            assert_sender_takes_the_fact(
                host.deliver(Caller::As(&cast.courier)).await,
                &cast.ana,
                &cast.ben,
                &json!({"origin": "policy", "row_ref": CRISIS_ROW, "tier": "imminent"}),
            );
        },
    );
}

/// doors.rs :4-5: a policy row's tier is the owner's. A person or an agent
/// is refused and the row stays a concern; the owner's set moves it.
#[test]
fn only_the_owner_sets_a_rows_tier() {
    run_on_engine_stack("only_the_owner_sets_a_rows_tier", || async {
        let host = Host::new();
        let cast = host.cast();
        host.install_crisis_gate().await;
        host.live_naming(&cast, "ask_first").await;

        let imminent = json!({"row_ref": CRISIS_ROW, "tier": "imminent"});
        for (who, principal) in [
            ("the person", &cast.ana),
            ("the contact", &cast.ben),
            ("a third person", &cast.cleo),
            ("an agent", &cast.courier),
        ] {
            host.call(Caller::As(principal), TIER, imminent.clone())
                .await
                .forbidden(
                    &format!("{who} setting a tier"),
                    "vault.trusted_contacts.tier.set is the vault owner's",
                );
        }

        // The refused sets left the row a concern: the crisis asks at it.
        let first = host
            .propose(&cast.ana, PRIVATE_TURN)
            .await
            .ok("a crisis after the refused sets");
        assert_eq!(first["open_asks"][0]["tier"], "concern", "{first}");
        let ask_ref = first["open_asks"][0]["ask"]
            .as_str()
            .expect("the ask's ref")
            .to_owned();
        let declined = host
            .call(
                Caller::As(&cast.ana),
                AUTHORIZE,
                json!({"ask_ref": ask_ref, "yes": false}),
            )
            .await
            .ok("the person's no");
        assert_eq!(declined["outcome"], "declined", "{declined}");

        let unwritten = host
            .call(
                Caller::Root,
                TIER,
                json!({"row_ref": "owner:unwritten", "tier": "imminent"}),
            )
            .await;
        assert_eq!(
            unwritten.status,
            StatusCode::NOT_FOUND,
            "a tier for a row the owner never wrote answered {}",
            unwritten.body
        );
        assert_eq!(host.owner_ok(TIER, imminent.clone()).await, imminent);

        // The owner's set moved the row: the next crisis asks at imminent.
        let second = host
            .propose(
                &cast.ana,
                "crisis-marker: the rail bridge at Halvard Street again",
            )
            .await
            .ok("a crisis after the owner's set");
        let open = second["open_asks"]
            .as_array()
            .expect("the proposal's open asks");
        assert_eq!(open.len(), 1, "{second}");
        assert_eq!(open[0]["tier"], "imminent", "{second}");
    });
}

/// :36 per person (doors.rs :3-4): a person reads and answers only their own
/// asks. Another person, the contact, the owner and an agent neither see nor
/// answer it, and a no stages nothing.
#[test]
fn a_person_reads_and_answers_only_their_own_asks() {
    run_on_engine_stack("a_person_reads_and_answers_only_their_own_asks", || async {
        let host = Host::new();
        let cast = host.cast();
        host.install_crisis_gate().await;
        host.live_naming(&cast, "ask_first").await;
        let proposal = host.propose(&cast.ana, PRIVATE_TURN).await.ok("the crisis");
        let ask_ref = proposal["open_asks"][0]["ask"]
            .as_str()
            .expect("the person's ask")
            .to_owned();

        for (who, principal) in [("a third person", &cast.cleo), ("the contact", &cast.ben)] {
            assert!(
                host.asks(Caller::As(principal)).await.is_empty(),
                "{who} reads the person's ask"
            );
        }
        let yes = json!({"ask_ref": ask_ref, "yes": true});
        for (who, principal) in [("a third person", &cast.cleo), ("the contact", &cast.ben)] {
            host.call(Caller::As(principal), AUTHORIZE, yes.clone())
                .await
                .forbidden(
                    &format!("{who} answering the person's ask"),
                    "this ask is not the person's",
                );
        }
        host.call(Caller::Root, AUTHORIZE, yes.clone())
            .await
            .forbidden(
                "the owner answering the person's ask",
                "consent owner not authenticated",
            );
        host.call(Caller::As(&cast.courier), AUTHORIZE, yes)
            .await
            .forbidden(
                "an agent answering the person's ask",
                "vault.trusted_contacts.concern.authorize is the vault owner's",
            );

        // The refused answers left the ask open and staged nothing.
        let open = host.asks(Caller::As(&cast.ana)).await;
        assert_eq!(open.len(), 1, "{open:?}");
        assert!(open[0]["answer"].is_null(), "{:?}", open[0]);
        host.deliver(Caller::As(&cast.courier))
            .await
            .nothing("the courier's deliver after the refused answers");

        let declined = host
            .call(
                Caller::As(&cast.ana),
                AUTHORIZE,
                json!({"ask_ref": ask_ref, "yes": false}),
            )
            .await
            .ok("the person's no");
        assert_eq!(declined["outcome"], "declined", "{declined}");
        assert_eq!(declined["system_notices"], json!([]), "{declined}");
        assert!(host.asks(Caller::As(&cast.ana)).await.is_empty());
        host.deliver(Caller::As(&cast.courier))
            .await
            .nothing("the courier's deliver after the no");
    });
}
