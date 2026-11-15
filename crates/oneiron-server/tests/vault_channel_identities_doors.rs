//! Promise tests for the `vault.channel_identities.*` doors, entered at
//! `POST /v1/core/facade/<verb>`. Canon: ARCH-0063
//! (oneiron/agents/oneiron-arch-0063-agent-inbox-email-identity-v1.md); the
//! doors' handlers are `api/facade/channel_doors.rs`.
//!
//! - :22 "a deleted self-held identity keeps its address ... a fresh id is
//!   refused", the never-recycle rule (:20 "quarantine/never-recycle") applied
//!   to a release: a self-held address the owner releases walks into the
//!   quarantine hold, keeps its occupant, routes inbound as retiring, and a
//!   new provision of the same address is refused.
//! - :71 "the product never minted it, never owns it, can never rotate or
//!   quarantine it" and :352 "no rotate/quarantine verbs on delegated rows":
//!   a delegated mailbox refuses a rotate, and its release stops at released
//!   with no hold. :22 "A delegated identity frees its key": the same mailbox
//!   binds again.
//! - :369 "Delegated custody names the exact mailbox it covers, and the engine
//!   checks that name at its door.": one member's custody record binds no
//!   other mailbox.
//! - :276 "one table decides, per RELATIONSHIP context, which face the agent
//!   wears": two relationships get two faces from one rule table, the owner's
//!   edit of a row changes the face its relationship gets, and a face no
//!   candidate wears is refused, never swapped for another face.
//! - :56 "An agent writes as itself. The owner's writer comes only from the
//!   owner's authentication, so a caller who only claims to be Human is
//!   refused": an agent's row carries the agent's stamp, an agent neither
//!   locks a row nor touches a locked one, the owner locks one, and a person
//!   is refused.
//! - The six lifecycle doors are the owner's (each row's `host_door_proof` is
//!   `owner`): an agent and a person are refused at each, and a refused call
//!   changes no row and claims no address.
//!
//! The gate: every lifecycle door but `fulfill` asks the ExternalEffect gate,
//! and the gate holds an owner's call that no scoped grant covers (a 200
//! whose outcome is `held`). The host installs one owner manifest with a
//! scoped `external:<verb>` grant per gated verb on the `email` channel, as
//! `it_esign_public.rs` does for its signing send.

#![cfg(unix)]

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
use oneiron::channel_identity::delegated_custody_scopes;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const PROVISION: &str = "vault.channel_identities.provision";
const BIND: &str = "vault.channel_identities.bind";
const FULFILL: &str = "vault.channel_identities.fulfill";
const ROTATE: &str = "vault.channel_identities.rotate";
const RELEASE: &str = "vault.channel_identities.release";
const ROUTE_INBOUND: &str = "vault.channel_identities.route_inbound";
const GET: &str = "vault.channel_identities.get";
const RULES: &str = "vault.channel_identities.selection.rules";
const UPDATE: &str = "vault.channel_identities.selection.update";
const SELECT: &str = "vault.channel_identities.select";

/// The lifecycle verbs the ExternalEffect gate decides (`fulfill` skips it).
const GATED_VERBS: [&str; 5] = ["provision", "bind", "rotate", "release", "route_inbound"];

const EMAIL: &str = "email";

/// The shipped quarantine floor (90 days); a release asks one day more.
const QUARANTINE_FLOOR_SECS: u64 = 90 * 24 * 60 * 60;
const DAY_SECS: u64 = 24 * 60 * 60;

/// The effector a delegated mailbox's custody binding serves.
const GMAIL_EFFECTOR: &str = "connector:gmail";

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

    /// Asserts `status` with error `code` and a message holding `words`.
    fn refused(&self, call: &str, status: StatusCode, code: &str, words: &str) {
        assert_eq!(self.status, status, "{call} answered {}", self.body);
        assert_eq!(self.body["error"]["code"], code, "{call}: {}", self.body);
        assert!(
            self.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(words)),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    /// Asserts a 403 `FORBIDDEN` whose message holds `words`.
    fn forbidden(&self, call: &str, words: &str) {
        self.refused(call, StatusCode::FORBIDDEN, "FORBIDDEN", words);
    }

    /// Asserts a 400 `BAD_REQUEST` whose message holds `words`.
    fn bad_request(&self, call: &str, words: &str) {
        self.refused(call, StatusCode::BAD_REQUEST, "BAD_REQUEST", words);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A self-held provision of `address` bound to `actor`, waiting on `mode`.
fn provision_input(address: &str, actor: EntityId, mode: &str) -> Value {
    json!({
        "channel": EMAIL,
        "address_or_handle": address,
        "shape": "dedicated_address",
        "binding": {"kind": "actor", "actor_ref": actor.to_hex(), "facet_ref": null},
        "fulfillment_mode": mode,
    })
}

/// A delegated bind of `mailbox` to `actor` under the custody record
/// `custody`, waiting on `mode`.
fn delegated_bind_input(mailbox: &str, custody: &str, actor: EntityId, mode: &str) -> Value {
    json!({
        "kind": "delegated",
        "channel": EMAIL,
        "address_or_handle": mailbox,
        "binding": {"kind": "actor", "actor_ref": actor.to_hex(), "facet_ref": null},
        "grant": {"custody_record_ref": custody, "scopes": ["mail.read"]},
        "fulfillment_mode": mode,
    })
}

/// One selection rule row as `selection.update` takes it, with no pin.
fn rule(rule_id: &str, relationship: &str, scope: Value, face: &str, amendable: bool) -> Value {
    json!({
        "rule_id": rule_id,
        "relationship": relationship,
        "scope": scope,
        "face": face,
        "pinned_identity_ref": null,
        "priority": 10,
        "enabled": true,
        "agent_amendable": amendable,
    })
}

/// An upsert of `rule` over the table at `revision`.
fn upsert(revision: u64, rule: Value) -> Value {
    json!({"expected_revision": revision, "patch": {"kind": "upsert", "rule": rule}})
}

/// The row `rule_id` of a rule-table answer.
fn row<'a>(table: &'a Value, rule_id: &str) -> &'a Value {
    table["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["rule_id"] == rule_id))
        .unwrap_or_else(|| panic!("the table holds no row {rule_id}: {table}"))
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temporary vault directory");
        let vault =
            Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("vault-channel-identities-doors".into()),
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
        let host = Self {
            _dir: dir,
            vault,
            app: build_app(server),
            issuer,
            slip,
            token,
            owner,
        };
        host.grant_lifecycle_effects();
        host
    }

    /// The owner's manifest: a scoped `external:<verb>` grant per gated
    /// lifecycle verb on the email channel, so the gate allows the owner's
    /// lifecycle calls rather than holding them.
    fn grant_lifecycle_effects(&self) {
        let mut effect = Scope::top();
        effect.verbs = ScopeAxis::Some(["effect".to_owned()].into());
        let grants = GATED_VERBS
            .iter()
            .map(|verb| {
                json!({
                    "actor_ref": self.owner.to_hex(),
                    "effector": format!("external:{verb}"),
                    "scope": effect,
                    "selectors": {"channel": EMAIL},
                })
            })
            .collect::<Vec<_>>();
        oneiron::conversation_dag::test_support::put_test_policy_manifest(
            &self.vault,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            EntityId::now(),
            &json!({
                "schema_version": "1.2",
                "pack_id": "channel-identity-doors",
                "pack_version": "v1",
                "min_engine_version": "0.0.0",
                "defaults": {"criticality": "normal", "sensitivity": "normal"},
                "rules": [],
                "actor_ceilings": [{
                    "actor_class": "human",
                    "actor_ref": self.owner.to_hex(),
                    "ceiling": "auto",
                }],
                "scoped_grants": grants,
            }),
        )
        .expect("install the owner's lifecycle grants");
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
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
        )
        .expect("the person's body");
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
            .expect("the person");
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

    /// A live custody record `name` whose Gmail binding grants read of
    /// `mailbox` and names it as its subject: the member's OAuth grant.
    fn custody(&self, name: &str, mailbox: &str) {
        self.vault
            .register_secret(SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: name.to_owned(),
                class: CustodyClass::CrossVault,
                device_only: true,
                model_reveal_allowed: false,
                value_bytes: b"member-oauth-token".to_vec(),
                status: SecretCustodyStatus::Active,
                registered_at: 1_800_000_000,
                rotated_at: None,
                rotation_generation: 0,
                bindings: vec![SecretBinding {
                    effector: GMAIL_EFFECTOR.to_owned(),
                    tier_ceiling: CustodyTier::T0Doored,
                    scopes: delegated_custody_scopes(EMAIL, mailbox),
                }],
                manifest_ref: String::new(),
                declared_paths: Vec::new(),
                policy_floor_snapshot: SecretCustodyFloor::default(),
            })
            .expect("the member's custody record");
    }

    /// A release window one day past the shipped quarantine floor.
    fn quarantine_until(&self) -> u64 {
        self.vault.now_recorded_at() + QUARANTINE_FLOOR_SECS + DAY_SECS
    }

    /// The owner's `get` of `identity`.
    async fn get(&self, identity: &Value) -> Value {
        self.owner_ok(GET, json!({"identity_ref": identity})).await
    }

    /// Takes a requested identity live: the lifecycle answer of `call` must
    /// wait on fulfillment, and the owner's fulfill then makes it active.
    /// Returns its `identity_ref`.
    async fn fulfilled(&self, call: &str, requested: Value) -> Value {
        assert_eq!(
            requested["outcome"], "pending_fulfillment",
            "{call}: {requested}"
        );
        assert_eq!(
            requested["identity"]["state"], "pending_fulfillment",
            "{call}: {requested}"
        );
        assert!(
            requested["gate_receipt_ref"].is_string(),
            "{call} names the gate's receipt: {requested}"
        );
        let identity = requested["identity_ref"].clone();
        let live = self
            .owner_ok(FULFILL, json!({"identity_ref": identity}))
            .await;
        assert_eq!(live["outcome"], "active", "{live}");
        assert_eq!(live["identity"]["state"], "active", "{live}");
        identity
    }

    /// The owner provisions `address` for `actor` and takes it live.
    async fn self_held(&self, address: &str, actor: EntityId) -> Value {
        let requested = self
            .owner_ok(PROVISION, provision_input(address, actor, "manual"))
            .await;
        self.fulfilled(PROVISION, requested).await
    }

    /// `select` for `relationship` over `candidates` (`(identity_ref, face)`).
    async fn select(&self, relationship: &str, candidates: &[(&Value, &str)]) -> Reply {
        let candidates = candidates
            .iter()
            .map(|(identity, face)| json!({"identity_ref": identity, "face": face}))
            .collect::<Vec<_>>();
        self.call(
            Caller::Root,
            SELECT,
            json!({"relationship": relationship, "candidates": candidates}),
        )
        .await
    }
}

/// :22 with :20: a released self-held address stays held in quarantine and
/// is never handed out again.
#[test]
fn a_released_self_held_address_stays_held_and_is_never_handed_out_again() {
    run_on_engine_stack(
        "a_released_self_held_address_stays_held_and_is_never_handed_out_again",
        || async {
            const ADDRESS: &str = "agent-desk@example.test";
            let host = Host::new();
            let keeper = host.agent("channel-keeper", 0x81);

            let identity = host.self_held(ADDRESS, keeper.id).await;
            let live = host.get(&identity).await;
            assert_eq!(live["state"], "active", "{live}");
            assert_eq!(live["custody"], "self_held", "{live}");
            assert_eq!(live["occupies_assignment_key"], true, "{live}");
            assert!(live["quarantine_until"].is_null(), "{live}");
            let routed = host
                .owner_ok(ROUTE_INBOUND, json!({"identity_ref": identity}))
                .await;
            assert_eq!(routed["outcome"], "routable", "{routed}");
            assert_eq!(routed["owner_visible_state"], "routable", "{routed}");

            let until = host.quarantine_until();
            let released = host
                .owner_ok(
                    RELEASE,
                    json!({"identity_ref": identity, "quarantine_until": until}),
                )
                .await;
            assert_eq!(released["outcome"], "quarantine", "{released}");
            assert_eq!(
                released["owner_visible_state"], "identity_retiring",
                "{released}"
            );
            assert_eq!(released["outbound_closed"], true, "{released}");
            assert_eq!(released["identity_retiring"], true, "{released}");
            assert_eq!(released["identity"]["state"], "quarantine", "{released}");
            assert_eq!(
                released["identity"]["quarantine_until"], until,
                "{released}"
            );

            let held = host.get(&identity).await;
            assert_eq!(held["state"], "quarantine", "{held}");
            assert_eq!(held["address_or_handle"], ADDRESS, "{held}");
            assert_eq!(held["occupies_assignment_key"], true, "{held}");
            assert_eq!(held["outbound_eligible"], false, "{held}");
            assert_eq!(held["quarantine_until"], until, "{held}");

            // A new request for the same address (another fulfillment lane,
            // so it is no replay of the first) is refused at the slot.
            host.call(
                Caller::Root,
                PROVISION,
                provision_input(ADDRESS, keeper.id, "review"),
            )
            .await
            .bad_request(PROVISION, "channel identity already exists");
            let still = host.get(&identity).await;
            assert_eq!(still["state"], "quarantine", "{still}");
            assert_eq!(still["occupies_assignment_key"], true, "{still}");

            let retiring = host
                .owner_ok(ROUTE_INBOUND, json!({"identity_ref": identity}))
                .await;
            assert_eq!(retiring["outcome"], "routable", "{retiring}");
            assert_eq!(
                retiring["owner_visible_state"], "identity_retiring",
                "{retiring}"
            );
            assert_eq!(retiring["outbound_closed"], true, "{retiring}");
            assert_eq!(retiring["identity_retiring"], true, "{retiring}");
        },
    );
}

/// :71 and :352: a delegated mailbox is never rotated or quarantined; :22:
/// its release frees its key, so the same mailbox binds again.
#[test]
fn a_delegated_mailbox_is_never_rotated_or_quarantined_and_its_release_frees_it() {
    run_on_engine_stack(
        "a_delegated_mailbox_is_never_rotated_or_quarantined_and_its_release_frees_it",
        || async {
            const MAILBOX: &str = "yara.member@example.test";
            const GRANT: &str = "yara-gmail-grant";
            let host = Host::new();
            let keeper = host.agent("channel-keeper", 0x81);
            host.custody(GRANT, MAILBOX);

            let requested = host
                .owner_ok(
                    BIND,
                    delegated_bind_input(MAILBOX, GRANT, keeper.id, "manual"),
                )
                .await;
            assert_eq!(
                requested["identity"]["shape"], "delegated_grant",
                "{requested}"
            );
            assert_eq!(requested["identity"]["custody"], "delegated", "{requested}");
            let identity = host.fulfilled(BIND, requested).await;
            let live = host.get(&identity).await;
            assert_eq!(live["state"], "active", "{live}");
            assert_eq!(live["occupies_assignment_key"], true, "{live}");

            host.call(Caller::Root, ROTATE, json!({"identity_ref": identity}))
                .await
                .bad_request(ROTATE, "never rotated or quarantined");
            let unrotated = host.get(&identity).await;
            assert_eq!(unrotated["state"], "active", "{unrotated}");

            let released = host
                .owner_ok(
                    RELEASE,
                    json!({"identity_ref": identity, "quarantine_until": host.quarantine_until()}),
                )
                .await;
            assert_eq!(released["outcome"], "released", "{released}");
            assert_eq!(
                released["owner_visible_state"], "identity_retiring",
                "{released}"
            );
            assert_eq!(released["outbound_closed"], true, "{released}");
            assert_eq!(released["identity"]["state"], "released", "{released}");
            assert!(
                released["identity"]["quarantine_until"].is_null(),
                "a delegated release takes no hold: {released}"
            );

            let retired = host.get(&identity).await;
            assert_eq!(retired["state"], "released", "{retired}");
            assert_eq!(retired["custody"], "delegated", "{retired}");
            assert_eq!(retired["outbound_eligible"], false, "{retired}");
            assert_eq!(retired["occupies_assignment_key"], false, "{retired}");

            let again = host
                .owner_ok(
                    BIND,
                    delegated_bind_input(MAILBOX, GRANT, keeper.id, "review"),
                )
                .await;
            assert_eq!(again["outcome"], "pending_fulfillment", "{again}");
            assert_ne!(
                again["identity_ref"], identity,
                "a re-consent is a new identity: {again}"
            );
        },
    );
}

/// :369: a member's custody record binds that member's own mailbox and no
/// other.
#[test]
fn a_custody_record_binds_only_the_mailbox_it_names() {
    run_on_engine_stack(
        "a_custody_record_binds_only_the_mailbox_it_names",
        || async {
            const INES: &str = "ines.member@example.test";
            const JONAS: &str = "jonas.member@example.test";
            const INES_GRANT: &str = "ines-gmail-grant";
            let host = Host::new();
            let keeper = host.agent("channel-keeper", 0x81);
            host.custody(INES_GRANT, INES);

            host.call(
                Caller::Root,
                BIND,
                delegated_bind_input(JONAS, INES_GRANT, keeper.id, "manual"),
            )
            .await
            .bad_request(BIND, GMAIL_EFFECTOR);
            host.call(
                Caller::Root,
                BIND,
                delegated_bind_input(JONAS, "no-such-grant", keeper.id, "manual"),
            )
            .await
            .bad_request(BIND, "no-such-grant");

            let own = host
                .owner_ok(
                    BIND,
                    delegated_bind_input(INES, INES_GRANT, keeper.id, "manual"),
                )
                .await;
            assert_eq!(own["identity"]["address_or_handle"], INES, "{own}");
            assert_eq!(own["identity"]["custody"], "delegated", "{own}");
            let identity = host.fulfilled(BIND, own).await;
            assert_eq!(host.get(&identity).await["state"], "active");

            // The refusals claimed nothing: Jonas's own record binds his
            // mailbox.
            host.custody("jonas-gmail-grant", JONAS);
            let jonas = host
                .owner_ok(
                    BIND,
                    delegated_bind_input(JONAS, "jonas-gmail-grant", keeper.id, "manual"),
                )
                .await;
            assert_eq!(jonas["outcome"], "pending_fulfillment", "{jonas}");
        },
    );
}

/// :276: one table gives each relationship its own face; the owner's edit of
/// a row changes the face that relationship gets, and a face no candidate
/// wears is refused rather than swapped.
#[test]
fn one_table_gives_each_relationship_its_own_face() {
    run_on_engine_stack("one_table_gives_each_relationship_its_own_face", || async {
        let host = Host::new();
        let keeper = host.agent("channel-keeper", 0x81);
        let named = host.self_held("desk@example.test", keeper.id).await;
        let side = host
            .self_held("outreach@side.example.test", keeper.id)
            .await;
        let candidates = [
            (&named, "agent_named_address"),
            (&side, "side_domain_address"),
        ];

        let table = host.owner_ok(RULES, json!({})).await;
        assert_eq!(table["revision"], 0, "{table}");
        let rows = table["rows"].as_array().expect("the table's rows");
        assert_eq!(rows.len(), 6, "{table}");
        for row in rows {
            assert_eq!(row["agent_amendable"], true, "{row}");
            assert_eq!(row["writer_kind"], "system_default", "{row}");
        }
        assert_eq!(
            row(&table, "builtin.scheduling_logistics")["face"],
            "agent_named_address"
        );
        assert_eq!(
            row(&table, "builtin.campaign_outreach")["face"],
            "side_domain_address"
        );

        let scheduling = host
            .select("scheduling_logistics", &candidates)
            .await
            .ok(SELECT);
        assert_eq!(scheduling["revision"], 0, "{scheduling}");
        assert_eq!(
            scheduling["decision"]["identity_ref"], named,
            "{scheduling}"
        );
        assert_eq!(
            scheduling["decision"]["face"], "agent_named_address",
            "{scheduling}"
        );
        assert_eq!(
            scheduling["decision"]["rule_id"], "builtin.scheduling_logistics",
            "{scheduling}"
        );
        assert_eq!(
            scheduling["decision"]["used_thread_pin"], false,
            "{scheduling}"
        );
        assert_eq!(scheduling["mask"]["identity_ref"], named, "{scheduling}");
        let campaign = host
            .select("campaign_outreach", &candidates)
            .await
            .ok(SELECT);
        assert_eq!(campaign["decision"]["identity_ref"], side, "{campaign}");
        assert_eq!(
            campaign["decision"]["face"], "side_domain_address",
            "{campaign}"
        );

        // No candidate wears the house face: refused, never another face.
        host.select("transactional_system", &candidates)
            .await
            .refused(
                SELECT,
                StatusCode::CONFLICT,
                "INVALID_STATE",
                "no active candidate wears",
            );

        // The owner moves scheduling onto the side domain.
        let mut moved = rule(
            "builtin.scheduling_logistics",
            "scheduling_logistics",
            json!({"kind": "vault_default"}),
            "side_domain_address",
            true,
        );
        moved["priority"] = json!(0);
        let edited = host.owner_ok(UPDATE, upsert(0, moved)).await;
        assert_eq!(edited["revision"], 1, "{edited}");
        let edited_row = row(&edited, "builtin.scheduling_logistics");
        assert_eq!(edited_row["face"], "side_domain_address", "{edited}");
        assert_eq!(edited_row["writer_kind"], "owner", "{edited}");
        assert_eq!(edited_row["updated_by"], host.owner.to_hex(), "{edited}");
        assert_eq!(
            edited["rows"].as_array().map(Vec::len),
            Some(6),
            "the edit replaced its row in place: {edited}"
        );

        let rescheduled = host
            .select("scheduling_logistics", &candidates)
            .await
            .ok(SELECT);
        assert_eq!(rescheduled["revision"], 1, "{rescheduled}");
        assert_eq!(
            rescheduled["decision"]["identity_ref"], side,
            "{rescheduled}"
        );
        assert_eq!(
            rescheduled["decision"]["rule_id"], "builtin.scheduling_logistics",
            "{rescheduled}"
        );
        let unchanged = host
            .select("campaign_outreach", &candidates)
            .await
            .ok(SELECT);
        assert_eq!(unchanged["decision"]["identity_ref"], side, "{unchanged}");
    });
}

/// :56: an agent writes a row as itself and cannot lock one or touch a
/// locked one; the owner's writer comes only from the owner's proof, so the
/// owner locks a row and a person is refused.
#[test]
fn only_the_owner_writes_as_the_owner_and_an_agent_writes_as_itself() {
    run_on_engine_stack(
        "only_the_owner_writes_as_the_owner_and_an_agent_writes_as_itself",
        || async {
            const ROW: &str = "agent.space_alpha";
            let host = Host::new();
            let keeper = host.agent("channel-keeper", 0x81);
            let mina = host.person("Mina Okafor-Lindqvist", 0x82);
            let space = || json!({"kind": "space", "space_ref": "space.alpha"});
            let amendable = rule(ROW, "group_space", space(), "agent_named_address", true);
            let locked = rule(ROW, "group_space", space(), "agent_named_address", false);

            let written = host
                .call(Caller::As(&keeper), UPDATE, upsert(0, amendable.clone()))
                .await
                .ok(UPDATE);
            assert_eq!(written["revision"], 1, "{written}");
            assert_eq!(row(&written, ROW)["writer_kind"], "agent", "{written}");
            assert_eq!(
                row(&written, ROW)["updated_by"],
                keeper.id.to_hex(),
                "{written}"
            );

            host.call(Caller::As(&keeper), UPDATE, upsert(1, locked.clone()))
                .await
                .forbidden(UPDATE, "an agent writer cannot lock");

            let owned = host.owner_ok(UPDATE, upsert(1, locked)).await;
            assert_eq!(owned["revision"], 2, "{owned}");
            assert_eq!(row(&owned, ROW)["writer_kind"], "owner", "{owned}");
            assert_eq!(
                row(&owned, ROW)["updated_by"],
                host.owner.to_hex(),
                "{owned}"
            );
            assert_eq!(row(&owned, ROW)["agent_amendable"], false, "{owned}");

            host.call(Caller::As(&keeper), UPDATE, upsert(2, amendable.clone()))
                .await
                .forbidden(UPDATE, "not agent-amendable");
            host.call(
                Caller::As(&keeper),
                UPDATE,
                json!({"expected_revision": 2, "patch": {"kind": "remove", "rule_id": ROW}}),
            )
            .await
            .forbidden(UPDATE, "not agent-amendable");

            host.call(Caller::As(&mina), UPDATE, upsert(2, amendable))
                .await
                .forbidden(UPDATE, &format!("{UPDATE} is the vault owner's"));

            // A stale revision is refused for the owner as well.
            host.call(
                Caller::Root,
                UPDATE,
                upsert(
                    0,
                    rule(
                        "owner.late",
                        "work_deal",
                        space(),
                        "agent_named_address",
                        true,
                    ),
                ),
            )
            .await
            .refused(
                UPDATE,
                StatusCode::CONFLICT,
                "INVALID_STATE",
                "revision conflict",
            );

            let table = host.owner_ok(RULES, json!({})).await;
            assert_eq!(table["revision"], 2, "{table}");
            assert_eq!(row(&table, ROW)["writer_kind"], "owner", "{table}");
            assert_eq!(row(&table, ROW)["agent_amendable"], false, "{table}");
            let readable = host
                .call(Caller::As(&keeper), RULES, json!({}))
                .await
                .ok(RULES);
            assert_eq!(readable["revision"], 2, "{readable}");
        },
    );
}

/// The six lifecycle doors are the owner's: an agent and a person are
/// refused at each, and a refused call changes no row and claims no address.
#[test]
fn no_lifecycle_door_opens_for_anyone_but_the_owner() {
    run_on_engine_stack(
        "no_lifecycle_door_opens_for_anyone_but_the_owner",
        || async {
            const KEPT: &str = "kept@example.test";
            const UNCLAIMED: &str = "unclaimed@example.test";
            const MAILBOX: &str = "olu.member@example.test";
            const GRANT: &str = "olu-gmail-grant";
            let host = Host::new();
            let keeper = host.agent("channel-keeper", 0x81);
            let mina = host.person("Mina Okafor-Lindqvist", 0x82);
            host.custody(GRANT, MAILBOX);
            let identity = host.self_held(KEPT, keeper.id).await;
            let until = host.quarantine_until();

            let doors = [
                (PROVISION, provision_input(UNCLAIMED, keeper.id, "manual")),
                (
                    BIND,
                    delegated_bind_input(MAILBOX, GRANT, keeper.id, "manual"),
                ),
                (FULFILL, json!({"identity_ref": identity})),
                (ROTATE, json!({"identity_ref": identity})),
                (
                    RELEASE,
                    json!({"identity_ref": identity, "quarantine_until": until}),
                ),
                (ROUTE_INBOUND, json!({"identity_ref": identity})),
            ];
            for caller in [&keeper, &mina] {
                for (verb, input) in &doors {
                    host.call(Caller::As(caller), verb, input.clone())
                        .await
                        .forbidden(verb, &format!("{verb} is the vault owner's"));
                }
            }

            let kept = host.get(&identity).await;
            assert_eq!(kept["state"], "active", "{kept}");
            assert!(kept["quarantine_until"].is_null(), "{kept}");

            // Neither refused provision nor refused bind claimed its address.
            let unclaimed = host
                .owner_ok(PROVISION, provision_input(UNCLAIMED, keeper.id, "manual"))
                .await;
            assert_eq!(unclaimed["outcome"], "pending_fulfillment", "{unclaimed}");
            let bound = host
                .owner_ok(
                    BIND,
                    delegated_bind_input(MAILBOX, GRANT, keeper.id, "manual"),
                )
                .await;
            assert_eq!(bound["outcome"], "pending_fulfillment", "{bound}");
        },
    );
}
