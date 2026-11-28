//! Promise tests for the model doors (ruling L4-23 = A: each test proves a
//! promise at its door): `vault.models.manifest.read` and `.replace`,
//! `.routes.read`, `.roles.read` and `.invoke`, `.oneironer.bind`,
//! `.catalog.get`, `.diff` and `.refresh`, the six `.trials.*` doors, and
//! `.bindings.propose`, `.get`, `.read`, `.accept` and `.deny`, and
//! `.descriptions.set` and `.read`, each entered at its generated HTTP facade
//! route, `POST /v1/core/facade/<verb>`.
//!
//! The promises, one test each:
//! - Where the vault's model calls run is the owner's rule (canon ARCH-0036
//!   :327, "R9 makes the route dial per-vault policy"; :159, "Every binding
//!   is a manifest row"): a person, an agent that holds no grant and another
//!   vault's credential are refused at the manifest, route and role doors and
//!   at the Oneironer bind; a refused replace that would send the llm slot to
//!   a third party moves nothing. The owner's narrowing to the device lands,
//!   and the role receipt names it.
//! - The catalog is evidence (`model_catalog_doors.rs:1-2`, "Only an explicit
//!   owner acceptance can change a role binding; refresh, nomination, trials
//!   and denial never do"; ARCH-0036 :161, "A catalog row is an offer"): the
//!   same callers are refused at get, diff and refresh, and the owner's
//!   refresh lands a revision and changes no role binding.
//! - A model trial answers its owner alone: the same callers are refused at
//!   all six trial doors, the refusal is the same for a trial that exists and
//!   one that does not, and nothing moves the trial.
//! - A binding proposal serves nothing until its owner accepts it: no other
//!   caller reads, accepts or denies it; the owner's acceptance binds the
//!   candidate, and a later denial cannot undo it.
//! - A denied proposal changes no binding, and no acceptance follows it.
//! - A seat description row is its owner's word (FIX
//!   SEAT-DESCRIPTION-ROW-NO-PUBLIC-DOOR; Engine ACCEPT
//!   PLAN-SEAT-DESCRIPTION-DOOR, 28 Nov 13:13): the row decides which model a
//!   run is born on (llm/seat.rs, a birth reads it), so the same callers are
//!   refused at set and read, no refusal names a model and nothing is
//!   stored. The owner's row is the one the seat pick reads; it needs a
//!   registered model, a facet and a line; the read answers it, and the set
//!   answers the row it replaced. A host with no code-mode seat pick reports
//!   no facet (`api/tests/mcp_quickjs.rs` proves a host that binds one).
//!
//! Left out: `vault.models.routes.replace` (open #8977 and #8978 delete it),
//! an agent's granted proposal (`model_binding_proposer_grant.rs` proves it
//! at the door), and every owner call that needs a served model seat (the
//! answer of roles.invoke, trials.run).
//!
//! The vault holds one completed held-out trial offer, its catalog revision
//! and a manifest, from the cfg door
//! `oneiron::test_doors::model_binding_proposer`. The owner calls on the
//! host-root credential of a profiled install, as a serving start enrols it;
//! a person and an agent on a slip of their own, signed by their own key.
//! Deterministic: an in-process vault and router (`oneshot`), no TCP port, no
//! sleep, no model.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_models_owner_doors`.

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
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::seat::{ModelDescription, SeatDescriptionsRead};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::model_binding_proposer::{
    PROPOSE_ROLE, TrialFixture, ensure_completed_trial_offer,
};
use oneiron::{EntityId, ModelId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const MANIFEST_READ: &str = "vault.models.manifest.read";
const MANIFEST_REPLACE: &str = "vault.models.manifest.replace";
const ROUTES_READ: &str = "vault.models.routes.read";
const ROLES_READ: &str = "vault.models.roles.read";
const ROLES_INVOKE: &str = "vault.models.roles.invoke";
const ONEIRONER_BIND: &str = "vault.models.oneironer.bind";
const CATALOG_GET: &str = "vault.models.catalog.get";
const CATALOG_DIFF: &str = "vault.models.catalog.diff";
const CATALOG_REFRESH: &str = "vault.models.catalog.refresh";
const TRIALS_NOMINATE: &str = "vault.models.trials.nominate";
const TRIALS_GET: &str = "vault.models.trials.get";
const TRIALS_APPROVE: &str = "vault.models.trials.approve";
const TRIALS_RUN: &str = "vault.models.trials.run";
const TRIALS_COMPLETE: &str = "vault.models.trials.complete";
const TRIALS_RESEND_ARM: &str = "vault.models.trials.resend_arm";
const BINDINGS_PROPOSE: &str = "vault.models.bindings.propose";
const BINDINGS_GET: &str = "vault.models.bindings.get";
const BINDINGS_READ: &str = "vault.models.bindings.read";
const BINDINGS_ACCEPT: &str = "vault.models.bindings.accept";
const BINDINGS_DENY: &str = "vault.models.bindings.deny";
const DESCRIPTIONS_SET: &str = "vault.models.descriptions.set";
const DESCRIPTIONS_READ: &str = "vault.models.descriptions.read";

/// The prefix of every model the fixture names: no refusal may hold one.
const FIXTURE_MODELS: &str = "test/bp-";

/// One served vault: the owner on the host root of a profiled install.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// A person or an agent on its own slip, signed by its own key.
struct Principal {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request: this vault's owner on the host root, another
/// vault's owner on that vault's host root, or a principal.
#[derive(Clone, Copy)]
enum Caller<'a> {
    Owner,
    Stranger(&'a Host),
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

    /// Asserts `verb`'s owner refusal of `caller`: another vault's
    /// credential is refused before any door (401 or 403); a person or an
    /// agent of this vault meets the door's `<verb> is the vault owner's`.
    fn refused(&self, call: &str, verb: &str, caller: Caller<'_>) {
        if matches!(caller, Caller::Stranger(_)) {
            assert!(
                matches!(
                    self.status,
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "{call} answered {}",
                self.body
            );
            return;
        }
        assert_eq!(
            self.status,
            StatusCode::FORBIDDEN,
            "{call} answered {}",
            self.body
        );
        assert_eq!(self.body["error"]["code"], "FORBIDDEN", "{call}");
        assert_eq!(
            self.body["error"]["message"],
            format!("{verb} is the vault owner's"),
            "{call}"
        );
    }

    /// Asserts a client error whose message holds `words`.
    fn rejected(&self, call: &str, words: &str) {
        assert!(
            self.status.is_client_error(),
            "{call} answered {}",
            self.body
        );
        assert!(
            self.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(words)),
            "{call} must say `{words}`: {}",
            self.body
        );
    }

    /// The refusal as a caller can compare it: status, code, message and
    /// suggestions. The request id differs per call.
    fn refusal(&self) -> Value {
        let error = &self.body["error"];
        json!({
            "status": self.status.as_u16(),
            "code": error["code"],
            "message": error["message"],
            "suggestions": error["suggestions"],
        })
    }

    /// Asserts that the reply holds none of `words`.
    fn holds_none(&self, call: &str, words: &[&str]) {
        let text = self.body.to_string();
        for word in words {
            assert!(!text.contains(word), "{call} holds `{word}`: {text}");
        }
    }
}

/// A host whose vault serves the facade; its owner is the vault's embedded
/// owner, on the host root.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-models-owner-doors".into()),
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
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Host {
        _dir: dir,
        vault,
        app: build_app(server),
        issuer,
        owner,
        owner_slip,
        owner_token,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The propose input for the fixture trial: the role, with the incumbent's
/// binding and only the measured model changed to the candidate.
fn propose_input(trial: &TrialFixture) -> Value {
    json!({
        "question": trial.question.to_hex(),
        "trial": trial.trial.to_hex(),
        "role": PROPOSE_ROLE,
        "binding": {"model": trial.candidate, "slot": "llm", "tier": trial.tier},
    })
}

/// The model `reply` names, as a string.
fn model(reply: &Value) -> &str {
    reply["model"].as_str().unwrap_or_default()
}

impl Host {
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// `holder`'s own slip as a `class` caller that allows `verbs`, signed
    /// by the key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8, verbs: &[&str]) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
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
        Principal { slip, key }
    }

    /// A person named `name` whom this vault knows, on a read-and-write
    /// human slip of their own.
    fn person(&self, name: &str, seed: u8) -> Principal {
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
        self.principal(id, "human", seed, &["core:read", "core:write"])
    }

    /// The vault's own agent `name`, bound with full access, on its own
    /// read-and-write slip. It holds no grant.
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
        self.principal(agent, "agent", seed, &["core:read", "core:write"])
    }

    /// `caller`'s call to `verb` at its facade route, sent to this host.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let root = |host: &Host| {
            (
                host.owner_token.clone(),
                hex(&host
                    .issuer
                    .binding_proof(&host.owner_slip, &challenge)
                    .expect("owner holder proof")),
            )
        };
        let (token, signature) = match caller {
            Caller::Owner => root(self),
            Caller::Stranger(other) => root(other),
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
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
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
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("facade response body");
        // An authentication refusal may answer text, not the JSON envelope.
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Reply { status, body }
    }

    /// The owner's 200 answer at `verb`.
    async fn owner_call(&self, verb: &str, input: Value) -> Value {
        self.send(Caller::Owner, verb, input).await.ok(verb)
    }

    /// The binding the manifest holds for the fixture role.
    async fn binding(&self) -> Value {
        self.owner_call(BINDINGS_READ, json!({"role": PROPOSE_ROLE}))
            .await
    }

    /// The receipt of the fixture role.
    async fn role(&self) -> Value {
        self.owner_call(ROLES_READ, json!({"role": PROPOSE_ROLE}))
            .await
    }

    /// The owner's proposal of the trial's candidate for the fixture role.
    async fn proposal(&self, trial: &TrialFixture) -> Value {
        let proposal = self
            .owner_call(BINDINGS_PROPOSE, propose_input(trial))
            .await;
        assert_eq!(proposal["status"], "proposed", "{proposal}");
        proposal
    }
}

/// Where the vault's model calls run is the owner's rule: canon
/// `oneiron/extraction/oneiron-arch-0036-model-families-v1.md:327`, "R9 makes
/// the route dial per-vault policy", and :159, "Every binding is a manifest
/// row". A person on their own slip, a full-access agent that holds no grant
/// and another vault's owner are refused at the manifest read and replace,
/// the route and role reads, the role call and the Oneironer bind; no
/// refusal names a model. A refused replace that would send the llm slot to
/// a third party moves no route. The owner's narrowing of the llm slot to
/// the device lands, and the role receipt names the device; with no
/// Oneironer loaded, the owner's own bind is refused and moves nothing.
#[test]
fn where_the_model_calls_run_is_the_owners_rule() {
    run_on_engine_stack("models-manifest-owner", || async {
        let (host, other) = (host(), host());
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("models-agent", 0x32);
        let manifest = host.owner_call(MANIFEST_READ, json!({})).await;
        assert_eq!(manifest["routes"]["llm"], "own_server", "{manifest}");
        let llm = json!({"slot": "llm"});
        let route = host.owner_call(ROUTES_READ, llm.clone()).await;
        let role = host.role().await;
        assert_eq!(model(&role), trial.incumbent, "{role}");

        let mut cloud = manifest.clone();
        cloud["routes"]["llm"] = json!("third_party");
        let doors = [
            (MANIFEST_READ, json!({})),
            (MANIFEST_REPLACE, json!({"manifest": cloud})),
            (ROUTES_READ, llm.clone()),
            (ROLES_READ, json!({"role": PROPOSE_ROLE})),
            (
                ROLES_INVOKE,
                json!({
                    "role": "retrieval_embedder",
                    "input": {"kind": "embed", "text": "where the harbour opens"},
                }),
            ),
            (ONEIRONER_BIND, json!({})),
        ];
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for (verb, input) in &doors {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input.clone()).await;
                reply.refused(&call, verb, caller);
                reply.holds_none(&call, &[FIXTURE_MODELS, "own_server"]);
            }
        }
        assert_eq!(
            host.owner_call(MANIFEST_READ, json!({})).await,
            manifest,
            "a refused replace moves nothing"
        );
        assert_eq!(host.owner_call(ROUTES_READ, llm.clone()).await, route);
        assert_eq!(host.role().await, role);

        let mut device = manifest.clone();
        device["routes"]["llm"] = json!("on_device");
        let replaced = host
            .owner_call(MANIFEST_REPLACE, json!({"manifest": device}))
            .await;
        assert_eq!(replaced, device, "the owner's narrowing lands");
        let narrowed = host.owner_call(ROUTES_READ, llm).await;
        assert_eq!(
            (&narrowed["pin"], &narrowed["route"]),
            (&json!("on_device"), &json!("on_device")),
            "{narrowed}"
        );
        let receipt = host.role().await;
        assert_eq!(receipt["route"], "on_device", "{receipt}");
        assert_eq!(model(&receipt), trial.incumbent, "{receipt}");

        let bind = host.send(Caller::Owner, ONEIRONER_BIND, json!({})).await;
        assert_eq!(
            (bind.status, &bind.body["error"]["code"]),
            (StatusCode::SERVICE_UNAVAILABLE, &json!("MODEL_UNAVAILABLE")),
            "only a loaded Oneironer binds: {}",
            bind.body
        );
        assert_eq!(host.owner_call(MANIFEST_READ, json!({})).await, device);
    });
}

/// The catalog is evidence: `model_catalog_doors.rs:1-2`, "Only an explicit
/// owner acceptance can change a role binding; refresh, nomination, trials
/// and denial never do", and canon ARCH-0036 :161, "A catalog row is an
/// offer". A person, a full-access agent that holds no grant and another
/// vault's owner are refused at the catalog get, diff and refresh doors; no
/// refusal names a model, and a refused refresh moves no revision. The
/// owner's refresh lands a new revision and leaves the role's binding.
#[test]
fn the_model_catalog_is_evidence_its_owner_alone_refreshes() {
    run_on_engine_stack("models-catalog-owner", || async {
        let (host, other) = (host(), host());
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let person = host.person("Ines Varga", 0x41);
        let agent = host.agent("catalog-agent", 0x42);
        let head = json!({"revision": null});
        let catalog = host.owner_call(CATALOG_GET, head.clone()).await;
        let revision = catalog["revision"].clone();
        assert!(revision.is_string(), "the fixture's revision: {catalog}");
        let binding = host.binding().await;
        assert_eq!(model(&binding), trial.incumbent, "{binding}");
        let refresh = |next: &str| {
            json!({
                "revision": next,
                "expected_revision": revision,
                "catalog": catalog["catalog"],
                "scores": [],
            })
        };

        let doors = [
            (CATALOG_GET, json!({"revision": revision})),
            (CATALOG_DIFF, json!({"from": revision, "to": revision})),
            (CATALOG_REFRESH, refresh("models-door-catalog-2")),
        ];
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for (verb, input) in &doors {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input.clone()).await;
                reply.refused(&call, verb, caller);
                reply.holds_none(&call, &[FIXTURE_MODELS]);
            }
        }
        assert_eq!(
            host.owner_call(CATALOG_GET, head.clone()).await,
            catalog,
            "a refused refresh moves no revision"
        );

        let refreshed = host
            .owner_call(CATALOG_REFRESH, refresh("models-door-catalog-3"))
            .await;
        assert_eq!(
            (&refreshed["revision"], &refreshed["previous_revision"]),
            (&json!("models-door-catalog-3"), &revision),
            "the owner's refresh lands"
        );
        assert_eq!(
            host.owner_call(CATALOG_GET, head).await["revision"],
            "models-door-catalog-3"
        );
        assert_eq!(
            host.binding().await,
            binding,
            "a refresh changes no role binding"
        );
        assert_eq!(model(&host.role().await), trial.incumbent);
    });
}

/// A model trial answers its owner alone: its view holds the held-out cases
/// and their labels. A person, a full-access agent that holds no grant and
/// another vault's owner are refused at the nominate, get, approve, run,
/// complete and resend-arm doors; the refusal for the fixture's trial is the
/// refusal for a trial that does not exist, no refusal names the trial or a
/// model, and the trial reads back unchanged.
#[test]
fn a_model_trial_answers_its_owner_alone() {
    run_on_engine_stack("models-trials-owner", || async {
        let (host, other) = (host(), host());
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let person = host.person("Ines Varga", 0x51);
        let agent = host.agent("trials-agent", 0x52);
        let (question, id) = (trial.question.to_hex(), trial.trial.to_hex());
        let get = json!({"question": question, "trial": id});
        let view = host.owner_call(TRIALS_GET, get.clone()).await;
        assert!(
            view["cases"]
                .as_array()
                .is_some_and(|cases| !cases.is_empty()),
            "the owner reads the held-out cases: {view}"
        );
        let assessment = view["receipt"]["assessment"].clone();
        assert!(assessment.is_object(), "a completed trial: {view}");
        let answer = view["cases"][0]["selection"]["answer"].clone();
        let doors = |trial: &str| {
            let trial_ref = json!({"question": question, "trial": trial});
            [
                (TRIALS_GET, trial_ref.clone()),
                (TRIALS_APPROVE, trial_ref.clone()),
                (TRIALS_RUN, trial_ref),
                (
                    TRIALS_COMPLETE,
                    json!({"question": question, "trial": trial, "assessment": assessment}),
                ),
                (
                    TRIALS_RESEND_ARM,
                    json!({
                        "question": question,
                        "trial": trial,
                        "answer": answer,
                        "arm": "candidate",
                    }),
                ),
            ]
        };
        let made_up = EntityId::now().to_hex();
        let nominate =
            json!({"catalog_revision": view["catalog_revision"], "request": view["request"]});

        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            let call = format!("{who} at {TRIALS_NOMINATE}");
            let reply = host.send(caller, TRIALS_NOMINATE, nominate.clone()).await;
            reply.refused(&call, TRIALS_NOMINATE, caller);
            for ((verb, input), (_, unknown)) in doors(&id).into_iter().zip(doors(&made_up)) {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input).await;
                reply.refused(&call, verb, caller);
                reply.holds_none(&call, &[id.as_str(), FIXTURE_MODELS, "cases"]);
                let refused_unknown = host.send(caller, verb, unknown).await;
                assert_eq!(
                    reply.refusal(),
                    refused_unknown.refusal(),
                    "{call}: the refusal does not say whether the trial exists"
                );
            }
        }
        assert_eq!(
            host.owner_call(TRIALS_GET, get).await,
            view,
            "a refused call moves nothing in the trial"
        );
    });
}

/// A binding proposal serves nothing until its owner accepts it:
/// `model_catalog_doors.rs:1-2`, "Only an explicit owner acceptance can
/// change a role binding". The owner proposes the trial's candidate; the
/// role still binds and reads the incumbent. A person, a full-access agent
/// that holds no grant and another vault's owner are refused at the
/// proposal's get, accept and deny and at the binding read; each refusal is
/// the refusal for a proposal that does not exist, and the proposal stays
/// proposed. The owner's acceptance binds the candidate, and a later denial
/// is refused and leaves it.
#[test]
fn a_binding_proposal_serves_nothing_until_its_owner_accepts() {
    run_on_engine_stack("models-bindings-accept", || async {
        let (host, other) = (host(), host());
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let person = host.person("Ines Varga", 0x61);
        let agent = host.agent("bindings-agent", 0x62);
        let incumbent = host.binding().await;
        assert_eq!(model(&incumbent), trial.incumbent, "{incumbent}");
        let proposal = host.proposal(&trial).await;
        let id = proposal["id"]
            .as_str()
            .expect("the proposal's id")
            .to_owned();
        assert_eq!(host.binding().await, incumbent, "a proposal binds nothing");
        assert_eq!(model(&host.role().await), trial.incumbent);

        let made_up = EntityId::now().to_hex();
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for verb in [BINDINGS_GET, BINDINGS_ACCEPT, BINDINGS_DENY] {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, json!({"proposal": id})).await;
                reply.refused(&call, verb, caller);
                reply.holds_none(&call, &[id.as_str(), FIXTURE_MODELS]);
                let refused_unknown = host.send(caller, verb, json!({"proposal": made_up})).await;
                assert_eq!(
                    reply.refusal(),
                    refused_unknown.refusal(),
                    "{call}: the refusal does not say whether the proposal exists"
                );
            }
            let call = format!("{who} at {BINDINGS_READ}");
            let reply = host
                .send(caller, BINDINGS_READ, json!({"role": PROPOSE_ROLE}))
                .await;
            reply.refused(&call, BINDINGS_READ, caller);
            reply.holds_none(&call, &[FIXTURE_MODELS]);
        }
        assert_eq!(
            host.owner_call(BINDINGS_GET, json!({"proposal": id})).await,
            proposal,
            "a refused accept or deny settles nothing"
        );
        assert_eq!(host.binding().await, incumbent);

        let accepted = host
            .owner_call(BINDINGS_ACCEPT, json!({"proposal": id}))
            .await;
        assert_eq!(accepted["status"], "accepted", "{accepted}");
        let candidate = host.binding().await;
        assert_eq!(model(&candidate), trial.candidate, "{candidate}");
        assert_eq!(model(&host.role().await), trial.candidate);
        host.send(Caller::Owner, BINDINGS_DENY, json!({"proposal": id}))
            .await
            .rejected("a denial after the acceptance", "already settled");
        assert_eq!(host.binding().await, candidate, "the acceptance stands");
    });
}

/// A denied proposal changes no binding: `model_catalog_doors.rs:1-2`,
/// "refresh, nomination, trials and denial never do". The owner proposes the
/// trial's candidate and denies it; the role still binds and reads the
/// incumbent, and an acceptance after the denial is refused and binds
/// nothing.
#[test]
fn a_denied_binding_proposal_changes_no_binding() {
    run_on_engine_stack("models-bindings-deny", || async {
        let host = host();
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let incumbent = host.binding().await;
        let id = host.proposal(&trial).await["id"].clone();
        let denied = host
            .owner_call(BINDINGS_DENY, json!({"proposal": id}))
            .await;
        assert_eq!(denied["status"], "denied", "{denied}");
        assert!(!denied["settled_at"].is_null(), "{denied}");
        assert_eq!(host.binding().await, incumbent, "a denial binds nothing");
        assert_eq!(model(&host.role().await), trial.incumbent);

        host.send(Caller::Owner, BINDINGS_ACCEPT, json!({"proposal": id}))
            .await
            .rejected("an acceptance after the denial", "already settled");
        assert_eq!(host.binding().await, incumbent);
        assert_eq!(
            host.owner_call(BINDINGS_GET, json!({"proposal": id})).await,
            denied,
            "the denial stands"
        );
    });
}

/// The seat description row `model` gets under `facet`, with the owner's
/// line alone.
fn seat_row(model: &str, facet: &str) -> ModelDescription {
    ModelDescription {
        model: ModelId::new(model).expect("fixture model id"),
        facet: facet.to_owned(),
        owner: Some(format!("{facet} work, by the owner")),
        measured: None,
        benchmarks: None,
        vendor: None,
    }
}

/// The owner's row is the one a seat birth reads (`Vault::model_description`,
/// llm/seat.rs: a birth seats only a model whose row names the task's
/// facet). Before the owner's set the model has none; after it, exactly the
/// row written. In-process, the answer names no host facet.
#[test]
fn an_owner_seat_description_is_the_row_the_seat_pick_reads() {
    run_on_engine_stack("models-seat-description-birth-row", || async {
        let host = host();
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let row = seat_row(&trial.incumbent, "code-task");
        assert_eq!(
            host.vault.model_description(&row.model).expect("read"),
            None
        );
        let written = host
            .vault
            .set_model_description_as_owner(&host.owner_proof(), row.clone())
            .expect("the owner's set");
        assert_eq!(written.description, row);
        assert_eq!(written.replaced, None);
        assert_eq!(
            (written.seat_facet, written.host_facet_matches),
            (None, None)
        );
        assert_eq!(
            host.vault.model_description(&row.model).expect("read"),
            Some(row),
            "the seat pick reads the owner's row"
        );
    });
}

/// A row needs a registered model, a facet and at least one line; a refused
/// set stores nothing.
#[test]
fn a_seat_description_needs_a_registered_model_a_facet_and_a_line() {
    run_on_engine_stack("models-seat-description-checks", || async {
        let host = host();
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let owner = host.owner_proof();
        let unregistered = seat_row("test/bp-unregistered@r1", "code-task");
        let mut no_facet = seat_row(&trial.incumbent, "code-task");
        no_facet.facet = " ".to_owned();
        let mut no_line = seat_row(&trial.incumbent, "code-task");
        no_line.owner = None;
        for refused in [unregistered, no_facet, no_line] {
            assert!(
                host.vault
                    .set_model_description_as_owner(&owner, refused.clone())
                    .is_err(),
                "{refused:?}"
            );
        }
        let read = host
            .vault
            .model_descriptions_as_owner(&owner, SeatDescriptionsRead::default())
            .expect("the owner's read");
        assert_eq!(read.rows, Vec::new(), "a refused set stores nothing");
    });
}

/// The read answers every row in key order, or one model's; a set over a
/// described model answers the row it replaced.
#[test]
fn the_seat_description_read_answers_what_the_owner_wrote() {
    run_on_engine_stack("models-seat-description-read", || async {
        let host = host();
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let owner = host.owner_proof();
        let incumbent = seat_row(&trial.incumbent, "code-task");
        let candidate = seat_row(&trial.candidate, "code-task");
        for row in [&incumbent, &candidate] {
            host.vault
                .set_model_description_as_owner(&owner, row.clone())
                .expect("the owner's set");
        }
        let mut both = vec![incumbent.clone(), candidate.clone()];
        both.sort_by(|a, b| a.model.as_str().cmp(b.model.as_str()));
        let all = host
            .vault
            .model_descriptions_as_owner(&owner, SeatDescriptionsRead::default())
            .expect("read every row");
        assert_eq!(all.rows, both);
        let one = host
            .vault
            .model_descriptions_as_owner(
                &owner,
                SeatDescriptionsRead {
                    model: Some(candidate.model.clone()),
                },
            )
            .expect("read one row");
        assert_eq!(one.rows, vec![candidate]);
        let review = seat_row(&trial.incumbent, "review-task");
        let rewritten = host
            .vault
            .set_model_description_as_owner(&owner, review.clone())
            .expect("the owner's second set");
        assert_eq!(rewritten.replaced, Some(incumbent));
        assert_eq!(
            host.vault.model_description(&review.model).expect("read"),
            Some(review)
        );
    });
}

/// A seat description is its owner's word: a person on their own slip, a
/// full-access agent that holds no grant and another vault's owner are
/// refused at the set and the read, no refusal names a model, and nothing is
/// stored. The owner's set lands at its HTTP door and the read answers it;
/// this host binds no code-mode seat pick, so both report no facet.
#[test]
fn a_seat_description_is_its_owners_word() {
    run_on_engine_stack("models-seat-description-owner", || async {
        let (host, other) = (host(), host());
        let trial = ensure_completed_trial_offer(&host.vault).expect("a completed trial offer");
        let person = host.person("Ines Varga", 0x61);
        let agent = host.agent("descriptions-agent", 0x62);
        let row = json!({"model": trial.incumbent, "facet": "code-task", "owner": "code-task work, by the owner"});
        let doors = [
            (DESCRIPTIONS_SET, row.clone()),
            (DESCRIPTIONS_READ, json!({})),
        ];
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for (verb, input) in &doors {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input.clone()).await;
                reply.refused(&call, verb, caller);
                reply.holds_none(&call, &[FIXTURE_MODELS, "code-task"]);
            }
        }
        let model = ModelId::new(&trial.incumbent).expect("fixture model id");
        assert_eq!(
            host.vault.model_description(&model).expect("read"),
            None,
            "a refused set stores nothing"
        );
        let written = host.owner_call(DESCRIPTIONS_SET, row).await;
        assert_eq!(
            written["description"]["model"], trial.incumbent,
            "{written}"
        );
        assert_eq!(written["description"]["facet"], "code-task", "{written}");
        assert_eq!(written["replaced"], Value::Null, "{written}");
        assert_eq!(written["seat_facet"], Value::Null, "{written}");
        assert_eq!(written["host_facet_matches"], Value::Null, "{written}");
        let read = host.owner_call(DESCRIPTIONS_READ, json!({})).await;
        assert_eq!(read["rows"].as_array().map(Vec::len), Some(1), "{read}");
        assert_eq!(read["rows"][0]["model"], trial.incumbent, "{read}");
        assert_eq!(read["seat_facet"], Value::Null, "{read}");
    });
}
