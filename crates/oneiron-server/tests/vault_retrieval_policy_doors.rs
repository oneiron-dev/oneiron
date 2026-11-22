//! Promise tests for the retrieval policy and outcome doors (ruling L4-23 = A:
//! each test proves a promise at its door): `vault.retrieval.policy.get`,
//! `.pin`, `.train`, `.evaluate`, `.admit` and `.update`, and
//! `vault.retrieval.outcomes.put` and `.end`, each entered at its generated
//! HTTP facade route, `POST /v1/core/facade/<verb>`.
//!
//! The promises, one test each:
//! - The retrieval policy is the owner's (canon ARCH-0037 :141, "Owner calls
//!   train, evaluate, admit and update the policy"; :251, a pin "fixes the
//!   value read"): a person, an agent that holds no grant and another vault's
//!   credential are refused at all six policy doors, read no policy, and move
//!   no weight, pin or posterior. The owner's pin lands, and no other caller
//!   clears it.
//! - The outcome labels are the owner's (ARCH-0037 :338, "Only the Owner uses
//!   the telemetry doors"; :56, an outcome "carries the reward signal"): the
//!   same callers are refused at both outcome doors, the refusal is the same
//!   for a run that exists and one that does not, and no refused outcome
//!   lands on the run. The owner's outcome lands.
//!
//! Refusals, and the owner's own pin and outcome, only: open PRs #7753 (read
//! shape pins) and #8444 (natural outcomes) change what an admitted pin,
//! update or end outcome does; neither changes who is admitted.
//!
//! The owner calls on the host-root credential of a profiled install, as a
//! serving start enrols it; a person and an agent on a slip of their own,
//! signed by their own key. The vault captures retrieval runs. Deterministic:
//! an in-process vault and router (`oneshot`), no TCP port, no sleep, no
//! model (recall reads by text alone).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_retrieval_policy_doors`.

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
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The word the seeded row holds and the recall asks for.
const WORD: &str = "quillmoor";
/// The words of every owner door's refusal.
const OWNER_REFUSAL: &str = "is the vault owner's";
/// The key of every outcome sent here.
const OUTCOME_KEY: &str = "policy-door-label";

const POLICY_GET: &str = "vault.retrieval.policy.get";
const POLICY_PIN: &str = "vault.retrieval.policy.pin";
const POLICY_TRAIN: &str = "vault.retrieval.policy.train";
const POLICY_EVALUATE: &str = "vault.retrieval.policy.evaluate";
const POLICY_ADMIT: &str = "vault.retrieval.policy.admit";
const POLICY_UPDATE: &str = "vault.retrieval.policy.update";
const OUTCOMES_PUT: &str = "vault.retrieval.outcomes.put";
const OUTCOMES_END: &str = "vault.retrieval.outcomes.end";

/// One served vault: the owner on the host root of a profiled install; the
/// vault captures retrieval runs.
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
            "{call} must say `{words}`: {}",
            self.body
        );
    }

    /// Asserts an owner door's refusal of `caller`: another vault's
    /// credential is refused before any door (401 or 403); a person or an
    /// agent of this vault meets the door's owner refusal.
    fn refused(&self, call: &str, caller: Caller<'_>) {
        if matches!(caller, Caller::Stranger(_)) {
            assert!(
                matches!(
                    self.status,
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "{call} answered {}",
                self.body
            );
        } else {
            self.forbidden(call, OWNER_REFUSAL);
        }
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

    /// Asserts that the reply holds no part of a policy view.
    fn reads_no_policy(&self, call: &str) {
        let text = self.body.to_string();
        for field in ["policy_version", "posterior", "pins", "manifest_digest"] {
            assert!(
                !text.contains(field),
                "{call} reads no policy ({field}): {text}"
            );
        }
    }
}

/// A host whose vault serves the facade and captures retrieval runs; its
/// owner is the vault's embedded owner, on the host root.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    config.retrieval_telemetry_capture = true;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-retrieval-policy-doors".into()),
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

/// A run id that names no run.
fn unknown_run() -> Value {
    json!({"bytes": vec![0x5a_u8; 16]})
}

/// The input outcome door `verb` is called with: an outcome of `run`, in
/// `turn` at the end door.
fn outcome(verb: &str, run: &Value, turn: [u8; 16]) -> Value {
    match verb {
        OUTCOMES_PUT => json!({
            "run_id": run,
            "key": OUTCOME_KEY,
            "reward": 0.5,
            "accepted": true,
            "metadata": {},
        }),
        OUTCOMES_END => json!({
            "retrievalRunIds": [run],
            "key": OUTCOME_KEY,
            "turn_id": turn,
            "gate_score": 0.5,
            "confirmed_fact_hit": true,
            "latency_scale_us": 1_000,
            "cost_weight": 0.0,
            "metadata": {},
        }),
        other => panic!("no outcome input for {other}"),
    }
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

    /// One approved, active claim about the owner that says `value`, its
    /// text published, so a recall has a row to read.
    fn claim(&self, value: &str) {
        let id = EntityId::now();
        let body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from(value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("a claim body");
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
            .expect("put the claim");
        self.vault
            .set_indexed_idle_delay_ms(0)
            .expect("idle delay row");
        let published = self
            .vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .expect("idle publication");
        assert!(
            published.failed.is_empty(),
            "every staged text publishes: {published:?}"
        );
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

    /// The served policy, as the owner reads it.
    async fn owner_policy(&self) -> Value {
        self.send(Caller::Owner, POLICY_GET, json!({}))
            .await
            .ok(POLICY_GET)
    }

    /// The owner's recall of [`WORD`], stamped with `turn`; the run it left.
    async fn recalled_run(&self, turn: [u8; 16]) -> Value {
        let episode = [0x0e_u8; 16];
        let input = json!({
            "query": WORD,
            "effort": "light",
            "limit": 10,
            "telemetry": {
                "capture_trace": true,
                "turn": {"turn_id": turn, "episode_id": episode, "turn_idx": 1},
            },
        });
        let pack = self
            .send(Caller::Owner, "vault.retrieval.recall", input)
            .await
            .ok("vault.retrieval.recall");
        let run = pack["retrieval_run_id"].clone();
        assert!(!run.is_null(), "a captured recall names its run: {pack}");
        run
    }

    /// The outcomes the owner reads on `run`.
    async fn outcomes(&self, run: &Value) -> Value {
        self.send(Caller::Owner, "vault.retrieval.run", json!({"run_id": run}))
            .await
            .ok("vault.retrieval.run")["outcomes"]
            .clone()
    }
}

/// The retrieval policy is the owner's: canon
/// `oneiron/retrieval/oneiron-arch-0037-retrieval-telemetry-and-policy-v1.md:141`,
/// "Owner calls train, evaluate, admit and update the policy", and :251, a
/// pin "fixes the value read". A person on their own slip, a full-access
/// agent that holds no grant and another vault's owner are refused at the
/// get, pin, train, evaluate, admit and update doors; no refusal holds any
/// part of the policy, and the refusals move no weight, pin or posterior.
/// The owner's pin lands, and a pin clear from any of them is refused and
/// leaves it.
#[test]
fn the_retrieval_policy_answers_its_owner_alone() {
    run_on_engine_stack("retrieval-policy-owner", || async {
        let (host, other) = (host(), host());
        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("policy-agent", 0x32);
        let callers = [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ];
        let before = host.owner_policy().await;
        assert_eq!(
            before["pins"],
            json!([]),
            "a fresh vault pins no weight: {before}"
        );

        let pin = json!({"signal": "recency", "value": 0.25});
        let weights = json!({
            "recency": 0.175,
            "salience": 0.15,
            "confidence": 0.1,
            "gravity": 0.075,
            "relevance": 0.5,
        });
        let digest = "0".repeat(64);
        let doors = [
            (POLICY_GET, json!({})),
            (POLICY_PIN, pin.clone()),
            (POLICY_TRAIN, json!({})),
            (
                POLICY_EVALUATE,
                json!({"weights": weights.clone(), "config": {}}),
            ),
            (
                POLICY_ADMIT,
                json!({"weights": weights, "manifest_digest": digest, "config": {}}),
            ),
            (POLICY_UPDATE, json!({})),
        ];
        for (who, caller) in callers {
            for (verb, input) in &doors {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input.clone()).await;
                reply.refused(&call, caller);
                reply.reads_no_policy(&call);
            }
        }
        assert_eq!(
            host.owner_policy().await,
            before,
            "a refused call moves no weight, pin or posterior"
        );

        let pinned = host
            .send(Caller::Owner, POLICY_PIN, pin.clone())
            .await
            .ok(POLICY_PIN);
        assert_eq!(
            pinned["pins"],
            json!([pin]),
            "the owner's pin lands: {pinned}"
        );
        assert_eq!(
            host.owner_policy().await,
            pinned,
            "the read answers the owner's pin"
        );

        let clear = json!({"signal": "recency"});
        for (who, caller) in callers {
            let call = format!("{who} clearing the owner's pin");
            host.send(caller, POLICY_PIN, clear.clone())
                .await
                .refused(&call, caller);
        }
        assert_eq!(
            host.owner_policy().await,
            pinned,
            "a refused clear leaves the owner's pin"
        );
    });
}

/// The outcome labels are the owner's: canon
/// `oneiron/retrieval/oneiron-arch-0037-retrieval-telemetry-and-policy-v1.md:338`,
/// "Only the Owner uses the telemetry doors", and :56, an outcome "carries
/// the reward signal". The owner's recall leaves a run. A person, a
/// full-access agent that holds no grant and another vault's owner are
/// refused at the outcome put and end doors; the refusal for the recorded
/// run is the refusal for a run that does not exist, and no refused outcome
/// lands on the run. The owner's outcome lands, and the run holds it.
#[test]
fn the_retrieval_outcomes_answer_their_owner_alone() {
    run_on_engine_stack("retrieval-policy-outcomes", || async {
        let (host, other) = (host(), host());
        host.claim(&format!("the {WORD} harbour opens at dawn"));
        let turn = [0x3d_u8; 16];
        let run = host.recalled_run(turn).await;
        assert_eq!(
            host.outcomes(&run).await,
            json!([]),
            "a fresh run holds no outcome"
        );

        let person = host.person("Ines Varga", 0x41);
        let agent = host.agent("outcome-agent", 0x42);
        let unknown = unknown_run();
        let unknown_turn = [0x6b_u8; 16];
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for verb in [OUTCOMES_PUT, OUTCOMES_END] {
                let call = format!("{who} at {verb}");
                let refused = host.send(caller, verb, outcome(verb, &run, turn)).await;
                refused.refused(&call, caller);
                let refused_unknown = host
                    .send(caller, verb, outcome(verb, &unknown, unknown_turn))
                    .await;
                assert_eq!(
                    refused.refusal(),
                    refused_unknown.refusal(),
                    "{call}: the refusal does not say whether the run exists"
                );
            }
        }
        assert_eq!(
            host.outcomes(&run).await,
            json!([]),
            "no refused outcome lands on the run"
        );

        let put = host
            .send(
                Caller::Owner,
                OUTCOMES_PUT,
                outcome(OUTCOMES_PUT, &run, turn),
            )
            .await
            .ok(OUTCOMES_PUT);
        assert!(
            put.as_array().is_some_and(|rows| rows.len() == 1
                && rows[0]["key"] == OUTCOME_KEY
                && rows[0]["reward"] == 0.5),
            "the owner's outcome lands: {put}"
        );
        assert_eq!(
            host.outcomes(&run).await,
            put,
            "the run holds the owner's outcome"
        );
    });
}
