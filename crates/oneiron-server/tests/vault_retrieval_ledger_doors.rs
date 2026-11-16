//! Promise tests for the retrieval ledger doors (ruling L4-23 = A: each test
//! proves a promise at its door): `vault.retrieval.recall`, `.run`, `.runs`,
//! `.turn`, `.trace`, `.export` and `.replay`, each entered at its generated
//! HTTP facade route, `POST /v1/core/facade/<verb>`.
//!
//! The promises, one test each:
//! - The run ledger is the owner's (the door module's rule,
//!   `retrieval_doors.rs`: "Typed owner-only retrieval diagnostics"; canon
//!   ARCH-0037 :338, "Only the Owner uses the telemetry doors"): what a recall
//!   read comes back to the owner alone. A person, an agent and another
//!   vault's credential are refused at every door, the refusal is the same
//!   for a run that exists and one that does not, and a refused recall leaves
//!   no run. No answer holds the query's words (ARCH-0037 :332).
//! - A Steward grant naming `read` opens the run list and nothing else
//!   (untangle 6.6c, `vault.retrieval.runs`).
//! - A recall reads base reality plus the worlds its caller chose, never
//!   every world (ARCH-0022 :176), and its run, trace, export and replay name
//!   no row of a world it did not read.
//! - The diagnostic recall answers what the plain recall answers: it still
//!   narrows through the one serving door (FIX 2905, `retrieval_doors.rs`).
//!
//! Not here: the policy, outcome and configuration doors of the family
//! (open PRs #7753 and #8444 change the policy and outcome rows).
//!
//! The owner calls on the host-root credential of a profiled install, as a
//! serving start enrols it; a person and each agent on a slip of its own,
//! signed by its own key. The vault captures retrieval runs. Deterministic:
//! an in-process vault and router (`oneshot`), no TCP port, no sleep, no
//! model (recall reads by text alone).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_retrieval_ledger_doors`.

#![cfg(all(unix, oneiron_test_support))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
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
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::steward::{STEWARD_READ_VERB, stand_steward_grant};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The word every seeded row holds and every recall here asks for.
const WORD: &str = "quillmoor";
/// The doors that read one recorded run, or the recall that records one.
const OWNER_DOORS: [&str; 6] = [
    "vault.retrieval.recall",
    "vault.retrieval.run",
    "vault.retrieval.turn",
    "vault.retrieval.trace",
    "vault.retrieval.export",
    "vault.retrieval.replay",
];
/// The words of every owner door's refusal.
const OWNER_REFUSAL: &str = "is the vault owner's";
/// The words of the run list's refusal of a caller holding no grant.
const READER_REFUSAL: &str = "Steward grant naming `read`";

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
    id: EntityId,
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
                auth_secret: Some("vault-retrieval-ledger-doors".into()),
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

/// `id`'s bytes as a recorded run names a row: a JSON array of 16 numbers.
fn row_bytes(id: EntityId) -> String {
    json!(id.as_bytes()).to_string()
}

/// The ids of the rows a recall's pack answers.
fn item_ids(pack: &Value) -> BTreeSet<String> {
    pack["items"]
        .as_array()
        .expect("a pack's items")
        .iter()
        .filter_map(|item| item["record"]["id"].as_str().map(str::to_owned))
        .collect()
}

/// The worlds a recall's pack says its scope left out.
fn left_out_worlds(pack: &Value) -> Value {
    pack["scope_honesty"]["out_of_scope_worlds"].clone()
}

/// A run id that names no run.
fn unknown_run() -> Value {
    json!({"bytes": [0x5a; 16]})
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
        Principal {
            id: holder,
            slip,
            key,
        }
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
    /// read-and-write slip.
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

    /// A WORLD row other than base reality; its id.
    fn world(&self) -> EntityId {
        let world = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault
            .put_entity(
                &world,
                ENTITY_TYPE_WORLD,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"world",
            )
            .expect("the WORLD row");
        world
    }

    /// One approved, active claim about the owner that says `value`, in
    /// `world` (base reality when `None`); its id.
    fn claim(&self, value: &str, world: Option<EntityId>) -> EntityId {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(self.owner),
            rmpv::Value::from(value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("a claim body");
        body.world = world;
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
        id
    }

    /// Publishes every staged text, as the idle loop does on a model-free
    /// host, so a recall reads every seeded row by its words.
    fn publish_text(&self) {
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

    /// The owner's diagnostic recall of [`WORD`] under `scope` (none when
    /// `Null`), capturing its trace in `turn`; the pack.
    async fn recall(&self, verb: &str, scope: Value, turn: [u8; 16]) -> Value {
        let mut input = json!({
            "query": WORD,
            "effort": "light",
            "limit": 10,
            "telemetry": {
                "capture_trace": true,
                "turn": {"turn_id": turn, "episode_id": [0x0e; 16], "turn_idx": 1},
            },
        });
        if !scope.is_null() {
            input["scope"] = scope;
        }
        self.send(Caller::Owner, verb, input).await.ok(verb)
    }

    /// The owner's reads of `run` at the five doors that read one run: each
    /// door with its input and answer.
    async fn run_reads(&self, run: &Value, turn: [u8; 16]) -> Vec<(&'static str, Value)> {
        let evidence = self
            .send(Caller::Owner, "vault.retrieval.run", json!({"run_id": run}))
            .await
            .ok("vault.retrieval.run");
        let fork_hash = evidence["run"]["trace"]["fork_hash"].clone();
        assert!(
            fork_hash.as_array().is_some_and(|bytes| bytes.len() == 32),
            "a captured run keeps its trace's fork hash: {evidence}"
        );
        let mut reads = vec![("vault.retrieval.run", evidence)];
        for (verb, input) in [
            ("vault.retrieval.turn", json!({"turn_id": turn})),
            ("vault.retrieval.trace", json!({"fork_hash": fork_hash})),
            ("vault.retrieval.export", json!({"run_ids": [run]})),
            ("vault.retrieval.replay", json!({"run_ids": [run]})),
        ] {
            let answer = self.send(Caller::Owner, verb, input).await.ok(verb);
            reads.push((verb, answer));
        }
        reads
    }

    /// The run ids the owner's run list holds.
    async fn listed_runs(&self) -> Vec<Value> {
        self.send(Caller::Owner, "vault.retrieval.runs", json!({}))
            .await
            .ok("vault.retrieval.runs")
            .as_array()
            .expect("the run list")
            .iter()
            .map(|evidence| evidence["run"]["run_id"].clone())
            .collect()
    }
}

/// The inputs each owner door is called with in a refusal case: `real`
/// names the recorded run, its turn and its fork hash, and `!real` names
/// none that exists.
fn door_input(verb: &str, run: &Value, turn: [u8; 16], fork: &Value, real: bool) -> Value {
    let (run, turn, fork) = if real {
        (run.clone(), json!(turn), fork.clone())
    } else {
        (unknown_run(), json!([0x6b; 16]), json!([0x7c; 32]))
    };
    match verb {
        "vault.retrieval.recall" => json!({"query": WORD, "effort": "light", "limit": 10}),
        "vault.retrieval.run" => json!({"run_id": run}),
        "vault.retrieval.turn" => json!({"turn_id": turn}),
        "vault.retrieval.trace" => json!({"fork_hash": fork}),
        "vault.retrieval.export" | "vault.retrieval.replay" => json!({"run_ids": [run]}),
        other => panic!("no input for {other}"),
    }
}

/// The run ledger is the owner's: canon
/// `oneiron/retrieval/oneiron-arch-0037-retrieval-telemetry-and-policy-v1.md:338`,
/// "Only the Owner uses the telemetry doors", and the door module's "Typed
/// owner-only retrieval diagnostics". The owner's recall leaves a run that
/// the run, run list, turn, trace, export and replay doors each answer, and
/// no answer holds the query's word (ARCH-0037 :332, "Raw query text | Never
/// persisted"). A person on their own slip, a full-access agent and another
/// vault's owner are refused at all seven doors; at each door that names a
/// run, the refusal for the recorded run is the refusal for a run that does
/// not exist; and the refused recalls leave no run.
#[test]
fn the_run_ledger_answers_its_owner_alone() {
    run_on_engine_stack("retrieval-ledger-owner", || async {
        let host = host();
        let other = host();
        host.claim(&format!("the {WORD} harbour opens at dawn"), None);
        host.publish_text();
        let turn = [0x1d; 16];

        let pack = host
            .recall("vault.retrieval.recall", Value::Null, turn)
            .await;
        assert!(
            !item_ids(&pack).is_empty(),
            "the recall reads the claim: {pack}"
        );
        let run = pack["retrieval_run_id"].clone();
        assert!(!run.is_null(), "a captured recall names its run: {pack}");
        let reads = host.run_reads(&run, turn).await;
        let fork = reads[0].1["run"]["trace"]["fork_hash"].clone();
        let run_bytes = run["bytes"].to_string();
        for (verb, answer) in &reads {
            if *verb == "vault.retrieval.trace" {
                assert_eq!(answer["fork_hash"], fork, "{verb} answers the run's trace");
            } else {
                assert!(
                    answer.to_string().contains(&run_bytes),
                    "{verb} answers the owner's run: {answer}"
                );
            }
            assert!(
                !answer.to_string().contains(WORD),
                "{verb} holds no word of the query: {answer}"
            );
        }
        let before = host.listed_runs().await;
        assert!(
            before.contains(&run),
            "the run list holds the run: {before:?}"
        );

        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("ledger-agent", 0x32);
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for verb in OWNER_DOORS {
                let refused = host
                    .send(caller, verb, door_input(verb, &run, turn, &fork, true))
                    .await;
                let call = format!("{who} at {verb}");
                if matches!(caller, Caller::Stranger(_)) {
                    assert!(
                        matches!(
                            refused.status,
                            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                        ),
                        "{call} answered {}",
                        refused.body
                    );
                } else {
                    refused.forbidden(&call, OWNER_REFUSAL);
                }
                let unknown = host
                    .send(caller, verb, door_input(verb, &run, turn, &fork, false))
                    .await;
                assert_eq!(
                    refused.refusal(),
                    unknown.refusal(),
                    "{call}: the refusal does not say whether the run exists"
                );
            }
            let listed = host.send(caller, "vault.retrieval.runs", json!({})).await;
            let call = format!("{who} at vault.retrieval.runs");
            if matches!(caller, Caller::Stranger(_)) {
                assert!(
                    matches!(
                        listed.status,
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                    ),
                    "{call} answered {}",
                    listed.body
                );
                assert!(
                    !listed.body.to_string().contains(&run_bytes),
                    "{call} names no run: {}",
                    listed.body
                );
            } else {
                listed.forbidden(&call, READER_REFUSAL);
            }
        }

        assert_eq!(
            host.listed_runs().await,
            before,
            "a refused recall leaves no run"
        );
    });
}

/// A Steward grant naming `read` opens the run list and nothing else: the
/// door's rule (`vault.retrieval.runs`, "the owner under its proof, or a
/// holder of a Steward grant naming `read` (untangle 6.6c)"). An agent is
/// refused at the run list until the owner stands its grant; with it, the
/// list answers the owner's run, and the six owner doors still refuse it.
#[test]
fn a_steward_read_grant_opens_the_run_list_alone() {
    run_on_engine_stack("retrieval-ledger-steward", || async {
        let host = host();
        host.claim(&format!("the {WORD} ferry runs at noon"), None);
        host.publish_text();
        let turn = [0x2d; 16];
        let pack = host
            .recall("vault.retrieval.recall", Value::Null, turn)
            .await;
        let run = pack["retrieval_run_id"].clone();
        assert!(!run.is_null(), "a captured recall names its run: {pack}");
        let fork = host.run_reads(&run, turn).await[0].1["run"]["trace"]["fork_hash"].clone();

        let reader = host.agent("ledger-reader", 0x41);
        host.send(Caller::As(&reader), "vault.retrieval.runs", json!({}))
            .await
            .forbidden("an agent with no grant at the run list", READER_REFUSAL);

        stand_steward_grant(&host.vault, reader.id, &[STEWARD_READ_VERB])
            .expect("the owner stands the agent's Steward read grant");
        let listed = host
            .send(Caller::As(&reader), "vault.retrieval.runs", json!({}))
            .await
            .ok("the read grant holder at vault.retrieval.runs");
        assert!(
            listed
                .as_array()
                .expect("the run list")
                .iter()
                .any(|evidence| evidence["run"]["run_id"] == run),
            "the run list answers the holder the owner's run: {listed}"
        );
        for verb in OWNER_DOORS {
            host.send(
                Caller::As(&reader),
                verb,
                door_input(verb, &run, turn, &fork, true),
            )
            .await
            .forbidden(&format!("the read grant holder at {verb}"), OWNER_REFUSAL);
        }
    });
}

/// A recall reads a set of worlds, never every world: canon
/// `oneiron/identity/oneiron-arch-0022-identity-world-model-v1.md:176`,
/// "The public recall default reads base reality plus the actor's active
/// world, or base alone when no default is granted". One word lives in a
/// base claim and in a claim of another world that the owner has no default
/// for. The owner's diagnostic recall with no scope answers the base claim,
/// not the world's, and says it left that world out; the run, its trace,
/// export and replay name the base claim and no row of that world. Chosen,
/// the world answers (its claim was readable all along).
#[test]
fn a_recall_reads_base_and_no_world_its_caller_did_not_choose() {
    run_on_engine_stack("retrieval-ledger-worlds", || async {
        let host = host();
        let world = host.world();
        let base_claim = host.claim(&format!("the {WORD} lighthouse is white"), None);
        let world_claim = host.claim(&format!("the {WORD} lighthouse is red"), Some(world));
        host.publish_text();
        let turn = [0x3d; 16];

        let pack = host
            .recall("vault.retrieval.recall", Value::Null, turn)
            .await;
        let items = item_ids(&pack);
        assert!(
            items.contains(&base_claim.to_hex()),
            "the default recall reads base reality: {pack}"
        );
        assert!(
            !items.contains(&world_claim.to_hex()),
            "the default recall reads no world its caller did not choose: {pack}"
        );
        assert!(
            left_out_worlds(&pack)
                .as_array()
                .is_some_and(|worlds| worlds.contains(&json!(world.to_hex()))),
            "the pack says it left the world out: {pack}"
        );
        let run = pack["retrieval_run_id"].clone();
        assert!(!run.is_null(), "a captured recall names its run: {pack}");
        for (verb, answer) in host.run_reads(&run, turn).await {
            let answer = answer.to_string();
            assert!(
                !answer.contains(&row_bytes(world_claim)),
                "{verb} names no row of a world the recall did not read: {answer}"
            );
            if verb != "vault.retrieval.trace" {
                assert!(
                    answer.contains(&row_bytes(base_claim)),
                    "{verb} names the row the recall read: {answer}"
                );
            }
        }

        let chosen = host
            .recall(
                "vault.retrieval.recall",
                json!({"worlds": {"kind": "world", "world_ref": world.to_hex(), "include_base": true}}),
                [0x3e; 16],
            )
            .await;
        let chosen_items = item_ids(&chosen);
        assert!(
            chosen_items.contains(&world_claim.to_hex())
                && chosen_items.contains(&base_claim.to_hex()),
            "a recall that chooses the world reads it beside base: {chosen}"
        );
    });
}

/// The diagnostic recall answers what the plain recall answers: the door's
/// rule (`vault_retrieval_recall`, "the host still embeds, budgets, narrows
/// and finalizes through the one existing serving door", FIX 2905). Over a
/// base claim and a claim of another world, for the default scope, base
/// alone and the world chosen beside base, `vault.retrieval.recall` and
/// `vault.recall` with the same input answer the same rows and leave out the
/// same worlds.
#[test]
fn the_diagnostic_recall_answers_what_the_plain_recall_answers() {
    run_on_engine_stack("retrieval-ledger-parity", || async {
        let host = host();
        let world = host.world();
        let base_claim = host.claim(&format!("the {WORD} bridge is stone"), None);
        let world_claim = host.claim(&format!("the {WORD} bridge is glass"), Some(world));
        host.publish_text();

        for (name, scope) in [
            ("the default scope", Value::Null),
            ("base alone", json!({"worlds": {"kind": "base"}})),
            (
                "the world beside base",
                json!({"worlds": {"kind": "world", "world_ref": world.to_hex(), "include_base": true}}),
            ),
        ] {
            let plain = host.recall("vault.recall", scope.clone(), [0x4d; 16]).await;
            let diagnostic = host
                .recall("vault.retrieval.recall", scope, [0x4e; 16])
                .await;
            assert!(
                item_ids(&plain).contains(&base_claim.to_hex()),
                "{name}: the plain recall reads base reality: {plain}"
            );
            assert_eq!(
                item_ids(&diagnostic),
                item_ids(&plain),
                "{name}: the diagnostic recall answers the plain recall's rows"
            );
            assert_eq!(
                left_out_worlds(&diagnostic),
                left_out_worlds(&plain),
                "{name}: the diagnostic recall leaves out the plain recall's worlds"
            );
        }
        let plain_default = host.recall("vault.recall", Value::Null, [0x4f; 16]).await;
        assert!(
            !item_ids(&plain_default).contains(&world_claim.to_hex()),
            "the plain default recall reads no unchosen world: {plain_default}"
        );
    });
}
