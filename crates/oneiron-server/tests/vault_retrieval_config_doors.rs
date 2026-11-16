//! Promise tests for the retrieval configuration doors (ruling L4-23 = A:
//! each test proves a promise at its door): `vault.retrieval.weights.get`
//! and `.configure`, `vault.retrieval.aging.get` and `.configure`, and
//! `vault.retrieval.hyde.configure`, `.get`, `.pending`, `.complete` and
//! `.receipt`, each entered at its generated HTTP facade route,
//! `POST /v1/core/facade/<verb>`.
//!
//! The promises, one test each (the verb rows' own words):
//! - The retrieval priors are the owner's ("The owner reads ...", "The owner
//!   sets independent retrieval priors against the current manifest hash").
//!   A person, an agent and another vault's credential are refused at both
//!   doors and move nothing; a configure naming a stale hash is refused.
//! - The class-aging profiles are the owner's, on the same terms.
//! - The HyDE binding is the owner's ("The owner binds or disables a host
//!   HyDE expander", "The owner reads the serving host HyDE binding"): no
//!   other caller reads its grounding or binds, replaces or drops it.
//! - HyDE host work answers the credential that recalled alone ("for the
//!   same credential that called recall", "credential-bound"): the work holds
//!   the recall's query, and no other credential lists it, reads its receipt
//!   or answers it. A free effort enqueues nothing.
//! - A new binding cancels the work left unanswered ("replacing the binding
//!   cancels unanswered work"), and a cancelled request takes no answer.
//!
//! The owner calls on the host-root credential of a profiled install, as a
//! serving start enrols it; a person and an agent on a slip of their own,
//! signed by their own key. No model: the host serves no reranker, so a paid
//! recall runs its HyDE expansion unreranked (`recall_door.rs`), and the test
//! answers the host work itself. In-process vault and router (`oneshot`), no
//! TCP port; the HyDE tests poll the pending list while the recall waits.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_retrieval_config_doors`.

#![cfg(all(unix, oneiron_test_support))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

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

/// The word the seeded row, the recall's query and the binding's grounding
/// hold: no refused caller's answer may hold it.
const WORD: &str = "quillmoor";
/// The query every recall here asks.
const QUERY: &str = "when does the quillmoor ferry leave";
/// A paid recall's deadline: the HyDE tests answer its host work before it.
const DEADLINE_MS: u64 = 6_000;
/// How often, and how many times, a HyDE test reads the pending list while
/// the recall waits on its host work.
const POLL: Duration = Duration::from_millis(20);
const POLLS: usize = 200;
/// The words of every owner door's refusal.
const OWNER_REFUSAL: &str = "is the vault owner's";

const WEIGHTS_GET: &str = "vault.retrieval.weights.get";
const WEIGHTS_CONFIGURE: &str = "vault.retrieval.weights.configure";
const AGING_GET: &str = "vault.retrieval.aging.get";
const AGING_CONFIGURE: &str = "vault.retrieval.aging.configure";
const HYDE_CONFIGURE: &str = "vault.retrieval.hyde.configure";
const HYDE_GET: &str = "vault.retrieval.hyde.get";
const HYDE_PENDING: &str = "vault.retrieval.hyde.pending";
const HYDE_COMPLETE: &str = "vault.retrieval.hyde.complete";
const HYDE_RECEIPT: &str = "vault.retrieval.hyde.receipt";

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

    /// Asserts a refusal of the request itself (a 4xx) whose message holds
    /// `words`.
    fn client_error(&self, call: &str, words: &str) {
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

    /// Asserts that the reply holds no word of the owner's query or grounding.
    fn holds_no_word(&self, call: &str) {
        assert!(
            !self.body.to_string().contains(WORD),
            "{call} holds no word of the owner's: {}",
            self.body
        );
    }
}

/// A host whose vault serves the facade; its owner is the vault's embedded
/// owner, on the host root.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-retrieval-config-doors".into()),
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

/// A HyDE binding of `expander` whose grounding names `home`.
fn binding(expander: &str, home: &str) -> Value {
    json!({"binding": {
        "expander": expander,
        "grounding": {"bindings": {"home": home}},
        "options": {"channel_limit": 4, "retry_once": false},
    }})
}

/// The completion of expansion work `request_id` for `query`.
fn expansion(request_id: &Value, query: &Value) -> Value {
    json!({
        "request_id": request_id,
        "answer": {"stage": "expansion", "expansion": {
            "grounded_query": query,
            "hypothetical_answer": "the first ferry leaves at seven",
            "embedding": [1.0, 0.0, 0.0, 0.0],
            "subqueries": [],
        }},
    })
}

/// The paid recall whose expansion waits on the host.
fn paid_recall() -> Value {
    json!({"query": QUERY, "effort": "high", "limit": 10, "deadline_ms": DEADLINE_MS})
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

    /// The owner's answer at `verb` with an empty input.
    async fn owner_reads(&self, verb: &str) -> Value {
        self.send(Caller::Owner, verb, json!({})).await.ok(verb)
    }

    /// The owner binds `input` (a [`binding`] or a null one); the answer.
    async fn bind(&self, input: &Value) -> Value {
        let bound = self
            .send(Caller::Owner, HYDE_CONFIGURE, input.clone())
            .await
            .ok(HYDE_CONFIGURE);
        assert_eq!(&bound, input, "the binding answers as bound");
        bound
    }

    /// `caller`'s pending HyDE work.
    async fn pending(&self, caller: Caller<'_>) -> Reply {
        self.send(caller, HYDE_PENDING, json!({"limit": 10})).await
    }

    /// The owner's receipt for `request_id`.
    async fn owner_receipt(&self, request_id: &Value) -> Value {
        self.send(
            Caller::Owner,
            HYDE_RECEIPT,
            json!({"request_id": request_id}),
        )
        .await
        .ok(HYDE_RECEIPT)
    }

    /// The owner's pending expansion work, read until it arrives while the
    /// owner's paid recall waits on it; `None` when none arrives.
    async fn awaited_work(&self) -> Option<Value> {
        for _ in 0..POLLS {
            let pending = self.pending(Caller::Owner).await.ok(HYDE_PENDING);
            if let Some(work) = pending.as_array().and_then(|rows| {
                rows.iter()
                    .find(|row| row["input"]["stage"] == "expansion")
                    .cloned()
            }) {
                return Some(work);
            }
            tokio::time::sleep(POLL).await;
        }
        None
    }
}

/// The retrieval priors are the owner's: the rows of
/// `vault.retrieval.weights.get` ("The owner reads effective affect, arousal,
/// community and semantic-edge VAD priors with the trusted manifest hash")
/// and `.configure` ("The owner sets independent retrieval priors against
/// the current manifest hash"). A person on their own slip, a full-access
/// agent and another vault's owner are refused at both doors and move no
/// prior. The owner's configure against the current hash lands, and a
/// configure naming the hash it replaced is refused and moves nothing.
#[test]
fn the_retrieval_weights_answer_their_owner_alone() {
    run_on_engine_stack("retrieval-config-weights", || async {
        let (host, other) = (host(), host());
        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("config-agent", 0x32);
        let before = host.owner_reads(WEIGHTS_GET).await;
        let asked = json!({"affect": 0.25, "arousal": 1.5, "community": 0.5, "vad": 0.125});
        assert_ne!(
            before["weights"], asked,
            "the asked priors differ from the vault's: {before}"
        );
        let configure = json!({"expected_body_hash": before["body_hash"], "weights": asked});

        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for (verb, input) in [
                (WEIGHTS_GET, json!({})),
                (WEIGHTS_CONFIGURE, configure.clone()),
            ] {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input).await;
                reply.refused(&call, caller);
                assert!(
                    !reply.body.to_string().contains("body_hash"),
                    "{call} reads no prior: {}",
                    reply.body
                );
            }
        }
        assert_eq!(
            host.owner_reads(WEIGHTS_GET).await,
            before,
            "a refused call moves no prior"
        );

        let receipt = host
            .send(Caller::Owner, WEIGHTS_CONFIGURE, configure)
            .await
            .ok(WEIGHTS_CONFIGURE);
        assert_eq!(
            receipt["configuration"]["weights"], asked,
            "the owner's configure lands: {receipt}"
        );
        let after = host.owner_reads(WEIGHTS_GET).await;
        assert_eq!(
            after, receipt["configuration"],
            "the read answers the receipt"
        );
        assert_ne!(
            after["body_hash"], before["body_hash"],
            "the configure moved the manifest"
        );

        let stale = host
            .send(
                Caller::Owner,
                WEIGHTS_CONFIGURE,
                json!({"expected_body_hash": before["body_hash"], "weights": before["weights"]}),
            )
            .await;
        stale.client_error(
            "the owner's configure on a stale hash",
            "expected_body_hash",
        );
        assert_eq!(
            host.owner_reads(WEIGHTS_GET).await,
            after,
            "a stale configure moves no prior"
        );
    });
}

/// The class-aging profiles are the owner's: the rows of
/// `vault.retrieval.aging.get` ("The owner reads class-level exponential
/// aging profiles and the trusted manifest hash") and `.configure` ("The
/// owner edits all class-aging profiles against the current manifest hash").
/// A person, a full-access agent and another vault's owner are refused at
/// both doors and move no profile. The owner's edit against the current hash
/// lands, and an edit naming the hash it replaced is refused and moves
/// nothing.
#[test]
fn the_claim_aging_profiles_answer_their_owner_alone() {
    run_on_engine_stack("retrieval-config-aging", || async {
        let (host, other) = (host(), host());
        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("config-agent", 0x32);
        let before = host.owner_reads(AGING_GET).await;
        let mut asked = before["profiles"].clone();
        let half_life = asked["ephemeral"]["half_life_secs"]
            .as_f64()
            .expect("the ephemeral class's half-life");
        asked["ephemeral"]["half_life_secs"] = json!(half_life * 2.0);
        let configure = json!({"expected_body_hash": before["body_hash"], "profiles": asked});

        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ] {
            for (verb, input) in [(AGING_GET, json!({})), (AGING_CONFIGURE, configure.clone())] {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input).await;
                reply.refused(&call, caller);
                assert!(
                    !reply.body.to_string().contains("half_life_secs"),
                    "{call} reads no profile: {}",
                    reply.body
                );
            }
        }
        assert_eq!(
            host.owner_reads(AGING_GET).await,
            before,
            "a refused call moves no profile"
        );

        let receipt = host
            .send(Caller::Owner, AGING_CONFIGURE, configure)
            .await
            .ok(AGING_CONFIGURE);
        assert_eq!(
            receipt["configuration"]["profiles"], asked,
            "the owner's edit lands: {receipt}"
        );
        let after = host.owner_reads(AGING_GET).await;
        assert_eq!(
            after, receipt["configuration"],
            "the read answers the receipt"
        );
        assert_ne!(
            after["body_hash"], before["body_hash"],
            "the edit moved the manifest"
        );

        let stale = host
            .send(
                Caller::Owner,
                AGING_CONFIGURE,
                json!({"expected_body_hash": before["body_hash"], "profiles": before["profiles"]}),
            )
            .await;
        stale.client_error("the owner's edit on a stale hash", "expected_body_hash");
        assert_eq!(
            host.owner_reads(AGING_GET).await,
            after,
            "a stale edit moves no profile"
        );
    });
}

/// The HyDE binding is the owner's: the rows of
/// `vault.retrieval.hyde.configure` ("The owner binds or disables a host HyDE
/// expander for paid recall") and `.get` ("The owner reads the serving host
/// HyDE binding, grounding and bounded retry options"). Before and after the
/// owner binds, a person, a full-access agent and another vault's owner are
/// refused at both doors: none reads the grounding, binds an expander of its
/// own or drops the owner's.
#[test]
fn the_hyde_binding_answers_its_owner_alone() {
    run_on_engine_stack("retrieval-config-hyde-binding", || async {
        let (host, other) = (host(), host());
        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("config-agent", 0x32);
        let unbound = host.owner_reads(HYDE_GET).await;
        assert_eq!(
            unbound,
            json!({"binding": null}),
            "a new host binds no expander"
        );
        let owners = binding("harbour-host", &format!("the {WORD} harbour"));
        let callers = [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&other)),
        ];

        for (who, caller) in callers {
            let theirs = binding(&format!("{who} host"), "elsewhere");
            for (verb, input) in [(HYDE_GET, json!({})), (HYDE_CONFIGURE, theirs)] {
                host.send(caller, verb, input)
                    .await
                    .refused(&format!("{who} at {verb}"), caller);
            }
        }
        assert_eq!(
            host.owner_reads(HYDE_GET).await,
            unbound,
            "a refused configure binds nothing"
        );

        host.bind(&owners).await;
        assert_eq!(
            host.owner_reads(HYDE_GET).await,
            owners,
            "the owner's binding"
        );
        for (who, caller) in callers {
            for (verb, input) in [
                (HYDE_GET, json!({})),
                (HYDE_CONFIGURE, json!({"binding": null})),
            ] {
                let call = format!("{who} at {verb}");
                let reply = host.send(caller, verb, input).await;
                reply.refused(&call, caller);
                reply.holds_no_word(&call);
            }
        }
        assert_eq!(
            host.owner_reads(HYDE_GET).await,
            owners,
            "no refused call drops the owner's binding"
        );
    });
}

/// HyDE host work answers the credential that recalled alone: the rows of
/// `vault.retrieval.hyde.pending` ("pending expansion and evidence-assessment
/// work for the same credential that called recall; free efforts enqueue
/// nothing"), `.complete` ("one credential-bound host expansion") and
/// `.receipt` ("one credential-bound host completion receipt"). The owner's
/// light recall enqueues nothing. The owner's paid recall leaves expansion
/// work holding its query; a person, a full-access agent and another vault's
/// owner list none of it, read no receipt for it and cannot answer it, and
/// no answer of theirs holds a word of the query. The owner answers it, and
/// the receipt stays the owner's alone.
#[test]
fn hyde_work_answers_the_credential_that_recalled_alone() {
    run_on_engine_stack("retrieval-config-hyde-work", || async {
        let (host, other) = (host(), host());
        let person = host.person("Ines Varga", 0x31);
        let agent = host.agent("config-agent", 0x32);
        host.claim(&format!("the {WORD} ferry leaves at seven"));
        host.bind(&binding("harbour-host", "the harbour")).await;

        host.send(
            Caller::Owner,
            "vault.recall",
            json!({"query": QUERY, "effort": "light", "limit": 10}),
        )
        .await
        .ok("the owner's light recall");
        assert_eq!(
            host.pending(Caller::Owner).await.ok(HYDE_PENDING),
            json!([]),
            "a free effort enqueues nothing"
        );

        let recall = host.send(Caller::Owner, "vault.recall", paid_recall());
        let checks = async {
            let Some(work) = host.awaited_work().await else {
                return false;
            };
            let query = work["input"]["request"]["query"].clone();
            assert!(
                query.as_str().is_some_and(|query| query.contains(WORD)),
                "the work holds the recall's query: {work}"
            );
            assert_eq!(work["expander"], "harbour-host", "{work}");
            let request_id = work["request_id"].clone();
            let held = host.owner_receipt(&request_id).await;
            assert_eq!(held["status"], "pending", "{held}");
            let answer = expansion(&request_id, &query);

            for (who, caller) in [
                ("person", Caller::As(&person)),
                ("agent", Caller::As(&agent)),
                ("another vault's owner", Caller::Stranger(&other)),
            ] {
                let stranger = matches!(caller, Caller::Stranger(_));
                let call = format!("{who} at {HYDE_PENDING}");
                let pending = host.pending(caller).await;
                pending.holds_no_word(&call);
                if stranger {
                    pending.refused(&call, caller);
                } else {
                    assert_eq!(pending.ok(&call), json!([]), "{call} lists no work");
                }

                let call = format!("{who} at {HYDE_RECEIPT}");
                let read = host
                    .send(caller, HYDE_RECEIPT, json!({"request_id": request_id}))
                    .await;
                if stranger {
                    read.refused(&call, caller);
                } else {
                    assert_eq!(read.ok(&call), Value::Null, "{call} reads no receipt");
                }

                let call = format!("{who} at {HYDE_COMPLETE}");
                let completed = host.send(caller, HYDE_COMPLETE, answer.clone()).await;
                completed.holds_no_word(&call);
                if stranger {
                    completed.refused(&call, caller);
                } else {
                    completed.client_error(&call, "unknown HyDE host request");
                }
            }
            assert_eq!(
                host.owner_receipt(&request_id).await,
                held,
                "no other credential settled the owner's work"
            );

            let done = host
                .send(Caller::Owner, HYDE_COMPLETE, answer)
                .await
                .ok(HYDE_COMPLETE);
            assert_eq!(done["status"], "completed", "{done}");
            assert_eq!(host.owner_receipt(&request_id).await, done);
            for (who, caller) in [
                ("person", Caller::As(&person)),
                ("agent", Caller::As(&agent)),
            ] {
                let call = format!("{who} at {HYDE_RECEIPT} after the answer");
                let read = host
                    .send(caller, HYDE_RECEIPT, json!({"request_id": request_id}))
                    .await
                    .ok(&call);
                assert_eq!(read, Value::Null, "{call} reads no receipt");
            }
            true
        };
        // The recall's own answer is not this promise; it names why no work
        // arrived, if none did.
        let (answered, worked) = tokio::join!(recall, checks);
        assert!(
            worked,
            "the owner's paid recall left no expansion work; it answered {} {}",
            answered.status, answered.body
        );
    });
}

/// A new binding cancels the work left unanswered: the row of
/// `vault.retrieval.hyde.configure` ("replacing the binding cancels
/// unanswered work"). While the owner's paid recall waits on its expansion,
/// the owner binds another expander: the waiting request's receipt says
/// `cancelled`, it leaves the pending list, and an answer for it is refused
/// and settles nothing.
#[test]
fn a_new_hyde_binding_cancels_the_work_left_unanswered() {
    run_on_engine_stack("retrieval-config-hyde-cancel", || async {
        let host = host();
        host.claim(&format!("the {WORD} ferry leaves at seven"));
        host.bind(&binding("harbour-host", "the harbour")).await;

        let recall = host.send(Caller::Owner, "vault.recall", paid_recall());
        let checks = async {
            let Some(work) = host.awaited_work().await else {
                return false;
            };
            let request_id = work["request_id"].clone();
            let query = work["input"]["request"]["query"].clone();
            assert_eq!(host.owner_receipt(&request_id).await["status"], "pending");

            host.bind(&binding("lighthouse-host", "the lighthouse"))
                .await;
            let cancelled = host.owner_receipt(&request_id).await;
            assert_eq!(cancelled["status"], "cancelled", "{cancelled}");
            assert_eq!(cancelled["expander"], "harbour-host", "{cancelled}");
            assert_eq!(
                host.pending(Caller::Owner).await.ok(HYDE_PENDING),
                json!([]),
                "cancelled work is no longer pending"
            );

            host.send(Caller::Owner, HYDE_COMPLETE, expansion(&request_id, &query))
                .await
                .client_error("an answer for cancelled work", "already settled");
            assert_eq!(
                host.owner_receipt(&request_id).await,
                cancelled,
                "a cancelled request takes no answer"
            );
            true
        };
        // The recall whose expansion was cancelled ends; its answer is not
        // this promise, but names why no work arrived, if none did.
        let (answered, worked) = tokio::join!(recall, checks);
        assert!(
            worked,
            "the owner's paid recall left no expansion work; it answered {} {}",
            answered.status, answered.body
        );
    });
}
