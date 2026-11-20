//! An account API key bound to an agent definition reads the owner's claim
//! through the agent's live read Grant on `POST /v1/core/query` and
//! `POST /v1/companion/memory/reason`, and the receipt on each reports that
//! Grant's reach, as vault.get does, not the key's own floor, which reads
//! nothing (FIX-LIST GRANT-RECEIPT-OTHER-READ-LANES part 3b, after
//! GRANT-READ-NARROWING-SAYS-DENY-ALL). The receipt only reports: with no
//! Grant, and after the owner revokes it, the same query finds nothing.
//! The reason answer cites the claim the Grant admits, where the key's own
//! floor once emptied its evidence read; a core query that asks for no kind
//! finds nothing on its hybrid and seeded searches, and its receipt still
//! names the Grant's ceiling (review round 1 of #9915).
//!
//! The control plane's key check is faked; its verdict takes the verifier's
//! own clock, so the test reads no wall clock.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test agent_grant_ranked_receipts`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::authority::{ActSurface, HostSlipIssuer};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::managed::account_keys;
use oneiron_server::managed::key_sync::{
    AccountKeyConfig, AccountKeyError, CentralCheckFuture, CentralKeyCheck, CentralKeyVerdict,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The one word only the owner's claim holds.
const WORD: &str = "quillmarsh";

/// The control plane's account-key check, faked: a presented key answers a
/// verdict naming the principal a test registered for it, with `core:read`,
/// checked at the verifier's `now`; any other key is refused.
#[derive(Default)]
struct CentralKeys {
    principals: Mutex<HashMap<Vec<u8>, (String, EntityId)>>,
}

impl CentralKeyCheck for CentralKeys {
    fn check_account_key<'a>(&'a self, plaintext: &'a [u8], now: u64) -> CentralCheckFuture<'a> {
        let verdict = self
            .principals
            .lock()
            .expect("principals")
            .get(plaintext)
            .map(|(key_id, principal)| CentralKeyVerdict {
                key_id: key_id.clone(),
                principal_ref: Some(principal.to_hex()),
                scopes: BTreeSet::from(["core:read".to_owned()]),
                expires_at: now + 3_600,
                checked_at: now,
            });
        Box::pin(async move { Ok::<_, AccountKeyError>(verdict) })
    }
}

/// A rooted server on its own device keystore that admits account keys
/// through [`CentralKeys`], and the vault's owner with an owner proof.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    _issuer: HostSlipIssuer,
    central_keys: Arc<CentralKeys>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let central_keys = Arc::new(CentralKeys::default());
    let checker: Arc<dyn CentralKeyCheck> = Arc::<CentralKeys>::clone(&central_keys);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("agent-grant-ranked-receipts".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server")
        .with_account_keys(Some(Arc::new(account_keys(
            checker,
            AccountKeyConfig::default(),
        )))),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    Served {
        _dir: dir,
        server,
        vault,
        _issuer: issuer,
        central_keys,
        owner,
        owner_proof,
    }
}

impl Served {
    /// An account API key the control plane verifies as `principal`'s: its
    /// plaintext, which is its Bearer token.
    fn account_key(&self, principal: EntityId) -> String {
        let key_id = self.vault.new_entity_id().expect("a key id").to_hex();
        let plaintext = format!("acct-{key_id}");
        self.central_keys
            .principals
            .lock()
            .expect("principals")
            .insert(
                plaintext.clone().into_bytes(),
                (format!("key-{key_id}"), principal),
            );
        plaintext
    }

    /// The owner remembers a claim about themself holding [`WORD`]: its id.
    fn owner_claim(&self) -> String {
        let owner = self.vault.memory(self.owner, EdgeActorClass::Human);
        let remembered = oneiron::verbs::invoke(
            &owner,
            "vault.remember",
            json!({
                "predicate": "project.deadline",
                "subject_ref": self.owner.to_hex(),
                "value": format!("The harbour survey of {WORD} is due on Friday."),
                "confidence": 0.9,
                "source": "user_stated",
            }),
        )
        .unwrap_or_else(|error| panic!("the owner remembers the claim: {error}"));
        remembered
            .pointer("/claim/id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("the remembered claim's id: {remembered:#}"))
            .to_owned()
    }

    /// An enabled agent the owner creates, with no Grant yet.
    fn agent(&self) -> EntityId {
        let agent = self.vault.new_entity_id().expect("an agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "ranked-reader",
                    "desc": "an agent that queries through the owner's read Grant",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("typed agent definition"),
            },
        )
        .expect("the owner creates an enabled agent definition");
        agent
    }

    /// The owner gives `agent` a live Grant that reads everything: its ref.
    fn read_grant(&self, agent: EntityId) -> EntityId {
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the agent a read Grant");
        assert!(minted.grant.confers, "the owner's read Grant is live");
        minted.grant.grant_ref
    }

    fn revoke(&self, grant: EntityId) {
        revoke_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantRevokeRequest {
                grant_ref: grant,
                seen: None,
            },
        )
        .expect("the owner revokes the Grant");
    }

    /// `POST uri` of `body` under the account key `key`: the body of its
    /// 200 answer.
    async fn post(&self, key: &str, uri: &str, body: Value) -> Value {
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Authorization", format!("Bearer {key}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4_194_304)
            .await
            .expect("response body");
        let body: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("{uri}: a JSON body: {}", String::from_utf8_lossy(&bytes)));
        assert_eq!(status, StatusCode::OK, "{uri}: {body:#}");
        body
    }

    /// The core query of [`WORD`] under `key`: its answer.
    async fn query(&self, key: &str) -> Value {
        self.post(key, "/v1/core/query", json!({ "query": WORD }))
            .await
    }

    /// The light memory reason of [`WORD`] under `key`: its answer.
    async fn reason(&self, key: &str) -> Value {
        self.post(
            key,
            "/v1/companion/memory/reason",
            json!({ "query": WORD, "depth": "light" }),
        )
        .await
    }
}

/// Whether the core query answer `answer` holds the row `id`.
fn finds(answer: &Value, id: &str) -> bool {
    answer["items"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["id"] == id))
}

/// Whether the receipt list `list` names `entry`.
fn lists(list: &Value, entry: &str) -> bool {
    list.as_array()
        .is_some_and(|entries| entries.iter().any(|named| named == entry))
}

/// The receipt `narrowing` of `route` states a live Grant's reach: its
/// ceiling and applied scopes deny nothing and it names no deny_all or
/// grant_scope narrowing.
fn assert_reports_the_grant(route: &str, narrowing: &Value) {
    for scope in ["actor_ceiling", "applied"] {
        assert_eq!(
            narrowing[scope]["deny_all"], false,
            "{route}: the {scope} scope denies all under the live Grant: {narrowing:#}"
        );
    }
    for list in ["narrowed_axes", "replan_hint"] {
        for entry in ["deny_all", "grant_scope"] {
            assert!(
                !lists(&narrowing[list], entry),
                "{route}: {list} names {entry} under the live Grant: {narrowing:#}"
            );
        }
    }
}

/// Runs one served case on threads that have the engine's native stack, as
/// `oneiron serve` runs its doors: a generated dispatch frame is larger than
/// a libtest thread's stack in a dev build (FIX 16372).
fn on_engine_stack<F>(case: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(case());
        })
        .expect("engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn an_agents_core_query_under_a_live_read_grant_reports_the_grant_not_deny_all() {
    on_engine_stack(|| async {
        let served = served();
        let claim = served.owner_claim();
        let owner_key = served.account_key(served.owner);
        let owner_answer = served.query(&owner_key).await;
        assert!(
            finds(&owner_answer, &claim),
            "the owner's own key finds the owner's claim: {owner_answer:#}"
        );

        let agent = served.agent();
        let agent_key = served.account_key(agent);
        let ungranted = served.query(&agent_key).await;
        assert!(
            !finds(&ungranted, &claim),
            "the agent's key finds the owner's claim with no Grant: {ungranted:#}"
        );

        let grant = served.read_grant(agent);
        let answer = served.query(&agent_key).await;
        assert!(
            finds(&answer, &claim),
            "the live Grant admits the owner's claim to the agent's core query: {answer:#}"
        );
        assert_reports_the_grant("/v1/core/query", &answer["narrowing"]);

        served.revoke(grant);
        let revoked = served.query(&agent_key).await;
        assert!(
            !finds(&revoked, &claim),
            "the agent's key still finds the owner's claim after the revoke: {revoked:#}"
        );
    });
}

/// Whether the reason answer `answer` cites evidence: a source, and no
/// "Not in memory." gap.
fn cites_evidence(answer: &Value) -> bool {
    answer["sources"]
        .as_array()
        .is_some_and(|sources| !sources.is_empty())
        && answer["answer"] != "Not in memory."
}

#[test]
fn an_agents_memory_reason_under_a_live_read_grant_reports_the_grant_not_deny_all() {
    on_engine_stack(|| async {
        let served = served();
        served.owner_claim();
        let agent = served.agent();
        let grant = served.read_grant(agent);
        let agent_key = served.account_key(agent);
        let answer = served.reason(&agent_key).await;
        assert!(
            cites_evidence(&answer),
            "the live Grant admits the owner's claim as the agent's reason evidence: {answer:#}"
        );
        let receipts = answer["narrowing"]
            .as_array()
            .unwrap_or_else(|| panic!("a reason answer with a receipt list: {answer:#}"));
        assert!(
            !receipts.is_empty(),
            "the reason answer carries its read's receipt: {answer:#}"
        );
        for narrowing in receipts {
            assert_reports_the_grant("/v1/companion/memory/reason", narrowing);
        }

        served.revoke(grant);
        let revoked = served.reason(&agent_key).await;
        assert!(
            !cites_evidence(&revoked),
            "the agent's reason still cites evidence after the revoke: {revoked:#}"
        );
    });
}

#[test]
fn an_agents_core_query_asking_no_kind_reports_the_grants_ceiling_on_hybrid_and_seeded_searches() {
    on_engine_stack(|| async {
        let served = served();
        let claim = served.owner_claim();
        let agent = served.agent();
        served.read_grant(agent);
        let agent_key = served.account_key(agent);
        // A text and vector query takes the hybrid search; one asked in an
        // affect takes the seeded search. Each asks for no kind, so its
        // candidates deny all and it answers before it ranks anything.
        for (search, body) in [
            (
                "hybrid",
                json!({
                    "query": WORD,
                    "query_vector": [0.1, 0.2, 0.3, 0.4],
                    "filter": { "entity_types": [] },
                }),
            ),
            (
                "seeded",
                json!({
                    "query": WORD,
                    "query_affect": { "valence": -0.4, "arousal": 0.7, "dominance": 0.5 },
                    "filter": { "entity_types": [] },
                }),
            ),
        ] {
            let answer = served.post(&agent_key, "/v1/core/query", body).await;
            assert!(
                !finds(&answer, &claim),
                "the {search} core query that asks for no kind finds the owner's claim: {answer:#}"
            );
            assert_eq!(
                answer["narrowing"]["actor_ceiling"]["deny_all"], false,
                "the {search} core query's actor_ceiling denies all under the live Grant: {answer:#}"
            );
        }
    });
}
