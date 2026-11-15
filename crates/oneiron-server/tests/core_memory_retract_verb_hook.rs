//! [CORE-MEMORY-VERB-SKIPS-FACADE-HOOKS] (FIX-LIST 25699): a token that is
//! not owner-grade retracts through the facade row `vault.claims.retract`
//! on `POST /v1/core/memory/verbs/retract`, so an owner verb hook that
//! skips that row stops the core route too — the hook's Skip is the
//! answer and the claim still stands. The owner's own full credential
//! keeps the owner's door, unchanged: its retract lands even under the
//! same hook.
//!
//! The row's annotation (FIX-LIST 25709) adds the oracle case: an agent
//! without read on an owner's expression-preference claim gets the same
//! status and code for it as for a random id, because the row's
//! `/claim_ref` reference admission refuses both identically. And the row
//! names delete too: `POST /v1/core/memory/verbs/delete` runs the facade
//! row `vault.delete`, so its verb hooks and its `/entity_ref` admission
//! judge the call, and the row's receipt still decodes into the response.
//!
//! Red on main: the retract arm calls `Vault::retract_claim` directly for
//! every caller, so the agent's retract lands (200) and the claim is
//! retracted; no hook ever runs. The oracle pair answers apart (400 for
//! the expression preference, 404 for the random id), and the delete hook
//! never runs either.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test core_memory_retract_verb_hook`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::claim::{ExpressionPreferenceOrigin, ExpressionPreferenceValue};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, Sensitivity, SensitivityCeiling};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlementVerdict, ExpressionPreferenceInput, resolve_entity_ref,
};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The pack the owner puts: one pre hook that skips `vault.claims.retract`.
const PACK: &str = "example.retracthook";
/// Its one hook.
const HOOK: &str = "skip-retract";

const PACK_MD: &str = "---
name: example.retracthook
description: One pre hook that skips retracts.
version: 1.0.0
kind: capability
hooks: [\"skip-retract\"]
---
A pack whose one hook skips every vault.claims.retract.
";

const HOOK_MD: &str = "---
name: skip-retract
version: 1.0.0
verbs: [\"vault.claims.retract\"]
actors: [\"agent\", \"human\"]
phase: pre
outcomes: [\"skip\"]
---
Skip every retract the hook is asked about.
";

const BODY_JS: &str =
    "return { kind: \"skip\", reason: \"retracts are held by the owner hook\" };\n";

/// The second pack the owner puts for the delete case: one pre hook that
/// skips `vault.delete`.
const DELETE_PACK: &str = "example.deletehook";
/// Its one hook.
const DELETE_HOOK: &str = "skip-delete";

const DELETE_PACK_MD: &str = "---
name: example.deletehook
description: One pre hook that skips deletes.
version: 1.0.0
kind: capability
hooks: [\"skip-delete\"]
---
A pack whose one hook skips every vault.delete.
";

const DELETE_HOOK_MD: &str = "---
name: skip-delete
version: 1.0.0
verbs: [\"vault.delete\"]
actors: [\"agent\", \"human\"]
phase: pre
outcomes: [\"skip\"]
---
Skip every delete the hook is asked about.
";

const DELETE_BODY_JS: &str =
    "return { kind: \"skip\", reason: \"deletes are held by the owner hook\" };\n";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6D; 32])
}

/// A rooted served vault, its owner, an agent the owner granted read and
/// propose, and, unless built hook-free, the owner's pack whose one pre
/// hook skips `vault.claims.retract`.
struct Served {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
    subject: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

fn served() -> Served {
    served_with_hooks(true)
}

/// [`served`] with no hook installed: the oracle and response-shape cases
/// judge admission and the answer alone, with no pre hook to answer first.
fn served_without_hooks() -> Served {
    served_with_hooks(false)
}

fn served_with_hooks(install_hooks: bool) -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("core-memory-retract-verb-hook".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let agent = vault
        .ensure_agent_principal("retract-hook-author")
        .expect("agent");
    let subject = vault
        .ensure_agent_principal("retract-hook-subject")
        .expect("subject");
    let facet = vault.default_facet().expect("default facet");
    vault
        .grant_foreign_principal(&owner_proof, &agent.to_hex())
        .expect("the owner grants the agent read and propose");
    if install_hooks {
        let files = vec![
            HubFile::new("PACK.md", PACK_MD),
            HubFile::new(format!("hooks/{HOOK}/HOOK.md"), HOOK_MD),
            HubFile::new(format!("hooks/{HOOK}/body.js"), BODY_JS),
        ];
        match vault.put_pack(&owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => {
                assert_eq!(receipt.pack_name, PACK);
            }
            other => panic!("the owner's put installs the pack and binds its hook: {other:?}"),
        }
    }
    Served {
        server,
        vault,
        issuer,
        owner,
        owner_proof,
        agent,
        subject,
        facet,
        _dir: dir,
    }
}

impl Served {
    /// The agent's claim, proposed and then approved by the owner: an
    /// approved claim the agent wrote.
    fn approved_agent_claim(&self) -> EntityId {
        let input = ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!("Yuki"),
            confidence: 1.0,
            confidence_details: None,
            source: "inferred".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex() })),
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        };
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_propose(&input)
            .expect("agent proposal");
        assert_eq!(receipt.approval, "proposed");
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("proposal id");
        let review_id = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("review")
            .review_id;
        let settled = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_settle_as_owner(
                &self.owner_proof,
                &ClaimSettleRequest {
                    claim_ref: id.to_hex(),
                    review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("settle");
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
        self.assert_standing(id, "the owner's approval stands before the retract");
        id
    }

    /// The claim still stands as the owner approved it.
    fn assert_standing(&self, id: EntityId, why: &str) {
        let body = self
            .vault
            .get_claim(&id)
            .expect("read claim")
            .expect("the claim exists");
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active, "{why}");
        assert_eq!(body.approval, ClaimApprovalStatus::Approved, "{why}");
        assert_eq!(body.valid_to, None, "{why}");
    }

    /// A live PERSON the owner's expression preference is about.
    fn person_subject(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        id
    }

    /// The owner's expression-preference claim:
    /// `companion.expression.language` about a live person, written through
    /// the typed door as an explicit user preference. It carries no scope,
    /// so it reads at the unstamped sensitivity band 2.
    fn owner_expression_claim(&self) -> EntityId {
        let person = self.person_subject();
        let at = self.vault.now_recorded_at();
        let receipt = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_expression_preference(
                &ExpressionPreferenceInput {
                    subject_ref: person.to_hex(),
                    value: ExpressionPreferenceValue::Language("en-US".to_owned()),
                    origin: ExpressionPreferenceOrigin::ExplicitUser,
                    valid_from: at,
                },
                at,
            )
            .expect("the owner seeds an expression preference");
        assert_eq!(receipt.approval, "auto");
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("preference id");
        let body = self
            .vault
            .get_claim(&id)
            .expect("read claim")
            .expect("the claim exists");
        assert_eq!(body.predicate.as_str(), "companion.expression.language");
        id
    }

    /// A credential this host mints `who` at actor class `class`, holding
    /// `read` and `write`: not owner-grade, as an agent's is not.
    fn credential(&self, who: EntityId, class: &str) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some(class.to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a credential")
    }

    /// The owner's own full slip: the host root's top scope, unattenuated,
    /// held by the owner — owner-grade.
    fn owner_credential(&self) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip")
    }

    /// A credential like [`Served::credential`], but narrowed to sensitivity
    /// `Private`: its holder reads band 0 and 1 rows, never an unstamped
    /// band 2 row — among them the owner's expression-preference claim.
    fn oracle_credential(&self, who: EntityId) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("agent".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        claims.scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Private);
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a narrowed credential")
    }

    /// `slip` posts `POST /v1/core/memory/verbs/retract` for the claim
    /// `id`: the status and the body.
    async fn retract(&self, slip: &CapabilitySlip, id: EntityId) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let token = slip.to_token().expect("token");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/memory/verbs/retract")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("x-oneiron-binding", binding.to_string())
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({ "id": id.to_hex() }).to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner puts the second pack: one pre hook that skips `vault.delete`.
    fn install_delete_hook(&self) {
        let files = vec![
            HubFile::new("PACK.md", DELETE_PACK_MD),
            HubFile::new(format!("hooks/{DELETE_HOOK}/HOOK.md"), DELETE_HOOK_MD),
            HubFile::new(format!("hooks/{DELETE_HOOK}/body.js"), DELETE_BODY_JS),
        ];
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => {
                assert_eq!(receipt.pack_name, DELETE_PACK);
            }
            other => panic!("the owner's delete pack installs and binds its hook: {other:?}"),
        }
    }

    /// A NOTE `author` writes about the subject, by its full hex ref.
    fn note_by(&self, author: EntityId) -> String {
        self.vault
            .memory(author, EdgeActorClass::Agent)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("author a NOTE")
            .id_hex
    }

    /// Whether `note` is a deleted shell.
    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
    }

    /// `slip` posts `POST /v1/core/memory/verbs/delete` for the NOTE `note`:
    /// the status and the body.
    async fn delete(&self, slip: &CapabilitySlip, note: &str) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let token = slip.to_token().expect("token");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/memory/verbs/delete")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("x-oneiron-binding", binding.to_string())
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({ "id": note }).to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`.
fn agent_with_grant(served: &Served, agent_id: &str, verbs: &[&str]) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &served.vault,
        &served.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Core memory verb hook test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        &served.vault,
        &served.owner_proof,
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
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    agent
}

/// Runs one served case on threads that have the engine's native stack, as
/// `oneiron serve` runs its doors: a generated dispatch frame is larger
/// than a libtest thread's stack in a dev build (FIX 16372).
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
fn a_non_owner_retract_meets_the_owners_skip_hook() {
    on_engine_stack(|| async {
        let fx = served();
        let claim = fx.approved_agent_claim();
        let token = fx.credential(fx.agent, "agent");

        let (status, body) = fx.retract(&token, claim).await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "INVALID_STATE", "{body}");
        assert_eq!(body["error"]["hook"]["status"], "skipped", "{body}");
        let reason = body["error"]["hook"]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("held by the owner hook"),
            "the answer carries the hook's own reason: {body}"
        );
        fx.assert_standing(claim, "a skipped retract retracts nothing");
    });
}

#[test]
fn the_owners_own_retract_is_unchanged_by_the_hook() {
    on_engine_stack(|| async {
        let fx = served();
        let claim = fx.approved_agent_claim();
        let token = fx.owner_credential();

        let (status, body) = fx.retract(&token, claim).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["verb"], "retract", "{body}");
        assert_eq!(body["id"], claim.to_hex(), "{body}");
        assert!(
            body["at"].is_u64(),
            "the owner door still echoes its time: {body}"
        );
        let retracted = fx
            .vault
            .get_claim(&claim)
            .expect("read claim")
            .expect("the claim exists");
        assert_eq!(retracted.lifecycle, ClaimLifecycleStatus::Retracted);
    });
}

#[test]
fn an_agent_without_read_gets_the_same_answer_for_an_unreadable_claim_as_for_a_random_id() {
    on_engine_stack(|| async {
        let fx = served_without_hooks();
        let claim = fx.owner_expression_claim();
        let oracle = fx
            .vault
            .ensure_agent_principal("oracle-reader")
            .expect("oracle agent");
        fx.vault
            .grant_foreign_principal(&fx.owner_proof, &oracle.to_hex())
            .expect("the owner grants the oracle read and propose");
        let token = fx.oracle_credential(oracle);

        let (status, body) = fx.retract(&token, claim).await;
        let (random_status, random_body) = fx.retract(&token, EntityId::now()).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["code"], "INVENTED_REFERENCE", "{body}");
        assert_eq!(
            random_status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{random_body}"
        );
        assert_eq!(
            random_body["error"]["code"], "INVENTED_REFERENCE",
            "{random_body}"
        );
        assert_eq!(status, random_status, "one refusal for both");
        assert_eq!(
            body["error"]["code"], random_body["error"]["code"],
            "one code for both"
        );
        let kept = fx
            .vault
            .get_claim(&claim)
            .expect("read claim")
            .expect("the claim exists");
        assert_eq!(kept.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(kept.approval, ClaimApprovalStatus::Auto);
    });
}

#[test]
fn a_non_owner_delete_meets_the_owners_skip_hook() {
    on_engine_stack(|| async {
        let fx = served();
        fx.install_delete_hook();
        let deleter = agent_with_grant(&fx, "hook_delete_agent", &["read", "delete"]);
        let note = fx.note_by(deleter);
        let token = fx.credential(deleter, "agent");

        let (status, body) = fx.delete(&token, &note).await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "INVALID_STATE", "{body}");
        assert_eq!(body["error"]["hook"]["status"], "skipped", "{body}");
        let reason = body["error"]["hook"]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("held by the owner hook"),
            "the answer carries the hook's own reason: {body}"
        );
        assert!(!fx.deleted(&note), "a skipped delete deletes nothing");
    });
}

#[test]
fn a_non_owner_delete_without_a_hook_still_deletes() {
    on_engine_stack(|| async {
        let fx = served();
        let deleter = agent_with_grant(&fx, "plain_delete_agent", &["read", "delete"]);
        let note = fx.note_by(deleter);
        let token = fx.credential(deleter, "agent");

        let (status, body) = fx.delete(&token, &note).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["verb"], "delete", "{body}");
        assert_eq!(body["operation"], "delete_entity", "{body}");
        assert_eq!(body["delete"]["existed"], true, "{body}");
        assert_eq!(body["delete"]["reason"], "user_delete", "{body}");
        assert_eq!(body["delete"]["hard"], false, "{body}");
        assert_eq!(body["delete"]["state"], "applied", "{body}");
        assert!(fx.deleted(&note), "the delete lands without a hook");
    });
}

#[test]
fn a_non_owner_retract_success_reports_no_time() {
    on_engine_stack(|| async {
        let fx = served_without_hooks();
        let claim = fx.approved_agent_claim();
        let token = fx.credential(fx.agent, "agent");

        let (status, body) = fx.retract(&token, claim).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["verb"], "retract", "{body}");
        assert_eq!(body["id"], claim.to_hex(), "{body}");
        assert!(
            body.get("at").is_none(),
            "the facade path reports no time: {body}"
        );
    });
}
