//! The `vault.identity` doors (ARCH-0055's identity topology,
//! oneiron/core/oneiron-arch-0055-entity-merge-split-consent-ramp-v1.md),
//! each entered at its facade route as the app serves it:
//!
//! - :51 "merge is an event plus a redirect, never a rewrite", :70 "No eager
//!   reference collapse, ever." and :225 "Claim subjects keep original entity
//!   ids forever.": a merge writes one event and one redirect, the loser's
//!   claims keep their subject and read through the survivor, and an undo is
//!   a counter-event that restores the loser.
//! - :66 "The loser is never deleted, never tombstoned. It takes lifecycle
//!   state `merged` and lives on as a redirect shell."
//! - :75 "A merge whose sources name the embedded owner fails with
//!   `OwnerMergedAway`. A split whose original is the embedded owner fails
//!   with `OwnerSplitAway`", while the owner as a merge's survivor stays
//!   allowed.
//! - §6 (:123-131) "auto by default; the propose lane is the exception": a
//!   proposed merge parks with no topology effect until the owner rules on
//!   it, and a rejected or resolved proposal takes no second ruling.
//! - :131 "'different things' mints `assert_distinct` (suppresses
//!   re-proposals forever ...)": a merge proposal over a distinct pair is
//!   refused, while the owner's own merge ruling still passes.
//! - §4 (:96-103) "E lives on as redirect-to-SET ... Unattributable residue
//!   stays on E, marked ambiguous": a split redirects through its new heads,
//!   moves no claim row, and keeps the residue on the original.
//! - Every row of the family is a host door whose proof is the owner's
//!   (scripts/sdk/verbs/vault.identity.*.json, `host_door_proof: owner`): no
//!   person or agent but the owner opens one, and a credential short of
//!   `core:write` stops at the scope guard of every write door.
//!
//! Not covered here: `vault.identity.facet`'s mask fork (pinned at the engine
//! by identity_topology/tests.rs
//! `facet_forks_claims_and_undo_brings_the_original_claims_back`) and
//! `vault.identity.mention`'s answer, which needs tagger-written mention rows
//! that no public path seeds; both doors are refused to non-owners below.
//!
//! `cargo test -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks --test vault_identity_doors`.

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
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const MERGE: &str = "vault.identity.merge";
const SPLIT: &str = "vault.identity.split";
const FACET: &str = "vault.identity.facet";
const ASSERT_DISTINCT: &str = "vault.identity.assert_distinct";
const PROPOSE: &str = "vault.identity.propose";
const UNDO: &str = "vault.identity.undo";
const RESOLVE: &str = "vault.identity.resolve";
const EVENTS_GET: &str = "vault.identity.events.get";
const PROPOSALS_RESOLVE: &str = "vault.identity.proposals.resolve";
const FOR_PAIR: &str = "vault.identity.proposals.for_pair";
const MENTION: &str = "vault.identity.mention";

/// The family's doors that write: each takes `core:write` at its scope
/// guard.
const WRITE_DOORS: [&str; 7] = [
    MERGE,
    SPLIT,
    FACET,
    ASSERT_DISTINCT,
    PROPOSE,
    UNDO,
    PROPOSALS_RESOLVE,
];

/// A fixed public occurrence time for seeded claims (E2E memory.test.ts
/// setup's 1769947200), never an engine clock override.
const OCCURRED_AT: u64 = 1_769_947_200;

const READ_WRITE: &[&str] = &["core:read", "core:write"];
const READ_ONLY: &[&str] = &["core:read"];

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

/// One reply: its status and its JSON (a body that is no JSON reads as its
/// text).
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

    /// Asserts a 403 FORBIDDEN whose message holds `words`.
    fn forbidden(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::FORBIDDEN,
            "{call} answered {}",
            self.body
        );
        assert_eq!(
            self.body["error"]["code"], "FORBIDDEN",
            "{call}: {}",
            self.body
        );
        assert!(
            self.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(words)),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    /// Asserts the 400 BAD_REQUEST an engine topology rejection answers,
    /// naming `words` (its variant) in the message.
    fn rejected(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::BAD_REQUEST,
            "{call} answered {}",
            self.body
        );
        assert_eq!(
            self.body["error"]["code"], "BAD_REQUEST",
            "{call}: {}",
            self.body
        );
        let message = self.body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("identity topology op rejected") && message.contains(words),
            "{call} must reject naming `{words}`: {}",
            self.body
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether the JSON array `list` holds the id `id`.
fn holds(list: &Value, id: &str) -> bool {
    list.as_array()
        .is_some_and(|rows| rows.iter().any(|row| row == id))
}

/// The strings of the JSON array `list`, sorted.
fn sorted(list: &Value) -> Vec<String> {
    let mut ids: Vec<String> = list
        .as_array()
        .unwrap_or_else(|| panic!("an id list: {list}"))
        .iter()
        .map(|id| id.as_str().expect("a hex id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// `receipt` without its `seen`, the revision a read computes live.
fn logged(receipt: &Value) -> Value {
    let mut logged = receipt.clone();
    logged
        .as_object_mut()
        .expect("a receipt object")
        .remove("seen");
    logged
}

/// One piece of identity evidence: the refs and the rationale.
fn evidence(turn: &str, rationale: &str) -> Value {
    json!({"refs": [turn], "rationale": rationale})
}

/// A merge of `source` into `survivor`, citing `turn`.
fn merge_input(source: &str, survivor: &str, turn: &str, rationale: &str) -> Value {
    json!({
        "sources": [source],
        "survivor": survivor,
        "evidence": evidence(turn, rationale),
        "survivorship_plan": "read_through",
    })
}

/// A proposal of the merge `spec`.
fn propose_input(spec: &Value) -> Value {
    json!({"operation": {"op": "merge", "spec": spec}})
}

impl Host {
    fn new(secret: &str) -> Self {
        let dir = tempfile::tempdir().expect("a temporary vault directory");
        let vault =
            Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(secret.into()),
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
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Reply { status, body }
    }

    /// The owner's call to `verb`, which must answer 200.
    async fn owner_ok(&self, verb: &str, input: Value) -> Value {
        self.call(Caller::Root, verb, input).await.ok(verb)
    }

    /// The owner's verified proof, for binding the vault's own agents.
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

    /// A live PERSON named `name`; answers its hex id.
    fn person_row(&self, name: &str) -> String {
        self.row(ENTITY_TYPE_PERSON, "name", name).to_hex()
    }

    /// A witnessed MESSAGE saying `words`, the evidence a topology op cites;
    /// answers its hex id.
    fn witnessed(&self, words: &str) -> String {
        self.row(ENTITY_TYPE_MESSAGE, "content", words).to_hex()
    }

    /// The scope a fresh vault's own claims take: base reality, the owner's
    /// substrate facet, every relationship and the default project
    /// (tests/e2e/support/fixtures.ts `ownerBaseClaimScope`).
    async fn base_claim_scope(&self) -> Value {
        let facets = self
            .owner_ok(
                "vault.neighbors",
                json!({
                    "entity_ref": self.owner.to_hex(),
                    "opts": {"edge_kind": "has_facet", "limit": 100}
                }),
            )
            .await;
        for facet in facets["value"].as_array().expect("the owner's facets") {
            let read = self
                .owner_ok("vault.get", json!({"entity_ref": facet["short_id"]}))
                .await;
            let row = &read["value"];
            if row["kind"] == "FACET" && row["body"]["kind"] == "substrate" {
                return json!({
                    "world_id": "00000000000000000000000000000001",
                    "scope_facet_id": row["id_hex"],
                    "scope_relationship_id": "all",
                    "scope_project_id": "00000000000000000000000000000002"
                });
            }
        }
        panic!("a fresh vault has no readable owner substrate facet: {facets}");
    }

    /// The owner's claim `predicate: value` about `subject`, in `scope`;
    /// answers the claim's hex id.
    async fn claim(&self, scope: &Value, subject: &str, predicate: &str, value: &str) -> String {
        let written = self
            .owner_ok(
                "vault.claims.upsert",
                json!({
                    "scope": scope, "subject_ref": subject, "predicate": predicate,
                    "value": value, "source": "user_stated", "confidence": 1,
                    "occurred_at": OCCURRED_AT
                }),
            )
            .await;
        assert_eq!(written["approval"], "auto", "{written}");
        let read = self
            .owner_ok(
                "vault.get",
                json!({"entity_ref": written["claim_short_id"]}),
            )
            .await;
        read["value"]["id_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("the claim's id: {read}"))
            .to_owned()
    }

    /// The current version of the claim `claim`, from its history.
    async fn claim_row(&self, claim: &str) -> Value {
        let history = self
            .owner_ok("vault.claims.history", json!({"claim_ref": claim}))
            .await;
        history["value"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["claim_ref"] == claim))
            .cloned()
            .unwrap_or_else(|| panic!("claim {claim} is absent from its history: {history}"))
    }

    /// The owner's read of `entity`'s topology.
    async fn resolve(&self, entity: &str) -> Value {
        self.owner_ok(RESOLVE, json!({"entity": entity})).await
    }

    /// The owner's read of the identity event `event`.
    async fn event(&self, event: &Value) -> Value {
        self.owner_ok(EVENTS_GET, json!({"event": event})).await
    }

    /// The owner's read of the open merge proposals and distinct claims of
    /// the pair `a`, `b`.
    async fn pair(&self, a: &str, b: &str) -> Value {
        self.owner_ok(FOR_PAIR, json!({"a": a, "b": b})).await
    }

    /// `holder`'s own slip as a `class` caller holding `verbs`, signed by
    /// the key `seed` makes.
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
        Principal { slip, key }
    }

    /// A live PERSON named `name`, on a human slip of its own.
    fn person(&self, name: &str, seed: u8) -> Principal {
        let id = self.row(ENTITY_TYPE_PERSON, "name", name);
        self.principal(id, "human", seed, READ_WRITE)
    }

    /// The vault's own agent `name`, bound at `tier`, on a slip of its own
    /// holding `verbs`.
    fn agent(&self, name: &str, seed: u8, tier: AgentTier, verbs: &[&str]) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &self.owner_proof(),
                agent,
                tier.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed, verbs)
    }
}

/// ARCH-0055 :51 "merge is an event plus a redirect, never a rewrite", :70
/// "No eager reference collapse, ever." and :225 "Claim subjects keep
/// original entity ids forever." The owner merges a duplicate into the
/// person it duplicates: one event, a `merged_into` redirect, and the
/// duplicate's claim keeps its subject while it reads through the survivor.
/// The event reads back as its receipt; its undo is a counter-event after it
/// that takes the redirect away and leaves every logged field and the claim
/// as they were.
#[test]
fn a_merge_is_one_event_and_a_redirect_that_rewrites_no_claim() {
    run_on_engine_stack("identity-doors-merge-redirect", || async {
        let host = Host::new("vault-identity-doors-merge-redirect");
        let scope = host.base_claim_scope().await;
        let ada = host.person_row("Ada North");
        let duplicate = host.person_row("A. North");
        let kept = host.claim(&scope, &ada, "profile.name", "Ada North").await;
        let moved = host
            .claim(
                &scope,
                &duplicate,
                "profile.employer",
                "Harbour Survey Office",
            )
            .await;
        let before = host.claim_row(&moved).await;
        assert_eq!(before["subject_ref"], duplicate, "{before}");
        let turn = host.witnessed("A. North signed the harbour log as Ada North");

        let input = merge_input(&duplicate, &ada, &turn, "one person signs both ways");
        let merged = host.owner_ok(MERGE, input.clone()).await;
        assert_eq!(merged["outcome"], "applied", "{merged}");
        let receipt = &merged["receipt"];
        assert_eq!(
            receipt["action"],
            json!({"op": "merge", "sources": [duplicate], "survivor": ada}),
            "{merged}"
        );
        assert_eq!(receipt["approval"], "auto", "{merged}");
        assert_eq!(receipt["evidence"], input["evidence"], "{merged}");
        assert_eq!(receipt["actor"], host.owner.to_hex(), "{merged}");

        let loser = host.resolve(&duplicate).await;
        assert_eq!(loser["heads"], json!([ada]), "{loser}");
        assert_eq!(loser["merged_into"], json!([ada]), "{loser}");
        let survivor = host.resolve(&ada).await;
        assert_eq!(survivor["heads"], json!([ada]), "{survivor}");
        assert!(holds(&survivor["remaining_claims"], &kept), "{survivor}");
        assert!(
            holds(&survivor["remaining_claims"], &moved),
            "the duplicate's claim reads through the survivor: {survivor}"
        );
        let during = host.claim_row(&moved).await;
        for field in ["subject_ref", "value", "made_by"] {
            assert_eq!(
                during[field], before[field],
                "a merge rewrites no claim ({field}): {during}"
            );
        }

        let stored = host.event(&receipt["event"]).await;
        assert_eq!(
            &stored, receipt,
            "the merge event reads back as its receipt"
        );

        let undone = host
            .owner_ok(
                UNDO,
                json!({"event": receipt["event"], "seen": receipt["seen"]}),
            )
            .await;
        assert_eq!(undone["outcome"], "applied", "{undone}");
        assert_eq!(
            undone["receipt"]["action"],
            json!({"op": "undo", "target": receipt["event"]}),
            "{undone}"
        );
        assert!(
            undone["receipt"]["seq"].as_u64() > receipt["seq"].as_u64(),
            "the undo is a counter-event after the merge: {undone}"
        );
        let restored = host.resolve(&duplicate).await;
        assert_eq!(restored["state"], "active", "{restored}");
        assert_eq!(restored["heads"], json!([duplicate]), "{restored}");
        assert_eq!(restored["merged_into"], json!([]), "{restored}");
        let survivor = host.resolve(&ada).await;
        assert!(
            !holds(&survivor["remaining_claims"], &moved),
            "the undone redirect reads nothing through: {survivor}"
        );
        let stored = host.event(&receipt["event"]).await;
        assert_eq!(
            logged(&stored),
            logged(receipt),
            "an undo leaves every logged field of its event as it was"
        );
        assert_eq!(host.claim_row(&moved).await, before);
    })
}

/// ARCH-0055 :66 "The loser is never deleted, never tombstoned. It takes
/// lifecycle state `merged` and lives on as a redirect shell." After the
/// owner's merge the loser answers its topology as a `merged` shell that
/// redirects to the survivor, and the vault still reads it back as the
/// PERSON it was; the survivor stays active.
#[test]
fn a_merged_loser_is_never_deleted_and_lives_on_as_a_merged_shell() {
    run_on_engine_stack("identity-doors-merged-shell", || async {
        let host = Host::new("vault-identity-doors-merged-shell");
        let ines = host.person_row("Ines Barros");
        let loser = host.person_row("Ines B.");
        let turn = host.witnessed("Ines B. is Ines Barros's own short form");

        let merged = host
            .owner_ok(
                MERGE,
                merge_input(&loser, &ines, &turn, "a short form of one name"),
            )
            .await;
        assert_eq!(merged["outcome"], "applied", "{merged}");
        assert!(
            merged["transitions"]
                .as_array()
                .is_some_and(|rows| rows.contains(&json!({"entity": loser, "state": "merged"}))),
            "the merge moves the loser to `merged`: {merged}"
        );

        let shell = host.resolve(&loser).await;
        assert_eq!(shell["state"], "merged", "{shell}");
        assert_eq!(shell["heads"], json!([ines]), "{shell}");
        let read = host
            .owner_ok("vault.get", json!({"entity_ref": loser}))
            .await;
        assert_eq!(read["value"]["id_hex"], loser, "{read}");
        assert_eq!(
            read["value"]["kind"], "PERSON",
            "the merged loser still reads back as its PERSON: {read}"
        );
        let survivor = host.resolve(&ines).await;
        assert_eq!(survivor["state"], "active", "{survivor}");
        assert_eq!(survivor["heads"], json!([ines]), "{survivor}");
    })
}

/// ARCH-0055 :75 "A merge whose sources name the embedded owner fails with
/// `OwnerMergedAway`. A split whose original is the embedded owner fails
/// with `OwnerSplitAway`". Both refusals answer the owner's own call with
/// 400 naming the rejection and leave the owner active; a merge with the
/// owner as its survivor still applies (consent/tests/owner_tier.rs
/// `a_merge_never_retires_the_vault_owner_and_the_owner_survives_one`).
#[test]
fn no_merge_or_split_retires_the_vault_owner() {
    run_on_engine_stack("identity-doors-owner-stays", || async {
        let host = Host::new("vault-identity-doors-owner-stays");
        let owner = host.owner.to_hex();
        let namesake = host.person_row("Owner's namesake");
        let alias = host.person_row("Owner's old handle");
        let turn = host.witnessed("the owner's old handle signed the lease");

        host.call(
            Caller::Root,
            MERGE,
            merge_input(&owner, &namesake, &turn, "the owner into a namesake"),
        )
        .await
        .rejected(MERGE, "OwnerMergedAway");
        let me = host.resolve(&owner).await;
        assert_eq!(me["state"], "active", "{me}");
        assert_eq!(me["heads"], json!([owner]), "{me}");
        let other = host.resolve(&namesake).await;
        assert_eq!(other["merged_into"], json!([]), "{other}");

        host.call(
            Caller::Root,
            SPLIT,
            json!({
                "entity": owner,
                "heads": [namesake],
                "reassignment_map": [],
                "evidence": evidence(&turn, "the owner split away"),
            }),
        )
        .await
        .rejected(SPLIT, "OwnerSplitAway");
        let me = host.resolve(&owner).await;
        assert_eq!(me["state"], "active", "{me}");
        assert_eq!(me["heads"], json!([owner]), "{me}");
        assert_eq!(me["split_into"], json!([]), "{me}");

        let merged = host
            .owner_ok(
                MERGE,
                merge_input(&alias, &owner, &turn, "the old handle is the owner's"),
            )
            .await;
        assert_eq!(merged["outcome"], "applied", "{merged}");
        let shell = host.resolve(&alias).await;
        assert_eq!(shell["heads"], json!([owner]), "{shell}");
        let me = host.resolve(&owner).await;
        assert_eq!(me["state"], "active", "{me}");
    })
}

/// ARCH-0055 §6 (:123-131) "auto by default; the propose lane is the
/// exception". The owner's proposal of a merge parks as a `proposed` event
/// with no topology effect: the duplicate stays active and the pair lists
/// the proposal. The owner's approval applies the proposed merge untouched
/// and closes the proposal. A second proposal the owner rejects applies
/// nothing, and the rejected proposal takes no later ruling.
#[test]
fn a_proposed_merge_parks_with_no_effect_until_the_owner_rules_on_it() {
    run_on_engine_stack("identity-doors-propose-lane", || async {
        let host = Host::new("vault-identity-doors-propose-lane");
        let jonas = host.person_row("Jonas Weber");
        let maybe = host.person_row("J. Weber");
        let turn = host.witnessed("J. Weber may be Jonas Weber");
        let spec = merge_input(&maybe, &jonas, &turn, "maybe one person");

        let parked = host.owner_ok(PROPOSE, propose_input(&spec)).await;
        assert_eq!(parked["outcome"], "parked", "{parked}");
        assert_eq!(parked["receipt"]["approval"], "proposed", "{parked}");
        assert_eq!(
            parked["receipt"]["action"],
            json!({"op": "merge", "sources": [maybe], "survivor": jonas}),
            "{parked}"
        );
        let proposal = parked["receipt"]["event"].clone();
        let untouched = host.resolve(&maybe).await;
        assert_eq!(untouched["state"], "active", "{untouched}");
        assert_eq!(untouched["heads"], json!([maybe]), "{untouched}");
        assert_eq!(untouched["merged_into"], json!([]), "{untouched}");
        let pair = host.pair(&jonas, &maybe).await;
        assert_eq!(pair["proposals"], json!([proposal]), "{pair}");
        assert_eq!(pair["distinct_claims"], json!([]), "{pair}");

        let seen = host.event(&proposal).await["seen"].clone();
        let ruled = host
            .owner_ok(
                PROPOSALS_RESOLVE,
                json!({"proposal": proposal, "seen": seen, "decision": {"ruling": "approve"}}),
            )
            .await;
        let ruling = &ruled["receipt"]["action"];
        assert_eq!(ruling["op"], "proposal_resolution", "{ruled}");
        assert_eq!(ruling["proposal"], proposal, "{ruled}");
        assert_eq!(ruling["outcome"], "approved_untouched", "{ruled}");
        assert_eq!(
            ruled["applied"]["action"],
            json!({"op": "merge", "sources": [maybe], "survivor": jonas}),
            "{ruled}"
        );
        assert_eq!(ruled["applied"]["approval"], "approved", "{ruled}");
        let merged = host.resolve(&maybe).await;
        assert_eq!(merged["state"], "merged", "{merged}");
        assert_eq!(merged["heads"], json!([jonas]), "{merged}");
        let pair = host.pair(&jonas, &maybe).await;
        assert_eq!(pair["proposals"], json!([]), "{pair}");

        let leo = host.person_row("Leo Marsh");
        let other = host.person_row("Leona Marsh");
        let spec = merge_input(&other, &leo, &turn, "two people, one surname");
        let parked = host.owner_ok(PROPOSE, propose_input(&spec)).await;
        assert_eq!(parked["outcome"], "parked", "{parked}");
        let declined = parked["receipt"]["event"].clone();
        let seen = host.event(&declined).await["seen"].clone();
        let rejected = host
            .owner_ok(
                PROPOSALS_RESOLVE,
                json!({"proposal": declined, "seen": seen, "decision": {"ruling": "reject"}}),
            )
            .await;
        assert_eq!(
            rejected["receipt"]["action"]["outcome"], "rejected",
            "{rejected}"
        );
        assert_eq!(rejected["applied"], Value::Null, "{rejected}");
        let kept = host.resolve(&other).await;
        assert_eq!(kept["state"], "active", "{kept}");
        assert_eq!(kept["heads"], json!([other]), "{kept}");
        let pair = host.pair(&leo, &other).await;
        assert_eq!(pair["proposals"], json!([]), "{pair}");

        let seen = host.event(&declined).await["seen"].clone();
        host.call(
            Caller::Root,
            PROPOSALS_RESOLVE,
            json!({"proposal": declined, "seen": seen, "decision": {"ruling": "approve"}}),
        )
        .await
        .rejected(PROPOSALS_RESOLVE, "ProposalAlreadyResolved");
        let kept = host.resolve(&other).await;
        assert_eq!(kept["state"], "active", "{kept}");
    })
}

/// ARCH-0055 :131 "'different things' mints `assert_distinct` (suppresses
/// re-proposals forever ...)". The owner's ruling that two people differ
/// mints one distinct claim for the pair; a later merge proposal of that
/// pair is refused 400 `DistinctPairSuppressed` and lists nothing, while the
/// owner's own merge of the pair, a ruling rather than a proposal, still
/// applies (oneiron-contracts identity_topology.rs, the suppression
/// contract).
#[test]
fn a_distinct_pair_refuses_every_later_merge_proposal_of_the_pair() {
    run_on_engine_stack("identity-doors-distinct-pair", || async {
        let host = Host::new("vault-identity-doors-distinct-pair");
        let first = host.person_row("Sam Ortiz");
        let second = host.person_row("Sam Ortiz (the neighbour)");
        let turn = host.witnessed("two people named Sam Ortiz live on the street");

        let distinct = host
            .owner_ok(
                ASSERT_DISTINCT,
                json!({"a": first, "b": second, "reason": "two people who share a name"}),
            )
            .await;
        assert_eq!(distinct["outcome"], "applied", "{distinct}");
        let action = &distinct["receipt"]["action"];
        assert_eq!(action["op"], "assert_distinct", "{distinct}");
        let claim = action["claim"]
            .as_str()
            .unwrap_or_else(|| panic!("the distinct claim: {distinct}"))
            .to_owned();
        let pair = host.pair(&first, &second).await;
        assert!(holds(&pair["distinct_claims"], &claim), "{pair}");
        assert_eq!(pair["proposals"], json!([]), "{pair}");

        let spec = merge_input(&second, &first, &turn, "maybe one person after all");
        host.call(Caller::Root, PROPOSE, propose_input(&spec))
            .await
            .rejected(PROPOSE, "DistinctPairSuppressed");
        let pair = host.pair(&first, &second).await;
        assert_eq!(pair["proposals"], json!([]), "{pair}");
        let kept = host.resolve(&second).await;
        assert_eq!(kept["state"], "active", "{kept}");
        assert_eq!(kept["heads"], json!([second]), "{kept}");

        let merged = host.owner_ok(MERGE, spec).await;
        assert_eq!(merged["outcome"], "applied", "{merged}");
        let shell = host.resolve(&second).await;
        assert_eq!(shell["heads"], json!([first]), "{shell}");
    })
}

/// ARCH-0055 §4 (:96-103) "E lives on as redirect-to-SET ... Unattributable
/// residue stays on E, marked ambiguous" and :225 "Claim subjects keep
/// original entity ids forever." The owner splits a conflated person into
/// two heads: each mapped claim is assigned to its head, the unmapped one
/// stays on the original as residue, the original resolves to both heads,
/// and no claim row changes subject. The undo restores the original.
#[test]
fn a_split_redirects_through_new_heads_and_moves_no_claim_row() {
    run_on_engine_stack("identity-doors-split", || async {
        let host = Host::new("vault-identity-doors-split");
        let scope = host.base_claim_scope().await;
        let conflated = host.person_row("Morgan Reyes");
        let north = host.person_row("Morgan Reyes of North Office");
        let south = host.person_row("Morgan Reyes of Southport");
        let at_north = host
            .claim(&scope, &conflated, "profile.employer", "North Office Ltd")
            .await;
        let at_south = host
            .claim(&scope, &conflated, "profile.lives_in", "Southport")
            .await;
        let residue = host
            .claim(&scope, &conflated, "profile.name", "Morgan Reyes")
            .await;
        let before = host.claim_row(&at_north).await;
        let turn = host.witnessed("two Morgan Reyes, one in each office");

        let split = host
            .owner_ok(
                SPLIT,
                json!({
                    "entity": conflated,
                    "heads": [north, south],
                    "reassignment_map": [
                        {"item": {"kind": "claim", "claim": at_north},
                         "target": {"kind": "head", "head": north}},
                        {"item": {"kind": "claim", "claim": at_south},
                         "target": {"kind": "head", "head": south}},
                        {"item": {"kind": "claim", "claim": residue},
                         "target": {"kind": "residue"}},
                    ],
                    "evidence": evidence(&turn, "two people under one name"),
                }),
            )
            .await;
        assert_eq!(split["outcome"], "applied", "{split}");
        let action = &split["receipt"]["action"];
        assert_eq!(action["op"], "split", "{split}");
        assert_eq!(action["applied_assigned"], 2, "{split}");
        assert_eq!(action["applied_residue"], 1, "{split}");
        assert!(
            split["transitions"]
                .as_array()
                .is_some_and(|rows| rows.contains(&json!({"entity": conflated, "state": "split"}))),
            "the split moves the original to `split`: {split}"
        );

        let mut heads = vec![north.clone(), south.clone()];
        heads.sort();
        let shell = host.resolve(&conflated).await;
        assert_eq!(shell["state"], "split", "{shell}");
        assert_eq!(sorted(&shell["heads"]), heads, "{shell}");
        assert_eq!(sorted(&shell["split_into"]), heads, "{shell}");
        assert!(holds(&shell["ambiguous_residue"], &residue), "{shell}");
        assert!(!holds(&shell["remaining_claims"], &at_north), "{shell}");
        assert!(!holds(&shell["remaining_claims"], &at_south), "{shell}");
        let north_view = host.resolve(&north).await;
        assert!(
            holds(&north_view["assigned_claims"], &at_north),
            "{north_view}"
        );
        assert!(
            !holds(&north_view["assigned_claims"], &at_south),
            "{north_view}"
        );
        let south_view = host.resolve(&south).await;
        assert!(
            holds(&south_view["assigned_claims"], &at_south),
            "{south_view}"
        );
        assert!(
            !holds(&south_view["assigned_claims"], &at_north),
            "{south_view}"
        );
        let during = host.claim_row(&at_north).await;
        for field in ["subject_ref", "value", "made_by"] {
            assert_eq!(
                during[field], before[field],
                "a split rewrites no claim ({field}): {during}"
            );
        }

        let receipt = &split["receipt"];
        let undone = host
            .owner_ok(
                UNDO,
                json!({"event": receipt["event"], "seen": receipt["seen"]}),
            )
            .await;
        assert_eq!(undone["outcome"], "applied", "{undone}");
        let restored = host.resolve(&conflated).await;
        assert_eq!(restored["state"], "active", "{restored}");
        assert_eq!(restored["heads"], json!([conflated]), "{restored}");
        let north_view = host.resolve(&north).await;
        assert!(
            !holds(&north_view["assigned_claims"], &at_north),
            "{north_view}"
        );
        assert_eq!(host.claim_row(&at_north).await, before);
    })
}

/// Every `vault.identity.*` row is a host door whose proof is the owner's.
/// A live person and a FullAccess agent, each on its own `core:read` +
/// `core:write` slip, are refused 403 "<verb> is the vault owner's" at all
/// eleven doors, each sent an input its row decodes (validate_input runs
/// before the door's admission). A ReadOnly agent stops at each write door's
/// scope guard and at each read door's owner proof. Nothing moves, and the
/// same merge then applies for the owner.
#[test]
fn no_identity_door_opens_for_anyone_but_the_owner() {
    run_on_engine_stack("identity-doors-owner-only", || async {
        let host = Host::new("vault-identity-doors-owner-only");
        let mina = host.person("Mina Okafor", 0x91);
        let keeper = host.agent("identity-keeper", 0x92, AgentTier::FullAccess, READ_WRITE);
        let reader = host.agent("identity-reader", 0x93, AgentTier::ReadOnly, READ_ONLY);
        let ada = host.person_row("Ada North");
        let duplicate = host.person_row("A. North");
        let turn = host.witnessed("A. North signed the harbour log as Ada North");
        let event = EntityId::now().to_hex();
        let seen = "00".repeat(32);
        let merge = merge_input(&duplicate, &ada, &turn, "one person signs both ways");
        let doors: Vec<(&str, Value)> = vec![
            (MERGE, merge.clone()),
            (
                SPLIT,
                json!({
                    "entity": duplicate, "heads": [ada], "reassignment_map": [],
                    "evidence": evidence(&turn, "a split"),
                }),
            ),
            (
                FACET,
                json!({
                    "entity": duplicate, "facets": [{"label": "work"}], "reassignment_map": [],
                    "evidence": evidence(&turn, "a mask"),
                }),
            ),
            (
                ASSERT_DISTINCT,
                json!({"a": ada, "b": duplicate, "reason": "two people"}),
            ),
            (PROPOSE, propose_input(&merge)),
            (UNDO, json!({"event": event, "seen": seen})),
            (
                PROPOSALS_RESOLVE,
                json!({"proposal": event, "seen": seen, "decision": {"ruling": "approve"}}),
            ),
            (RESOLVE, json!({"entity": duplicate})),
            (EVENTS_GET, json!({"event": event})),
            (FOR_PAIR, json!({"a": ada, "b": duplicate})),
            (
                MENTION,
                json!({"turn": turn, "message": turn, "start": 0, "end": 3}),
            ),
        ];

        for caller in [&mina, &keeper] {
            for (verb, input) in &doors {
                host.call(Caller::As(caller), verb, input.clone())
                    .await
                    .forbidden(verb, &format!("{verb} is the vault owner's"));
            }
        }
        for (verb, input) in &doors {
            let reply = host.call(Caller::As(&reader), verb, input.clone()).await;
            if WRITE_DOORS.contains(verb) {
                reply.forbidden(verb, "required scope");
            } else {
                reply.forbidden(verb, &format!("{verb} is the vault owner's"));
            }
        }

        let kept = host.resolve(&duplicate).await;
        assert_eq!(kept["state"], "active", "{kept}");
        assert_eq!(kept["heads"], json!([duplicate]), "{kept}");
        assert_eq!(kept["facets"], json!([]), "{kept}");
        let pair = host.pair(&ada, &duplicate).await;
        assert_eq!(pair["proposals"], json!([]), "{pair}");
        assert_eq!(pair["distinct_claims"], json!([]), "{pair}");

        let merged = host.owner_ok(MERGE, merge).await;
        assert_eq!(merged["outcome"], "applied", "{merged}");
    })
}
