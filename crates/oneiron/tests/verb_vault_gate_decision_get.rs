//! `vault.gate.decision.get` through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out, on the
//! caller's own `Memory`. Input is the existing `ExplainGateRequest`
//! (`{"receipt": "gate:<hex>"}`); output is `ScopedReadResult<Option<View>>`
//! (`{"value": <view|null>, "narrowing": {...}}`).
//!
//! An agent with no live Grant naming the verb is refused `FORBIDDEN`, even with a live
//! base read Grant: verb standing, not the read lane. The holder of a base-only Grant
//! naming the verb reads its own ordinary-agent-write gate receipt with its
//! `read_frontier_hash`; another actor's decision whose claim the base lane admits stays
//! visible but omits `read_frontier_hash` and the unreadable `grant_ref` (a 64-hex
//! standing-grant digest, which never resolves as an `EntityId`); another actor's claim
//! outside the lane answers `value: null`. No view carries `context` or `diff_handle`;
//! absent `actor_ref`, `claim_ref`, `grant_ref` and `read_frontier_hash` are omitted keys,
//! while `redacted_at` is always present (`null` here). Malformed and unknown receipts
//! answer `none`. Revoking the holder's Grant refuses the same
//! `Memory` handle live.
//!
//! Seeds are ordinary agent writes THROUGH the existing verb
//! `vault.claims.upsert` (via `invoke`, never direct store puts): each seeding writer holds
//! a read Grant so `subject_ref` passes `refs` admission, the holder on a base-only
//! read/write Grant (never top), the other writer on a top read/write Grant it retains.
//! The upsert replaces the standing claim on its key (subject, predicate, world, scope),
//! so the other writer's claims take the holder's claim as their subject: no seeding
//! write lands on another author's key.
//! The other's base decision carries a non-empty weave `grant_ref` (public
//! `mint_auto_weave_grant`, project scope, `Auto` landing): the writer's own read sees it,
//! the base-only holder sees the readable claim without it, proving non-vacuous removal.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_gate_decision_get`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::lifecycle::{
    AutoWeaveGrantRequest, AutoWeaveWriterClass, mint_auto_weave_grant,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MEMORY_CODE_FORBIDDEN, Memory, MemoryError,
    ScopedClaimInput,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const GATE_DECISION_GET_VERB: &str = "vault.gate.decision.get";
const GATE_DECISION_GET_UPSERT: &str = "vault.claims.upsert";
const GATE_DECISION_GET_NOW: u64 = 1_700_000_000;
const GATE_DECISION_GET_PREDICATE: &str = "profile.preference";
const GATE_DECISION_GET_EXCLUDED_WORLD: &str = "gate decision excluded world";

// Fixture ids are `[seed; 16]`, in `0x80..=0x8F`, off the pinned bytes a fresh vault holds.
const GATE_DECISION_GET_HOLDER: u8 = 0x80;
const GATE_DECISION_GET_OTHER: u8 = 0x81;
const GATE_DECISION_GET_READONLY: u8 = 0x82;
const GATE_DECISION_GET_NOGRANT: u8 = 0x83;
const GATE_DECISION_GET_HOLDER_CLAIM: u8 = 0x84;
const GATE_DECISION_GET_OTHER_INSIDE_CLAIM: u8 = 0x85;
const GATE_DECISION_GET_OTHER_OUTSIDE_CLAIM: u8 = 0x86;
const GATE_DECISION_GET_SUBJECT_CLAIM: u8 = 0x87;
const GATE_DECISION_GET_UNKNOWN_DECISION: u8 = 0x8F;

/// A vault where the holder (base-only) and the other writer (top) seeded ordinary agent
/// claims through `vault.claims.upsert`, the other's base claim under an auto-weave Grant.
struct GateDecisionGetFixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    holder: EntityId,
    other: EntityId,
    readonly: EntityId,
    nogrant: EntityId,
    holder_grant: EntityId,
    holder_claim: EntityId,
    holder_receipt: String,
    other_inside_claim: EntityId,
    other_inside_receipt: String,
    other_outside_receipt: String,
}

fn gate_decision_get_fixture() -> GateDecisionGetFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let staging = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner staging proof");
    let holder = EntityId::from_bytes([GATE_DECISION_GET_HOLDER; 16]).expect("holder agent id");
    let other = EntityId::from_bytes([GATE_DECISION_GET_OTHER; 16]).expect("other agent id");
    let readonly =
        EntityId::from_bytes([GATE_DECISION_GET_READONLY; 16]).expect("readonly agent id");
    let nogrant = EntityId::from_bytes([GATE_DECISION_GET_NOGRANT; 16]).expect("nogrant agent id");
    for (id, name) in [
        (holder, "gate_decision_get_holder"),
        (other, "gate_decision_get_other"),
        (readonly, "gate_decision_get_readonly"),
        (nogrant, "gate_decision_get_nogrant"),
    ] {
        create_agent_definition_as(
            &vault,
            &staging,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": name,
                    "desc": "gate decision get fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("owner creates agent definition");
    }
    let other_world = vault
        .create_world(
            &staging,
            GATE_DECISION_GET_EXCLUDED_WORLD,
            GATE_DECISION_GET_NOW,
        )
        .expect("owner creates excluded world");
    let facet_hex = vault.default_facet().expect("default facet").to_hex();
    let subject_claim =
        EntityId::from_bytes([GATE_DECISION_GET_SUBJECT_CLAIM; 16]).expect("subject claim id");
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(&staging)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(subject_claim.to_hex()),
            predicate: GATE_DECISION_GET_PREDICATE.to_owned(),
            subject_ref: owner.to_hex(),
            value: json!("subject observation"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: facet_hex.clone(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(GATE_DECISION_GET_NOW),
            learned_at: Some(GATE_DECISION_GET_NOW),
            salience: None,
        })
        .expect("owner writes readable subject claim");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("live owner proof");
    // Auto definitions are self-limits, not policy authority. The owner grants the
    // two fixture writers Auto ceilings in the existing default manifest.
    let policies = policy_manifests_as_owner(
        &vault,
        &owner_proof,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("owner reads the default manifest");
    let default_ref = policies.default_manifest_ref;
    let mut default_view = policies
        .manifests
        .into_iter()
        .find(|view| view.manifest_ref == default_ref)
        .expect("seeded default manifest");
    default_view
        .manifest
        .actor_ceilings
        .extend([holder, other].map(|actor| ActorCeiling {
            actor_class: "agent".to_owned(),
            actor_ref: Some(actor.to_hex()),
            ceiling: PolicyCeiling::Auto,
        }));
    put_policy_manifest_as_owner(
        &vault,
        &owner_proof,
        PolicyManifestPut {
            manifest_ref: Some(default_ref),
            expected_body_hash: Some(default_view.body_hash),
            manifest: default_view.manifest,
        },
    )
    .expect("owner authorizes Auto landings for fixture writers");
    mint_auto_weave_grant(
        &vault,
        &owner_proof,
        AutoWeaveGrantRequest {
            writer: other.to_hex(),
            writer_class: AutoWeaveWriterClass::Agent,
            scope: "project".to_owned(),
            scope_id: default_project_id().to_hex(),
        },
    )
    .expect("owner mints auto-weave grant for other writer");
    let mut holder_scope = Scope::top();
    holder_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    holder_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        GATE_DECISION_GET_UPSERT.to_owned(),
        GATE_DECISION_GET_VERB.to_owned(),
    ]));
    let holder_minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: holder,
            authority_scope: holder_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints holder base grant");
    assert!(holder_minted.grant.confers, "holder base grant confers");
    let mut other_scope = Scope::top();
    other_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        GATE_DECISION_GET_UPSERT.to_owned(),
        GATE_DECISION_GET_VERB.to_owned(),
    ]));
    let other_minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: other,
            authority_scope: other_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints other top grant");
    assert!(other_minted.grant.confers, "other top grant confers");
    let mut readonly_scope = Scope::top();
    readonly_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    readonly_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let readonly_minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: readonly,
            authority_scope: readonly_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints readonly base read grant");
    assert!(
        readonly_minted.grant.confers,
        "readonly base read grant confers"
    );
    let write_through_verb =
        |writer: EntityId, claim: EntityId, subject: EntityId, world: EntityId, value: &str| {
            let input = ScopedClaimInput {
                id: Some(claim.to_hex()),
                predicate: GATE_DECISION_GET_PREDICATE.to_owned(),
                subject_ref: subject.to_hex(),
                value: json!(value),
                confidence: 1.0,
                source: "observed".to_owned(),
                scope: ClaimScope {
                    world_id: world.to_hex(),
                    scope_facet_id: facet_hex.clone(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(GATE_DECISION_GET_NOW),
                learned_at: Some(GATE_DECISION_GET_NOW),
                salience: None,
            };
            let memory = vault.memory(writer, EdgeActorClass::Agent);
            let out = invoke(
                &memory,
                GATE_DECISION_GET_UPSERT,
                serde_json::to_value(&input).expect("upsert input json"),
            )
            .expect("agent seeds claim through vault.claims.upsert");
            assert_eq!(
                out["approval"],
                json!("auto"),
                "seeding write lands Auto: {out}"
            );
            let receipt = out["receipt_ref"]
                .as_str()
                .expect("upsert receipt ref")
                .to_owned();
            assert!(
                receipt.starts_with("gate:"),
                "seeding write leaves gate receipt: {out}"
            );
            receipt
        };
    let holder_claim =
        EntityId::from_bytes([GATE_DECISION_GET_HOLDER_CLAIM; 16]).expect("holder claim id");
    let holder_receipt = write_through_verb(
        holder,
        holder_claim,
        subject_claim,
        base_world_id(),
        "holder base observation",
    );
    let other_inside_claim = EntityId::from_bytes([GATE_DECISION_GET_OTHER_INSIDE_CLAIM; 16])
        .expect("other inside claim id");
    let other_inside_receipt = write_through_verb(
        other,
        other_inside_claim,
        holder_claim,
        base_world_id(),
        "other base observation",
    );
    let other_outside_claim = EntityId::from_bytes([GATE_DECISION_GET_OTHER_OUTSIDE_CLAIM; 16])
        .expect("other outside claim id");
    let other_outside_receipt = write_through_verb(
        other,
        other_outside_claim,
        holder_claim,
        other_world,
        "other excluded observation",
    );
    GateDecisionGetFixture {
        vault,
        _dir: dir,
        owner_proof,
        holder,
        other,
        readonly,
        nogrant,
        holder_grant: holder_minted.grant.grant_ref,
        holder_claim,
        holder_receipt,
        other_inside_claim,
        other_inside_receipt,
        other_outside_receipt,
    }
}

/// The verb by name, as a client calls it: JSON in, JSON out.
fn gate_decision_get_call(memory: &Memory<'_>, receipt: &str) -> Result<Value, MemoryError> {
    invoke(memory, GATE_DECISION_GET_VERB, json!({"receipt": receipt}))
}

/// A live base read Grant without the verb is refused `FORBIDDEN`: verb standing, not the
/// read lane. On main the name is unknown and the refusal is `BAD_REQUEST`, so this fails
/// there.
#[test]
fn gate_decision_get_read_grant_without_verb_is_refused() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture
        .vault
        .memory(fixture.readonly, EdgeActorClass::Agent);
    let error = gate_decision_get_call(&memory, &fixture.holder_receipt)
        .expect_err("read grant without verb is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "unexpected refusal: {error:?}"
    );
    assert!(
        error.message.contains(GATE_DECISION_GET_VERB),
        "refusal names verb: {error:?}"
    );
}

/// No live Grant at all is refused `FORBIDDEN` as well. On main the name is unknown and the
/// refusal is `BAD_REQUEST`, so this fails there.
#[test]
fn gate_decision_get_no_grant_is_refused() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.nogrant, EdgeActorClass::Agent);
    let error = gate_decision_get_call(&memory, &fixture.holder_receipt)
        .expect_err("agent with no grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "unexpected refusal: {error:?}"
    );
    assert!(
        error.message.contains(GATE_DECISION_GET_VERB),
        "refusal names verb: {error:?}"
    );
}

/// The holder reads its own ordinary-agent-write receipt with its frontier hash, no grant
/// (no weave), no `context`/`diff_handle`, and `redacted_at: null`. On main the name is
/// unknown and the call errors, so the unwrap fails there.
#[test]
fn gate_decision_get_holder_reads_own_with_frontier() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let out = gate_decision_get_call(&memory, &fixture.holder_receipt)
        .expect("holder reads own gate receipt");
    assert!(out["value"].is_object(), "own receipt stays visible: {out}");
    let view = &out["value"];
    assert_eq!(view["receipt_id"], json!(fixture.holder_receipt), "{out}");
    assert_eq!(view["actor_class"], json!("agent"), "{out}");
    assert_eq!(view["actor_ref"], json!(fixture.holder.to_hex()), "{out}");
    assert_eq!(
        view["claim_ref"],
        json!(fixture.holder_claim.to_hex()),
        "{out}"
    );
    assert_eq!(view["content_kind"], json!("claim"), "{out}");
    assert_eq!(view["outcome"], json!("allow"), "{out}");
    let frontier = view["read_frontier_hash"]
        .as_str()
        .expect("own frontier is a hex string");
    assert_eq!(frontier.len(), 64, "frontier hex length: {out}");
    assert!(
        frontier.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "frontier hex digits: {out}"
    );
    assert_eq!(view["version"], json!(0), "fresh decision version: {out}");
    assert!(
        view.get("grant_ref").is_none(),
        "no weave grant, so absent: {out}"
    );
    assert!(view.get("context").is_none(), "no context: {out}");
    assert!(view.get("diff_handle").is_none(), "no diff_handle: {out}");
    assert!(
        view.get("redacted_at").is_some(),
        "redacted_at always present: {out}"
    );
    assert!(view["redacted_at"].is_null(), "fresh decision: {out}");
    assert!(view["reason_codes"].is_array(), "{out}");
    assert!(view["receipt_reasons"].is_array(), "{out}");
    assert!(view["notices"].is_array(), "{out}");
    assert!(view["decided_at"].is_u64(), "{out}");
    assert!(view["policy_manifest_version"].is_string(), "{out}");
    assert!(out.get("narrowing").is_some(), "receipt travels: {out}");
}

/// The writer's own read of its weave decision sees the non-empty 64-hex standing-grant
/// digest. On main the name is unknown and the call errors, so the unwrap fails there.
#[test]
fn gate_decision_get_other_reads_own_with_nonempty_grant() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.other, EdgeActorClass::Agent);
    let out = gate_decision_get_call(&memory, &fixture.other_inside_receipt)
        .expect("writer reads own weave decision");
    assert!(
        out["value"].is_object(),
        "own weave receipt stays visible: {out}"
    );
    let view = &out["value"];
    let grant = view
        .get("grant_ref")
        .expect("own sees nonempty grant: {out}");
    let digest = grant.as_str().expect("grant_ref is string: {out}");
    assert!(!digest.is_empty(), "grant digest nonempty: {out}");
    assert_eq!(digest.len(), 64, "weave bound digest hex: {out}");
    assert!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "digest hex digits: {out}"
    );
    assert!(
        view.get("read_frontier_hash")
            .is_some_and(|value| !value.is_null()),
        "own sees frontier: {out}"
    );
    assert_eq!(
        view["claim_ref"],
        json!(fixture.other_inside_claim.to_hex()),
        "{out}"
    );
    assert!(view.get("context").is_none(), "no context: {out}");
    assert!(view.get("diff_handle").is_none(), "no diff_handle: {out}");
    assert!(view["redacted_at"].is_null(), "fresh decision: {out}");
    assert!(out.get("narrowing").is_some(), "receipt travels: {out}");
}

/// The same weave decision through the holder's base lane: the readable base claim stays
/// visible, but the frontier and the 64-hex digest (never an `EntityId`) are omitted. This
/// is the non-vacuous removal: the writer above sees both. On main the name is unknown
/// and the call errors, so the unwrap fails there.
#[test]
fn gate_decision_get_holder_reads_other_inside_without_frontier_or_grant() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let out = gate_decision_get_call(&memory, &fixture.other_inside_receipt)
        .expect("readable base claim stays visible");
    assert!(
        out["value"].is_object(),
        "other inside stays visible: {out}"
    );
    let view = &out["value"];
    assert_eq!(
        view["receipt_id"],
        json!(fixture.other_inside_receipt),
        "{out}"
    );
    assert_eq!(
        view["claim_ref"],
        json!(fixture.other_inside_claim.to_hex()),
        "base lane admits claim: {out}"
    );
    assert!(
        view.get("read_frontier_hash").is_none(),
        "other reader omits frontier: {out}"
    );
    assert!(
        view.get("grant_ref").is_none(),
        "unreadable digest omitted: {out}"
    );
    if let Some(actor) = view.get("actor_ref") {
        assert_eq!(
            actor,
            &json!(fixture.other.to_hex()),
            "actor when shown is writer: {out}"
        );
    }
    assert!(view.get("context").is_none(), "no context: {out}");
    assert!(view.get("diff_handle").is_none(), "no diff_handle: {out}");
    assert!(view["redacted_at"].is_null(), "fresh decision: {out}");
    assert!(out.get("narrowing").is_some(), "receipt travels: {out}");
}

/// Another actor's claim outside the holder's base lane withholds the whole decision as
/// `value: null`. On main the name is unknown and the call errors, so the unwrap fails
/// there.
#[test]
fn gate_decision_get_holder_reads_other_outside_as_none() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let out = gate_decision_get_call(&memory, &fixture.other_outside_receipt)
        .expect("outside lane answers none, never refused");
    assert!(
        out["value"].is_null(),
        "outside claim withholds decision: {out}"
    );
    assert!(out.get("narrowing").is_some(), "receipt travels: {out}");
}

/// Unknown and malformed receipts both answer `none`. On main the name is unknown and the first call
/// errors, so the unwrap fails there.
#[test]
fn gate_decision_get_malformed_and_unknown_are_none() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let unknown = format!(
        "gate:{}",
        EntityId::from_bytes([GATE_DECISION_GET_UNKNOWN_DECISION; 16])
            .expect("unknown decision id")
            .to_hex()
    );
    let out =
        gate_decision_get_call(&memory, &unknown).expect("unknown receipt is none, not refused");
    assert!(out["value"].is_null(), "unknown receipt withholds: {out}");
    assert!(out.get("narrowing").is_some(), "receipt travels: {out}");
    for malformed in ["not-a-receipt", "gate:zzz", "gate:", "", "gate:00"] {
        let out = gate_decision_get_call(&memory, malformed)
            .expect("malformed receipt is none, not refused");
        assert!(
            out["value"].is_null(),
            "malformed {malformed} is none: {out}"
        );
        assert!(out.get("narrowing").is_some(), "receipt travels: {out}");
    }
}

/// The same call, which reads before the revoke, after the owner revokes the holder's base
/// Grant: refused again on the same handle, live. On main the name is unknown and the first
/// call errors, so the unwrap fails there.
#[test]
fn gate_decision_get_revoked_grant_refuses_again() {
    let fixture = gate_decision_get_fixture();
    let memory = fixture.vault.memory(fixture.holder, EdgeActorClass::Agent);
    let before = gate_decision_get_call(&memory, &fixture.holder_receipt)
        .expect("holder reads before revoke");
    assert!(
        before["value"].is_object(),
        "pre-revoke read holds row: {before}"
    );
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: fixture.holder_grant,
            seen: None,
        },
    )
    .expect("owner revokes holder grant");
    assert!(revoked.changed, "revoke lands");
    let error = gate_decision_get_call(&memory, &fixture.holder_receipt)
        .expect_err("revoked grant is refused live");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "unexpected refusal: {error:?}"
    );
}
