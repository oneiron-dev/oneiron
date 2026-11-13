//! `vault.revisions.read`: an agent with no Grant is refused, the holder reads
//! only its lane's rows with live revisions, and a revoked Grant is refused
//! again. The verb is called by name through the string-keyed embedded door,
//! and the output is read as JSON, so this file uses no item the PR adds.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_revisions_read`

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MEMORY_CODE_BAD_REQUEST,
    MEMORY_CODE_FORBIDDEN, Memory, ScopedClaimInput,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;
const VERB: &str = "vault.revisions.read";

// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds
// (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const OWEN: u8 = 0x60;
const YUKI: u8 = 0x61;

/// An enabled, active agent definition the owner creates as `name`.
fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "home-reads revisions fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    base_claim: EntityId,
    other_claim: EntityId,
    owen: EntityId,
    yuki: EntityId,
    _dir: tempfile::TempDir,
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    value: &str,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(NOW),
            learned_at: Some(NOW),
            salience: None,
        })
        .expect("owner writes a claim in the requested world");
    id
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let owen = EntityId::from_bytes([OWEN; 16]).expect("owen id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &owen,
            &definition("owen"),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates owen");
    let yuki = EntityId::from_bytes([YUKI; 16]).expect("yuki id");
    vault
        .create_agent_definition_as(
            &owner_proof,
            &yuki,
            &definition("yuki"),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates yuki");
    let other_world = vault
        .create_world(&owner_proof, "outside lane world", NOW)
        .expect("owner creates the second world");
    let base_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        base_world_id(),
        "base-world claim",
    );
    let other_claim = write_owner_claim(
        &vault,
        owner,
        &owner_proof,
        other_world,
        "other-world claim",
    );
    Fixture {
        vault,
        owner,
        base_claim,
        other_claim,
        owen,
        yuki,
        _dir: dir,
    }
}

/// The owner grants `agent` the base world with `read` and this verb, rooted
/// and enrolled first as a serving start does. Returns the grant's row.
fn mint_lane_grant(fixture: &Fixture, agent: EntityId) -> EntityId {
    let issuer = fixture
        .vault
        .bootstrap_host_slip_issuer()
        .expect("host issuer");
    fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root");
    fixture
        .vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install carries the owner's grant act");
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof,
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
    .expect("owner mints the revisions grant");
    assert!(minted.grant.confers, "the grant confers");
    minted.grant.grant_ref
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
}

fn call(memory: &Memory<'_>, refs: &[String]) -> Result<Value, oneiron::memory::MemoryError> {
    oneiron::task_verb::sdk::invoke(memory, VERB, json!({ "refs": refs }))
}

#[test]
fn agent_with_no_grant_is_refused() {
    let fixture = fixture();
    let memory = fixture.vault.memory(fixture.yuki, EdgeActorClass::Agent);
    let refs = vec![fixture.base_claim.to_hex()];
    let error = call(&memory, &refs).expect_err("an agent with no grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a no-grant refusal names FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(VERB),
        "the refusal names the verb; got {}",
        error.message,
    );
}

#[test]
fn holder_reads_only_its_lane_with_live_revision() {
    let fixture = fixture();
    mint_lane_grant(&fixture, fixture.owen);
    let memory = fixture.vault.memory(fixture.owen, EdgeActorClass::Agent);
    let refs = vec![fixture.base_claim.to_hex(), fixture.other_claim.to_hex()];
    let out = call(&memory, &refs).expect("the holder reads its lane");
    let value = out
        .get("value")
        .and_then(Value::as_array)
        .expect("the value is the slots in order");
    assert_eq!(value.len(), 2, "one slot per ref; got {out}");
    let first = value[0]
        .as_object()
        .expect("the inside-lane row is present");
    let view = first
        .get("view")
        .and_then(Value::as_object)
        .expect("the entry carries its view");
    assert_eq!(
        view.get("id_hex").and_then(Value::as_str),
        Some(fixture.base_claim.to_hex()).as_deref(),
        "the inside-lane view is the base claim; got {view:?}",
    );
    let revision = first
        .get("revision")
        .expect("the entry carries its revision");
    assert!(
        revision.as_array().is_some_and(|bytes| bytes.len() == 16),
        "the live revision is present; got {revision}",
    );
    assert!(
        value[1].is_null(),
        "the row outside the lane is withheld as none; got {}",
        value[1],
    );
    assert!(
        out.get("narrowing").and_then(Value::as_object).is_some(),
        "the read keeps its narrowing receipt; got {out}",
    );
}

#[test]
fn revoked_grant_is_refused_again() {
    let fixture = fixture();
    let grant_ref = mint_lane_grant(&fixture, fixture.owen);
    let memory = fixture.vault.memory(fixture.owen, EdgeActorClass::Agent);
    let refs = vec![fixture.base_claim.to_hex()];
    let out = call(&memory, &refs).expect("the holder reads before the revoke");
    assert!(
        out.get("value")
            .and_then(Value::as_array)
            .and_then(|slots| slots.first())
            .is_some_and(|slot| slot.is_object()),
        "the pre-revoke read holds the row; got {out}",
    );
    revoke_grant(&fixture, grant_ref);
    let error = call(&memory, &refs).expect_err("the revoked grant is refused");
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "a revoked-grant refusal names FORBIDDEN; got {}: {}",
        error.code, error.message,
    );
}

#[test]
fn empty_and_oversize_lists_are_refused() {
    let fixture = fixture();
    mint_lane_grant(&fixture, fixture.owen);
    let memory = fixture.vault.memory(fixture.owen, EdgeActorClass::Agent);
    let empty: Vec<String> = Vec::new();
    let error = call(&memory, &empty).expect_err("an empty list is refused");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "an empty list names BAD_REQUEST; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains("must not be empty"),
        "the empty-list refusal names the list; got {}",
        error.message,
    );
    let oversize = vec![fixture.base_claim.to_hex(); 10_001];
    let error = call(&memory, &oversize).expect_err("an over-long list is refused");
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "an over-long list names BAD_REQUEST; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains("batch ceiling"),
        "the over-long refusal names the ceiling; got {}",
        error.message,
    );
}
