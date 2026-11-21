//! FIX [PUT-CLAIM-LANDS-ON-ARCHIVED-PERSON] (Engine ANSWER
//! PUT-CLAIM-ARCHIVED-PERSON-RESTORE = A, 20 Nov 22:50): the vault cleanup
//! archives only a PERSON no live claim is about, so a claim the owner or an
//! agent lands about a PERSON under the cleanup's archive marker restores her
//! in the claim's own write, as the Dreamer's claim writers already do
//! (ARCH-0073 §6: "a re-mention restores the archived record"). Only the
//! cleanup's marker is lifted: a PERSON the owner deleted, and one the owner
//! archived herself (a soft delete), stay as they are.
//!
//! Each PERSON is a plain stored row that the fixture archives as the cleanup
//! does (`archive_as_cleanup` writes the cleanup's archive marker), so no
//! test depends on the cleanup's listing rules. Each claim goes through one
//! public claim door: the owner's raw `Vault::put_claim`, an owner batch's
//! `commit` and `apply`, the owner's `claim_upsert_scoped`, and an agent's
//! `vault.claims.upsert` through the verb dispatch, which lands Proposed.
//!
//! Red without the fix (the first five tests): the claim lands and the
//! PERSON keeps her archive marker. Guards that hold with and without it
//! (the last two): a claim about a deleted PERSON, or about one the owner
//! archived, lifts nothing.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_write_restores_archived_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::row_live;
use oneiron::test_doors::dreamer_promotion_seconds::open_auto_promotion_vault;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, DeleteReason, EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use serde_json::json;

const READER: &str = "reader";
const UPSERT_VERB: &str = "vault.claims.upsert";
const AGENT_SEED: u8 = 0xD3;

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A stored PERSON named `name`.
fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("name", name)]))
        .expect("a PERSON body");
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(at), at, &body)
        .expect("FIXTURE: a live PERSON");
    id
}

/// `person`, archived as the cleanup archives a PERSON no live claim is
/// about: its row and body stay, under the cleanup's archive marker.
fn archived_person(vault: &Vault, name: &str) -> EntityId {
    let id = person(vault, name);
    archive_as_cleanup(vault, &id).expect("FIXTURE: the cleanup's archive marker");
    assert!(
        vault.archived_entity(&id).expect("read").is_some(),
        "FIXTURE: she is archived by the cleanup"
    );
    id
}

/// `person` is the owner's to read again: no archive marker, and her row is
/// live.
fn assert_restored(vault: &Vault, person: EntityId, door: &str) {
    assert!(
        vault.archived_entity(&person).expect("read").is_none(),
        "the claim {door} landed restored her: she bears no archive marker"
    );
    assert!(
        row_live(vault, person).expect("read"),
        "her row is live after the claim {door} landed"
    );
}

/// The owner's raw claim about `subject`, as the vault's holder writes it:
/// a `user_stated` preference at Auto, in the default facet.
fn put_owner_claim(vault: &Vault, subject: EntityId) -> oneiron::Result<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("green tea"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = vault.default_facet().expect("FIXTURE: default facet");
    let now = vault.now_recorded_at();
    vault.put_claim(&id, &body, range(now), now).map(|()| id)
}

/// An owner batch's claim about `subject`, written by a fresh PERSON as a
/// human: a `user_stated` preference at Auto.
fn owner_batch_claim(
    vault: &Vault,
    subject: EntityId,
) -> (EntityId, ClaimCandidate, WriteEnvelope) {
    let actor = person(vault, "Owen");
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("archived person fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("sencha"),
        0.9,
    );
    (EntityId::now(), candidate, envelope)
}

/// The scope of a claim in the base world, the default facet and project.
fn base_scope(vault: &Vault) -> ClaimScope {
    ClaimScope {
        world_id: base_world_id().to_hex(),
        scope_facet_id: vault.default_facet().expect("default facet").to_hex(),
        scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
        scope_project_id: default_project_id().to_hex(),
    }
}

/// A claim door's input: `predicate` about `subject` from `source`.
fn scoped_input(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    source: &str,
    sensitivity: Option<u8>,
) -> ScopedClaimInput {
    ScopedClaimInput {
        id: Some(id.to_hex()),
        predicate: "profile.name".to_owned(),
        subject_ref: subject.to_hex(),
        value: json!("Ann"),
        confidence: 1.0,
        source: source.to_owned(),
        scope: base_scope(vault).into(),
        sensitivity,
        evidence_turn_refs: Vec::new(),
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("live owner proof")
}

/// A vault with signing, a rooted serving install and one agent the owner
/// registered and granted `read` and `vault.claims.upsert` in the base
/// world (the fixture of `commitment_agent_series_approval`).
fn vault_with_upserting_agent(dir: &std::path::Path) -> (Vault, EntityId) {
    let vault = Vault::open(dir, VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let agent = EntityId::from_bytes([AGENT_SEED; 16]).expect("fixture agent id");
    create_agent_definition_as(
        &vault,
        &owner_proof(&vault, owner),
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "archived_person_agent",
                "desc": "an agent that writes what it learns about people",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("the owner registers the agent");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), UPSERT_VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof(&vault, owner),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent its upsert");
    assert!(minted.grant.confers, "FIXTURE: the agent's grant confers");
    (vault, agent)
}

#[test]
fn an_owner_put_claim_about_a_person_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let ann = archived_person(&vault, "Ann");

    let claim = put_owner_claim(&vault, ann).expect("the owner's claim about her lands");
    assert!(
        vault.get_claim(&claim).expect("read").is_some(),
        "the claim is stored"
    );
    assert_restored(&vault, ann, "put_claim");
}

#[test]
fn an_owner_batch_commit_about_a_person_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = archived_person(&vault, "Ann");

    let (id, candidate, envelope) = owner_batch_claim(&vault, ann);
    let now = vault.now_recorded_at();
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, range(now), now)
        .commit()
        .expect("the batch's claim about her lands");
    assert!(
        vault.get_claim(&id).expect("read").is_some(),
        "the claim is stored"
    );
    assert_restored(&vault, ann, "a batch committed");
}

#[test]
fn an_owner_batch_applied_in_its_callers_write_restores_a_person_the_cleanup_archived() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let ann = archived_person(&vault, "Ann");

    let (id, candidate, envelope) = owner_batch_claim(&vault, ann);
    let now = vault.now_recorded_at();
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch()
                .claim_candidate(&id, candidate, &envelope, range(now), now)
                .apply(wtxn)
        })
        .expect("the batch's claim about her lands in the caller's write");
    assert!(
        vault.get_claim(&id).expect("read").is_some(),
        "the claim is stored"
    );
    assert_restored(&vault, ann, "a batch applied");
}

#[test]
fn an_owner_scoped_upsert_about_a_person_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let ann = archived_person(&vault, "Ann");

    let id = EntityId::now();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert_scoped(&scoped_input(&vault, id, ann, "user_stated", Some(0)))
        .unwrap_or_else(|error| {
            panic!(
                "the owner's claim about her is admitted, got {}: {}",
                error.code, error.message
            )
        });
    assert_eq!(receipt.approval, "auto", "the owner's claim lands auto");
    assert_restored(&vault, ann, "vault.claims.upsert (owner)");
}

#[test]
fn an_agent_upsert_about_a_person_the_cleanup_archived_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, agent) = vault_with_upserting_agent(dir.path());
    let ann = archived_person(&vault, "Ann");

    let id = EntityId::now();
    let receipt = oneiron::verbs::invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        UPSERT_VERB,
        serde_json::to_value(scoped_input(&vault, id, ann, "observed", None))
            .expect("upsert input json"),
    )
    .expect("the agent writes its claim about her through vault.claims.upsert");
    assert_eq!(
        receipt["approval"],
        json!("proposed"),
        "an agent's claim lands proposed: {receipt}"
    );
    assert_eq!(
        vault
            .get_claim(&id)
            .expect("read")
            .expect("the agent's claim is stored")
            .approval,
        ClaimApprovalStatus::Proposed
    );
    assert_restored(&vault, ann, "vault.claims.upsert (agent)");
}

#[test]
fn a_claim_about_a_person_the_owner_deleted_lifts_nothing() {
    // A delete signs with this install's key: the vault needs a keystore.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_auto_promotion_vault(dir.path()).expect("vault");
    let ann = archived_person(&vault, "Ann");
    assert!(
        vault.delete_entity(&ann).expect("the owner's delete"),
        "FIXTURE: the delete found her row"
    );

    // Whether the door lands the claim or refuses it, the delete stands.
    let put = put_owner_claim(&vault, ann);
    assert!(
        vault.archived_entity(&ann).expect("read").is_some(),
        "a delete keeps the archive marker, and the claim cleared none: {put:?}"
    );
    assert!(
        !row_live(&vault, ann).expect("read"),
        "a deletion stands: no claim restores a deleted PERSON: {put:?}"
    );
}

#[test]
fn a_claim_about_a_person_the_owner_archived_lifts_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_auto_promotion_vault(dir.path()).expect("vault");
    let ann = person(&vault, "Ann");
    // The owner's own soft archive: an archive marker with the owner's
    // reason, never the cleanup's.
    vault
        .delete_entity_with_reason(&ann, DeleteReason::UserDelete)
        .expect("the owner archives her");
    assert!(
        !row_live(&vault, ann).expect("read"),
        "FIXTURE: the owner's archive hides her row"
    );
    assert!(
        vault.archived_entity(&ann).expect("read").is_none(),
        "FIXTURE: no cleanup archive marker"
    );

    let put = put_owner_claim(&vault, ann);
    assert!(
        !row_live(&vault, ann).expect("read"),
        "the owner's archive stands: a claim lifts only the cleanup's marker: {put:?}"
    );
    assert!(
        vault.archived_entity(&ann).expect("read").is_none(),
        "the claim wrote no cleanup marker: {put:?}"
    );
}
