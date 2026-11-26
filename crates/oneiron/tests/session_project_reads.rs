//! RECALL-SESSION-PROJECT PR 2 (rows RECALL-SESSION-PROJECT and RECALL-SESSION-PROJECT-ALL-READS;
//! Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q1 = A, Q2 = A): a handle bound to an
//! attached session's folder (`Memory::in_session_workspace`) reads only the CLAIM rows of the
//! folder's project and the projects below it, list verbs and point reads included, and every
//! receipt names the axis; an unbound folder reads no claim and its receipt says
//! `no_project_bound`; a handle with no folder reads as before.
//!
//! The recall A/B's leak came through `vault.claims.list` and `vault.claims.list_filtered`, so
//! both are read here. A call that names its projects gets no session default: the MCP gateway
//! binds none (crates/oneiron-server/tests/mcp_session_project_reads.rs).
//!
//! Red on the base: `Memory::in_session_workspace` does not exist there, so this file does not
//! build.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! session_project_reads`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::authority::HostSlipIssuer;
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    AllRelationships, ClaimFilteredListRequest, ClaimFilteredReadRequest, ClaimListFilter,
    ClaimRelationships, ClaimScope, Memory, ScopedClaimInput,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::{NO_PROJECT_BOUND_AXIS, SESSION_PROJECT_AXIS, WorkspaceBindRequest};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The bound folder's own digest.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A linked worktree of it, with no binding of its own.
const WORKTREE_DIGEST: &str =
    "blake3:1f0e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A rooted vault whose owner made two projects under the root, `alpha` and `beta`, and
/// `alpha-docs` under `alpha`, with one owner claim in each, and bound the folder `MAIN_DIGEST` to
/// `alpha`. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    in_alpha: String,
    in_alpha_docs: String,
    in_beta: String,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let root = vault.root_project()?;
    vault.sign_owner_project(&proof, &vault.owner_project_signer(&issuer)?, root)?;
    let facet = EntityId::now();
    vault.put_entity(
        &facet,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&json!({ "name": "session project facet" }))?,
    )?;
    let alpha = project_under(&vault, &issuer, &proof, owner, root, facet, 2)?;
    let alpha_docs = project_under(&vault, &issuer, &proof, owner, alpha, facet, 1)?;
    let beta = project_under(&vault, &issuer, &proof, owner, root, facet, 2)?;
    let in_alpha = remember(
        &vault,
        owner,
        &proof,
        facet,
        alpha,
        "profile.hobby",
        "gardening",
    )?;
    let in_alpha_docs = remember(
        &vault,
        owner,
        &proof,
        facet,
        alpha_docs,
        "profile.instrument",
        "cello",
    )?;
    let in_beta = remember(
        &vault,
        owner,
        &proof,
        facet,
        beta,
        "profile.occupation",
        "baker",
    )?;
    let binding = vault.bind_workspace_as_owner(
        &proof,
        Some(ActSurface::ThisInstall),
        WorkspaceBindRequest {
            folder_digest: MAIN_DIGEST.to_owned(),
            project: alpha,
            label: Some("alpha".to_owned()),
        },
    )?;
    assert_eq!(
        binding.project,
        Some(alpha),
        "FIXTURE: the owner binds the folder"
    );
    Ok(Fixture {
        vault,
        owner,
        in_alpha,
        in_alpha_docs,
        in_beta,
        _dir: dir,
    })
}

/// An owner-born project under `parent`, sliced to `facet`, with `depth_remaining` levels
/// below it.
fn project_under(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    proof: &AuthenticatedOwner,
    owner: EntityId,
    parent: EntityId,
    facet: EntityId,
    depth_remaining: u64,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent), vault.root_project()?, owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = depth_remaining;
    create_owner_project(
        vault,
        issuer,
        proof,
        &vault.owner_project_signer(issuer)?,
        owner,
        id,
        &record,
    )?;
    Ok(id)
}

/// The owner's claim about themself stamped with `project`; its 32-hex id.
fn remember(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    facet: EntityId,
    project: EntityId,
    predicate: &str,
    value: &str,
) -> TestResult<String> {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: facet.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: project.to_hex(),
            }
            .into(),
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(1),
            learned_at: Some(1),
            salience: None,
        })
        .map_err(|error| format!("FIXTURE: the owner's claim in a project: {error:?}"))?;
    Ok(id.to_hex())
}

impl Fixture {
    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The claims `vault.claims.list` serves on `memory`, and its receipt's axes.
    fn listed(&self, memory: &Memory<'_>) -> TestResult<(BTreeSet<String>, Vec<String>)> {
        let filter: ClaimListFilter = serde_json::from_value(json!({ "limit": 100 }))?;
        let served = memory
            .claim_list(&filter)
            .map_err(|error| format!("vault.claims.list: {error:?}"))?;
        Ok((
            served
                .value
                .into_iter()
                .map(|view| view.claim_ref)
                .collect(),
            served.receipt.narrowed_axes,
        ))
    }

    /// The claims `vault.claims.list_filtered` serves on `memory` for `request`.
    fn listed_filtered(
        &self,
        memory: &Memory<'_>,
        request: serde_json::Value,
    ) -> TestResult<BTreeSet<String>> {
        let request: ClaimFilteredListRequest = serde_json::from_value(request)?;
        let served = memory
            .claim_list_filtered(&request)
            .map_err(|error| format!("vault.claims.list_filtered: {error:?}"))?;
        Ok(served
            .value
            .into_iter()
            .map(|view| view.claim_ref)
            .collect())
    }

    /// Whether `vault.claims.read_filtered` of `claim`, naming no project, serves it on
    /// `memory`.
    fn reads(&self, memory: &Memory<'_>, claim: &str) -> TestResult<bool> {
        let request: ClaimFilteredReadRequest =
            serde_json::from_value(json!({ "claim_ref": claim }))?;
        Ok(memory
            .claim_read_filtered(&request)
            .map_err(|error| format!("vault.claims.read_filtered: {error:?}"))?
            .value
            .is_some())
    }
}

fn set(ids: &[&String]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).clone()).collect()
}

#[test]
fn a_handle_with_no_folder_reads_every_project_as_before() -> TestResult {
    let fixture = open()?;
    let (listed, axes) = fixture.listed(&fixture.memory())?;
    let all = set(&[&fixture.in_alpha, &fixture.in_alpha_docs, &fixture.in_beta]);
    assert!(all.is_subset(&listed), "{listed:?}");
    assert!(
        !axes
            .iter()
            .any(|axis| axis == SESSION_PROJECT_AXIS || axis == NO_PROJECT_BOUND_AXIS),
        "{axes:?}"
    );
    Ok(())
}

#[test]
fn a_bound_folders_list_reads_its_project_and_the_projects_below_it() -> TestResult {
    let fixture = open()?;
    let session = fixture
        .memory()
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    let (listed, axes) = fixture.listed(&session)?;
    assert_eq!(
        listed,
        set(&[&fixture.in_alpha, &fixture.in_alpha_docs]),
        "vault.claims.list reads alpha and alpha-docs, never beta"
    );
    assert!(
        axes.iter().any(|axis| axis == SESSION_PROJECT_AXIS),
        "the receipt names the session project axis: {axes:?}"
    );
    Ok(())
}

#[test]
fn a_filtered_list_that_names_no_project_reads_the_session_project() -> TestResult {
    let fixture = open()?;
    let session = fixture
        .memory()
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    assert_eq!(
        fixture.listed_filtered(&session, json!({ "limit": 100 }))?,
        set(&[&fixture.in_alpha, &fixture.in_alpha_docs])
    );
    Ok(())
}

#[test]
fn a_point_read_of_another_projects_claim_reads_nothing() -> TestResult {
    let fixture = open()?;
    let session = fixture
        .memory()
        .in_session_workspace(&[MAIN_DIGEST.to_owned()]);
    assert!(fixture.reads(&session, &fixture.in_alpha)?);
    assert!(
        !fixture.reads(&session, &fixture.in_beta)?,
        "beta's claim is not read in alpha's folder"
    );
    assert!(fixture.reads(&fixture.memory(), &fixture.in_beta)?);
    Ok(())
}

#[test]
fn a_linked_worktree_reads_its_main_checkouts_project() -> TestResult {
    let fixture = open()?;
    let session = fixture
        .memory()
        .in_session_workspace(&[WORKTREE_DIGEST.to_owned(), MAIN_DIGEST.to_owned()]);
    let (listed, _) = fixture.listed(&session)?;
    assert_eq!(listed, set(&[&fixture.in_alpha, &fixture.in_alpha_docs]));
    Ok(())
}

#[test]
fn an_unbound_folder_reads_no_claim_and_its_receipt_says_why() -> TestResult {
    let fixture = open()?;
    let session = fixture
        .memory()
        .in_session_workspace(&[UNBOUND_DIGEST.to_owned()]);
    let (listed, axes) = fixture.listed(&session)?;
    for claim in [&fixture.in_alpha, &fixture.in_alpha_docs, &fixture.in_beta] {
        assert!(!listed.contains(claim), "no claim is read: {listed:?}");
    }
    assert!(
        axes.iter().any(|axis| axis == NO_PROJECT_BOUND_AXIS),
        "the receipt says no project is bound: {axes:?}"
    );
    assert!(
        fixture
            .listed_filtered(&session, json!({ "limit": 100 }))?
            .is_empty()
    );
    assert!(!fixture.reads(&session, &fixture.in_alpha)?);
    Ok(())
}
