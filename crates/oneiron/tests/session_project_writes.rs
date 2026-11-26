//! RECALL-SESSION-PROJECT PR 3, the write default (row START-RECALL-WRITES-ROOT-PROJECT; Engine
//! ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q2 = A, an unbound folder's writes keep the
//! root default): a handle bound to an attached session's folder for its writes
//! (`Memory::placing_in_session_workspace`) places a claim that names no project in the folder's
//! project, through the typed `vault.claims.upsert` and through `vault.remember`'s untyped
//! claim alike, so the session's own project-scoped reads read it back. A claim that names its
//! project lands there; an unbound folder, and a handle with no folder, keep the root's default
//! project.
//!
//! Red on the base: `Memory::placing_in_session_workspace` does not exist there, so this file
//! does not build.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! session_project_writes`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimFilteredListRequest, ClaimInput, ClaimListFilter, ClaimScopeInput, Memory,
    ScopedClaimInput,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The digest of the folder bound to `alpha`.
const MAIN_DIGEST: &str = "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A rooted vault whose owner made `alpha` and `beta` under the root and bound the folder
/// `MAIN_DIGEST` to `alpha`. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    facet: EntityId,
    alpha: EntityId,
    beta: EntityId,
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
        &rmp_serde::to_vec_named(&json!({ "name": "session write facet" }))?,
    )?;
    let alpha = project_under(&vault, &issuer, &proof, owner, root, facet)?;
    let beta = project_under(&vault, &issuer, &proof, owner, root, facet)?;
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
        proof,
        facet,
        alpha,
        beta,
        _dir: dir,
    })
}

/// An owner-born project under `parent`, sliced to `facet`.
fn project_under(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    proof: &AuthenticatedOwner,
    owner: EntityId,
    parent: EntityId,
    facet: EntityId,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent), vault.root_project()?, owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = 1;
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

impl Fixture {
    /// The owner's handle, bound for its writes to the folder `folder_digest` when given.
    fn writer(&self, folder_digest: Option<&str>) -> Memory<'_> {
        let memory = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.proof);
        match folder_digest {
            Some(digest) => memory.placing_in_session_workspace(&[digest.to_owned()]),
            None => memory,
        }
    }

    /// `vault.claims.upsert` on `memory`: the owner's claim about themself on the facet,
    /// naming `project` when given; its 32-hex id.
    fn upserted(
        &self,
        memory: &Memory<'_>,
        project: Option<EntityId>,
        predicate: &str,
    ) -> TestResult<String> {
        let id = EntityId::now();
        memory
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: predicate.to_owned(),
                subject_ref: self.owner.to_hex(),
                value: json!("session write"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScopeInput {
                    world_id: None,
                    scope_facet_id: Some(self.facet.to_hex()),
                    scope_relationship_id: None,
                    scope_project_id: project.map(|project| project.to_hex()),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(1),
                learned_at: Some(1),
                salience: None,
            })
            .map_err(|error| format!("vault.claims.upsert: {error:?}"))?;
        Ok(id.to_hex())
    }

    /// `vault.remember`'s untyped claim on `memory`, its scope `scope`; its 32-hex id.
    fn remembered(
        &self,
        memory: &Memory<'_>,
        scope: Option<serde_json::Value>,
        predicate: &str,
    ) -> TestResult<String> {
        let id = EntityId::now();
        let input: ClaimInput = serde_json::from_value(json!({
            "id": id.to_hex(),
            "predicate": predicate,
            "subject_ref": self.owner.to_hex(),
            "value": "session remember",
            "confidence": 1.0,
            "source": "user_stated",
            "scope": scope,
            "occurred_at": 1,
            "learned_at": 1,
        }))?;
        memory
            .claim_upsert(&input)
            .map_err(|error| format!("vault.remember: {error:?}"))?;
        Ok(id.to_hex())
    }

    /// The claims `vault.claims.list_filtered` serves the owner for `project`.
    fn in_project(&self, project: EntityId) -> TestResult<BTreeSet<String>> {
        let request: ClaimFilteredListRequest =
            serde_json::from_value(json!({ "limit": 100, "project_refs": [project.to_hex()] }))?;
        Ok(self
            .writer(None)
            .claim_list_filtered(&request)
            .map_err(|error| format!("vault.claims.list_filtered: {error:?}"))?
            .value
            .into_iter()
            .map(|view| view.claim_ref)
            .collect())
    }

    /// The claims `vault.claims.list` serves a read of the folder `folder_digest`.
    fn session_reads(&self, folder_digest: &str) -> TestResult<BTreeSet<String>> {
        let filter: ClaimListFilter = serde_json::from_value(json!({ "limit": 100 }))?;
        Ok(self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .in_session_workspace(&[folder_digest.to_owned()])
            .claim_list(&filter)
            .map_err(|error| format!("vault.claims.list: {error:?}"))?
            .value
            .into_iter()
            .map(|view| view.claim_ref)
            .collect())
    }

    /// Every claim `vault.claims.list` serves the owner, with no folder.
    fn all_claims(&self) -> TestResult<BTreeSet<String>> {
        let filter: ClaimListFilter = serde_json::from_value(json!({ "limit": 100 }))?;
        Ok(self
            .writer(None)
            .claim_list(&filter)
            .map_err(|error| format!("vault.claims.list: {error:?}"))?
            .value
            .into_iter()
            .map(|view| view.claim_ref)
            .collect())
    }
}

#[test]
fn an_upsert_that_names_no_project_lands_in_the_folders_project() -> TestResult {
    let fixture = open()?;
    let claim = fixture.upserted(&fixture.writer(Some(MAIN_DIGEST)), None, "profile.hobby")?;
    assert!(
        fixture.in_project(fixture.alpha)?.contains(&claim),
        "the claim is alpha's"
    );
    assert!(!fixture.in_project(fixture.beta)?.contains(&claim));
    assert!(
        fixture.session_reads(MAIN_DIGEST)?.contains(&claim),
        "the session's own reads read it back"
    );
    Ok(())
}

#[test]
fn an_upsert_that_names_its_project_lands_there() -> TestResult {
    let fixture = open()?;
    let claim = fixture.upserted(
        &fixture.writer(Some(MAIN_DIGEST)),
        Some(fixture.beta),
        "profile.occupation",
    )?;
    assert!(
        fixture.in_project(fixture.beta)?.contains(&claim),
        "the named project decides"
    );
    assert!(!fixture.in_project(fixture.alpha)?.contains(&claim));
    Ok(())
}

#[test]
fn an_unbound_folders_upsert_keeps_the_root_default() -> TestResult {
    let fixture = open()?;
    let unbound = fixture.upserted(&fixture.writer(Some(UNBOUND_DIGEST)), None, "profile.hobby")?;
    let no_folder = fixture.upserted(&fixture.writer(None), None, "profile.instrument")?;
    for claim in [&unbound, &no_folder] {
        assert!(
            fixture.all_claims()?.contains(claim),
            "the claim is written"
        );
        assert!(
            !fixture.in_project(fixture.alpha)?.contains(claim),
            "no folder's project takes it"
        );
        assert!(!fixture.in_project(fixture.beta)?.contains(claim));
        assert!(
            !fixture.session_reads(MAIN_DIGEST)?.contains(claim),
            "the bound folder's reads do not read the root default's claim"
        );
    }
    Ok(())
}

#[test]
fn a_remembered_claim_that_names_no_project_lands_in_the_folders_project() -> TestResult {
    let fixture = open()?;
    let writer = fixture.writer(Some(MAIN_DIGEST));
    let bare = fixture.remembered(&writer, None, "profile.hobby")?;
    let with_facet = fixture.remembered(
        &writer,
        Some(json!({ "facet": fixture.facet.to_hex() })),
        "profile.instrument",
    )?;
    let named = fixture.remembered(
        &writer,
        Some(json!({ "scopeProjectId": fixture.beta.to_hex() })),
        "profile.occupation",
    )?;
    let alpha = fixture.in_project(fixture.alpha)?;
    assert!(
        alpha.contains(&bare) && alpha.contains(&with_facet),
        "a claim with no project is alpha's: {alpha:?}"
    );
    assert!(!alpha.contains(&named));
    assert!(
        fixture.in_project(fixture.beta)?.contains(&named),
        "a claim that names its project lands there"
    );
    assert!(
        fixture.session_reads(MAIN_DIGEST)?.contains(&bare),
        "the session's own reads read it back"
    );
    Ok(())
}

#[test]
fn a_batch_from_a_bound_folder_keeps_the_root_default_for_an_omitted_project() -> TestResult {
    let fixture = open()?;
    let omitted_id = EntityId::now();
    let explicit_id = EntityId::now();
    let omitted: ScopedClaimInput = serde_json::from_value(json!({
        "id": omitted_id.to_hex(),
        "predicate": "profile.hobby",
        "subject_ref": fixture.owner.to_hex(),
        "value": "a batched claim",
        "confidence": 1.0,
        "source": "user_stated",
        "scope": { "scope_facet_id": fixture.facet.to_hex() },
        "occurred_at": 1,
        "learned_at": 1,
    }))?;
    let explicit = ScopedClaimInput {
        id: Some(explicit_id.to_hex()),
        scope: ClaimScopeInput {
            scope_project_id: Some(fixture.beta.to_hex()),
            ..omitted.scope.clone()
        },
        ..omitted.clone()
    };
    let outcomes = fixture
        .writer(Some(MAIN_DIGEST))
        .commit_scoped(&[omitted, explicit], false)
        .map_err(|error| format!("vault.commit: {error:?}"))?;
    let defaulted = fixture
        .vault
        .get_claim(&omitted_id)?
        .ok_or_else(|| format!("the batch's defaulted claim is stored: {outcomes:?}"))?;
    let named = fixture
        .vault
        .get_claim(&explicit_id)?
        .ok_or_else(|| format!("the batch's explicit claim is stored: {outcomes:?}"))?;
    assert_eq!(
        defaulted.scope_project,
        oneiron::claim::default_project_id()
    );
    assert_eq!(named.scope_project, fixture.beta);
    Ok(())
}
