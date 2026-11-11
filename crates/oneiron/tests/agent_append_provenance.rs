//! Blob append provenance follows the bound writer class.
//!
//! Public doors only. The owner installs an actor-bound Auto ceiling so the
//! no-run-reference regression reaches the provenance decision on main. A
//! pending output has no version claim until Keep; the tests first read the
//! unchanged live artifact, then Keep as the owner and read the stored claim.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::blob_artifact::{ArtifactRefRequest, ArtifactView, ProposalSettleRequest};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome, Memory};
use oneiron::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{ClaimSource, EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const INITIAL_BYTES: &[u8] = b"the owner's first version";
const APPENDED_BYTES: &[u8] = b"the next artifact version";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    artifact: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"agent append provenance integration host")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let human = vault.memory(owner, EdgeActorClass::Human);
        let proof = human.embedded_owner("vault.agents.create")?;
        let agent = EntityId::now();
        let definition: AgentDefinitionSpec = serde_json::from_value(json!({
            "agent_id": "artifact-version-writer",
            "display_name": "Artifact version writer",
            "desc": "Appends artifact versions",
            "version": "1",
            "ceiling": "auto",
        }))?;
        oneiron::verbs::create_agent_definition_as(
            &vault,
            &proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition,
            },
        )?;

        let mut read = Scope::top();
        read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let policy = json!({
            "schema_version": "1.2",
            "pack_id": "agent-append-provenance",
            "pack_version": "1.0.0",
            "min_engine_version": "0.0.0",
            "defaults": {},
            "rules": [{
                "prefix": "blob.version",
                "exact": true,
                "axes": {"criticality": "normal", "sensitivity": "normal"},
            }],
            "actor_ceilings": [{
                "actor_class": "agent",
                "actor_ref": agent.to_hex(),
                "ceiling": "auto",
            }],
            "scoped_grants": [{
                "actor_ref": agent.to_hex(),
                "effector": "core:read",
                "scope": read,
                "receipt_required": false,
                "selectors": {"entity_types": [ENTITY_TYPE_BLOB_ARTIFACT]},
            }],
        });
        vault.install_owner_policy_manifest(
            &proof,
            EntityId::now(),
            rmp_serde::to_vec_named(&policy)?,
            vault.now_recorded_at(),
        )?;

        let artifact = EntityId::now();
        let now = vault.now_recorded_at();
        human.put_blob_artifact(&BlobArtifactInput {
            id: Some(artifact.to_hex()),
            name: "versioned.bin".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            occurred_at: now,
            learned_at: None,
        })?;
        let first =
            human.append_blob_version(&artifact.to_hex(), INITIAL_BYTES, None, now, None)?;
        assert!(
            matches!(first, BlobVersionAppendOutcome::Landed(_)),
            "FIXTURE: the owner's first version lands: {first:?}"
        );
        Ok(Self {
            vault,
            owner,
            agent,
            artifact,
            _dir: dir,
        })
    }

    fn human(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    fn agent(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    fn view(&self) -> TestResult<ArtifactView> {
        Ok(self
            .human()
            .artifacts_view(&ArtifactRefRequest {
                artifact_ref: self.artifact.to_hex(),
            })?
            .ok_or("the artifact is visible to its owner")?)
    }

    fn assert_live_unchanged(&self, before: &ArtifactView) -> TestResult {
        assert_eq!(
            &self.view()?,
            before,
            "a proposal must not advance the live artifact"
        );
        assert_eq!(
            self.human()
                .read_blob_version(&self.artifact.to_hex(), 1)?
                .as_deref(),
            Some(INITIAL_BYTES),
            "the owner's live bytes must stay unchanged"
        );
        Ok(())
    }

    fn keep_and_read_source(&self, proposal_ref: &str) -> TestResult<EntityId> {
        // The proposal's ledger claim is born only when the owner keeps it.
        let kept = self.human().artifacts_keep(&ProposalSettleRequest {
            artifact_ref: self.artifact.to_hex(),
            proposal_ref: proposal_ref.to_owned(),
            brief_ref: None,
            reason: None,
        })?;
        let head = self
            .vault
            .blob_artifact_head(&self.artifact)?
            .ok_or("Keep creates the next live version")?;
        assert_eq!(head.version, kept.version.version);
        assert_eq!(head.provenance.run_ref(), Some(proposal_ref));
        let claim = self
            .vault
            .get_claim(&head.claim_id)?
            .ok_or("the kept proposal has a stored version claim")?;
        assert_eq!(claim.source, Some(ClaimSource::Generated));
        assert_eq!(
            self.human()
                .read_blob_version(&self.artifact.to_hex(), head.version)?
                .as_deref(),
            Some(APPENDED_BYTES)
        );
        Ok(head.claim_id)
    }
}

#[test]
fn an_agent_append_without_run_ref_is_a_generated_proposal() -> TestResult {
    let fixture = Fixture::open()?;
    let before = fixture.view()?;
    assert_eq!(before.head, Some(1));
    let outcome = fixture
        .agent()
        .append_blob_version(
            &fixture.artifact.to_hex(),
            APPENDED_BYTES,
            None,
            fixture.vault.now_recorded_at(),
            None,
        )
        .expect("FIXTURE: the agent's Auto ceiling lets the append pass");
    let BlobVersionAppendOutcome::Proposed(proposal) = outcome else {
        panic!("expected a generated proposal, not a live version: {outcome:?}");
    };
    assert_eq!(proposal.base_version, before.head);
    assert_eq!(proposal.retained_by, fixture.agent);
    fixture.assert_live_unchanged(&before)?;
    let stored = fixture
        .vault
        .pending_proposal(&fixture.artifact, &proposal.proposal_ref)?
        .ok_or("the proposal waits beside the live version")?;
    assert_eq!(stored, proposal);
    let claim_id = fixture.keep_and_read_source(&proposal.proposal_ref)?;
    assert_eq!(
        proposal.proposal_ref,
        claim_id.to_hex(),
        "the fallback key is the version claim id"
    );
    Ok(())
}

#[test]
fn an_agent_append_with_run_ref_stays_a_generated_proposal() -> TestResult {
    let fixture = Fixture::open()?;
    let before = fixture.view()?;
    let run_ref = "artifact-append-control";
    let outcome = fixture.agent().append_blob_version(
        &fixture.artifact.to_hex(),
        APPENDED_BYTES,
        Some(run_ref),
        fixture.vault.now_recorded_at(),
        None,
    )?;
    let BlobVersionAppendOutcome::Proposed(proposal) = outcome else {
        panic!("an agent append with run_ref must remain a proposal: {outcome:?}");
    };
    assert_eq!(proposal.proposal_ref, run_ref);
    assert_eq!(proposal.base_version, before.head);
    fixture.assert_live_unchanged(&before)?;
    fixture.keep_and_read_source(run_ref)?;
    Ok(())
}

#[test]
fn the_owners_append_without_run_ref_still_lands_live() -> TestResult {
    let fixture = Fixture::open()?;
    let before = fixture.view()?;
    let outcome = fixture.human().append_blob_version(
        &fixture.artifact.to_hex(),
        APPENDED_BYTES,
        None,
        fixture.vault.now_recorded_at(),
        None,
    )?;
    let BlobVersionAppendOutcome::Landed(version) = outcome else {
        panic!("the owner's append without run_ref must land live: {outcome:?}");
    };
    let after = fixture.view()?;
    assert_eq!(
        version.version,
        before.head.ok_or("the first version is live")? + 1
    );
    assert_eq!(after.head, Some(version.version));
    assert_eq!(after.versions.len(), before.versions.len() + 1);
    assert_eq!(
        fixture
            .human()
            .read_blob_version(&fixture.artifact.to_hex(), version.version)?
            .as_deref(),
        Some(APPENDED_BYTES)
    );
    let claim = fixture
        .vault
        .get_claim(&EntityId::from_hex(&version.claim_ref)?)?
        .ok_or("the owner's append has a stored version claim")?;
    assert_eq!(claim.source, Some(ClaimSource::UserStated));
    assert!(
        fixture
            .vault
            .pending_proposals(&fixture.artifact)?
            .is_empty()
    );
    Ok(())
}
