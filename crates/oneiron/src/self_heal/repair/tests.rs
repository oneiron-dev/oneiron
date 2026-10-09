//! ONE-1395 runner tests. Existing detector tests remain unchanged.

use std::path::{Path, PathBuf};

use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::gate::resolve_policy_manifest;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::write_envelope::WriteActor;

fn repair_proposal() -> RepairProposal {
    RepairProposal {
        proposal_id: seed_id(10),
        diagnostic_refs: vec![seed_id(11)],
        actor: RepairActor {
            actor_class: "human".to_owned(),
            actor_ref: seed_id(12),
        },
        source: ClaimSource::UserStated,
        target_predicate: "maintenance.index".to_owned(),
        operation: RepairOperation::Reindex {
            scope_ref: "scope.fixture".to_owned(),
        },
        session_tag: "healer.chosen.session".to_owned(),
    }
}

fn registered(healer: &dyn Healer) -> RegisteredHealer<'_> {
    RegisteredHealer {
        healer_id: "test.fixture_healer",
        actor: WriteActor::new(seed_id(13), EdgeActorClass::System),
        agent_definition_ceiling: None,
        healer,
    }
}

fn operations() -> [RepairOperation; 8] {
    [
        RepairOperation::Reindex {
            scope_ref: "scope.fixture".to_owned(),
        },
        RepairOperation::Rescore {
            target_ref: seed_id(2),
        },
        RepairOperation::Retry {
            run_ref: "run.fixture".to_owned(),
        },
        RepairOperation::NarrowPolicy {
            predicate: "maintenance.index".to_owned(),
            value: Value::from("proposed"),
        },
        RepairOperation::ProposeClaim {
            predicate: "maintenance.index".to_owned(),
            value: Value::from("suggestion"),
        },
        RepairOperation::SkillEdit {
            skill_ref: seed_id(3),
            patch_ref: "patch.fixture".to_owned(),
        },
        RepairOperation::DevPatch {
            repo_ref: "repo.fixture".to_owned(),
            patch_ref: "patch.fixture".to_owned(),
        },
        RepairOperation::SchemaPatch {
            schema_ref: "schema.fixture".to_owned(),
            patch_ref: "patch.fixture".to_owned(),
        },
    ]
}

/// Read every file, including vault/index storage and dev-time patch targets.
fn file_snapshot(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut snapshot = BTreeMap::new();
    for entry in std::fs::read_dir(directory).expect("read fixture directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            snapshot.extend(file_snapshot(&path));
        } else {
            let bytes = std::fs::read(&path).expect("read fixture file");
            snapshot.insert(path, bytes);
        }
    }
    snapshot
}

struct BoundedHealer {
    observations: Vec<DiagnosticObservation>,
    diagnostics: Vec<DiagnosticEvent>,
    proposals: Vec<RepairProposal>,
}

impl Healer for BoundedHealer {
    fn propose(
        &self,
        working_set: &DiagnosticWorkingSet<'_>,
        diagnostics: &[DiagnosticEvent],
    ) -> Vec<RepairProposal> {
        assert_eq!(working_set.scope_ref, "scope.fixture");
        assert_eq!(working_set.observations, self.observations.as_slice());
        assert_eq!(diagnostics, self.diagnostics.as_slice());
        self.proposals.clone()
    }
}

#[test]
fn healer_proposes_not_applies() -> Result<()> {
    let (dir, vault) = open_vault();
    vault.put_entity(&seed_id(2), ENTITY_TYPE_PERSON, at(1_000), 1_001, b"target")?;
    let skill = SkillRecord::new(
        "fixture.repair.skill",
        "Repair fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    );
    vault.put_skill_record(&seed_id(3), &skill, at(1_000), 1_001)?;
    std::fs::write(dir.path().join("repo.fixture"), b"unchanged code").expect("seed code");
    std::fs::write(dir.path().join("schema.fixture"), b"unchanged schema").expect("seed schema");
    let observations = [observation(2, 1_000)];
    let working_set = DiagnosticWorkingSet {
        scope_ref: "scope.fixture",
        observations: &observations,
    };
    let ids = run_deterministic_detectors(&vault, &working_set, &[&StubDetector])?;
    let diagnostics = vec![decode_diagnostic_event_body(&stored_body(
        &vault, &ids[0],
    )?)?];
    let proposals: Vec<_> = operations()
        .into_iter()
        .zip(20_u8..)
        .map(|(operation, id)| RepairProposal {
            proposal_id: seed_id(id),
            diagnostic_refs: ids.clone(),
            operation,
            ..repair_proposal()
        })
        .collect();
    let healer = BoundedHealer {
        observations: observations.to_vec(),
        diagnostics: diagnostics.clone(),
        proposals: proposals.clone(),
    };
    let census_before = type_census(&vault)?;
    // Keep the same read transaction alive across both snapshots, so LMDB's
    // reader-lock bookkeeping is not confused with a healer side effect.
    let txn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &txn)?;
    let policy_before = policy.clone();
    let files_before = file_snapshot(dir.path());
    let bundle = run_healer_proposals(
        &policy,
        &registered(&healer),
        "engine.run",
        "engine.session",
        &working_set,
        &diagnostics,
    )?;
    assert_eq!(
        file_snapshot(dir.path()),
        files_before,
        "no files or stored indexes changed"
    );
    assert_eq!(policy, policy_before);
    assert_eq!(diagnostics, healer.diagnostics);
    assert_eq!(observations.as_slice(), healer.observations.as_slice());
    drop(txn);
    assert_eq!(type_census(&vault)?, census_before);
    assert_eq!(vault.get_skill_record(&seed_id(3))?, Some(skill));
    assert_eq!(bundle.session_tag(), "engine.session");
    assert_eq!(bundle.proposals().len(), proposals.len());
    for (member, mut expected) in bundle.proposals().iter().zip(proposals) {
        expected.session_tag = "engine.session".to_owned();
        assert_eq!(member.proposal(), &expected);
        assert_eq!(member.invocation().session_tag(), "engine.session");
        assert_eq!(member.invocation().actor().actor_ref, seed_id(13));
        assert_eq!(member.invocation().source(), ClaimSource::Generated);
        assert!(vault.get_raw(&expected.proposal_id)?.is_none());
    }
    Ok(())
}
