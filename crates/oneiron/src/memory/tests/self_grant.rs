//! Self-Grant and private admin-ruling falsification tests.
use super::*;
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::store::GateDecisionId;
use crate::write_envelope::WriteActor;

fn skill() -> SkillRecord {
    SkillRecord::new(
        "local.skill",
        "candidate instructions",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("origin"), Value::from("test"))]),
    )
}
fn owner_proof(vault: &crate::Vault, actor: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .unwrap()
}
fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

#[test]
fn own_skill_save_edit_and_foreign_fork_preserve_authorship_and_admission() {
    let (_dir, vault) = open_vault();
    let resident = put_person(&vault, 0x21);
    let stranger = put_person(&vault, 0x22);
    let memory = vault.memory(resident, EdgeActorClass::Agent);
    let saved = memory.skill_save(id(0x23), &skill(), None, 100).unwrap();
    assert_eq!(saved.author, resident);
    let mut record = vault.get_skill_record(&saved.skill_id).unwrap().unwrap();
    assert_eq!(record.source, ClaimSource::Generated);
    assert!(record.generated);
    assert!(!record.human_authored);
    assert_eq!(record.approval_status, ClaimApprovalStatus::Proposed);
    record.version = "2".to_owned();
    record.desc = "edited candidate".to_owned();
    memory
        .skill_save(saved.skill_id, &record, Some("1"), 101)
        .unwrap();
    assert_eq!(
        vault
            .get_skill_record(&saved.skill_id)
            .unwrap()
            .unwrap()
            .desc,
        "edited candidate"
    );
    let before = vault.get_raw(&saved.skill_id).unwrap();
    assert_eq!(
        vault
            .memory(stranger, EdgeActorClass::Agent)
            .skill_save(saved.skill_id, &record, Some("2"), 102)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(vault.get_raw(&saved.skill_id).unwrap(), before);
    record.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        memory
            .skill_save(saved.skill_id, &record, Some("2"), 102)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    let fork = vault
        .memory(stranger, EdgeActorClass::Agent)
        .skill_fork(saved.skill_id, id(0x24), "local.fork", 103)
        .unwrap();
    assert_eq!(fork.author, stranger);
    let fork_record = vault.get_skill_record(&fork.skill_id).unwrap().unwrap();
    assert_eq!(fork_record.forked_from, Some(saved.skill_id));
    assert_eq!(fork_record.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(vault.get_raw(&saved.skill_id).unwrap(), before);
}

#[test]
fn foreign_claim_upsert_retract_and_same_id_put_cannot_erase_history() {
    let (_dir, vault) = open_vault();
    let author = put_person(&vault, 0x31);
    let subject = put_person(&vault, 0x32);
    let mut first = claim_input(
        "profile.name",
        &subject,
        "observed",
        serde_json::json!("original"),
    );
    first.id = Some(id(0x33).to_hex());
    facade_for(&vault, author).claim_upsert(&first).unwrap();
    let before = vault.get_raw(&id(0x33)).unwrap();
    let attacker = vault.memory(subject, EdgeActorClass::Agent);
    let mut replacement = first.clone();
    replacement.id = Some(id(0x34).to_hex());
    replacement.value = serde_json::json!("replacement");
    replacement.learned_at = Some(101);
    assert_eq!(
        attacker.claim_upsert(&replacement).unwrap_err().code,
        MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(
        attacker.claim_retract(&id(0x33).to_hex()).unwrap_err().code,
        MEMORY_CODE_FORBIDDEN
    );
    replacement.id = first.id;
    assert_eq!(
        attacker.claim_upsert(&replacement).unwrap_err().code,
        MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(vault.get_raw(&id(0x33)).unwrap(), before);
    assert!(vault.get_raw(&id(0x34)).unwrap().is_none());

    // A new own revision still supersedes under the same ordinary door.
    replacement.id = Some(id(0x35).to_hex());
    facade_for(&vault, author)
        .claim_upsert(&replacement)
        .unwrap();
    assert_eq!(
        vault.get_claim(&id(0x33)).unwrap().unwrap().lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault.get_claim(&id(0x35)).unwrap().unwrap().value,
        Value::from("replacement")
    );
}

#[test]
fn runtime_supersede_trap_refuses_foreign_authored_head_before_receipts() {
    use crate::code_run::{
        HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemorySupersedeClaimCall,
    };
    let (_dir, vault) = open_vault();
    let author = put_person(&vault, 0x41);
    let attacker = put_person(&vault, 0x42);
    let subject = put_person(&vault, 0x43);
    for (actor, claim_id, value) in [
        (author, id(0x44), "original"),
        (attacker, id(0x45), "other"),
    ] {
        let mut input = claim_input(
            "profile.name",
            &subject,
            "observed",
            serde_json::json!(value),
        );
        input.id = Some(claim_id.to_hex());
        facade_for(&vault, actor).claim_propose(&input).unwrap();
    }
    let dispatcher = HostSelfDispatcher::new(
        &vault,
        WriteActor::new(attacker, EdgeActorClass::Agent),
        "foreign-head",
    )
    .unwrap();
    let before = vault.get_raw(&id(0x44)).unwrap();
    let receipts = vault.gate_decisions(1000).unwrap().len();
    let err = dispatcher
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall {
                new_id: id(0x45),
                old_id: id(0x44),
                now: 200,
            },
        ))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ActorLacksClaimAuthority);
    assert_eq!(vault.get_raw(&id(0x44)).unwrap(), before);
    assert_eq!(vault.gate_decisions(1000).unwrap().len(), receipts);
}

#[test]
fn daemon_needs_exact_owner_delegation_even_for_its_own_skill() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x51);
    let machine = put_machine(&vault, 0x52);
    root_vault_binding(&vault, 0x53, owner, "human");
    let proof = owner_proof(&vault, owner);
    let daemon = vault.memory(machine, EdgeActorClass::System);
    assert_eq!(
        daemon
            .skill_save(id(0x54), &skill(), None, 100)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    facade_for(&vault, owner)
        .delegate_memory_authoring(
            &proof,
            WriteActor::new(machine, EdgeActorClass::System),
            MemoryAuthoringAction::CreateSkill,
            id(0x54),
        )
        .unwrap();
    daemon.skill_save(id(0x54), &skill(), None, 101).unwrap();
    assert_eq!(
        daemon
            .skill_save(id(0x55), &skill(), None, 101)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    let mut stored = vault.get_skill_record(&id(0x54)).unwrap().unwrap();
    stored.version = "2".to_owned();
    stored.desc = "daemon edit".to_owned();
    assert_eq!(
        daemon
            .skill_save(id(0x54), &stored, Some("1"), 102)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    facade_for(&vault, owner)
        .delegate_memory_authoring(
            &proof,
            WriteActor::new(machine, EdgeActorClass::System),
            MemoryAuthoringAction::EditSkill,
            id(0x54),
        )
        .unwrap();
    daemon
        .skill_save(id(0x54), &stored, Some("1"), 103)
        .unwrap();
    assert_eq!(
        vault
            .memory(machine, EdgeActorClass::Agent)
            .skill_save(id(0x56), &skill(), None, 104)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
}

struct ConflictFixture {
    owner: EntityId,
    author: EntityId,
    subject: EntityId,
    bundle: ClaimConflictBundle,
}
fn conflict(vault: &crate::Vault) -> ConflictFixture {
    let owner = put_person(vault, 0x61);
    let author = put_person(vault, 0x62);
    let subject = put_person(vault, 0x63);
    root_vault_binding(vault, 0x64, owner, "human");
    let mut input = claim_input(
        "profile.reliability",
        &subject,
        "observed",
        serde_json::json!("contested"),
    );
    input.id = Some(id(0x65).to_hex());
    facade_for(vault, author).claim_upsert(&input).unwrap();
    input.id = Some(id(0x66).to_hex());
    input.value = serde_json::json!("corrected");
    facade_for(vault, subject).claim_propose(&input).unwrap();
    let bundle = facade_for(vault, subject)
        .question_claim_conflict(
            ClaimConflictQuestion::ConflictOfInterest,
            &id(0x65).to_hex(),
            &id(0x66).to_hex(),
        )
        .unwrap();
    ConflictFixture {
        owner,
        author,
        subject,
        bundle,
    }
}

#[test]
fn one_private_admin_bundle_ruling_is_atomic_receipted_and_replay_safe() {
    let (_dir, vault) = open_vault();
    let f = conflict(&vault);
    let subject = facade_for(&vault, f.subject);
    let again = subject
        .question_claim_conflict(
            ClaimConflictQuestion::ConflictOfInterest,
            &f.bundle.disputed.to_hex(),
            &f.bundle.proposal.to_hex(),
        )
        .unwrap();
    assert_eq!(again, f.bundle);
    let owner = facade_for(&vault, f.owner);
    let proof = owner_proof(&vault, f.owner);
    assert_eq!(
        owner.pending_claim_conflicts(&proof).unwrap(),
        vec![f.bundle.clone()]
    );
    let outsider = put_person(&vault, 0x67);
    assert_eq!(
        facade_for(&vault, outsider)
            .claim_conflict(f.bundle.bundle_id)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(
        facade_for(&vault, f.author)
            .claim_conflict(f.bundle.bundle_id)
            .unwrap(),
        f.bundle
    );
    assert_eq!(
        subject
            .rule_claim_conflict(&owner_proof(&vault, f.subject), f.bundle.bundle_id, 200)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    let original = vault.get_claim(&f.bundle.disputed).unwrap().unwrap();
    let proposal = vault.get_claim(&f.bundle.proposal).unwrap().unwrap();
    let receipt = owner
        .rule_claim_conflict(&proof, f.bundle.bundle_id, 200)
        .unwrap();
    let replay = owner
        .rule_claim_conflict(&proof, f.bundle.bundle_id, 201)
        .unwrap();
    assert_eq!(receipt, replay);
    let old = vault.get_claim(&f.bundle.disputed).unwrap().unwrap();
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old.value, original.value);
    assert_eq!(old.evidence, original.evidence);
    let proposal_after = vault.get_claim(&f.bundle.proposal).unwrap().unwrap();
    assert_eq!(proposal_after.value, proposal.value);
    assert_eq!(proposal_after.evidence, proposal.evidence);
    assert_eq!(proposal_after.source, proposal.source);
    assert_eq!(proposal_after.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(
        vault
            .get_claim(&receipt.ruling_claim)
            .unwrap()
            .unwrap()
            .value,
        Value::from("corrected")
    );
    let decisions = vault.gate_decisions(1000).unwrap();
    assert_eq!(
        decisions
            .iter()
            .filter(|d| d.content_kind == "consent_bundle:claim_conflict" && d.outcome == "pending")
            .count(),
        1
    );
    assert_eq!(decisions.iter().filter(|d| d.content_kind == "consent_bundle:claim_conflict" && d.outcome == "approved").count(), 1);
    assert!(owner.pending_claim_conflicts(&proof).unwrap().is_empty());
}

#[test]
fn stale_review_refuses_without_any_ruling_or_receipt() {
    let (_dir, vault) = open_vault();
    let f = conflict(&vault);
    let owner = facade_for(&vault, f.owner);
    let proof = owner_proof(&vault, f.owner);
    // A context member changed after review. The packet binds this row too.
    vault
        .put_entity(
            &f.author,
            ENTITY_TYPE_PERSON,
            test_time(100),
            100,
            b"changed author context",
        )
        .unwrap();
    let before = vault.get_raw(&f.bundle.disputed).unwrap();
    let receipts = vault.gate_decisions(1000).unwrap().len();
    assert_eq!(
        owner
            .rule_claim_conflict(&proof, f.bundle.bundle_id, 200)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(vault.get_raw(&f.bundle.disputed).unwrap(), before);
    assert_eq!(vault.gate_decisions(1000).unwrap().len(), receipts);
}

#[test]
fn admin_power_is_named_delegation_not_a_person_or_position_claim() {
    let (_dir, vault) = open_vault();
    let f = conflict(&vault);
    let admin = put_person(&vault, 0x68);
    let reviewer = facade_for(&vault, admin);
    let proof = owner_proof(&vault, admin);
    assert!(reviewer.pending_claim_conflicts(&proof).unwrap().is_empty());
    assert_eq!(
        reviewer
            .rule_claim_conflict(&proof, f.bundle.bundle_id, 200)
            .unwrap_err()
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    facade_for(&vault, f.owner)
        .delegate_memory_authoring(
            &owner_proof(&vault, f.owner),
            WriteActor::new(admin, EdgeActorClass::Human),
            MemoryAuthoringAction::ReviewConflict,
            f.bundle.disputed,
        )
        .unwrap();
    assert_eq!(reviewer.pending_claim_conflicts(&proof).unwrap().len(), 1);
    let receipt = reviewer
        .rule_claim_conflict(&proof, f.bundle.bundle_id, 200)
        .unwrap();
    assert!(vault.get_claim(&receipt.ruling_claim).unwrap().is_some());
}

#[test]
fn explicit_owner_retraction_is_a_durable_override_not_implicit_self_grant() {
    let (_dir, vault) = open_vault();
    let f = conflict(&vault);
    facade_for(&vault, f.owner)
        .claim_retract(&f.bundle.disputed.to_hex())
        .unwrap();
    let old = vault.get_claim(&f.bundle.disputed).unwrap().unwrap();
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(old.value, Value::from("contested"));
    let receipts = vault.gate_decisions(1000).unwrap();
    assert_eq!(
        receipts
            .iter()
            .filter(|r| r.content_kind == "memory_claim_override"
                && r.actor_ref == Some(f.owner.to_hex()))
            .count(),
        1
    );
}

#[test]
fn authored_source_save_update_and_fork_keep_real_files_atomic_and_candidate() {
    use crate::skill_hub::HubFile;
    let (dir, vault) = open_vault();
    let resident = put_person(&vault, 0x21);
    let stranger = put_person(&vault, 0x22);
    let id = EntityId::now();
    let fork = EntityId::now();
    let files = |version: &str| {
        vec![
        HubFile::new("SKILL.md",format!("---\nname: local.skill\nversion: {version}\n---\n\nUse the supplied rows only.\n").into_bytes()),
        HubFile::new("scripts/check.py",b"print(17)\n".to_vec()),
    ]
    };
    let source_files = |vault: &crate::Vault, id: EntityId| {
        let txn = vault.store.env.read_txn().unwrap();
        vault
            .export_hub_package_in_txn(&txn, &id)
            .unwrap()
            .unwrap()
            .files
    };
    let receipt = vault
        .memory(resident, EdgeActorClass::Agent)
        .skill_save_with_source(id, &skill(), files("1"), None, 100)
        .unwrap();
    assert_eq!(receipt.author, resident);
    let original = vault.get_skill_record(&id).unwrap().unwrap();
    assert_eq!(original.source, ClaimSource::Generated);
    assert_eq!(original.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(original.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(source_files(&vault, id), files("1"));
    let mut edited = original.clone();
    edited.version = "2".into();
    edited.content_hash = None;
    assert!(
        vault
            .memory(stranger, EdgeActorClass::Agent)
            .skill_save_with_source(id, &edited, files("2"), Some("1"), 101)
            .is_err()
    );
    assert_eq!(source_files(&vault, id), files("1"));
    // Missing SKILL.md is rejected after candidate staging but rolls back the
    // candidate bytes, source retirement and author receipt in the same txn.
    assert!(
        vault
            .memory(resident, EdgeActorClass::Agent)
            .skill_save_with_source(
                id,
                &edited,
                vec![HubFile::new("scripts/check.py", b"print(19)\n".to_vec())],
                Some("1"),
                101
            )
            .is_err()
    );
    assert_eq!(vault.get_skill_record(&id).unwrap(), Some(original.clone()));
    assert_eq!(source_files(&vault, id), files("1"));
    vault
        .memory(resident, EdgeActorClass::Agent)
        .skill_save_with_source(id, &edited, files("2"), Some("1"), 102)
        .unwrap();
    let fork_receipt = vault
        .memory(stranger, EdgeActorClass::Agent)
        .skill_fork(id, fork, "local.copy", 103)
        .unwrap();
    assert_eq!(fork_receipt.author, stranger);
    let fork_record = vault.get_skill_record(&fork).unwrap().unwrap();
    assert_eq!(fork_record.forked_from, Some(id));
    assert_eq!(fork_record.lifecycle_status, SkillLifecycle::Candidate);
    let copied = source_files(&vault, fork);
    assert_eq!(
        copied
            .iter()
            .find(|file| file.path == "scripts/check.py")
            .unwrap()
            .content,
        b"print(17)\n"
    );
    assert!(
        std::str::from_utf8(
            &copied
                .iter()
                .find(|file| file.path == "SKILL.md")
                .unwrap()
                .content
        )
        .unwrap()
        .contains("name: \"local.copy\"")
    );
    drop(vault);
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    assert_eq!(source_files(&vault, id), files("2"));
    assert_eq!(source_files(&vault, fork), copied);
    let export = vault
        .export_whole_vault(crate::context_pack::PackFormat::Json)
        .unwrap();
    let (_other_dir, target) = open_vault();
    target.import_whole_vault_json(export.bytes()).unwrap();
    assert_eq!(source_files(&target, id), files("2"));
    assert_eq!(source_files(&target, fork), copied);
    let imported = target.get_skill_record(&id).unwrap().unwrap();
    assert_eq!(imported.source, ClaimSource::Imported);
    assert_eq!(imported.lifecycle_status, SkillLifecycle::Candidate);
    // A copied foreign author-proof field cannot authenticate a new local act.
    assert!(
        target
            .memory(resident, EdgeActorClass::Agent)
            .skill_save_with_source(id, &imported, files("2"), Some("2"), 104)
            .is_err()
    );
}
