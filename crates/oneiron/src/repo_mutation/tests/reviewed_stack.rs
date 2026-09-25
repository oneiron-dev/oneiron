use super::*;
use crate::contract_oracle::{ContractOracle, ContractSpec, WorkspaceGraph};
use crate::critic::{CriticLens, CritiqueVerdict, LensCatalog};
use crate::merge_queue::{
    BatchState, CheckPhase, CheckReport, MergeBatch, MergeFile, MergeProposal, MergeQueue,
};
use crate::repo_mutation::proposal::{RepoProposal, RepoProposalOperation, RepoProposalStatus};
use std::collections::BTreeMap;

fn propose(vault: &Vault, repo: &TempDir, operation: RepoMutationOperation) -> RepoProposal {
    let actor = EntityId::now();
    let session = EntityId::now();
    for (id, kind) in [
        (actor, crate::registry::ENTITY_TYPE_PERSON),
        (session, crate::registry::ENTITY_TYPE_SESSION),
    ] {
        vault
            .put_entity(
                &id,
                kind,
                TimeRange { start: 1, end: 1 },
                1,
                b"review fixture",
            )
            .unwrap();
    }
    vault
        .propose_repo_mutation(
            RepoMutationRequest::new(repo_ref(repo), operation)
                .with_actor_id(actor)
                .with_session_id(session)
                .with_provenance_claim_id(put_repo_provenance_claim(vault)),
            LensCatalog {
                schema_version: 1,
                lenses: vec![
                    CriticLens::new(
                        "correctness",
                        "fixture review",
                        "critique.v1",
                        true,
                        "code_review",
                    )
                    .unwrap(),
                ],
            },
        )
        .unwrap()
}
fn commit(vault: &Vault, repo: &TempDir, path: &str, text: &[u8]) -> RepoProposal {
    propose(
        vault,
        repo,
        RepoMutationOperation::CommitFile {
            path: path.into(),
            content: text.into(),
            message: format!("Review {path}"),
        },
    )
}
fn approve(vault: &Vault, proposal: &RepoProposal) {
    vote_proposal(vault, proposal, CritiqueVerdict::Accept, true);
    vote_proposal(vault, proposal, CritiqueVerdict::Accept, true);
}
fn queue<'a>(vault: &'a Vault, repo: &TempDir) -> MergeQueue<'a> {
    let queue = MergeQueue::open(vault, repo_ref(repo)).unwrap();
    let spec = ContractSpec::default();
    let oracle = ContractOracle::new(vault);
    let baseline = oracle
        .record_baseline(
            spec.clone(),
            ContractOracle::capture(&spec, repo.path(), BTreeMap::new()).unwrap(),
        )
        .unwrap();
    let metadata = serde_json::json!({
        "workspace_root":repo.path(), "workspace_members":["fixture"],
        "packages":[{"id":"fixture", "manifest_path":repo.path().join("Cargo.toml"), "targets":[{"name":"fixture", "test":true}]}],
        "resolve":{"nodes":[{"id":"fixture", "dependencies":[]}]}
    });
    queue
        .initialize(
            &baseline.id,
            WorkspaceGraph::from_cargo_metadata(&serde_json::to_vec(&metadata).unwrap()).unwrap(),
        )
        .unwrap();
    queue
}
fn candidate(vault: &Vault, proposal: &RepoProposal, green: &str) -> MergeProposal {
    let old = vault
        .mount_repo_ref(
            &RepoRef::parse(&proposal.repo).unwrap(),
            super::super::mount::RepoMountRef::Fork(proposal.pre_action_fork_hash),
        )
        .unwrap();
    MergeProposal {
        id: proposal.id.to_hex(),
        base_green: green.into(),
        files: vec![MergeFile {
            path: proposal.path.clone(),
            expected: old.read_file(&proposal.path).unwrap().map(<[u8]>::to_vec),
            content: Some(proposal.content.clone()),
        }],
    }
}
fn ready(queue: &MergeQueue<'_>, batch: &MergeBatch) {
    queue.stage(&batch.id).unwrap();
    for mask in 1..(1 << batch.proposals.len()) {
        queue
            .check(&batch.id, mask, CheckPhase::Fast, &mut |_| {
                Ok(CheckReport {
                    tests_passed: true,
                    ..CheckReport::default()
                })
            })
            .unwrap();
    }
    assert_eq!(queue.batch(&batch.id).unwrap().state, BatchState::Ready);
}
fn cleanup(queue: &MergeQueue<'_>, batch: &MergeBatch) {
    queue
        .check(
            &batch.id,
            (1 << batch.proposals.len()) - 1,
            CheckPhase::Slow,
            &mut |_| {
                Ok(CheckReport {
                    tests_passed: true,
                    ..CheckReport::default()
                })
            },
        )
        .unwrap();
    queue.settle_slow().unwrap();
    queue.cleanup(&batch.id).unwrap();
}

#[test]
fn reviewed_stack_lands_same_base_proposals_without_rebasing_standalone_gate() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    let first = commit(&vault, &repo, "README.md", b"first\n");
    let second = commit(&vault, &repo, "second.rs", b"fn second() {}\n");
    let stale = commit(&vault, &repo, "stale.rs", b"stale\n");
    for row in [&first, &second, &stale] {
        approve(&vault, row);
    }
    assert_eq!(first.pre_action_fork_hash, second.pre_action_fork_hash);
    let queue = queue(&vault, &repo);
    let green = queue.pointers().unwrap().green;
    let batch = queue
        .enqueue(vec![
            candidate(&vault, &first, &green),
            candidate(&vault, &second, &green),
        ])
        .unwrap();
    ready(&queue, &batch);
    let landed = queue.land_reviewed(&batch.id).unwrap();
    assert_eq!(landed.state, BatchState::HeadAdvanced);
    assert_eq!(fs::read(repo.path().join("README.md")).unwrap(), b"first\n");
    assert_eq!(
        fs::read(repo.path().join("second.rs")).unwrap(),
        b"fn second() {}\n"
    );
    let rows = vault.repo_mutation_oplog(&repo_ref(&repo)).unwrap();
    let a = vault.repo_proposal(first.id).unwrap().unwrap();
    let b = vault.repo_proposal(second.id).unwrap().unwrap();
    assert_eq!(a.status, RepoProposalStatus::Applied);
    assert_eq!(b.status, RepoProposalStatus::Applied);
    let a_receipt = rows
        .iter()
        .find(|r| Some(r.seq) == a.operation_seq)
        .unwrap();
    let b_receipt = rows
        .iter()
        .find(|r| Some(r.seq) == b.operation_seq)
        .unwrap();
    assert_eq!(
        a_receipt.expected_post_action_fork_hash,
        Some(b_receipt.pre_action_fork_hash)
    );
    assert_eq!(
        vault.get_claim(&first.id).unwrap().unwrap().approval,
        ClaimApprovalStatus::Approved
    );
    assert!(matches!(
        vault.apply_repo_proposal(stale.id),
        Err(Error::ConcurrentWrite(_))
    ));
    assert!(vault.apply_repo_proposal(first.id).is_err());
    assert!(!repo.path().join("stale.rs").exists());
    cleanup(&queue, &batch);
}

#[test]
fn reviewed_stack_admission_is_atomic_for_missing_votes_and_forged_tested_bytes() {
    for forged in [false, true] {
        let (_dir, vault) = open_test_vault();
        let repo = init_repo();
        let first = commit(&vault, &repo, "README.md", b"first\n");
        let second = commit(&vault, &repo, "second.rs", b"second\n");
        approve(&vault, &first);
        if forged {
            approve(&vault, &second);
        }
        let queue = queue(&vault, &repo);
        let green = queue.pointers().unwrap().green;
        let mut second_candidate = candidate(&vault, &second, &green);
        if forged {
            second_candidate.files[0].content = Some(b"unreviewed\n".to_vec());
        }
        let batch = queue
            .enqueue(vec![candidate(&vault, &first, &green), second_candidate])
            .unwrap();
        ready(&queue, &batch);
        assert!(queue.land_reviewed(&batch.id).is_err());
        assert_eq!(fs::read(repo.path().join("README.md")).unwrap(), b"base\n");
        assert!(!repo.path().join("second.rs").exists());
        for row in [&first, &second] {
            let retained = vault.repo_proposal(row.id).unwrap().unwrap();
            assert_eq!(retained.status, RepoProposalStatus::Proposed);
            assert_eq!(retained.operation_seq, None);
            assert_eq!(vault.code_file_edit_receipt(row.id).unwrap(), None);
        }
        assert_eq!(queue.recover().unwrap().head, green);
        queue.cancel(&batch.id).unwrap();
        queue.cleanup(&batch.id).unwrap();
    }
}

#[test]
fn reviewed_stack_recovery_replays_only_its_durable_authorized_prefix() {
    for crash in [
        RepoMutationCrashPoint::AfterPreparedBeforeAction,
        RepoMutationCrashPoint::AfterDocumentBeforeAction,
        RepoMutationCrashPoint::AfterActionBeforeApplied,
        RepoMutationCrashPoint::AfterStackMember,
    ] {
        let (dir, vault) = open_test_vault();
        let repo = init_repo();
        let first = commit(&vault, &repo, "README.md", b"first\n");
        let second = commit(&vault, &repo, "second.rs", b"second\n");
        approve(&vault, &first);
        approve(&vault, &second);
        let batch;
        {
            let queue = queue(&vault, &repo);
            let green = queue.pointers().unwrap().green;
            batch = queue
                .enqueue(vec![
                    candidate(&vault, &first, &green),
                    candidate(&vault, &second, &green),
                ])
                .unwrap();
            ready(&queue, &batch);
            INJECT_REPO_MUTATION_CRASH.with(|cell| cell.set(crash));
            assert!(queue.land_reviewed(&batch.id).is_err());
            assert_eq!(queue.batch(&batch.id).unwrap().state, BatchState::Landing);
        }
        drop(vault);
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        let queue = MergeQueue::open(&vault, repo_ref(&repo)).unwrap();
        assert!(vault.apply_repo_proposal(second.id).is_err());
        queue.recover().unwrap();
        assert_eq!(
            queue.batch(&batch.id).unwrap().state,
            BatchState::HeadAdvanced
        );
        assert_eq!(fs::read(repo.path().join("README.md")).unwrap(), b"first\n");
        assert_eq!(
            fs::read(repo.path().join("second.rs")).unwrap(),
            b"second\n"
        );
        let before = vault.repo_mutation_oplog(&repo_ref(&repo)).unwrap();
        queue.recover().unwrap();
        assert_eq!(vault.repo_mutation_oplog(&repo_ref(&repo)).unwrap(), before);
        for row in [&first, &second] {
            assert_eq!(
                vault.repo_proposal(row.id).unwrap().unwrap().status,
                RepoProposalStatus::Applied
            );
            let receipt = vault.code_file_edit_receipt(row.id).unwrap().unwrap();
            assert_eq!(
                vault
                    .code_document_receipts(&receipt.document_id)
                    .unwrap()
                    .len(),
                1
            );
        }
        cleanup(&queue, &batch);
    }
}

#[test]
fn reviewed_stack_recovery_refuses_unjournaled_partial_tree_changes() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    let first = commit(&vault, &repo, "README.md", b"first\n");
    let second = commit(&vault, &repo, "second.rs", b"second\n");
    approve(&vault, &first);
    approve(&vault, &second);
    let queue = queue(&vault, &repo);
    let green = queue.pointers().unwrap().green;
    let batch = queue
        .enqueue(vec![
            candidate(&vault, &first, &green),
            candidate(&vault, &second, &green),
        ])
        .unwrap();
    ready(&queue, &batch);
    INJECT_REPO_MUTATION_CRASH.with(|cell| cell.set(RepoMutationCrashPoint::AfterStackMember));
    assert!(queue.land_reviewed(&batch.id).is_err());
    fs::write(repo.path().join("unreviewed.txt"), b"outside").unwrap();
    assert!(matches!(queue.recover(), Err(Error::ConcurrentWrite(_))));
    assert!(!repo.path().join("second.rs").exists());
    assert_eq!(
        fs::read(repo.path().join("unreviewed.txt")).unwrap(),
        b"outside"
    );
    fs::remove_file(repo.path().join("unreviewed.txt")).unwrap();
    queue.recover().unwrap();
    cleanup(&queue, &batch);
}

#[test]
fn conflict_resolution_uses_review_journal_and_stack_recovery_preserves_claims() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    create_conflicting_branches(&repo);
    let subject = put_branch_subject(&vault);
    let open = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::RecordConflict {
                branch_subject: subject,
                branch_name: "left".into(),
                ours_ref: "left".into(),
                theirs_ref: "right".into(),
            },
        ))
        .unwrap()
        .repo_conflict_claim_id
        .unwrap();
    run_git_at_path(repo.path(), &["checkout".into(), "left".into()]).unwrap();
    let proposal = propose(
        &vault,
        &repo,
        RepoMutationOperation::ResolveConflictFile {
            branch_subject: subject,
            open_conflict_claim_id: open,
            branch_name: "left".into(),
            path: "README.md".into(),
            content: b"resolved\n".to_vec(),
            message: "Reviewed resolution".into(),
        },
    );
    assert!(
        matches!(proposal.operation, RepoProposalOperation::ResolveConflictFile { open_conflict_claim_id, .. } if open_conflict_claim_id == open)
    );
    assert!(vault.apply_repo_proposal(proposal.id).is_err());
    assert_eq!(vault.repo_conflict_claims(&subject).unwrap().len(), 1);
    approve(&vault, &proposal);
    let second = commit(&vault, &repo, "second.rs", b"after resolution\n");
    approve(&vault, &second);
    let queue = queue(&vault, &repo);
    let green = queue.pointers().unwrap().green;
    let batch = queue
        .enqueue(vec![
            candidate(&vault, &proposal, &green),
            candidate(&vault, &second, &green),
        ])
        .unwrap();
    ready(&queue, &batch);
    INJECT_REPO_MUTATION_CRASH.with(|cell| cell.set(RepoMutationCrashPoint::AfterStackMember));
    assert!(queue.land_reviewed(&batch.id).is_err());
    assert!(vault.repo_conflict_claims(&subject).unwrap().is_empty());
    queue.recover().unwrap();
    assert_eq!(
        fs::read(repo.path().join("README.md")).unwrap(),
        b"resolved\n"
    );
    assert_eq!(
        vault.repo_proposal(proposal.id).unwrap().unwrap().status,
        RepoProposalStatus::Applied
    );
    let resolutions = vault.repo_conflict_resolution_claims(&subject).unwrap();
    assert_eq!(resolutions.len(), 1);
    assert_eq!(resolutions[0].open_conflict_claim_id, open);
    assert!(
        vault
            .edge_exists(
                &resolutions[0].claim_id,
                crate::edge::EdgeKind::Supersedes,
                &open
            )
            .unwrap()
    );
    cleanup(&queue, &batch);
}

#[test]
fn standalone_reviewed_conflict_resolution_is_bound_and_replays_its_claim_receipt() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    create_conflicting_branches(&repo);
    let subject = put_branch_subject(&vault);
    let open = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::RecordConflict {
                branch_subject: subject,
                branch_name: "left".into(),
                ours_ref: "left".into(),
                theirs_ref: "right".into(),
            },
        ))
        .unwrap()
        .repo_conflict_claim_id
        .unwrap();
    let proposed = propose(
        &vault,
        &repo,
        RepoMutationOperation::ResolveConflictFile {
            branch_subject: subject,
            open_conflict_claim_id: open,
            branch_name: "left".into(),
            path: "README.md".into(),
            content: b"resolved\n".to_vec(),
            message: "Reviewed resolution".into(),
        },
    );
    approve(&vault, &proposed);
    let first = vault.apply_repo_proposal(proposed.id).unwrap();
    assert_eq!(first.entry.operation_kind, "resolve_conflict_file");
    assert!(first.repo_conflict_claim_id.is_some());
    assert_eq!(vault.apply_repo_proposal(proposed.id).unwrap(), first);
    assert_eq!(
        fs::read(repo.path().join("README.md")).unwrap(),
        b"resolved\n"
    );
    assert!(vault.repo_conflict_claims(&subject).unwrap().is_empty());
}

#[test]
fn stale_later_document_refuses_whole_stack_before_first_effect() {
    let (_dir, vault) = open_test_vault();
    let repo = init_repo();
    let first = commit(&vault, &repo, "README.md", b"first\n");
    let second = commit(&vault, &repo, "second.rs", b"second\n");
    approve(&vault, &first);
    approve(&vault, &second);
    // Edit the canonical document scope captured by the proposal, not a path alias.
    let scope = super::super::oplog::repo_mutation_repo_key(&RepoRef::parse(&second.repo).unwrap());
    let mut session = vault
        .open_code_document(&scope, "second.rs", "", second.session)
        .unwrap();
    vault
        .apply_code_file_edit(
            &mut session,
            &crate::code_document::CodeFileEdit::between("second.rs", "", "unseen live edit"),
            crate::write_envelope::WriteActor::new(
                second.actor,
                crate::edge::EdgeActorClass::Agent,
            ),
        )
        .unwrap();
    let queue = queue(&vault, &repo);
    let green = queue.pointers().unwrap().green;
    let batch = queue
        .enqueue(vec![
            candidate(&vault, &first, &green),
            candidate(&vault, &second, &green),
        ])
        .unwrap();
    ready(&queue, &batch);
    assert!(matches!(
        queue.land_reviewed(&batch.id),
        Err(Error::ConcurrentWrite(_))
    ));
    assert_eq!(fs::read(repo.path().join("README.md")).unwrap(), b"base\n");
    assert!(!repo.path().join("second.rs").exists());
    assert_eq!(vault.code_file_edit_receipt(first.id).unwrap(), None);
    assert_eq!(session.text(), "unseen live edit");
    queue.recover().unwrap();
    queue.cancel(&batch.id).unwrap();
    queue.cleanup(&batch.id).unwrap();
}
