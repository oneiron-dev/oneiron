use super::staging::git;
use super::*;
use crate::{
    VaultConfig,
    contract_oracle::{ContractOracle, ContractSpec, WorkspaceGraph},
    error::Error,
    repo_mutation::{RepoMutationOperation, RepoMutationOutcome, RepoMutationRequest},
};
use std::collections::BTreeMap;
use std::path::Path;

struct Fixture {
    _vault_dir: tempfile::TempDir,
    repo_dir: tempfile::TempDir,
    vault: Vault,
    repo_ref: RepoRef,
    base: String,
}
impl Fixture {
    fn new() -> Self {
        Self::with_contracts(ContractSpec::default(), &[])
    }
    fn with_contracts(spec: ContractSpec, extra_files: &[(&str, &[u8])]) -> Self {
        let vault_dir = tempfile::tempdir().unwrap();
        let repo_dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(vault_dir.path(), VaultConfig::default()).unwrap();
        git(repo_dir.path(), &["init"]).unwrap();
        for file in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(repo_dir.path().join(file), b"base\n").unwrap();
        }
        for (path, bytes) in extra_files {
            std::fs::write(repo_dir.path().join(path), bytes).unwrap();
        }
        git(repo_dir.path(), &["add", "--", "."]).unwrap();
        git(
            repo_dir.path(),
            &[
                "-c",
                "user.name=Oneiron",
                "-c",
                "user.email=oneiron@example.invalid",
                "commit",
                "-m",
                "initial",
            ],
        )
        .unwrap();
        let base = String::from_utf8(git(repo_dir.path(), &["rev-parse", "HEAD"]).unwrap())
            .unwrap()
            .trim()
            .to_owned();
        let repo_ref = RepoRef::LocalFolder {
            path: repo_dir.path().to_string_lossy().into_owned(),
            commit: base.clone(),
        };
        let baseline = ContractOracle::new(&vault)
            .record_baseline(
                spec.clone(),
                ContractOracle::capture(&spec, repo_dir.path(), BTreeMap::new()).unwrap(),
            )
            .unwrap();
        let metadata = serde_json::json!({
            "workspace_root": repo_dir.path(), "workspace_members": ["fixture"],
            "packages": [{"id":"fixture", "manifest_path":repo_dir.path().join("Cargo.toml"), "targets":[{"name":"fixture", "test":true}]}],
            "resolve":{"nodes":[{"id":"fixture", "dependencies":[]}]}
        });
        let graph =
            WorkspaceGraph::from_cargo_metadata(&serde_json::to_vec(&metadata).unwrap()).unwrap();
        MergeQueue::open(&vault, repo_ref.clone())
            .unwrap()
            .initialize(&baseline.id, graph)
            .unwrap();
        Self {
            _vault_dir: vault_dir,
            repo_dir,
            vault,
            repo_ref,
            base,
        }
    }
    fn queue(&self) -> MergeQueue<'_> {
        MergeQueue::open(&self.vault, self.repo_ref.clone()).unwrap()
    }
    fn proposal(&self, name: &str, content: &[u8]) -> MergeProposal {
        MergeProposal {
            id: name.into(),
            base_green: self.queue().pointers().unwrap().green,
            files: vec![MergeFile {
                path: format!("{name}.txt"),
                expected: Some(b"base\n".to_vec()),
                content: Some(content.to_vec()),
            }],
        }
    }
    fn host(&self, fail_after: Option<usize>) -> Host<'_> {
        Host {
            vault: &self.vault,
            repo: self.repo_ref.clone(),
            root: self.repo_dir.path(),
            fail_after,
            calls: 0,
        }
    }
    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.repo_dir.path().join(format!("{name}.txt"))).unwrap()
    }
}

// Trusted-admin test adapter. Production hosts replace this with their per-op
// authenticated proposal/gate adapter; the queue never fabricates gate approval.
struct Host<'a> {
    vault: &'a Vault,
    repo: RepoRef,
    root: &'a Path,
    fail_after: Option<usize>,
    calls: usize,
}
impl MergeLanding for Host<'_> {
    fn land(
        &mut self,
        permit: &LandingPermit,
        tested: &TestedBatch,
    ) -> Result<Vec<RepoMutationOutcome>> {
        self.calls += 1;
        let actual = String::from_utf8(git(self.root, &["rev-parse", "HEAD"])?).unwrap();
        assert_eq!(permit.expected_head(), actual.trim());
        assert_eq!(permit.expected_head(), tested.batch().expected_head);
        assert!(!permit.repo_identity().is_empty());
        let mut outcomes = Vec::new();
        if self.fail_after == Some(0) {
            return Err(Error::InvariantViolation("host interrupted before effect"));
        }
        for proposal in &tested.batch().proposals {
            for file in &proposal.files {
                outcomes.push(self.vault.apply_repo_mutation(RepoMutationRequest::new(
                    self.repo.clone(),
                    RepoMutationOperation::CommitFile {
                        path: file.path.clone(),
                        content: file.content.clone().unwrap(),
                        message: format!("Land {}", proposal.id),
                    },
                ))?);
                if self.fail_after == Some(outcomes.len()) {
                    return Err(Error::InvariantViolation("host interrupted after effect"));
                }
            }
        }
        Ok(outcomes)
    }
}

fn green(invocation: &CheckInvocation) -> Result<CheckReport> {
    assert!(invocation.worktree.join(".git").is_file());
    assert!(invocation.selected_tests.packages.contains("fixture"));
    assert_eq!(
        String::from_utf8(git(&invocation.worktree, &["rev-parse", "HEAD^{tree}"])?)
            .unwrap()
            .trim(),
        invocation.tree
    );
    Ok(CheckReport {
        tests_passed: true,
        ..CheckReport::default()
    })
}
fn ready(queue: &MergeQueue<'_>, batch: &MergeBatch) {
    queue.stage(&batch.id).unwrap();
    for mask in (1..(1 << batch.proposals.len())).rev() {
        queue
            .check(&batch.id, mask, CheckPhase::Fast, &mut green)
            .unwrap();
    }
    assert_eq!(queue.batch(&batch.id).unwrap().state, BatchState::Ready);
}
fn finish(queue: &MergeQueue<'_>, batch: &MergeBatch) {
    queue
        .check(
            &batch.id,
            (1 << batch.proposals.len()) - 1,
            CheckPhase::Slow,
            &mut green,
        )
        .unwrap();
    queue.settle_slow().unwrap();
    queue.cleanup(&batch.id).unwrap();
}

#[test]
fn materialized_paths_finish_out_of_order_and_only_all_path_agreement_lands_artifacts() {
    let fixture = Fixture::new();
    let queue = fixture.queue();
    let batch = queue
        .enqueue(vec![
            fixture.proposal("a", b"A\n"),
            fixture.proposal("b", b"B\n"),
        ])
        .unwrap();
    let staged = queue.stage(&batch.id).unwrap();
    assert_eq!(staged.paths.len(), 3);
    assert_eq!(
        std::fs::read(staged.paths[0].worktree.join("a.txt")).unwrap(),
        b"A\n"
    );
    assert_eq!(
        std::fs::read(staged.paths[0].worktree.join("b.txt")).unwrap(),
        b"base\n"
    );
    assert_eq!(
        std::fs::read(staged.paths[1].worktree.join("a.txt")).unwrap(),
        b"base\n"
    );
    assert_eq!(
        std::fs::read(staged.paths[2].worktree.join("b.txt")).unwrap(),
        b"B\n"
    );
    queue
        .check(&batch.id, 3, CheckPhase::Fast, &mut green)
        .unwrap();
    let mut host = fixture.host(None);
    assert!(queue.land(&batch.id, &mut host).is_err());
    assert_eq!(host.calls, 0);
    queue
        .check(&batch.id, 1, CheckPhase::Fast, &mut green)
        .unwrap();
    assert!(queue.land(&batch.id, &mut host).is_err());
    queue
        .check(&batch.id, 2, CheckPhase::Fast, &mut green)
        .unwrap();
    let landed = queue.land(&batch.id, &mut host).unwrap();
    assert_eq!(landed.state, BatchState::HeadAdvanced);
    assert_eq!(fixture.read("a"), b"A\n");
    assert_eq!(fixture.read("b"), b"B\n");
    assert_eq!(queue.pointers().unwrap().green, fixture.base);
    finish(&queue, &batch);
    assert_eq!(
        queue.pointers().unwrap().head,
        queue.pointers().unwrap().green
    );
}

#[test]
fn red_batch_bisects_culprit_quarantines_and_lands_survivors() {
    let fixture = Fixture::new();
    let queue = fixture.queue();
    let batch = queue
        .enqueue(vec![
            fixture.proposal("a", b"A\n"),
            fixture.proposal("b", b"red\n"),
            fixture.proposal("c", b"C\n"),
        ])
        .unwrap();
    queue.stage(&batch.id).unwrap();
    let mut runner = |invocation: &CheckInvocation| -> Result<CheckReport> {
        Ok(CheckReport {
            tests_passed: std::fs::read(invocation.worktree.join("b.txt"))? != b"red\n",
            ..CheckReport::default()
        })
    };
    let quarantine = queue.diagnose_red(&batch.id, &mut runner).unwrap();
    assert_eq!(quarantine.proposal_ids, vec!["b"]);
    assert_eq!(quarantine.failing_mask, 2);
    assert_eq!(
        queue.batch(&batch.id).unwrap().state,
        BatchState::Quarantined
    );
    assert_eq!(fixture.read("b"), b"base\n");
    let survivors = queue.requeue_survivors(&batch.id).unwrap().unwrap();
    ready(&queue, &survivors);
    queue.land(&survivors.id, &mut fixture.host(None)).unwrap();
    assert_eq!(fixture.read("a"), b"A\n");
    assert_eq!(fixture.read("b"), b"base\n");
    assert_eq!(fixture.read("c"), b"C\n");
    finish(&queue, &survivors);
    queue.cleanup(&batch.id).unwrap();
}

#[test]
fn slow_results_wait_for_prefix_and_red_restores_actual_last_green_tree() {
    let fixture = Fixture::new();
    let queue = fixture.queue();
    let first = queue.enqueue(vec![fixture.proposal("a", b"A\n")]).unwrap();
    ready(&queue, &first);
    queue.land(&first.id, &mut fixture.host(None)).unwrap();
    finish(&queue, &first);
    let green_head = queue.pointers().unwrap().green;
    let second = queue.enqueue(vec![fixture.proposal("b", b"B\n")]).unwrap();
    ready(&queue, &second);
    queue.land(&second.id, &mut fixture.host(None)).unwrap();
    let third = queue.enqueue(vec![fixture.proposal("c", b"C\n")]).unwrap();
    ready(&queue, &third);
    queue.land(&third.id, &mut fixture.host(None)).unwrap();
    queue
        .check(&third.id, 1, CheckPhase::Slow, &mut green)
        .unwrap();
    assert_eq!(queue.settle_slow().unwrap().green, green_head);
    queue
        .check(&second.id, 1, CheckPhase::Slow, &mut |_| {
            Ok(CheckReport::default())
        })
        .unwrap();
    let pointers = queue.settle_slow().unwrap();
    assert_eq!(pointers.head, green_head);
    assert_eq!(pointers.green, green_head);
    assert!(pointers.pending_slow.is_empty());
    assert_eq!(fixture.read("a"), b"A\n");
    assert_eq!(fixture.read("b"), b"base\n");
    assert_eq!(fixture.read("c"), b"base\n");
    assert_eq!(
        queue.batch(&second.id).unwrap().state,
        BatchState::RolledBack
    );
    assert_eq!(
        queue.batch(&third.id).unwrap().state,
        BatchState::RolledBack
    );
    queue.cleanup(&second.id).unwrap();
    queue.cleanup(&third.id).unwrap();
}

#[test]
fn reopen_recovers_before_after_and_partial_compound_landing() {
    for fail_after in [0, 1, 2] {
        let fixture = Fixture::new();
        let batch;
        {
            let queue = fixture.queue();
            batch = queue
                .enqueue(vec![
                    fixture.proposal("a", b"A\n"),
                    fixture.proposal("b", b"B\n"),
                ])
                .unwrap();
            ready(&queue, &batch);
            assert!(
                queue
                    .land(&batch.id, &mut fixture.host(Some(fail_after)))
                    .is_err()
            );
        }
        let queue = fixture.queue();
        let pointers = queue.recover().unwrap();
        if fail_after == 2 {
            assert_ne!(pointers.head, fixture.base);
            assert_eq!(
                queue.batch(&batch.id).unwrap().state,
                BatchState::HeadAdvanced
            );
        } else {
            assert_eq!(pointers.head, fixture.base);
            assert_eq!(fixture.read("a"), b"base\n");
            assert_eq!(fixture.read("b"), b"base\n");
            assert_eq!(queue.batch(&batch.id).unwrap().state, BatchState::Ready);
            queue.land(&batch.id, &mut fixture.host(None)).unwrap();
        }
        finish(&queue, &batch);
    }
}

#[test]
fn stale_expected_head_never_calls_landing_and_dirty_test_tree_is_refused() {
    let fixture = Fixture::new();
    let queue = fixture.queue();
    let batch = queue.enqueue(vec![fixture.proposal("a", b"A\n")]).unwrap();
    let staged = queue.stage(&batch.id).unwrap();
    std::fs::write(staged.paths[0].worktree.join("a.txt"), b"tampered\n").unwrap();
    assert!(
        queue
            .check(&batch.id, 1, CheckPhase::Fast, &mut green)
            .is_err()
    );
    std::fs::write(staged.paths[0].worktree.join("a.txt"), b"A\n").unwrap();
    queue
        .check(&batch.id, 1, CheckPhase::Fast, &mut green)
        .unwrap();
    fixture
        .vault
        .apply_repo_mutation(RepoMutationRequest::new(
            fixture.repo_ref.clone(),
            RepoMutationOperation::CommitFile {
                path: "c.txt".into(),
                content: b"elsewhere\n".to_vec(),
                message: "external write".into(),
            },
        ))
        .unwrap();
    let mut host = fixture.host(None);
    assert!(queue.land(&batch.id, &mut host).is_err());
    assert_eq!(host.calls, 0);
    assert!(queue.recover().is_err());
    queue.cancel(&batch.id).unwrap();
    queue.cleanup(&batch.id).unwrap();
}

#[test]
fn removed_public_name_is_a_persisted_queue_veto_even_when_tests_pass() {
    let old = b"pub fn retained() {} pub fn removed() {}\n";
    let spec = ContractSpec {
        rust_crates: BTreeMap::from([("fixture".into(), "lib.rs".into())]),
        ..ContractSpec::default()
    };
    let fixture = Fixture::with_contracts(spec, &[("lib.rs", old)]);
    let queue = fixture.queue();
    let proposal = MergeProposal {
        id: "api".into(),
        base_green: fixture.base.clone(),
        files: vec![MergeFile {
            path: "lib.rs".into(),
            expected: Some(old.to_vec()),
            content: Some(b"pub fn retained() {}\n".to_vec()),
        }],
    };
    let batch = queue.enqueue(vec![proposal]).unwrap();
    queue.stage(&batch.id).unwrap();
    let verdict = queue
        .check(&batch.id, 1, CheckPhase::Fast, &mut green)
        .unwrap();
    assert!(verdict.tests_passed);
    assert!(!verdict.passes());
    assert!(verdict.diffs.iter().any(|diff| matches!(diff, crate::contract_oracle::ContractDiff::RemovedPublicName { name } if name == "fixture::removed")));
    assert_eq!(
        ContractOracle::new(&fixture.vault)
            .verdict(&verdict.id)
            .unwrap(),
        Some(verdict)
    );
    let mut host = fixture.host(None);
    assert!(queue.land(&batch.id, &mut host).is_err());
    assert_eq!(host.calls, 0);
    assert_eq!(queue.pointers().unwrap().head, fixture.base);
    queue.diagnose_red(&batch.id, &mut green).unwrap();
    queue.cleanup(&batch.id).unwrap();
}

#[test]
fn interacting_red_pair_is_quarantined_together_not_falsely_blamed_on_one_member() {
    let fixture = Fixture::new();
    let queue = fixture.queue();
    let batch = queue
        .enqueue(vec![
            fixture.proposal("a", b"A\n"),
            fixture.proposal("b", b"B\n"),
        ])
        .unwrap();
    queue.stage(&batch.id).unwrap();
    let mut runner = |invocation: &CheckInvocation| -> Result<CheckReport> {
        let a = std::fs::read(invocation.worktree.join("a.txt"))?;
        let b = std::fs::read(invocation.worktree.join("b.txt"))?;
        Ok(CheckReport {
            tests_passed: a != b"A\n" || b != b"B\n",
            ..CheckReport::default()
        })
    };
    let quarantine = queue.diagnose_red(&batch.id, &mut runner).unwrap();
    assert_eq!(quarantine.failing_mask, 3);
    assert_eq!(quarantine.proposal_ids, vec!["a", "b"]);
    assert!(queue.requeue_survivors(&batch.id).unwrap().is_none());
    queue.cleanup(&batch.id).unwrap();
}
