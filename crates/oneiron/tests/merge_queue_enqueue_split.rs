//! [MERGE-QUEUE-ENQUEUE-SPLITS-LARGE-BATCH] (RULING RESTRICTION-WAVE-15-ROWS
//! C107 = A): one merge batch holds at most 63 proposals, the width of its
//! path mask, and an enqueue of more forms consecutive batches of at most 63
//! in request order instead of being refused. Each later batch waits Queued
//! until the batch it follows has landed, then stages on that landed head.
//!
//! The queue is the low-level one on a plain Git repository, and each batch
//! is an owner's trusted batch: every proposal adds its own new file. The
//! test plays the host: every check passes, and its landing commits each
//! proposal's file through the vault's journaled repo mutation.
//!
//! Red on main: the enqueue of 64 or of 200 proposals is refused ("a merge
//! batch holds one to 63 proposals"). The batch links are read from the
//! batch's serialized form, so this file compiles on main too.
//!
//! `cargo test --locked -p oneiron --all-features --test merge_queue_enqueue_split`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron::codebase::RepoRef;
use oneiron::contract_oracle::{ContractOracle, ContractSpec, WorkspaceGraph};
use oneiron::merge_queue::{
    BatchState, CheckPhase, CheckReport, LandingPermit, MergeBatch, MergeFile, MergeLanding,
    MergeProposal, MergeQueue, TestedBatch,
};
use oneiron::repo_mutation::{RepoMutationOperation, RepoMutationOutcome, RepoMutationRequest};
use oneiron::{Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The most proposals one batch holds.
const BATCH_WIDTH: usize = 63;

fn git(dir: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git").args(args).current_dir(dir).output()?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// A fresh vault and a one-commit Git repository whose merge queue is
/// initialized green at that commit.
struct QueueFixture {
    vault: Vault,
    _vault_dir: tempfile::TempDir,
    _repo_dir: tempfile::TempDir,
    root: PathBuf,
    /// The commit the queue is green and at head on.
    green: String,
}

impl QueueFixture {
    fn new() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Vault::open(vault_dir.path(), VaultConfig::default())?;
        let repo_dir = tempfile::tempdir()?;
        let root = repo_dir.path().canonicalize()?;
        git(&root, &["init", "--quiet"])?;
        std::fs::write(root.join("README.md"), "base\n")?;
        git(&root, &["add", "--", "README.md"])?;
        git(
            &root,
            &[
                "-c",
                "user.name=Oneiron",
                "-c",
                "user.email=oneiron@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "initial",
            ],
        )?;
        let green = git(&root, &["rev-parse", "HEAD"])?;
        let fixture = Self {
            vault,
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
            root,
            green,
        };
        let spec = ContractSpec::default();
        let baseline = ContractOracle::new(&fixture.vault).record_baseline(
            spec.clone(),
            ContractOracle::capture(&spec, &fixture.root, BTreeMap::new())?,
        )?;
        let pointers = fixture
            .queue()?
            .initialize(&baseline.id, WorkspaceGraph::unfiltered())?;
        assert_eq!(
            pointers.green, fixture.green,
            "the queue is green at the commit"
        );
        Ok(fixture)
    }

    fn repo_ref(&self) -> TestResult<RepoRef> {
        Ok(RepoRef::LocalFolder {
            path: self.root.to_str().ok_or("UTF-8 repo path")?.to_owned(),
            commit: git(&self.root, &["rev-parse", "HEAD"])?,
        })
    }

    fn queue(&self) -> TestResult<MergeQueue<'_>> {
        Ok(MergeQueue::open(&self.vault, self.repo_ref()?)?)
    }
}

/// `count` proposals on `green`, in order: proposal `n` adds `split/n.txt`.
fn proposals(count: usize, green: &str) -> Vec<MergeProposal> {
    (0..count)
        .map(|index| MergeProposal {
            id: format!("split-{index:03}"),
            base_green: green.to_owned(),
            files: vec![MergeFile {
                path: format!("split/{index:03}.txt"),
                expected: None,
                content: Some(format!("proposal {index}\n").into_bytes()),
                metadata_edit: None,
            }],
        })
        .collect()
}

/// `batch`'s link `name` (`follows` or `followed_by`), read from its
/// serialized form: a link it does not hold is absent there.
fn link(batch: &MergeBatch, name: &str) -> TestResult<Option<String>> {
    Ok(serde_json::to_value(batch)?
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

/// The batches one enqueue formed, from its first along `followed_by`.
fn chain(queue: &MergeQueue<'_>, first: MergeBatch) -> TestResult<Vec<MergeBatch>> {
    let mut batches = vec![first];
    loop {
        let last = batches.last().ok_or("an enqueue answers a batch")?;
        let Some(next) = link(last, "followed_by")? else {
            return Ok(batches);
        };
        if batches.len() > 200 {
            return Err("the followed_by links do not end".into());
        }
        batches.push(queue.batch(&next)?);
    }
}

/// The test's landing host: it commits each proposal's file, in batch
/// order, through the vault's journaled repo mutation on the live head.
struct CommitHost<'a> {
    vault: &'a Vault,
    root: &'a Path,
}

impl MergeLanding for CommitHost<'_> {
    fn land(
        &mut self,
        permit: &LandingPermit,
        tested: &TestedBatch,
    ) -> oneiron::Result<Vec<RepoMutationOutcome>> {
        assert_eq!(permit.expected_head(), tested.batch().expected_head);
        let path = self.root.to_str().expect("UTF-8 repo path").to_owned();
        let mut outcomes = Vec::new();
        for proposal in &tested.batch().proposals {
            for file in &proposal.files {
                let head = git(self.root, &["rev-parse", "HEAD"]).expect("the live head");
                outcomes.push(self.vault.apply_repo_mutation(RepoMutationRequest::new(
                    RepoRef::LocalFolder {
                        path: path.clone(),
                        commit: head,
                    },
                    RepoMutationOperation::CommitFile {
                        path: file.path.clone(),
                        content: file.content.clone().expect("each proposal adds its file"),
                        message: format!("Land {}", proposal.id),
                    },
                ))?);
            }
        }
        Ok(outcomes)
    }
}

fn passing(_: &oneiron::merge_queue::CheckInvocation) -> oneiron::Result<CheckReport> {
    Ok(CheckReport {
        tests_passed: true,
        ..CheckReport::default()
    })
}

/// Stages batch `id`, passes the fast check of every staged path and lands
/// it through [`CommitHost`]: the batch at head, its slow check pending.
fn stage_check_land(
    fixture: &QueueFixture,
    queue: &MergeQueue<'_>,
    id: &str,
) -> TestResult<MergeBatch> {
    let staged = queue.stage(id)?;
    assert_eq!(staged.state, BatchState::Staged, "the batch stages");
    for path in &staged.paths {
        queue.check(id, path.mask, CheckPhase::Fast, &mut passing)?;
    }
    assert_eq!(
        queue.batch(id)?.state,
        BatchState::Ready,
        "every path passed"
    );
    let landed = queue.land(
        id,
        &mut CommitHost {
            vault: &fixture.vault,
            root: &fixture.root,
        },
    )?;
    assert_eq!(landed.state, BatchState::HeadAdvanced, "the batch lands");
    Ok(landed)
}

/// Passes the slow check of each landed batch in `ids`, settles them green
/// and collects their worktrees.
fn settle_and_collect(queue: &MergeQueue<'_>, ids: &[&str]) -> TestResult {
    for id in ids {
        let batch = queue.batch(id)?;
        let mask = batch
            .paths
            .last()
            .ok_or("a staged batch has its full path")?
            .mask;
        queue.check(id, mask, CheckPhase::Slow, &mut passing)?;
    }
    queue.settle_slow()?;
    for id in ids {
        assert_eq!(queue.batch(id)?.state, BatchState::GreenAdvanced);
        queue.cleanup(id)?;
    }
    Ok(())
}

#[test]
fn enqueue_of_64_stages_the_second_batch_on_the_first_landed_head() -> TestResult {
    let fixture = QueueFixture::new()?;
    let queue = fixture.queue()?;
    let first = queue.enqueue(proposals(64, &fixture.green))?;
    let batches = chain(&queue, first)?;
    let sizes: Vec<usize> = batches.iter().map(|batch| batch.proposals.len()).collect();
    assert_eq!(
        sizes,
        [BATCH_WIDTH, 1],
        "64 proposals form a batch of 63 and one of 1"
    );
    let (first, second) = (&batches[0], &batches[1]);
    assert_eq!(
        link(first, "follows")?,
        None,
        "the first batch follows none"
    );
    assert_eq!(link(second, "follows")?.as_deref(), Some(first.id.as_str()));
    assert_eq!(
        link(second, "followed_by")?,
        None,
        "the last batch is followed by none"
    );
    assert_eq!(second.proposals[0].id, "split-063", "request order is kept");
    assert_eq!(second.state, BatchState::Queued);

    // Before the first batch lands, the second waits Queued, with no path.
    let waiting = queue.stage(&second.id)?;
    assert_eq!(
        waiting.state,
        BatchState::Queued,
        "it waits for the batch it follows"
    );
    assert!(waiting.paths.is_empty(), "nothing is staged for it yet");

    let first_landed = stage_check_land(&fixture, &queue, &first.id)?;
    let first_head = first_landed
        .landed_head
        .clone()
        .ok_or("a landed batch has its landed head")?;
    assert_eq!(queue.pointers()?.head, first_head);

    // Now it stages on the head the first batch landed, and lands after it.
    let staged = queue.stage(&second.id)?;
    assert_eq!(staged.state, BatchState::Staged);
    assert_eq!(
        staged.expected_head, first_head,
        "it stages on the first's landed head"
    );
    let second_landed = stage_check_land(&fixture, &queue, &second.id)?;
    let second_head = second_landed
        .landed_head
        .clone()
        .ok_or("a landed batch has its landed head")?;
    assert_eq!(
        git(
            &fixture.root,
            &[
                "rev-list",
                "--count",
                &format!("{first_head}..{second_head}")
            ]
        )?,
        "1",
        "the second batch's one file lands on top of the first batch"
    );
    for index in 0..64 {
        assert!(
            fixture.root.join(format!("split/{index:03}.txt")).is_file(),
            "proposal {index} landed"
        );
    }
    assert_eq!(
        queue.pointers()?.pending_slow,
        [first.id.clone(), second.id.clone()]
    );
    settle_and_collect(&queue, &[&first.id, &second.id])
}

#[test]
fn enqueue_of_200_forms_four_batches_each_waiting_on_the_one_before() -> TestResult {
    let fixture = QueueFixture::new()?;
    let queue = fixture.queue()?;
    let requested = proposals(200, &fixture.green);
    let ids: Vec<String> = requested
        .iter()
        .map(|proposal| proposal.id.clone())
        .collect();
    let first = queue.enqueue(requested)?;
    let batches = chain(&queue, first)?;
    let sizes: Vec<usize> = batches.iter().map(|batch| batch.proposals.len()).collect();
    assert_eq!(sizes, [BATCH_WIDTH, BATCH_WIDTH, BATCH_WIDTH, 11]);
    let queued: Vec<String> = batches
        .iter()
        .flat_map(|batch| batch.proposals.iter().map(|proposal| proposal.id.clone()))
        .collect();
    assert_eq!(
        queued, ids,
        "every proposal is queued once, in request order"
    );
    assert_eq!(link(&batches[0], "follows")?, None);
    for pair in batches.windows(2) {
        assert_eq!(
            link(&pair[1], "follows")?.as_deref(),
            Some(pair[0].id.as_str())
        );
        assert_eq!(
            link(&pair[0], "followed_by")?.as_deref(),
            Some(pair[1].id.as_str())
        );
    }
    assert_eq!(link(&batches[3], "followed_by")?, None);
    for batch in &batches {
        assert_eq!(batch.state, BatchState::Queued);
        assert_eq!(
            batch.expected_head, fixture.green,
            "formed on the queue head"
        );
        assert_eq!(batch.base_green, fixture.green);
    }

    // No later batch stages before the one it follows lands.
    for batch in &batches[1..] {
        let waiting = queue.stage(&batch.id)?;
        assert_eq!(
            waiting.state,
            BatchState::Queued,
            "it waits for the batch it follows"
        );
        assert!(waiting.paths.is_empty());
    }

    // A batch whose followed batch ended without landing never stages; the
    // one after it still waits on it.
    assert_eq!(queue.cancel(&batches[0].id)?.state, BatchState::Cancelled);
    let refused = queue
        .stage(&batches[1].id)
        .expect_err("the batch it follows was cancelled");
    assert!(
        refused.to_string().contains("ended without landing"),
        "refused: {refused}"
    );
    assert_eq!(queue.batch(&batches[1].id)?.state, BatchState::Queued);
    assert_eq!(queue.stage(&batches[2].id)?.state, BatchState::Queued);
    Ok(())
}

#[test]
fn enqueue_of_63_stays_one_batch() -> TestResult {
    let fixture = QueueFixture::new()?;
    let queue = fixture.queue()?;
    let batch = queue.enqueue(proposals(BATCH_WIDTH, &fixture.green))?;
    assert_eq!(batch.proposals.len(), BATCH_WIDTH);
    assert_eq!(link(&batch, "follows")?, None);
    assert_eq!(link(&batch, "followed_by")?, None);
    let serialized = serde_json::to_value(&batch)?;
    assert!(
        serialized.get("follows").is_none() && serialized.get("followed_by").is_none(),
        "a batch of at most 63 writes no link"
    );
    Ok(())
}
