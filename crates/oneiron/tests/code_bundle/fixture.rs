//! The L4-25 file-bundle tests' shared fixture: a fresh owned vault, and a
//! repo that is a committed two-file snapshot the owner ingested, with its
//! merge-queue check plan committed beside it for the queue case. Both test
//! files submit native bundles through the public owner door
//! `Memory::code_proposal_submit_bundle_as`
//! (`vault.code.proposal_submit_bundle`).
#![allow(dead_code)] // each integration binary uses a subset of these helpers

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::code_document::CodeOpProvenance;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::memory::code_doors::{
    CodeProposalBundleFile, CodeProposalBundleSubmitRequest, CodeProposalSubmitted,
};
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::merge_queue::REPO_CHECK_PLAN_PATH;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The repo's two files at the base commit, as committed.
pub(crate) const A_RS: &str = "pub fn a() -> u32 {\n    1\n}\n";
pub(crate) const B_RS: &str = "pub fn b() -> u32 {\n    2\n}\n";

/// The base commit's check plan: one fast and one slow command, no
/// contract outputs. The queue case freezes this plan at its checked
/// init; the other cases never read it.
const CHECK_PLAN: &str = r#"{"schema_version":1,"fast":[{"argv":["true"],"env_allowlist":{},"platform":{},"declared_outputs":[],"secret_taint_refs":[],"class":"verify"}],"slow":[{"argv":["true"],"env_allowlist":{},"platform":{},"declared_outputs":[],"secret_taint_refs":[],"class":"verify"}]}"#;

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

/// A Git repository on `refs/heads/main` with `a.rs` and `b.rs` in one
/// commit, and its check plan too for the queue case's checked init, and
/// that commit's 40-hex id.
fn committed_repo() -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"])?;
    std::fs::write(dir.path().join("a.rs"), A_RS)?;
    std::fs::write(dir.path().join("b.rs"), B_RS)?;
    git(dir.path(), &["add", "--", "a.rs", "b.rs"])?;
    let plan = dir.path().join(REPO_CHECK_PLAN_PATH);
    std::fs::create_dir_all(plan.parent().ok_or("the plan has a folder")?)?;
    std::fs::write(&plan, CHECK_PLAN)?;
    git(dir.path(), &["add", "--", REPO_CHECK_PLAN_PATH])?;
    git(
        dir.path(),
        &[
            "-c",
            "user.name=owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "two files",
        ],
    )?;
    let commit = git(dir.path(), &["rev-parse", "HEAD"])?;
    Ok((dir, commit))
}

/// One bundle file: `content` bytes, or `None` to delete the path.
pub(crate) fn bundle_file(path: &str, content: Option<&[u8]>) -> CodeProposalBundleFile {
    CodeProposalBundleFile {
        path: path.to_owned(),
        content: content.map(|bytes| bytes.to_vec()),
        mode: None,
    }
}

/// A fresh owned vault, its owner, and the repo the owner ingested.
pub(crate) struct BundleFixture {
    pub(crate) vault: Vault,
    _vault_dir: tempfile::TempDir,
    _repo_dir: tempfile::TempDir,
    pub(crate) owner: EntityId,
    pub(crate) owner_proof: AuthenticatedOwner,
    /// The ingested snapshot's CODE_ARTIFACT.
    pub(crate) repo: EntityId,
    /// The canonical repository pointer the import recorded.
    pub(crate) repo_ref: String,
    /// The commit `refs/heads/main` names.
    pub(crate) commit: String,
}

impl BundleFixture {
    pub(crate) fn new() -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        let vault = Vault::open_owned(vault_dir.path(), config)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // The owner's agent Grant act is carried by this install's live
        // machine profile, as a serving start enrols it (FIX 4648).
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let project = vault.root_project()?;

        // The repo: a committed snapshot the owner ingested, a member of
        // the root PROJECT.
        let (repo_dir, commit) = committed_repo()?;
        let folder = repo_dir.path().canonicalize()?;
        let snapshot = vault
            .memory(owner, EdgeActorClass::Human)
            .code_snapshot_ingest_as(
                &owner_proof,
                CodeSnapshotIngestRequest {
                    project_id: project.to_hex(),
                    pointer: CodeRepoPointer {
                        local_folder: folder.to_str().ok_or("UTF-8 repo path")?.to_owned(),
                        commit: commit.clone(),
                    },
                    repository: None,
                },
            )?;
        let repo = snapshot.repo;
        vault.put_project_member(repo, project)?;
        Ok(Self {
            vault,
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
            owner,
            owner_proof,
            repo,
            repo_ref: snapshot.repo_ref,
            commit,
        })
    }

    /// The owner's own Memory handle.
    pub(crate) fn owner_memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// Stages `files` as one native bundle proposal through the public
    /// owner door: the engine binds the session and provenance claim.
    pub(crate) fn submit_bundle(
        &self,
        files: Vec<CodeProposalBundleFile>,
        message: &str,
    ) -> TestResult<CodeProposalSubmitted> {
        Ok(self.owner_memory().code_proposal_submit_bundle_as(
            &self.owner_proof,
            CodeProposalBundleSubmitRequest {
                repo: self.repo,
                files,
                message: message.to_owned(),
                op_provenance: CodeOpProvenance::default(),
                catalog: None,
            },
        )?)
    }
}
