//! FIX 2229 (OF-067; Engine RULING FIX-2229-WITHHELD-WRITE = A): an
//! ordinary reviewed write to a file the pinned snapshot withholds stays
//! refused, since a review reads the replaced file from its snapshot, and
//! the snapshot does not hold a withheld file's bytes. The refusal names the
//! route, `gate.secret_scan.remediation_route`: the owner's
//! `vault.code.secrets.propose` remediation (SECRETS-IN-REPOS = A) is the one
//! reviewed write that changes or removes such a file, and it is admitted for
//! the same file. A write whose own bytes hold a secret is refused without
//! the route: no remediation makes those bytes reviewable.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_withheld_write_remediation_route`.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::code_document::CodeOpProvenance;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::code_doors::{
    CodeProposalSubmitRequest, CodeRepoSecretProposeRequest, CodeRepoSecretRemediationAction,
    CodeRepoSecretRemediationStatus,
};
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REMEDIATION_ROUTE: &str = "gate.secret_scan.remediation_route";
const WITHHELD_PATH: &str = "gate.secret_scan.withheld_path";

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

/// A Git repository on `refs/heads/main` whose one commit holds a README
/// and a live `.env` with one non-empty value, and that commit's 40-hex id.
/// The release scan reads `API_TOKEN=local-value-1` as a secret, so every
/// snapshot of that commit withholds `.env`.
fn repo_with_live_dotenv() -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"])?;
    std::fs::write(dir.path().join("README.md"), "base\n")?;
    std::fs::write(dir.path().join(".env"), "API_TOKEN=local-value-1\n")?;
    git(dir.path(), &["add", "--", "README.md", ".env"])?;
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
            "base",
        ],
    )?;
    let commit = git(dir.path(), &["rev-parse", "HEAD"])?;
    Ok((dir, commit))
}

/// The owner's vault with that repository ingested at its one commit: the
/// vault, the owner and his proof, the CODE_ARTIFACT, the commit, and the
/// two directories, dropped after the vault.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    repo: EntityId,
    head: String,
    _vault_dir: tempfile::TempDir,
    _repo_dir: tempfile::TempDir,
}

impl Fixture {
    fn new(project_id: &str) -> TestResult<Self> {
        let vault_dir = tempfile::tempdir()?;
        let vault = Vault::open(vault_dir.path(), VaultConfig::device())?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        oneiron::test_support::provision_engine_machines(&vault);
        let (owner, proof) = embedded_owner(&vault)?;
        let (repo_dir, head) = repo_with_live_dotenv()?;
        let snapshot = vault
            .memory(owner, EdgeActorClass::Human)
            .code_snapshot_ingest_as(
                &proof,
                CodeSnapshotIngestRequest {
                    project_id: project_id.to_owned(),
                    pointer: CodeRepoPointer {
                        local_folder: repo_dir
                            .path()
                            .canonicalize()?
                            .to_str()
                            .ok_or("UTF-8 repo path")?
                            .to_owned(),
                        commit: head.clone(),
                    },
                    repository: None,
                },
            )?;
        Ok(Self {
            vault,
            owner,
            proof,
            repo: snapshot.repo,
            head,
            _vault_dir: vault_dir,
            _repo_dir: repo_dir,
        })
    }

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner's one-file proposal of `content` at `path`.
    fn submit(&self, path: &str, content: &[u8]) -> TestResult<MemoryError> {
        let input: CodeProposalSubmitRequest = serde_json::from_value(json!({
            "repo": self.repo,
            "path": path,
            "content": content,
            "message": "Owner edit",
            "op_provenance": CodeOpProvenance::default(),
        }))?;
        match self.memory().code_proposal_submit_as(&self.proof, input) {
            Ok(submitted) => Err(format!(
                "the owner's write to {path} was admitted as {:?}",
                submitted.proposal
            )
            .into()),
            Err(refused) => Ok(refused),
        }
    }
}

/// The gate reason codes a refusal carries, in order.
fn reason_codes(refused: &MemoryError) -> Vec<String> {
    refused
        .gate_denial
        .as_ref()
        .map(|denial| denial.reason_codes.clone())
        .unwrap_or_default()
}

#[test]
fn an_owner_write_to_a_withheld_file_names_the_remediation_route() -> TestResult {
    let fixture = Fixture::new("withheld-write-remediation-route")?;

    // Clean bytes, which the policy would keep: only the file they replace
    // is withheld.
    let refused = fixture.submit(".env", b"# The key moved to the vault's secret store.\n")?;
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        reason_codes(&refused),
        [
            "gate.secret_scan.detected",
            WITHHELD_PATH,
            REMEDIATION_ROUTE
        ],
        "the refusal of a write to a withheld file names the remediation route: {refused:?}"
    );
    assert!(
        refused.message.contains(REMEDIATION_ROUTE),
        "the message names the route too: {}",
        refused.message
    );

    // The route it names: the owner's remediation of the same file is
    // admitted, and its bundle removes the withheld dotenv file.
    let input: CodeRepoSecretProposeRequest = serde_json::from_value(json!({
        "repo": fixture.repo,
        "op_provenance": CodeOpProvenance::default(),
    }))?;
    let remediation = fixture
        .memory()
        .code_repo_secrets_propose_as(&fixture.proof, input)?;
    assert_eq!(
        remediation.status,
        CodeRepoSecretRemediationStatus::Proposed,
        "{remediation:?}"
    );
    assert_eq!(remediation.base_commit, fixture.head);
    assert!(
        remediation
            .actions
            .contains(&CodeRepoSecretRemediationAction::RemoveDotenv {
                path: ".env".to_owned()
            }),
        "{remediation:?}"
    );
    let proposal_id = remediation.proposal.ok_or("one bundle is staged")?;
    let proposal = fixture
        .vault
        .repo_proposal(proposal_id)?
        .ok_or("the staged bundle is stored")?;
    let dotenv = proposal
        .files
        .iter()
        .find(|file| file.path == ".env")
        .ok_or("the bundle stages the withheld file")?;
    assert!(
        dotenv.content.is_none(),
        "the bundle removes the withheld file"
    );
    // Its base was withheld: the bundle keeps only the BLAKE3 of the bytes
    // it replaces (FIX 10974), never the bytes.
    assert_eq!(
        dotenv.withheld_base_blake3,
        Some(*blake3::hash(b"API_TOKEN=local-value-1\n").as_bytes()),
        "the remediation was admitted over the withheld base"
    );
    Ok(())
}

#[test]
fn a_write_whose_bytes_hold_a_secret_names_no_remediation_route() -> TestResult {
    let fixture = Fixture::new("secret-write-no-route")?;

    // README.md is a kept file; the new bytes are what custody withholds.
    let refused = fixture.submit("README.md", b"API_TOKEN=another-value-2\n")?;
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let codes = reason_codes(&refused);
    assert_eq!(
        codes.first().map(String::as_str),
        Some("gate.secret_scan.detected"),
        "{refused:?}"
    );
    assert!(
        !codes
            .iter()
            .any(|code| code == REMEDIATION_ROUTE || code == WITHHELD_PATH),
        "a secret in the written bytes is no withheld base: {refused:?}"
    );
    Ok(())
}
