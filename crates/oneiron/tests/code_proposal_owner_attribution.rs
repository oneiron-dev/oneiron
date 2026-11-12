//! NO-DOOR CODE-PROPOSAL-ATTRIBUTION (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-04, -05, -08; Engine CODECUSTODY-ATTRIB Q1 = A, Q2 = A): the
//! owner's `vault.code.proposal_submit` takes no session or provenance claim
//! from the caller. The engine binds the owner's sitting on this install and
//! a reserved `repo.provenance` CLAIM on it in the closed `owner_request`
//! form: the owner, the sitting, the request hash, the staged bytes' BLAKE3,
//! the repository, the path and the pinned base commit, and no model field.
//! A caller that is not the owner is refused, and a generic claim write of
//! the same body stays refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_proposal_owner_attribution`.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::claim::{ClaimBody, ClaimSubject};
use oneiron::code_document::CodeOpProvenance;
use oneiron::codebase::RepoRef;
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::memory::code_doors::{CodeProposalSubmitRequest, CodeProposalSubmitted};
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::registry::ENTITY_TYPE_SESSION;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

/// A Git repository on `refs/heads/main` with one committed file, and that
/// commit's 40-hex id.
fn committed_repo() -> TestResult<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir()?;
    git(dir.path(), &["init", "--quiet"])?;
    git(dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"])?;
    std::fs::write(dir.path().join("README.md"), "base\n")?;
    git(dir.path(), &["add", "--", "README.md"])?;
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

/// The string at `key` of a MessagePack map.
fn text<'a>(map: &'a Value, key: &str) -> Option<&'a str> {
    map.as_map()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
}

/// The map at `key` of a MessagePack map.
fn nested<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// The keys of a MessagePack map, sorted.
fn keys(map: &Value) -> Vec<String> {
    let mut keys: Vec<String> = map
        .as_map()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|(key, _)| key.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    keys.sort();
    keys
}

#[test]
fn the_engine_attributes_an_owner_proposal_without_caller_sources() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let vault = Vault::open(vault_dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let (owner, proof) = embedded_owner(&vault)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let (repo_dir, head) = committed_repo()?;
    let snapshot = memory.code_snapshot_ingest_as(
        &proof,
        CodeSnapshotIngestRequest {
            project_id: "owner-attribution".to_owned(),
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
    let repo = snapshot.repo;
    let repo_ref = RepoRef::parse(&snapshot.repo_ref)?.canonical();

    // The owner's input names no session and no provenance claim. On main
    // both are required, so this input does not decode.
    let content = b"base plus an owner edit\n".to_vec();
    let input: CodeProposalSubmitRequest = serde_json::from_value(json!({
        "repo": repo,
        "path": "README.md",
        "content": content,
        "message": "Owner edit",
        "op_provenance": CodeOpProvenance::default(),
    }))?;

    // Another caller cannot borrow the owner's proof.
    let refused = vault
        .memory(EntityId::now(), EdgeActorClass::Human)
        .code_proposal_submit_as(&proof, input.clone())
        .expect_err("a caller that is not the owner is refused");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    let submitted: CodeProposalSubmitted = memory.code_proposal_submit_as(&proof, input.clone())?;
    assert_eq!((submitted.actor, submitted.repo), (owner, repo));
    assert_eq!(
        vault.get_entity_type(&submitted.session)?,
        Some(ENTITY_TYPE_SESSION),
        "the proposal's session is a SESSION"
    );

    // The claim, read back on its own: the closed owner_request form.
    let claim: ClaimBody = vault
        .get_claim(&submitted.provenance_claim)?
        .ok_or("the proposal's provenance claim is stored")?;
    assert_eq!(claim.predicate, "repo.provenance");
    assert_eq!(claim.subject, ClaimSubject::Entity(submitted.session));
    let value = &claim.value;
    assert_eq!(
        keys(value),
        [
            "actor",
            "derivation_envelope",
            "diff_lineage_receipt",
            "request_hash",
            "session",
            "source_kind",
        ],
        "exactly the owner_request keys, no model field"
    );
    assert_eq!(text(value, "source_kind"), Some("owner_request"));
    assert_eq!(text(value, "actor"), Some(owner.to_hex().as_str()));
    assert_eq!(
        text(value, "session"),
        Some(submitted.session.to_hex().as_str())
    );
    let content_hash = blake3::hash(&content).to_hex().to_string();
    let envelope = nested(value, "derivation_envelope").ok_or("an envelope")?;
    assert_eq!(keys(envelope), ["content_hash", "version"]);
    assert_eq!(text(envelope, "content_hash"), Some(content_hash.as_str()));
    assert_eq!(
        text(envelope, "version"),
        Some("vault.code.owner_request.v1")
    );
    let lineage = nested(value, "diff_lineage_receipt").ok_or("a lineage")?;
    assert_eq!(keys(lineage), ["base_commit", "path", "repo"]);
    assert_eq!(text(lineage, "repo"), Some(repo.to_hex().as_str()));
    assert_eq!(text(lineage, "path"), Some("README.md"));
    assert_eq!(text(lineage, "base_commit"), Some(head.as_str()));

    // The request hash is over the verb, the owner, the sitting, the typed
    // input, the pointer, the base and the staged bytes' hash.
    let preimage = json!({
        "version": "vault.code.owner_request.v1",
        "verb": "vault.code.proposal_submit",
        "actor": owner.to_hex(),
        "session": submitted.session.to_hex(),
        "input": serde_json::to_value(&input)?,
        "repo_ref": repo_ref,
        "base_commit": head,
        "effective_content_hash": content_hash,
    });
    let request_hash = blake3::hash(&oneiron::llm::canonical_json_bytes(&preimage)?)
        .to_hex()
        .to_string();
    assert_eq!(text(value, "request_hash"), Some(request_hash.as_str()));

    // The same body through the generic claim writer: `repo.*` stays the
    // engine's.
    let forged = EntityId::now();
    let at = vault.now_recorded_at();
    assert!(
        vault
            .put_claim(&forged, &claim, TimeRange { start: at, end: at }, at)
            .is_err(),
        "a generic write of repo.provenance is refused"
    );
    assert!(vault.get_claim(&forged)?.is_none());

    // A second proposal reuses the owner's open sitting and gets its own
    // claim.
    let again = memory.code_proposal_submit_as(&proof, input)?;
    assert_eq!(again.session, submitted.session);
    assert_ne!(again.provenance_claim, submitted.provenance_claim);
    Ok(())
}
