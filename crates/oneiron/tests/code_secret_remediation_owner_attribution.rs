//! NO-DOOR CODE-PROPOSAL-ATTRIBUTION, the fifth owner door (Engine
//! CODECUSTODY-ATTRIB Q1 = A, Q2 = A): the owner's
//! `vault.code.secrets.propose` takes no session or provenance claim from
//! the caller. Once the remediation's bundle and its pinned HEAD are final,
//! the engine binds the owner's sitting and one reserved `repo.provenance`
//! CLAIM in the closed `owner_request` form. A bundle has no one path: the
//! lineage lists every staged path in byte order with its new bytes' BLAKE3,
//! null for a removal, and the envelope's content hash is the BLAKE3 of that
//! list's canonical JSON. No model field appears.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_secret_remediation_owner_attribution`.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::claim::{ClaimBody, ClaimSubject};
use oneiron::code_document::CodeOpProvenance;
use oneiron::codebase::RepoRef;
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::memory::code_doors::{
    CodeRepoSecretProposeRequest, CodeRepoSecretRemediationAction, CodeRepoSecretRemediationStatus,
};
use oneiron::memory::codebase_doors::{CodeRepoPointer, CodeSnapshotIngestRequest};
use oneiron::registry::ENTITY_TYPE_SESSION;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
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

/// A Git repository on `refs/heads/main` whose one commit holds a README
/// and a live `.env` with one non-empty value, and that commit's 40-hex id.
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

/// The value at `key` of a MessagePack map.
fn entry<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// The string at `key` of a MessagePack map.
fn text<'a>(map: &'a Value, key: &str) -> Option<&'a str> {
    entry(map, key).and_then(Value::as_str)
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
fn the_engine_attributes_an_owner_secret_remediation_bundle() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let vault = Vault::open(vault_dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let (owner, proof) = embedded_owner(&vault)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let (repo_dir, head) = repo_with_live_dotenv()?;
    let snapshot = memory.code_snapshot_ingest_as(
        &proof,
        CodeSnapshotIngestRequest {
            project_id: "secret-remediation-attribution".to_owned(),
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

    // The owner's input names no session and no provenance claim. On the
    // base both are required, so this input does not decode.
    let input: CodeRepoSecretProposeRequest = serde_json::from_value(json!({
        "repo": repo,
        "op_provenance": CodeOpProvenance::default(),
    }))?;
    // A caller that names either source is refused at the decode: the
    // sources are the engine's.
    let named = EntityId::now();
    assert!(
        serde_json::from_value::<CodeRepoSecretProposeRequest>(json!({
            "repo": repo,
            "session": named,
            "provenance_claim": named,
            "op_provenance": CodeOpProvenance::default(),
        }))
        .is_err(),
        "an owner request naming a session or provenance claim does not decode"
    );

    // Another caller cannot borrow the owner's proof.
    let refused = vault
        .memory(EntityId::now(), EdgeActorClass::Human)
        .code_repo_secrets_propose_as(&proof, input.clone())
        .expect_err("a caller that is not the owner is refused");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    let remediation = memory.code_repo_secrets_propose_as(&proof, input.clone())?;
    assert_eq!(
        remediation.status,
        CodeRepoSecretRemediationStatus::Proposed,
        "{remediation:?}"
    );
    assert_eq!(remediation.base_commit, head);
    assert!(
        remediation
            .actions
            .contains(&CodeRepoSecretRemediationAction::RemoveDotenv {
                path: ".env".to_owned()
            }),
        "{remediation:?}"
    );
    let proposal_id = remediation.proposal.ok_or("one bundle is staged")?;
    let proposal = vault
        .repo_proposal(proposal_id)?
        .ok_or("the staged bundle is stored")?;
    assert_eq!(
        vault.get_entity_type(&proposal.session)?,
        Some(ENTITY_TYPE_SESSION),
        "the bundle's session is a SESSION"
    );

    // The claim, read back on its own: the closed owner_request form.
    let claim: ClaimBody = vault
        .get_claim(&proposal.provenance_claim)?
        .ok_or("the bundle's provenance claim is stored")?;
    assert_eq!(claim.predicate, "repo.provenance");
    assert_eq!(claim.subject, ClaimSubject::Entity(proposal.session));
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
        Some(proposal.session.to_hex().as_str())
    );

    // The lineage: the repository, the pinned HEAD and every staged path in
    // byte order, each with the BLAKE3 of the bytes the bundle stages, null
    // for the removed dotenv file.
    let lineage = entry(value, "diff_lineage_receipt").ok_or("a lineage")?;
    assert_eq!(keys(lineage), ["base_commit", "files", "repo"]);
    assert_eq!(text(lineage, "repo"), Some(repo.to_hex().as_str()));
    assert_eq!(text(lineage, "base_commit"), Some(head.as_str()));
    let mut staged: Vec<(String, Option<String>)> = proposal
        .files
        .iter()
        .map(|file| {
            let hash = file
                .content
                .as_ref()
                .map(|content| blake3::hash(content).to_hex().to_string());
            (file.path.clone(), hash)
        })
        .collect();
    staged.sort();
    let paths: Vec<&str> = staged.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, [".env", ".env.example", ".gitignore"]);
    let files = entry(lineage, "files")
        .and_then(Value::as_array)
        .ok_or("the lineage lists its files")?;
    let listed: Vec<(String, Option<String>)> = files
        .iter()
        .map(|file| {
            assert_eq!(keys(file), ["content_hash", "path"]);
            (
                text(file, "path").unwrap_or_default().to_owned(),
                text(file, "content_hash").map(str::to_owned),
            )
        })
        .collect();
    assert_eq!(listed, staged, "each staged path with its new bytes' hash");
    assert!(
        files
            .first()
            .and_then(|file| entry(file, "content_hash"))
            .is_some_and(Value::is_nil),
        "the removed dotenv file's hash is null"
    );

    // The envelope: the BLAKE3 of the listed files' canonical JSON.
    let listed_json = serde_json::Value::Array(
        staged
            .iter()
            .map(|(path, hash)| json!({ "path": path, "content_hash": hash }))
            .collect(),
    );
    let content_hash = blake3::hash(&oneiron::llm::canonical_json_bytes(&listed_json)?)
        .to_hex()
        .to_string();
    let envelope = entry(value, "derivation_envelope").ok_or("an envelope")?;
    assert_eq!(keys(envelope), ["content_hash", "version"]);
    assert_eq!(text(envelope, "content_hash"), Some(content_hash.as_str()));
    assert_eq!(
        text(envelope, "version"),
        Some("vault.code.owner_request.v1")
    );

    // The request hash is over the verb, the owner, the sitting, the typed
    // input, the pointer at the pinned HEAD, that HEAD and the bundle hash.
    let preimage = json!({
        "version": "vault.code.owner_request.v1",
        "verb": "vault.code.secrets.propose",
        "actor": owner.to_hex(),
        "session": proposal.session.to_hex(),
        "input": serde_json::to_value(&input)?,
        "repo_ref": repo_ref,
        "base_commit": head,
        "effective_content_hash": content_hash,
    });
    let request_hash = blake3::hash(&oneiron::llm::canonical_json_bytes(&preimage)?)
        .to_hex()
        .to_string();
    assert_eq!(text(value, "request_hash"), Some(request_hash.as_str()));
    Ok(())
}
