use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use super::*;
use crate::codebase::RepoIngestConfig;
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::error::ErrorKind;
use crate::temporal::TimeRange;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.text_analyzer = TextAnalyzerConfig::default();
    config
}

fn run_git(repo_dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| Error::InvariantViolation("git test command failed to start"))?;
    if !status.success() {
        return Err(Error::InvariantViolation("git test command failed"));
    }
    Ok(())
}

fn create_test_repo(index: &[u8]) -> Result<tempfile::TempDir> {
    let repo_dir = tempfile::tempdir()?;
    fs::write(repo_dir.path().join("index.html"), index)?;
    fs::write(
        repo_dir.path().join("app.js"),
        b"document.body.dataset.app='ok';\n",
    )?;
    run_git(repo_dir.path(), &["init"])?;
    run_git(
        repo_dir.path(),
        &["config", "user.email", "oneiron@example.test"],
    )?;
    run_git(repo_dir.path(), &["config", "user.name", "Oneiron Test"])?;
    run_git(repo_dir.path(), &["add", "."])?;
    run_git(repo_dir.path(), &["commit", "-m", "initial"])?;
    Ok(repo_dir)
}

fn commit_index(repo_dir: &Path, index: &[u8], message: &str) -> Result<()> {
    fs::write(repo_dir.join("index.html"), index)?;
    run_git(repo_dir, &["add", "index.html"])?;
    run_git(repo_dir, &["commit", "-m", message])
}

fn ingest_artifact(
    vault: &Vault,
    repo_dir: &Path,
    artifact: &str,
    learned_at: u64,
) -> Result<crate::codebase::RepoIngestResult> {
    let config = RepoIngestConfig::new(repo_dir, ["index.html", "app.js"])?;
    let result = vault.ingest_local_repo_at_commit(
        artifact,
        &config,
        "HEAD",
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    let body = vault
        .get_code_artifact(&result.code_artifact_id)?
        .ok_or(Error::EntityNotFound)?
        .with_class(CodeArtifactClass::Artifact);
    vault.put_code_artifact(
        &result.code_artifact_id,
        &body,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
    )?;
    Ok(result)
}

#[test]
fn artifact_pointer_repoints_unpublishes_and_keeps_fork_mounts() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let first = ingest_artifact(&vault, repo.path(), "site", 10)?;

    vault.publish_artifact_pointer(
        "site",
        ArtifactPointerChannel::Published,
        &first.snapshot.fork_hash,
    )?;
    let served = vault
        .resolve_artifact_file(
            "site",
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
            "index.html",
        )?
        .expect("published pointer serves");
    assert_eq!(served.bytes, b"<h1>v1</h1>\n");

    commit_index(repo.path(), b"<h1>v2</h1>\n", "second")?;
    let second = ingest_artifact(&vault, repo.path(), "site", 20)?;
    let still_pinned = vault
        .resolve_artifact_file(
            "site",
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
            "index.html",
        )?
        .expect("published pointer still serves old fork");
    assert_eq!(still_pinned.bytes, b"<h1>v1</h1>\n");

    let draft = vault
        .resolve_artifact_file(
            "site",
            ArtifactSnapshotSelector::ForkHash(second.snapshot.fork_hash),
            "index.html",
        )?
        .expect("new fork is directly mountable");
    assert_eq!(draft.bytes, b"<h1>v2</h1>\n");

    vault.publish_artifact_pointer(
        "site",
        ArtifactPointerChannel::Published,
        &second.snapshot.fork_hash,
    )?;
    let repointed = vault
        .resolve_artifact_file(
            "site",
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
            "index.html",
        )?
        .expect("repointed pointer serves new fork");
    assert_eq!(repointed.bytes, b"<h1>v2</h1>\n");

    assert!(vault.unpublish_artifact_pointer("site", ArtifactPointerChannel::Published)?);
    assert!(
        vault
            .resolve_artifact_file(
                "site",
                ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
                "index.html",
            )?
            .is_none(),
        "unpublish removes the channel pointer"
    );
    let old_hash = vault
        .resolve_artifact_file(
            "site",
            ArtifactSnapshotSelector::ForkHash(first.snapshot.fork_hash),
            "index.html",
        )?
        .expect("old fork remains directly mountable");
    assert_eq!(old_hash.bytes, b"<h1>v1</h1>\n");
    Ok(())
}

#[test]
fn artifact_serving_rejects_codebase_class_snapshots() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>codebase</h1>\n")?;
    let config = RepoIngestConfig::new(repo.path(), ["index.html", "app.js"])?;
    let result = vault.ingest_local_repo_at_commit(
        "repo",
        &config,
        "HEAD",
        TimeRange { start: 10, end: 10 },
        10,
    )?;
    assert!(
        vault
            .resolve_artifact_file(
                "repo",
                ArtifactSnapshotSelector::ForkHash(result.snapshot.fork_hash),
                "index.html",
            )?
            .is_none(),
        "codebase-class snapshots must not be hostable"
    );
    Ok(())
}

fn test_publisher(vault: &Vault) -> Result<WriteActor> {
    let id = EntityId::from_bytes([0x31; 16])?;
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"publisher",
    )?;
    // This module's shared test fixture clears policy for legacy local-pointer
    // tests. Dispatch needs an actual resolved Gate policy to authorize grants.
    crate::test_util::put_policy_manifest_bytes(
        vault,
        EntityId::from_bytes([0x35; 16])?,
        &crate::gate::default_policy_manifest(),
    )?;
    Ok(WriteActor::new(id, crate::edge::EdgeActorClass::Human))
}

fn grant_artifact_publish(vault: &Vault, actor: WriteActor, artifact: &str) -> Result<EntityId> {
    let id = EntityId::from_bytes([0x32; 16])?;
    vault.mint_standing_outbound_grant(
        &id,
        &crate::genui::GrantMintIntent {
            principal_ref: actor.entity_ref().to_hex(),
            origin_component_id: "artifact.publish".to_owned(),
            origin_action_id: "auto_publish_this_artifact".to_owned(),
            origin_receipt_ref: None,
            scope: crate::genui::GrantMintIntentScope::ArtifactPublish {
                artifact: artifact.to_owned(),
            },
        },
        11,
    )?;
    Ok(id)
}

#[test]
fn ungranted_publish_proposes_until_grant_then_receipts_and_replays() -> Result<()> {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = test_publisher(&vault)?;
    let publish_id = EntityId::from_bytes([0x33; 16])?;
    let request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        publish_id,
        12,
    );
    let proposed = vault.request_artifact_publish(&request)?;
    assert_eq!(proposed.status, ArtifactPublishVerbStatus::Proposed);
    assert!(proposed.receipt.is_none());
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none()
    );
    assert!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Share))?
            .iter()
            .all(|receipt| receipt.receipt_id != format!("share:artifact:{}", publish_id.to_hex()))
    );

    let grant_id = grant_artifact_publish(&vault, actor, "site")?;
    let published = vault.request_artifact_publish(&request)?;
    assert_eq!(published.status, ArtifactPublishVerbStatus::Published);
    let receipt = published.receipt.expect("publish receipt");
    assert_eq!(receipt.receipt_kind, ReceiptKind::Share);
    assert_eq!(
        receipt.fields.get("gate_receipt_ref"),
        Some(&published.gate_decision_ref)
    );
    assert_eq!(
        receipt.fields.get("artifact").map(String::as_str),
        Some("site")
    );
    assert_eq!(
        published.pointer.expect("published pointer").fork_hash,
        result.snapshot.fork_hash
    );
    let stored = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Share))?;
    assert!(stored.contains(&receipt));
    vault.revoke_standing_outbound_grant(&grant_id, 13)?;
    // Revoking a grant blocks a NEW publish, but cannot erase the old proof.
    let next = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x36; 16])?,
        14,
    );
    assert_eq!(
        vault.request_artifact_publish(&next)?.status,
        ArtifactPublishVerbStatus::Proposed
    );
    assert!(vault.unpublish_artifact_pointer("site", ArtifactPointerChannel::Published)?);
    let replay = vault.request_artifact_publish(&request)?;
    assert_eq!(replay.receipt, Some(receipt.clone()));
    assert!(
        replay.pointer.is_none(),
        "a replay cannot resurrect an unpublished pointer"
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), test_config())?;
    assert!(
        reopened
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Share))?
            .contains(&receipt)
    );
    assert_eq!(
        reopened.request_artifact_publish(&request)?.receipt,
        Some(receipt)
    );
    Ok(())
}

#[test]
fn artifact_publish_grant_is_per_artifact_and_replay_cannot_rebind() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let first = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let second = ingest_artifact(&vault, repo.path(), "other", 11)?;
    let actor = test_publisher(&vault)?;
    grant_artifact_publish(&vault, actor, "site")?;
    let id = EntityId::from_bytes([0x34; 16])?;
    let other = ArtifactPublishVerbRequest::new(
        "other",
        ArtifactPointerChannel::Published,
        second.snapshot.fork_hash,
        actor,
        id,
        12,
    );
    assert_eq!(
        vault.request_artifact_publish(&other)?.status,
        ArtifactPublishVerbStatus::Proposed
    );
    let allowed = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        first.snapshot.fork_hash,
        actor,
        id,
        12,
    );
    assert_eq!(
        vault.request_artifact_publish(&allowed)?.status,
        ArtifactPublishVerbStatus::Published
    );
    let rebound = ArtifactPublishVerbRequest::new(
        "other",
        ArtifactPointerChannel::Published,
        second.snapshot.fork_hash,
        actor,
        id,
        12,
    );
    assert!(vault.request_artifact_publish(&rebound).is_err());
    assert!(
        vault
            .artifact_pointer("other", ArtifactPointerChannel::Published)?
            .is_none()
    );
    Ok(())
}

#[test]
fn malformed_artifact_fork_hash_fails_closed() {
    let err = parse_codebase_fork_hash_hex("not-a-fork")
        .expect_err("fork hash parser must reject malformed hex");
    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
}
