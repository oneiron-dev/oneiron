use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::codebase::RepoIngestConfig;
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

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

#[test]
fn publish_verb_stub_parks_as_proposed_without_writing_pointer() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        false,
    );

    let outcome = vault.request_artifact_publish(&request)?;

    assert_eq!(outcome.status, ArtifactPublishVerbStatus::Proposed);
    assert!(outcome.pointer.is_none());
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none(),
        "proposed publish must not make the artifact served"
    );
    Ok(())
}

#[cfg(feature = "artifact-publish-verb")]
#[test]
fn publish_verb_honors_standing_grant_by_publishing_pointer() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        true,
    );

    let outcome = vault.request_artifact_publish(&request)?;

    assert_eq!(outcome.status, ArtifactPublishVerbStatus::Published);
    let pointer = outcome.pointer.expect("published pointer returned");
    assert_eq!(
        pointer.export,
        ArtifactExportRef::ForkHash(result.snapshot.fork_hash)
    );
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_some(),
        "standing grant publish should make the artifact served"
    );
    Ok(())
}

#[test]
fn malformed_artifact_fork_hash_fails_closed() {
    let err = parse_codebase_fork_hash_hex("not-a-fork")
        .expect_err("fork hash parser must reject malformed hex");
    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
}

fn blob_fixture(vault: &Vault) -> Result<(EntityId, WriteActor)> {
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("report.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let person = EntityId::now();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"publisher",
    )?;
    Ok((id, WriteActor::new(person, EdgeActorClass::Human)))
}

#[test]
fn blob_export_published_preview_pin_repoint_unpublish_and_direct_version() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    let first = vault.append_blob_artifact_version(
        &id,
        b"%PDF-first",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    let artifact = id.to_hex();
    assert!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
                "report.pdf"
            )?
            .is_none()
    );
    let published = vault.publish_blob_artifact_pointer(
        &id,
        ArtifactPointerChannel::Published,
        first.version,
    )?;
    assert_eq!(
        published.export,
        ArtifactExportRef::BlobVersion {
            artifact_id: id,
            version: 1
        }
    );
    let second = vault.append_blob_artifact_version(
        &id,
        b"%PDF-second",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    vault.publish_blob_artifact_pointer(&id, ArtifactPointerChannel::Preview, second.version)?;
    let served = |selector| -> Result<ArtifactServedFile> {
        vault
            .resolve_artifact_file(&artifact, selector, "report.pdf")?
            .ok_or(Error::EntityNotFound)
    };
    assert_eq!(
        served(ArtifactSnapshotSelector::Channel(
            ArtifactPointerChannel::Published
        ))?
        .bytes,
        b"%PDF-first"
    );
    let preview = served(ArtifactSnapshotSelector::Channel(
        ArtifactPointerChannel::Preview,
    ))?;
    assert_eq!(preview.bytes, b"%PDF-second");
    assert_eq!(preview.media_type.as_deref(), Some("application/pdf"));
    assert_eq!(
        served(ArtifactSnapshotSelector::BlobVersion(1))?.bytes,
        b"%PDF-first"
    );
    assert_eq!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::BlobVersion(1),
                "export"
            )?
            .expect("stable export route")
            .bytes,
        b"%PDF-first"
    );
    vault.publish_blob_artifact_pointer(&id, ArtifactPointerChannel::Published, second.version)?;
    assert_eq!(
        served(ArtifactSnapshotSelector::Channel(
            ArtifactPointerChannel::Published
        ))?
        .bytes,
        b"%PDF-second"
    );
    assert!(vault.unpublish_artifact_pointer(&artifact, ArtifactPointerChannel::Published)?);
    assert!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
                "report.pdf"
            )?
            .is_none()
    );
    assert_eq!(
        served(ArtifactSnapshotSelector::Channel(
            ArtifactPointerChannel::Preview
        ))?
        .bytes,
        b"%PDF-second"
    );
    assert_eq!(
        served(ArtifactSnapshotSelector::BlobVersion(1))?.bytes,
        b"%PDF-first"
    );
    assert!(
        vault
            .publish_blob_artifact_pointer(&id, ArtifactPointerChannel::Preview, 99)
            .is_err()
    );
    assert!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::BlobVersion(0),
                "report.pdf"
            )?
            .is_none()
    );
    assert!(
        vault
            .resolve_artifact_file(
                "another",
                ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Preview),
                "report.pdf"
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn deleting_blob_export_removes_both_channel_pointers() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    vault.append_blob_artifact_version(
        &id,
        b"report",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        vault.publish_blob_artifact_pointer(&id, channel, 1)?;
    }
    assert!(vault.delete_entity(&id)?);
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        assert!(
            !vault.unpublish_blob_artifact_pointer(&id, channel)?,
            "deletion must already have removed the pointer row"
        );
    }
    Ok(())
}

#[test]
fn blob_publish_verb_needs_grant_and_feature() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    vault.append_blob_artifact_version(
        &id,
        b"report",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    let request =
        ArtifactPublishVerbRequest::new_blob(id, ArtifactPointerChannel::Published, 1, false);
    assert_eq!(
        vault.request_artifact_publish(&request)?.status,
        ArtifactPublishVerbStatus::Proposed
    );
    assert!(
        vault
            .artifact_pointer(&id.to_hex(), ArtifactPointerChannel::Published)?
            .is_none()
    );
    let request =
        ArtifactPublishVerbRequest::new_blob(id, ArtifactPointerChannel::Published, 1, true);
    let outcome = vault.request_artifact_publish(&request)?;
    if cfg!(feature = "artifact-publish-verb") {
        assert_eq!(outcome.status, ArtifactPublishVerbStatus::Published);
        assert!(
            vault
                .artifact_pointer(&id.to_hex(), ArtifactPointerChannel::Published)?
                .is_some()
        );
    } else {
        assert_eq!(outcome.status, ArtifactPublishVerbStatus::Proposed);
        assert!(
            vault
                .artifact_pointer(&id.to_hex(), ArtifactPointerChannel::Published)?
                .is_none()
        );
    }
    Ok(())
}
