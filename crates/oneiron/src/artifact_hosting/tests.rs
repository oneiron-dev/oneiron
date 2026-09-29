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
fn artifact_link_capability_survives_reopen_and_unpublish_kills_hash_url() -> Result<()> {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>link</h1>\n")?;
    let snapshot = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let hash = snapshot.snapshot.fork_hash;
    let selector = ArtifactSnapshotSelector::ForkHash(hash);
    let (tier, token) = ArtifactServeTier::mint_link_token();
    assert!(
        vault
            .resolve_authorized_artifact_file("site", selector, "index.html", Some(&token), None)?
            .is_none()
    );
    vault.publish_artifact_pointer_with_tier(
        "site",
        ArtifactPointerChannel::Published,
        &hash,
        tier,
    )?;
    assert!(
        vault
            .resolve_authorized_artifact_file("site", selector, "index.html", None, None)?
            .is_none()
    );
    assert!(
        vault
            .resolve_authorized_artifact_file(
                "site",
                selector,
                "index.html",
                Some(&"0".repeat(64)),
                None
            )?
            .is_none()
    );
    assert!(
        vault
            .resolve_authorized_artifact_file("site", selector, "index.html", Some(&token), None)?
            .is_some()
    );
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    assert_eq!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .unwrap()
            .serve_tier,
        tier
    );
    assert!(
        vault
            .resolve_authorized_artifact_file("site", selector, "index.html", Some(&token), None)?
            .is_some()
    );
    vault.unpublish_artifact_pointer("site", ArtifactPointerChannel::Published)?;
    assert!(
        vault
            .resolve_authorized_artifact_file("site", selector, "index.html", Some(&token), None)?
            .is_none()
    );
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
        &crate::gate::default_policy_manifest().unwrap(),
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
        published.pointer.expect("published pointer").export,
        ArtifactExportRef::ForkHash(result.snapshot.fork_hash)
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
    let changed_tier = ArtifactPublishVerbRequest {
        serve_tier: ArtifactServeTier::Public,
        ..allowed
    };
    assert!(vault.request_artifact_publish(&changed_tier).is_err());
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
fn one_off_owner_approval_publishes_exact_request_without_standing_grant() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = test_publisher(&vault)?;
    let mut request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x41; 16])?,
        12,
    );
    request.serve_tier = ArtifactServeTier::Public;
    let other = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x42; 16])?,
        13,
    );
    assert_eq!(
        vault.request_artifact_publish(&request)?.status,
        ArtifactPublishVerbStatus::Proposed
    );
    let digest = vault.artifact_publish_approval_digest(&request)?;
    assert_ne!(digest, vault.artifact_publish_approval_digest(&other)?);
    let preview = ArtifactPublishVerbRequest {
        channel: ArtifactPointerChannel::Preview,
        ..request.clone()
    };
    assert_ne!(digest, vault.artifact_publish_approval_digest(&preview)?);
    let foreign = ingest_artifact(&vault, repo.path(), "other", 11)?;
    let different_artifact = ArtifactPublishVerbRequest::new(
        "other",
        ArtifactPointerChannel::Published,
        foreign.snapshot.fork_hash,
        actor,
        request.publish_id,
        request.occurred_at,
    );
    assert_ne!(
        digest,
        vault.artifact_publish_approval_digest(&different_artifact)?
    );
    commit_index(repo.path(), b"<h1>v2</h1>\n", "v2")?;
    let second = ingest_artifact(&vault, repo.path(), "site", 11)?;
    let different_fork = ArtifactPublishVerbRequest {
        export: ArtifactExportRef::ForkHash(second.snapshot.fork_hash),
        ..request.clone()
    };
    assert_ne!(
        digest,
        vault.artifact_publish_approval_digest(&different_fork)?
    );
    let second_actor_id = EntityId::from_bytes([0x45; 16])?;
    vault.put_entity(
        &second_actor_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"second publisher",
    )?;
    let different_actor = ArtifactPublishVerbRequest {
        actor: WriteActor::new(second_actor_id, crate::edge::EdgeActorClass::Human),
        ..request.clone()
    };
    assert_ne!(
        digest,
        vault.artifact_publish_approval_digest(&different_actor)?
    );
    let owner = vault.authenticate_owner(
        actor.entity_ref(),
        &actor.entity_ref().to_hex(),
        true,
        GateDecisionId::now(),
    )?;
    vault.approve_once(&owner, digest)?;
    let approved = vault.request_artifact_publish(&request)?;
    assert_eq!(approved.status, ArtifactPublishVerbStatus::Published);
    let receipt = approved.receipt.expect("publish receipt");
    assert!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Share))?
            .contains(&receipt)
    );
    assert_eq!(
        vault.request_artifact_publish(&request)?.receipt,
        Some(receipt)
    );
    assert_eq!(
        vault.request_artifact_publish(&other)?.status,
        ArtifactPublishVerbStatus::Proposed
    );
    Ok(())
}

#[test]
fn publish_receipt_replays_after_snapshot_entity_deletion() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = test_publisher(&vault)?;
    grant_artifact_publish(&vault, actor, "site")?;
    let request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x43; 16])?,
        12,
    );
    let receipt = vault
        .request_artifact_publish(&request)?
        .receipt
        .expect("receipt");
    assert!(vault.delete_entity(&result.code_artifact_id)?);
    assert!(
        vault
            .resolve_artifact_snapshot_by_fork("site", &result.snapshot.fork_hash)?
            .is_none()
    );
    let replay = vault.request_artifact_publish(&request)?;
    assert_eq!(replay.receipt, Some(receipt.clone()));
    assert!(replay.pointer.is_none());
    let rebound = ArtifactPublishVerbRequest {
        occurred_at: 13,
        ..request
    };
    assert!(vault.request_artifact_publish(&rebound).is_err());
    assert!(
        vault
            .receipts(ReceiptQuery::new(1).with_kind(ReceiptKind::Share))?
            .contains(&receipt)
    );
    Ok(())
}

#[test]
fn publish_receipt_replays_after_same_entity_snapshot_replacement() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = test_publisher(&vault)?;
    grant_artifact_publish(&vault, actor, "site")?;
    let request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x44; 16])?,
        12,
    );
    let receipt = vault
        .request_artifact_publish(&request)?
        .receipt
        .expect("receipt");
    let replacement = CodebaseSnapshot::new(
        "site",
        result.snapshot.repo_ref.clone(),
        result.snapshot.commit_hash.clone(),
        result
            .snapshot
            .files
            .iter()
            .filter(|file| file.path == "index.html")
            .cloned()
            .collect(),
    )?;
    assert_ne!(replacement.fork_hash, result.snapshot.fork_hash);
    vault.put_codebase_snapshot(&result.code_artifact_id, &replacement, &|path| {
        fs::read(repo.path().join(path)).ok()
    })?;
    assert!(
        vault
            .resolve_artifact_snapshot_by_fork("site", &result.snapshot.fork_hash)?
            .is_none()
    );
    let replay = vault.request_artifact_publish(&request)?;
    assert_eq!(replay.receipt, Some(receipt));
    assert!(replay.pointer.is_none());
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none()
    );
    Ok(())
}

#[test]
fn publish_share_query_with_limit_one_keeps_the_newest_receipt() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = test_publisher(&vault)?;
    grant_artifact_publish(&vault, actor, "site")?;
    let first = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x46; 16])?,
        12,
    );
    let later = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0x47; 16])?,
        13,
    );
    let earlier_receipt = vault
        .request_artifact_publish(&first)?
        .receipt
        .expect("first receipt");
    let later_receipt = vault
        .request_artifact_publish(&later)?
        .receipt
        .expect("later receipt");
    assert_ne!(earlier_receipt, later_receipt);
    assert_eq!(
        vault.receipts(ReceiptQuery::new(1).with_kind(ReceiptKind::Share))?,
        vec![later_receipt]
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
fn blob_link_tier_survives_reopen_and_requires_live_pointer() -> Result<()> {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    vault.append_blob_artifact_version(
        &id,
        b"report",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    let (tier, token) = ArtifactServeTier::mint_link_token();
    let selector = ArtifactSnapshotSelector::BlobVersion(1);
    let artifact = id.to_hex();
    assert!(
        vault
            .resolve_authorized_artifact_file(&artifact, selector, "export", Some(&token), None)?
            .is_none()
    );
    vault.publish_blob_artifact_pointer_with_tier(
        &id,
        ArtifactPointerChannel::Published,
        1,
        tier,
    )?;
    assert_eq!(
        vault
            .artifact_pointer(&artifact, ArtifactPointerChannel::Published)?
            .unwrap()
            .serve_tier,
        tier
    );
    assert!(
        vault
            .resolve_authorized_artifact_file(&artifact, selector, "export", None, None)?
            .is_none()
    );
    assert_eq!(
        vault
            .resolve_authorized_artifact_file(&artifact, selector, "export", Some(&token), None)?
            .expect("live token serves pinned blob")
            .bytes,
        b"report"
    );
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    assert_eq!(
        vault
            .artifact_pointer(&artifact, ArtifactPointerChannel::Published)?
            .unwrap()
            .serve_tier,
        tier
    );
    assert!(
        vault
            .resolve_authorized_artifact_file(&artifact, selector, "export", Some(&token), None)?
            .is_some()
    );
    assert!(vault.unpublish_blob_artifact_pointer(&id, ArtifactPointerChannel::Published)?);
    assert!(
        vault
            .resolve_authorized_artifact_file(&artifact, selector, "export", Some(&token), None)?
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
        let tier = match channel {
            ArtifactPointerChannel::Published => ArtifactServeTier::mint_link_token().0,
            ArtifactPointerChannel::Preview => ArtifactServeTier::WorldMembers(42),
        };
        vault.publish_blob_artifact_pointer_with_tier(&id, channel, 1, tier)?;
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
fn blob_publish_after_delete_in_the_writer_cannot_revive_on_id_reuse() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    let first = vault.append_blob_artifact_version(
        &id,
        b"old bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    let artifact = id.to_hex();
    let mut wtxn = vault.store.env.write_txn()?;
    vault.batch_in().delete(&id).apply(&mut wtxn)?;
    // The delete and attempted publish share the writer. This is the
    // dangerous order if publish validated before taking that writer.
    let error = vault
        .publish_export_pointer_in_txn(
            &mut wtxn,
            &artifact,
            ArtifactPointerChannel::Published,
            ArtifactExportRef::BlobVersion {
                artifact_id: id,
                version: first.version,
            },
            ArtifactServeTier::Private,
        )
        .expect_err("deleted export cannot be published");
    assert!(matches!(error, Error::EntityNotFound));
    wtxn.commit()?;

    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("report.pdf", "application/pdf"),
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    let replacement = vault.append_blob_artifact_version(
        &id,
        b"replacement bytes",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 4, end: 4 },
        4,
    )?;
    assert_ne!(replacement.version, first.version);
    assert!(
        vault
            .artifact_pointer(&artifact, ArtifactPointerChannel::Published)?
            .is_none()
    );
    assert!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
                "export"
            )?
            .is_none()
    );
    assert!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::BlobVersion(first.version),
                "export"
            )?
            .is_none()
    );
    assert_eq!(
        vault
            .resolve_artifact_file(
                &artifact,
                ArtifactSnapshotSelector::BlobVersion(replacement.version),
                "export"
            )?
            .expect("replacement has only its new version URL")
            .bytes,
        b"replacement bytes"
    );
    Ok(())
}

#[test]
fn deleted_blob_id_never_reuses_a_direct_version_url() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    let first = vault.append_blob_artifact_version(
        &id,
        b"first",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    assert!(vault.delete_entity(&id)?);
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("report.pdf", "application/pdf"),
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    let second = vault.append_blob_artifact_version(
        &id,
        b"second",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 4, end: 4 },
        4,
    )?;
    assert_eq!(second.version, first.version + 1);
    assert!(
        vault
            .resolve_artifact_file(
                &id.to_hex(),
                ArtifactSnapshotSelector::BlobVersion(first.version),
                "export"
            )?
            .is_none()
    );
    assert_eq!(vault.blob_artifact_versions(&id)?, vec![second]);
    Ok(())
}

#[test]
fn pinned_blob_export_keeps_name_and_media_type_after_body_reput() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, actor) = blob_fixture(&vault)?;
    let first = vault.append_blob_artifact_version(
        &id,
        b"original",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    vault.publish_blob_artifact_pointer(&id, ArtifactPointerChannel::Published, first.version)?;
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("renamed.txt", "text/plain"),
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    let pinned = vault
        .resolve_artifact_file(
            &id.to_hex(),
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published),
            "report.pdf",
        )?
        .expect("old export name is pinned");
    assert_eq!(pinned.bytes, b"original");
    assert_eq!(pinned.media_type.as_deref(), Some("application/pdf"));
    assert!(
        vault
            .resolve_artifact_file(
                &id.to_hex(),
                ArtifactSnapshotSelector::BlobVersion(first.version),
                "renamed.txt"
            )?
            .is_none()
    );
    assert_eq!(
        vault
            .resolve_artifact_file(
                &id.to_hex(),
                ArtifactSnapshotSelector::BlobVersion(first.version),
                "export"
            )?
            .expect("stable export path")
            .media_type
            .as_deref(),
        Some("application/pdf")
    );
    let next = vault.append_blob_artifact_version(
        &id,
        b"new content",
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: 4, end: 4 },
        4,
    )?;
    assert_eq!(next.export_name, "renamed.txt");
    assert_eq!(next.export_media_type, "text/plain");
    assert_eq!(first.export_name, "report.pdf");
    assert_eq!(first.export_media_type, "application/pdf");
    Ok(())
}

#[test]
fn blob_publish_requires_grant_then_receipts_and_replays() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let (id, uploader) = blob_fixture(&vault)?;
    vault.append_blob_artifact_version(
        &id,
        b"report",
        &BlobVersionProvenance::UserUpload,
        uploader,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    let actor = test_publisher(&vault)?;
    let mut request = ArtifactPublishVerbRequest::new_blob(
        id,
        ArtifactPointerChannel::Published,
        1,
        actor,
        EntityId::from_bytes([0x63; 16])?,
        12,
    );
    request.serve_tier = ArtifactServeTier::Public;
    let proposed = vault.request_artifact_publish(&request)?;
    assert_eq!(proposed.status, ArtifactPublishVerbStatus::Proposed);
    assert!(proposed.receipt.is_none());
    assert!(
        vault
            .artifact_pointer(&id.to_hex(), ArtifactPointerChannel::Published)?
            .is_none()
    );
    grant_artifact_publish(&vault, actor, &id.to_hex())?;
    let published = vault.request_artifact_publish(&request)?;
    assert_eq!(published.status, ArtifactPublishVerbStatus::Published);
    assert_eq!(
        published.pointer.as_ref().expect("pointer").export,
        ArtifactExportRef::BlobVersion {
            artifact_id: id,
            version: 1
        }
    );
    assert_eq!(
        published.pointer.as_ref().expect("pointer").serve_tier,
        ArtifactServeTier::Public
    );
    let receipt = published.receipt.expect("share receipt");
    assert_eq!(
        receipt.fields.get("serve_tier").map(String::as_str),
        Some("Public")
    );
    let changed_tier = ArtifactPublishVerbRequest {
        serve_tier: ArtifactServeTier::Private,
        ..request.clone()
    };
    assert!(vault.request_artifact_publish(&changed_tier).is_err());
    assert_eq!(receipt.receipt_kind, ReceiptKind::Share);
    assert_eq!(receipt.fields.get("blob_artifact_id"), Some(&id.to_hex()));
    assert_eq!(
        receipt.fields.get("blob_version").map(String::as_str),
        Some("1")
    );
    assert!(
        vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Share))?
            .contains(&receipt)
    );
    assert!(vault.unpublish_blob_artifact_pointer(&id, ArtifactPointerChannel::Published)?);
    let replay = vault.request_artifact_publish(&request)?;
    assert_eq!(replay.receipt, Some(receipt));
    assert!(
        replay.pointer.is_none(),
        "replay must not restore a dead channel"
    );
    let rebound = ArtifactPublishVerbRequest {
        export: ArtifactExportRef::BlobVersion {
            artifact_id: id,
            version: 2,
        },
        ..request
    };
    assert!(vault.request_artifact_publish(&rebound).is_err());
    Ok(())
}

#[test]
fn receipt_retention_keeps_publish_admission_for_idempotent_replay() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = test_publisher(&vault)?;
    grant_artifact_publish(&vault, actor, "site")?;
    let request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        result.snapshot.fork_hash,
        actor,
        EntityId::from_bytes([0xC3; 16])?,
        12,
    );
    let receipt = vault
        .request_artifact_publish(&request)?
        .receipt
        .expect("publish receipt");
    let gate_id = vault
        .store
        .gate_decisions(100)?
        .into_iter()
        .find(|row| {
            format!("gate:{}", row.decision_id.to_hex()) == receipt.fields["gate_receipt_ref"]
        })
        .expect("publish decision")
        .decision_id;
    let unrelated = vault.with_write_txn(|txn| {
        let mut old = vault
            .store
            .gate_decision_in_txn(txn, gate_id)?
            .expect("publish gate");
        vault.store.delete_gate_decision_in_txn(txn, gate_id)?;
        old.created_at = 1;
        vault.store.append_gate_decision_in_txn(txn, &old)?;
        let mut unrelated = old;
        unrelated.decision_id = crate::store::GateDecisionId::now();
        vault.store.append_gate_decision_in_txn(txn, &unrelated)?;
        Ok(unrelated.decision_id)
    })?;
    let owner = vault.authenticate_owner(
        actor.entity_ref(),
        "principal:publish-retention",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.set_gate_decision_retention_secs(&owner, Some(60))?;
    assert_eq!(vault.sweep_gate_decision_retention()?, 1);
    assert!(
        vault
            .store
            .gate_decisions(100)?
            .iter()
            .all(|row| row.decision_id != unrelated)
    );
    assert!(vault.delete_entity(&result.code_artifact_id)?);
    assert_eq!(
        vault.request_artifact_publish(&request)?.receipt,
        Some(receipt.clone())
    );
    assert!(
        vault
            .receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Share))?
            .contains(&receipt)
    );
    Ok(())
}
