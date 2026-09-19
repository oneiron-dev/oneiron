use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use super::*;
use crate::codebase::RepoIngestConfig;
use crate::config::{HnswConfig, TextAnalyzerConfig, VaultConfig};
use crate::error::ErrorKind;
use crate::temporal::TimeRange;

pub(super) fn test_config() -> VaultConfig {
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

pub(super) fn publisher(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"publisher",
    )?;
    publish_policy(vault, &[id])?;
    Ok(id)
}

fn publish_policy(vault: &Vault, actors: &[EntityId]) -> Result<()> {
    // The legacy vault fixture removes the default policy. Give each actor an
    // Auto ceiling, but NO outbound grant: publishing still requires the
    // exact artifact grant and the absent-policy fail-closed gate stays intact.
    let policy = rmp_serde::to_vec_named(&serde_json::json!({
        "schema_version": "1.1",
        "pack_id": "artifact-publish-test",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality":"normal", "sensitivity":"normal"},
        "rules": [],
        "actor_ceilings": actors.iter().flat_map(|id| [
            serde_json::json!({"actor_class":"agent", "actor_ref":id.to_hex(), "ceiling":"auto"}),
            serde_json::json!({"actor_class":"human", "actor_ref":id.to_hex(), "ceiling":"auto"}),
        ]).collect::<Vec<_>>(),
        "scoped_grants": []
    }))
    .expect("encode policy fixture");
    crate::test_util::put_policy_manifest_bytes(vault, crate::test_util::entity(0xE0), &policy)
}

#[test]
fn publish_verb_parks_then_granted_publish_is_receipted_and_replayable()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>v1</h1>\n")?;
    let result = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = publisher(&vault)?;
    let mut request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        ArtifactPinnedVersion::Code(result.snapshot.fork_hash),
        crate::outbound::OutboundDispatchActor::agent(actor),
        "intent:publish",
        20,
    );
    let proposed = vault.request_artifact_publish(&request)?;
    assert_eq!(proposed.status, ArtifactPublishVerbStatus::Proposed);
    assert!(proposed.pointer.is_none());
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none()
    );
    vault
        .memory(actor, crate::edge::EdgeActorClass::Human)
        .grant_artifact_publish("site", actor, 21)?;
    request.occurred_at = 22;
    let published = vault.request_artifact_publish(&request)?;
    assert_eq!(
        published.status,
        ArtifactPublishVerbStatus::Published,
        "{:?}",
        published.receipt
    );
    assert_eq!(published.pointer.as_ref().unwrap().version, request.version);
    let share = published
        .share_receipt
        .expect("publish is a share-style receipt");
    assert_eq!(share.receipt_kind, crate::receipt::ReceiptKind::Share);
    let replay = vault.request_artifact_publish(&request)?;
    assert_eq!(replay.share_receipt, Some(share.clone()));
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    assert!(vault.unpublish_artifact_pointer("site", ArtifactPointerChannel::Published)?);
    request.occurred_at = 30;
    assert_eq!(
        vault.request_artifact_publish(&request)?.share_receipt,
        Some(share.clone())
    );
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none()
    );
    assert!(
        vault
            .receipts(
                crate::receipt::ReceiptQuery::new(100)
                    .with_kind(crate::receipt::ReceiptKind::Share)
            )?
            .contains(&share)
    );
    Ok(())
}

#[test]
fn blob_export_pointers_pin_repoint_and_do_not_republish_on_old_replay()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = publisher(&vault)?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &crate::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    for (at, bytes) in [(2, b"export-one".as_slice()), (3, b"export-two".as_slice())] {
        vault.append_blob_artifact_version(
            &id,
            bytes,
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Human),
            TimeRange { start: at, end: at },
            at,
        )?;
    }
    vault
        .memory(actor, crate::edge::EdgeActorClass::Human)
        .grant_artifact_publish("report", actor, 5)?;
    let request = |channel, version, intent| {
        ArtifactPublishVerbRequest::new(
            "report",
            channel,
            ArtifactPinnedVersion::Blob {
                artifact_id: id,
                version,
            },
            crate::outbound::OutboundDispatchActor::agent(actor),
            intent,
            10,
        )
    };
    let v1 = request(ArtifactPointerChannel::Published, 1, "publish:v1");
    let published = vault.request_artifact_publish(&v1)?;
    assert_eq!(
        published.status,
        ArtifactPublishVerbStatus::Published,
        "{:?}",
        published.receipt
    );
    vault.request_artifact_publish(&request(ArtifactPointerChannel::Preview, 2, "preview:v2"))?;
    let read = |channel| {
        vault.resolve_artifact_file(
            "report",
            ArtifactSnapshotSelector::Channel(channel),
            "index.html",
        )
    };
    assert_eq!(
        read(ArtifactPointerChannel::Published)?.unwrap().bytes,
        b"export-one"
    );
    assert_eq!(
        read(ArtifactPointerChannel::Preview)?.unwrap().bytes,
        b"export-two"
    );
    vault.request_artifact_publish(&request(ArtifactPointerChannel::Published, 2, "publish:v2"))?;
    vault.request_artifact_publish(&v1)?;
    assert_eq!(
        read(ArtifactPointerChannel::Published)?.unwrap().bytes,
        b"export-two"
    );
    assert!(vault.unpublish_artifact_pointer("report", ArtifactPointerChannel::Published)?);
    assert!(read(ArtifactPointerChannel::Published)?.is_none());
    assert!(read(ArtifactPointerChannel::Preview)?.is_some());
    Ok(())
}

#[test]
fn artifact_grant_is_exact_and_codec_preserves_its_scope() {
    use crate::outbound_grant::StandingOutboundGrantScope;
    let scope = StandingOutboundGrantScope::ArtifactPublish {
        artifact: "report".into(),
    };
    assert!(scope.matches_effect("publish", "artifact", Some("report"), None));
    assert!(!scope.matches_effect("publish", "artifact", Some("another"), None));
    assert!(!scope.matches_effect("send", "email", Some("report"), None));
    assert!(
        !StandingOutboundGrantScope::Contact {
            contact_ref: "report".into()
        }
        .matches_effect("publish", "artifact", Some("report"), None)
    );
}

#[test]
fn malformed_artifact_fork_hash_fails_closed() {
    let err = parse_codebase_fork_hash_hex("not-a-fork")
        .expect_err("fork hash parser must reject malformed hex");
    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
}

#[test]
fn publish_verb_parks_then_approved_once_publish_replays_after_reopen() -> Result<()> {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo = create_test_repo(b"<h1>approved once</h1>\n")?;
    let ingested = ingest_artifact(&vault, repo.path(), "site", 10)?;
    let actor = publisher(&vault)?;
    let mut request = ArtifactPublishVerbRequest::new(
        "site",
        ArtifactPointerChannel::Published,
        ArtifactPinnedVersion::Code(ingested.snapshot.fork_hash),
        crate::outbound::OutboundDispatchActor::agent(actor),
        "intent:publish-once",
        20,
    );
    let proposed = vault.request_artifact_publish(&request)?;
    assert_eq!(proposed.status, ArtifactPublishVerbStatus::Proposed);
    assert!(proposed.pointer.is_none());
    assert!(proposed.share_receipt.is_none());
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none()
    );
    assert!(
        vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                false,
                crate::store::GateDecisionId::now()
            )
            .is_err()
    );
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let approval = vault.approve_artifact_publish(&owner, &request)?;
    assert!(matches!(
        approval,
        crate::consent::ConsentReceipt::Approved {
            grant: crate::consent::ConsentGrant::ApproveOnce(_),
            ..
        }
    ));
    assert!(vault.active_standing_consent_grants()?.is_empty());
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_OUTBOUND_GRANT)?
            .is_empty()
    );
    // Approval survives restart, and occurrence time does not change its identity.
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    request.occurred_at = 21;
    let published = vault.request_artifact_publish(&request)?;
    assert_eq!(published.status, ArtifactPublishVerbStatus::Published);
    assert_eq!(published.pointer.as_ref().unwrap().version, request.version);
    let share = published
        .share_receipt
        .expect("a publish has a share receipt");
    assert_eq!(share.receipt_kind, crate::receipt::ReceiptKind::Share);
    assert_eq!(share.fields["artifact"], "site");
    assert_eq!(share.fields["artifact_channel"], "published");
    assert_eq!(share.actor.as_deref(), Some(actor.to_hex().as_str()));
    assert_eq!(
        share.trigger_ref.as_deref(),
        Some(request.intent_ref.as_str())
    );
    assert_eq!(
        vault
            .approve_artifact_publish(&owner, &request)
            .expect_err("the owner cannot re-arm a consumed intent")
            .kind(),
        ErrorKind::ConsentApproveOnceSpent
    );
    assert!(vault.unpublish_artifact_pointer("site", ArtifactPointerChannel::Published)?);
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    request.occurred_at = 30;
    let replay = vault.request_artifact_publish(&request)?;
    assert_eq!(replay.status, ArtifactPublishVerbStatus::Published);
    assert_eq!(replay.share_receipt, Some(share.clone()));
    assert!(
        vault
            .artifact_pointer("site", ArtifactPointerChannel::Published)?
            .is_none(),
        "receipt replay must not restore an unpublished pointer"
    );
    request.intent_ref = "intent:publish-again".into();
    assert_eq!(
        vault.request_artifact_publish(&request)?.status,
        ArtifactPublishVerbStatus::Proposed,
        "approval is not a standing publish grant"
    );
    assert_eq!(
        vault.receipts(
            crate::receipt::ReceiptQuery::new(100).with_kind(crate::receipt::ReceiptKind::Share)
        )?,
        vec![share]
    );
    Ok(())
}

#[test]
fn publish_approval_binds_artifact_channel_version_actor_and_intent() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = publisher(&vault)?;
    let other_actor = EntityId::now();
    vault.put_entity(
        &other_actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"another publisher",
    )?;
    publish_policy(&vault, &[actor, other_actor])?;
    let first = EntityId::now();
    let other = EntityId::now();
    for id in [first, other] {
        vault.put_blob_artifact(
            &id,
            &crate::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf"),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
        for (at, bytes) in [(2, b"export-one".as_slice()), (3, b"export-two".as_slice())] {
            vault.append_blob_artifact_version(
                &id,
                bytes,
                &crate::blob_artifact::BlobVersionProvenance::UserUpload,
                crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Human),
                TimeRange { start: at, end: at },
                at,
            )?;
        }
    }
    let request = ArtifactPublishVerbRequest::new(
        "report",
        ArtifactPointerChannel::Published,
        ArtifactPinnedVersion::Blob {
            artifact_id: first,
            version: 1,
        },
        crate::outbound::OutboundDispatchActor::agent(actor),
        "intent:exact-publish",
        10,
    );
    assert_eq!(
        vault.request_artifact_publish(&request)?.status,
        ArtifactPublishVerbStatus::Proposed
    );
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.approve_artifact_publish(&owner, &request)?;
    let mut substitutions = Vec::new();
    let mut changed = request.clone();
    changed.artifact = "another-artifact".into();
    substitutions.push(("artifact", changed));
    let mut changed = request.clone();
    changed.channel = ArtifactPointerChannel::Preview;
    substitutions.push(("channel", changed));
    let mut changed = request.clone();
    changed.version = ArtifactPinnedVersion::Blob {
        artifact_id: first,
        version: 2,
    };
    substitutions.push(("version", changed));
    let mut changed = request.clone();
    changed.version = ArtifactPinnedVersion::Blob {
        artifact_id: other,
        version: 1,
    };
    substitutions.push(("blob identity", changed));
    let mut changed = request.clone();
    // Both classes have the same Auto policy ceiling. Only the exact approval
    // binding, not a missing policy ceiling, must refuse this substitution.
    changed.actor.actor_class = "human".into();
    substitutions.push(("actor class", changed));
    let mut changed = request.clone();
    changed.actor = crate::outbound::OutboundDispatchActor::agent(other_actor);
    substitutions.push(("actor identity", changed));
    let mut changed = request.clone();
    changed.intent_ref = "intent:other-publish".into();
    substitutions.push(("intent", changed));
    for (axis, changed) in &substitutions {
        let outcome = vault.request_artifact_publish(changed)?;
        assert_eq!(
            outcome.status,
            ArtifactPublishVerbStatus::Proposed,
            "{axis}"
        );
        assert!(outcome.share_receipt.is_none(), "{axis}");
        assert!(
            vault
                .artifact_pointer(&changed.artifact, changed.channel)?
                .is_none(),
            "{axis}"
        );
    }
    let published = vault.request_artifact_publish(&request)?;
    assert_eq!(published.status, ArtifactPublishVerbStatus::Published);
    assert_eq!(published.pointer.as_ref().unwrap().version, request.version);
    let share = published
        .share_receipt
        .expect("exact approval was not consumed by another op");
    assert_eq!(
        vault.request_artifact_publish(&request)?.share_receipt,
        Some(share)
    );
    for (axis, changed) in &substitutions {
        if changed.intent_ref == request.intent_ref {
            assert!(
                vault.request_artifact_publish(changed).is_err(),
                "{axis}: mismatched replay"
            );
        } else {
            assert_eq!(
                vault.request_artifact_publish(changed)?.status,
                ArtifactPublishVerbStatus::Proposed
            );
        }
    }
    assert!(vault.active_standing_consent_grants()?.is_empty());
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_OUTBOUND_GRANT)?
            .is_empty()
    );
    Ok(())
}
