//! FIX 295: an unpublish retires the sync replica's staged code snapshot.
//!
//! A published code pointer reaches the server replica as a publication: the
//! pointer row plus the snapshot manifest that serves it. Unpublishing must
//! take both back, unless the other channel still serves that fork. On main
//! the unpublish deletes only the pointer row, and the staged manifest stays
//! behind on the replica, still resolvable by its fork.
//!
//! Red at main: both tests' final `get_codebase_snapshot` reads `Some` where
//! they assert `None`. Green with the fix, which retires the staged snapshot
//! once no channel pointer names its fork.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fix_295_unpublish_retires_staged_snapshot`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-hooks"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use oneiron::artifact_hosting::{ArtifactPointerChannel, ArtifactPublicationOutcome};
use oneiron::code_artifact::CodeArtifactClass;
use oneiron::codebase::{CodebaseForkHash, RepoIngestConfig};
use oneiron::test_doors::artifact_publication_pump::pump_artifact_publications;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const SITE: &str = "site";
/// The project a replica-local ingest of the same bytes is seeded under: the
/// files' content-addressed bytes land, while its snapshot never matches the
/// published route.
const SHADOW: &str = "site-shadow";
const PAGE: &[u8] = b"<h1>fix 295</h1>\n";

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git starts");
    assert!(status.success(), "git {args:?} failed");
}

fn open_vault(dir: &tempfile::TempDir) -> Vault {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    vault
}

/// Every receipt the pump answered applied its publication.
fn assert_all_applied(outcomes: &[(EntityId, ArtifactPublicationOutcome)]) {
    assert!(
        !outcomes.is_empty(),
        "the pump settled at least one publication"
    );
    for (entity, outcome) in outcomes {
        assert_eq!(
            *outcome,
            ArtifactPublicationOutcome::Applied,
            "publication {} applied",
            entity.to_hex()
        );
    }
}

struct PublishedSite {
    _repo: tempfile::TempDir,
    _device_dir: tempfile::TempDir,
    _server_dir: tempfile::TempDir,
    device: Vault,
    server: Vault,
    fork_hash: CodebaseForkHash,
    owner: EntityId,
    shadow_owner: EntityId,
}

/// A device vault publishing `site` on its Published channel, and a server
/// vault holding what window sync would have carried there: the owner row
/// and the files' bytes, the latter seeded by a replica-local ingest of the
/// same bytes under another project. Nothing is pumped yet.
fn published_site() -> PublishedSite {
    let repo = tempfile::tempdir().expect("repo");
    std::fs::write(repo.path().join("index.html"), PAGE).expect("write page");
    git(repo.path(), &["init"]);
    git(repo.path(), &["config", "user.email", "oneiron@example.test"]);
    git(repo.path(), &["config", "user.name", "Oneiron Test"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-m", "bundle"]);

    let device_dir = tempfile::tempdir().expect("device dir");
    let device = open_vault(&device_dir);
    let ingest = RepoIngestConfig::new(repo.path(), ["index.html"]).expect("ingest config");
    let result = device
        .ingest_local_repo_at_commit(
            SITE,
            &ingest,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("ingest");
    let body = device
        .get_code_artifact(&result.code_artifact_id)
        .expect("read code artifact")
        .expect("code artifact exists")
        .with_class(CodeArtifactClass::Artifact);
    device
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("mark hostable");
    device
        .publish_artifact_pointer(
            SITE,
            ArtifactPointerChannel::Published,
            &result.snapshot.fork_hash,
        )
        .expect("publish");

    let server_dir = tempfile::tempdir().expect("server dir");
    let server = open_vault(&server_dir);
    server
        .put_code_artifact(
            &result.code_artifact_id,
            &body,
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("replica owner row");
    let shadow = server
        .ingest_local_repo_at_commit(
            SHADOW,
            &ingest,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            10,
        )
        .expect("seed bytes");

    PublishedSite {
        _repo: repo,
        _device_dir: device_dir,
        _server_dir: server_dir,
        device,
        server,
        fork_hash: result.snapshot.fork_hash,
        owner: result.code_artifact_id,
        shadow_owner: shadow.code_artifact_id,
    }
}

#[test]
fn unpublish_retires_the_replicas_staged_snapshot() {
    let site = published_site();
    let outcomes =
        pump_artifact_publications(&site.device, &site.server).expect("pump the publish");
    assert_all_applied(&outcomes);
    assert!(
        site.server
            .artifact_pointer(SITE, ArtifactPointerChannel::Published)
            .expect("read pointer")
            .is_some(),
        "the publish lands the pointer on the replica"
    );
    assert!(
        site.server
            .get_codebase_snapshot(&site.owner)
            .expect("read staged snapshot")
            .is_some(),
        "the publish stages the snapshot on the replica"
    );

    assert!(
        site.device
            .unpublish_artifact_pointer(SITE, ArtifactPointerChannel::Published)
            .expect("unpublish"),
        "the device held the pointer"
    );
    let outcomes =
        pump_artifact_publications(&site.device, &site.server).expect("pump the unpublish");
    assert_all_applied(&outcomes);
    assert!(
        site.server
            .artifact_pointer(SITE, ArtifactPointerChannel::Published)
            .expect("read pointer")
            .is_none(),
        "the unpublish removes the replica pointer"
    );
    assert!(
        site.server
            .get_codebase_snapshot(&site.owner)
            .expect("read staged snapshot")
            .is_none(),
        "FIX 295: the unpublish retires the replica's staged snapshot"
    );
    // What window sync owns stays: the owner row and this vault's own snapshot.
    assert!(
        site.server
            .get_code_artifact(&site.owner)
            .expect("read owner")
            .is_some(),
        "the unpublish keeps the owner row"
    );
    assert!(
        site.server
            .get_codebase_snapshot(&site.shadow_owner)
            .expect("read local snapshot")
            .is_some(),
        "the unpublish keeps this vault's own snapshot"
    );
}

#[test]
fn unpublish_keeps_the_snapshot_while_the_other_channel_serves_it() {
    let site = published_site();
    site.device
        .publish_artifact_pointer(SITE, ArtifactPointerChannel::Preview, &site.fork_hash)
        .expect("publish preview");
    let outcomes =
        pump_artifact_publications(&site.device, &site.server).expect("pump the publishes");
    assert_all_applied(&outcomes);
    assert_eq!(
        outcomes.len(),
        2,
        "each channel's publication is answered"
    );

    assert!(
        site.device
            .unpublish_artifact_pointer(SITE, ArtifactPointerChannel::Published)
            .expect("unpublish published"),
        "the device held the published pointer"
    );
    let outcomes =
        pump_artifact_publications(&site.device, &site.server).expect("pump the unpublish");
    assert_all_applied(&outcomes);
    assert!(
        site.server
            .artifact_pointer(SITE, ArtifactPointerChannel::Preview)
            .expect("read pointer")
            .is_some(),
        "the other channel still serves the replica"
    );
    assert!(
        site.server
            .get_codebase_snapshot(&site.owner)
            .expect("read staged snapshot")
            .is_some(),
        "the snapshot stays while the other channel serves its fork"
    );

    assert!(
        site.device
            .unpublish_artifact_pointer(SITE, ArtifactPointerChannel::Preview)
            .expect("unpublish preview"),
        "the device held the preview pointer"
    );
    let outcomes =
        pump_artifact_publications(&site.device, &site.server).expect("pump the last unpublish");
    assert_all_applied(&outcomes);
    assert!(
        site.server
            .get_codebase_snapshot(&site.owner)
            .expect("read staged snapshot")
            .is_none(),
        "FIX 295: the last unpublish retires the staged snapshot"
    );
}
