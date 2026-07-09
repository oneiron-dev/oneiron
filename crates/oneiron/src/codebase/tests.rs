use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::code_artifact::{CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody};
use crate::code_revision::{CODE_REVISION_CLAIM_PREDICATE, CodeRevision};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, ErrorKind};
use crate::pipeline::WorldScope;
use crate::registry::{ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::temporal::TimeRange;
use crate::types::{HnswConfig, PackFormat, TextAnalyzerConfig, VaultConfig};
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteEnvelope;
use crate::write_envelope::WriteProvenance;
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.text_analyzer = TextAnalyzerConfig::default();
    config
}

fn repo_ref() -> RepoRef {
    RepoRef::parse("github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
        .expect("repo ref")
}

fn repo_ref_b() -> RepoRef {
    RepoRef::parse("github:oneiron-dev/other#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .expect("repo ref")
}

fn local_repo_ref() -> RepoRef {
    RepoRef::parse("local:/Users/example/project#9d561405a81ffbf29d1369cd848e0ef9fca4f277")
        .expect("local repo ref")
}

fn local_repo_ref_b() -> RepoRef {
    RepoRef::parse("local:/Users/example/project#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .expect("local repo ref")
}

fn entity_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("entity id")
}

const GITHUB_TOKEN_SECRET_FIXTURE: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

fn assert_secret_scan_rejected(err: Error) {
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &["gate.secret_scan.detected", "gate.secret_scan.github_token"]
            );
        }
        other => panic!("expected secret-scan GateWriteRejected, got {other:?}"),
    }
}

fn file(path: &str, hash_byte: u8) -> CodebaseFileEntry {
    CodebaseFileEntry::new(
        path,
        [hash_byte; CODEBASE_CONTENT_HASH_LEN],
        u64::from(hash_byte),
    )
}

fn snapshot(project_id: &str, repo_ref: RepoRef) -> Result<CodebaseSnapshot> {
    CodebaseSnapshot::new(
        project_id,
        repo_ref,
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        vec![file("src/lib.rs", 2), file("Cargo.toml", 1)],
    )
}

fn code_body(repo_ref: &RepoRef) -> CodeArtifactBody {
    CodeArtifactBody::new(
        "Summarize the codebase snapshot.",
        [0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
        repo_ref.canonical(),
    )
}

fn put_session(vault: &Vault, id: EntityId, learned_at: u64) -> Result<()> {
    vault.put_entity(
        &id,
        ENTITY_TYPE_SESSION,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"session",
    )
}

fn put_code_revision_claim(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    learned_at: u64,
) -> Result<()> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        b"repo ref reviewer",
    )?;
    let candidate = ClaimCandidate::new(
        CODE_REVISION_CLAIM_PREDICATE,
        ClaimSubject::Entity(subject),
        Value::from("repo_ref changed"),
        0.9,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("repo-ref-change"))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
        )
        .commit()?;
    vault.put_edge(&id, EdgeKind::ClaimOf, &subject, 1.0)
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

fn create_test_repo() -> Result<tempfile::TempDir> {
    let repo_dir = tempfile::tempdir()?;
    fs::create_dir_all(repo_dir.path().join("src"))?;
    fs::write(
        repo_dir.path().join("Cargo.toml"),
        b"[package]\nname = \"tiny\"\n",
    )?;
    fs::write(
        repo_dir.path().join("src/lib.rs"),
        b"pub fn answer() -> u8 { 42 }\n",
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

fn commit_test_file(repo_dir: &Path, path: &str, bytes: &[u8], message: &str) -> Result<()> {
    let full_path = repo_dir.join(path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(full_path, bytes)?;
    run_git(repo_dir, &["add", path])?;
    run_git(repo_dir, &["commit", "-m", message])
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HashMatchCall {
    project_id: String,
    path: String,
    media_type: &'static str,
    content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
    size_bytes: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct RecordingHashMatchProvider {
    calls: RefCell<Vec<HashMatchCall>>,
}

impl HostedMediaHashMatchProvider for RecordingHashMatchProvider {
    fn check_hosted_media(
        &self,
        input: HostedMediaHashMatchInput<'_>,
    ) -> Result<HostedMediaHashMatchDecision> {
        self.calls.borrow_mut().push(HashMatchCall {
            project_id: input.project_id.to_owned(),
            path: input.path.to_owned(),
            media_type: input.media_type,
            content_hash: input.content_hash,
            size_bytes: input.size_bytes,
            bytes: input.bytes.to_vec(),
        });
        Ok(HostedMediaHashMatchDecision::NoMatch)
    }
}

#[derive(Debug, Clone, Copy)]
struct KnownMatchProvider;

impl HostedMediaHashMatchProvider for KnownMatchProvider {
    fn check_hosted_media(
        &self,
        _input: HostedMediaHashMatchInput<'_>,
    ) -> Result<HostedMediaHashMatchDecision> {
        Ok(HostedMediaHashMatchDecision::KnownMatch {
            provider: "unit-provider".to_owned(),
            reference: "case-123".to_owned(),
        })
    }
}

#[test]
fn noop_hosted_media_hash_match_provider_reports_no_match() -> Result<()> {
    let bytes = b"secret-media-bytes";
    let input = HostedMediaHashMatchInput {
        project_id: "project.alpha",
        path: "portrait.JPG",
        media_type: "image/jpeg",
        content_hash: *blake3::hash(bytes).as_bytes(),
        size_bytes: u64::try_from(bytes.len())
            .map_err(|_| Error::ArithmeticOverflow("test bytes"))?,
        bytes,
    };

    let provider = NoopHostedMediaHashMatchProvider;
    assert_eq!(
        provider.check_hosted_media(input)?,
        HostedMediaHashMatchDecision::NoMatch
    );
    assert_eq!(
        hosted_media_type_for_blob("payload.bin", b"\xff\xd8\xff\xe0jpeg-body"),
        Some("image/jpeg")
    );
    assert_eq!(
        hosted_media_type_for_blob("portrait.JPG", b"extension-only-candidate"),
        Some("image/jpeg")
    );
    assert_eq!(hosted_media_type_for_blob("README.md", b"plain text"), None);

    let debug = format!("{input:?}");
    assert!(debug.contains("bytes: \"<redacted>\""));
    assert!(!debug.contains("secret-media-bytes"));
    Ok(())
}

#[test]
fn codebase_repo_ref_parse_validates_local_and_github_at_commit() -> Result<()> {
    let local = local_repo_ref();
    assert_eq!(
        local,
        RepoRef::LocalFolder {
            path: "/Users/example/project".to_owned(),
            commit: "9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned(),
        }
    );
    assert_eq!(
        local.canonical(),
        "local:/Users/example/project#9d561405a81ffbf29d1369cd848e0ef9fca4f277"
    );
    let err = RepoRef::parse("local:/Users/example/project")
        .expect_err("local repo refs must be pinned to a commit");
    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);

    let github = RepoRef::parse(
        "https://github.com/oneiron-dev/oneiron.git#9D561405A81FFBF29D1369CD848E0EF9FCA4F277",
    )?;
    assert_eq!(github, repo_ref());
    assert_eq!(
        github.canonical(),
        "github:oneiron-dev/oneiron#9d561405a81ffbf29d1369cd848e0ef9fca4f277"
    );

    let err = RepoRef::parse("github:oneiron-dev/oneiron#main")
        .expect_err("branch names are not commit-pinned repo refs");
    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
    Ok(())
}

#[test]
fn task_list_repo_url_migrates_to_repo_ref_with_commit() -> Result<()> {
    let migrated = RepoRef::from_task_list_repo_url(
        "https://github.com/oneiron-dev/oneiron.git",
        "9D561405A81FFBF29D1369CD848E0EF9FCA4F277",
    )?;
    assert_eq!(migrated, repo_ref());

    let local = RepoRef::from_task_list_repo_url(
        "file:///Users/example/project",
        "9d561405a81ffbf29d1369cd848e0ef9fca4f277",
    )?;
    assert_eq!(local, local_repo_ref());
    Ok(())
}

#[test]
fn codebase_snapshot_codec_round_trips_manifest() -> Result<()> {
    let snapshot = snapshot("project.alpha", repo_ref())?;
    assert_eq!(snapshot.files[0].path, "Cargo.toml");
    assert_eq!(snapshot.files[1].path, "src/lib.rs");

    let encoded = encode_codebase_snapshot(&snapshot)?;
    let decoded = decode_codebase_snapshot(&encoded)?;

    assert_eq!(decoded, snapshot);
    Ok(())
}

#[test]
fn codebase_snapshot_codec_rejects_unsorted_or_duplicate_manifest() {
    let raw = CodebaseSnapshot {
        project_id: "project.alpha".to_owned(),
        repo_ref: repo_ref(),
        commit_hash: Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        fork_hash: [0; CODEBASE_FORK_HASH_LEN],
        scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
        files: vec![file("src/lib.rs", 1), file("src/lib.rs", 2)],
    };
    let err = encode_codebase_snapshot(&raw).expect_err("duplicate paths fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
}

#[test]
fn codebase_snapshot_codec_rejects_backslash_manifest_paths() {
    let raw = CodebaseSnapshot {
        project_id: "project.alpha".to_owned(),
        repo_ref: repo_ref(),
        commit_hash: Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        fork_hash: [0; CODEBASE_FORK_HASH_LEN],
        scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
        files: vec![file("src\\..\\secret", 1)],
    };

    let err = encode_codebase_snapshot(&raw)
        .expect_err("backslash paths must fail closed instead of hiding traversal");

    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
}

#[test]
fn codebase_snapshot_codec_rejects_invalid_constructed_repo_ref() {
    let raw = CodebaseSnapshot {
        project_id: "project.alpha".to_owned(),
        repo_ref: RepoRef::GitHubAtCommit {
            owner: "oneiron-dev".to_owned(),
            repo: "oneiron".to_owned(),
            commit: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        },
        commit_hash: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
        fork_hash: [0; CODEBASE_FORK_HASH_LEN],
        scope_key: [0; CODEBASE_SCOPE_KEY_LEN],
        files: vec![file("src/main.rs", 1)],
    };

    let err = encode_codebase_snapshot(&raw)
        .expect_err("constructed repo_ref values must still satisfy the v1 grammar");

    assert_eq!(err.kind(), ErrorKind::InvalidCodebaseSnapshotBody);
}

#[test]
fn codebase_snapshot_vault_round_trip_and_queries() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let repo_ref = repo_ref();
    let snapshot = snapshot("project.alpha", repo_ref.clone())?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id, &snapshot)?;

    assert_eq!(vault.get_codebase_snapshot(&id)?, Some(snapshot));
    assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?, vec![id]);
    assert_eq!(
        vault.codebase_snapshots_by_project_id("project.alpha")?,
        vec![id]
    );
    assert!(
        vault
            .codebase_snapshots_by_project_id("project.beta")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn codebase_snapshot_rejects_secret_file_path_before_sidecar_mutation() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity_id(0x33);
    let repo_ref = repo_ref();
    let safe_snapshot = snapshot("project.alpha", repo_ref.clone())?;
    let secret_path = format!("src/{GITHUB_TOKEN_SECRET_FIXTURE}");
    let secret_snapshot = CodebaseSnapshot::new(
        "project.alpha",
        repo_ref.clone(),
        Some("9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned()),
        vec![file("Cargo.toml", 1), file(&secret_path, 3)],
    )?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id, &safe_snapshot)?;

    let err = vault
        .put_codebase_snapshot(&id, &secret_snapshot)
        .expect_err("secret file path must reject before sidecar mutation");

    assert_secret_scan_rejected(err);
    assert_eq!(vault.get_codebase_snapshot(&id)?, Some(safe_snapshot));
    assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?, vec![id]);
    assert_eq!(
        vault.codebase_snapshots_by_project_id("project.alpha")?,
        vec![id]
    );
    Ok(())
}

#[test]
fn repo_ref_change_records_version_history_edges_and_consent_record() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let session = EntityId::now();
    let first_revision_id = EntityId::now();
    let second_revision_id = EntityId::now();
    let provenance_claim_id = EntityId::now();
    let first_repo = local_repo_ref();
    let second_repo = local_repo_ref_b();

    put_session(&vault, session, 90)?;
    vault.put_code_artifact(
        &first_revision_id,
        &code_body(&first_repo),
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    vault.put_code_artifact(
        &second_revision_id,
        &code_body(&second_repo),
        TimeRange {
            start: 200,
            end: 200,
        },
        200,
    )?;
    put_code_revision_claim(&vault, provenance_claim_id, second_revision_id, 201)?;

    let first_revision = CodeRevision::commit(first_revision_id, session, 100);
    let second_revision =
        CodeRevision::commit_child(second_revision_id, session, first_revision_id, 200)
            .with_provenance_claim_id(provenance_claim_id);
    vault.commit_code_revision(&first_revision)?;
    vault.commit_code_revision(&second_revision)?;

    assert_eq!(
        vault.child_code_revisions(&first_revision_id)?,
        vec![second_revision]
    );
    assert_eq!(
        vault.targets(&second_revision_id, EdgeKind::Supersedes, None)?,
        vec![first_revision_id]
    );
    assert_eq!(
        vault.claims_for_subject(&second_revision_id)?,
        vec![provenance_claim_id]
    );
    let provenance = vault
        .get_claim(&provenance_claim_id)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(provenance.approval, ClaimApprovalStatus::Auto);
    assert_eq!(provenance.source, Some(ClaimSource::UserStated));
    Ok(())
}

#[test]
fn codebase_snapshot_delete_cleans_sidecar_indexes() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = EntityId::now();
    let repo_ref = repo_ref();
    let snapshot = snapshot("project.alpha", repo_ref.clone())?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id, &snapshot)?;
    assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?, vec![id]);

    assert!(vault.delete_entity(&id)?);

    assert!(vault.get_codebase_snapshot(&id)?.is_none());
    assert!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?.is_empty());
    assert!(
        vault
            .codebase_snapshots_by_project_id("project.alpha")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn codebase_snapshot_batch_delete_cleans_sidecar_indexes() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity_id(0x31);
    let repo_ref = repo_ref();
    let snapshot = snapshot("project.alpha", repo_ref.clone())?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_ref),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id, &snapshot)?;

    vault.batch().delete(&id).commit()?;

    assert!(vault.get_codebase_snapshot(&id)?.is_none());
    assert!(vault.codebase_snapshots_by_repo_ref(&repo_ref)?.is_empty());
    assert!(
        vault
            .codebase_snapshots_by_project_id("project.alpha")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn codebase_snapshot_code_artifact_repo_ref_overwrite_cleans_sidecar_indexes() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let id = entity_id(0x32);
    let repo_a = repo_ref();
    let repo_b = repo_ref_b();
    let snapshot = snapshot("project.alpha", repo_a.clone())?;

    vault.put_code_artifact(
        &id,
        &code_body(&repo_a),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id, &snapshot)?;
    assert_eq!(vault.codebase_snapshots_by_repo_ref(&repo_a)?, vec![id]);

    vault.put_code_artifact(
        &id,
        &code_body(&repo_b),
        TimeRange { start: 12, end: 12 },
        13,
    )?;

    assert!(vault.get_codebase_snapshot(&id)?.is_none());
    assert!(vault.codebase_snapshots_by_repo_ref(&repo_a)?.is_empty());
    assert!(vault.codebase_snapshots_by_repo_ref(&repo_b)?.is_empty());
    assert!(
        vault
            .codebase_snapshots_by_project_id("project.alpha")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn codebase_filters_apply_to_search_and_context_pack() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo_a = repo_ref();
    let repo_b = repo_ref_b();
    let id_a = EntityId::now();
    let id_b = EntityId::now();

    vault.put_code_artifact(
        &id_a,
        &code_body(&repo_a),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id_a, &snapshot("project.alpha", repo_a.clone())?)?;
    vault.put_code_artifact(
        &id_b,
        &code_body(&repo_b),
        TimeRange { start: 12, end: 12 },
        13,
    )?;
    vault.put_codebase_snapshot(
        &id_b,
        &CodebaseSnapshot::new(
            "project.beta",
            repo_b,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
            vec![file("src/main.rs", 3)],
        )?,
    )?;
    vault
        .batch()
        .text(&id_a, &[("body", "sharedneedle alpha")])
        .text(&id_b, &[("body", "sharedneedle beta")])
        .commit()?;

    let all = vault.query().search_text("sharedneedle", 10).run()?;
    assert_eq!(all.len(), 2);

    let by_repo = vault
        .query()
        .search_text("sharedneedle", 10)
        .filter_repo_ref(repo_a)
        .run()?;
    assert_eq!(by_repo.len(), 1);
    assert_eq!(by_repo[0].id, id_a);

    let by_project = vault
        .query()
        .search_text("sharedneedle", 10)
        .filter_project_id("project.beta")
        .run()?;
    assert_eq!(by_project.len(), 1);
    assert_eq!(by_project[0].id, id_b);

    let pack = vault
        .context_pack()
        .format(PackFormat::Json)
        .search_text("sharedneedle", 10)
        .filter_project_id("project.alpha")
        .run()?;
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, id_a);
    Ok(())
}

#[test]
fn local_repo_ingest_is_idempotent_and_mounts_files() -> Result<()> {
    let repo_dir = create_test_repo()?;
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;

    let first = vault.ingest_local_repo_at_commit(
        "project.alpha",
        &config,
        "HEAD",
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    let second = vault.ingest_local_repo_at_commit(
        "project.alpha",
        &config,
        "HEAD",
        TimeRange { start: 10, end: 10 },
        11,
    )?;

    assert_eq!(second.code_artifact_id, first.code_artifact_id);
    assert_eq!(second.snapshot.fork_hash, first.snapshot.fork_hash);
    assert_eq!(second.snapshot.scope_key, first.snapshot.scope_key);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_CODE_ARTIFACT)?, 1);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_ASSET)?, 2);
    assert_eq!(
        vault.codebase_snapshots_by_fork_hash(&first.snapshot.fork_hash)?,
        vec![first.code_artifact_id]
    );

    let mount = vault
        .mount_codebase_snapshot(&first.code_artifact_id)?
        .expect("snapshot mount");
    assert!(mount.is_read_only());
    assert_eq!(mount.list_files(), vec!["Cargo.toml", "src/lib.rs"]);
    assert_eq!(
        mount.read_file("src/lib.rs")?,
        Some(b"pub fn answer() -> u8 { 42 }\n".to_vec())
    );

    let definitions = vault.code_symbol_definitions(&first.code_artifact_id, "answer")?;
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        vault.get_entity_type(&definitions[0].entity_id)?,
        Some(ENTITY_TYPE_CODE_SYMBOL)
    );
    assert!(vault.edge_exists(
        &definitions[0].entity_id,
        EdgeKind::PartOf,
        &first.code_artifact_id
    )?);
    Ok(())
}

#[test]
fn local_repo_ingest_calls_hash_match_provider_for_hosted_media_candidates() -> Result<()> {
    let repo_dir = create_test_repo()?;
    let media_bytes = b"not-a-real-image-but-route-media-by-extension";
    let renamed_media_bytes = b"\x89PNG\r\n\x1a\nmisnamed-png-body";
    commit_test_file(
        repo_dir.path(),
        "assets/payload.bin",
        renamed_media_bytes,
        "add renamed media",
    )?;
    commit_test_file(
        repo_dir.path(),
        "assets/portrait.jpg",
        media_bytes,
        "add media",
    )?;
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;
    let provider = RecordingHashMatchProvider::default();

    vault.ingest_local_repo_at_commit_with_hosted_media_hash_match_provider(
        "project.alpha",
        &config,
        "HEAD",
        TimeRange { start: 10, end: 10 },
        11,
        &provider,
    )?;

    let calls = provider.calls.borrow();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls.as_slice(),
        &[
            HashMatchCall {
                project_id: "project.alpha".to_owned(),
                path: "assets/payload.bin".to_owned(),
                media_type: "image/png",
                content_hash: *blake3::hash(renamed_media_bytes).as_bytes(),
                size_bytes: u64::try_from(renamed_media_bytes.len())
                    .map_err(|_| Error::ArithmeticOverflow("test renamed media bytes"))?,
                bytes: renamed_media_bytes.to_vec(),
            },
            HashMatchCall {
                project_id: "project.alpha".to_owned(),
                path: "assets/portrait.jpg".to_owned(),
                media_type: "image/jpeg",
                content_hash: *blake3::hash(media_bytes).as_bytes(),
                size_bytes: u64::try_from(media_bytes.len())
                    .map_err(|_| Error::ArithmeticOverflow("test media bytes"))?,
                bytes: media_bytes.to_vec(),
            },
        ]
    );
    Ok(())
}

#[test]
fn local_repo_ingest_preserves_known_match_metadata() -> Result<()> {
    let repo_dir = create_test_repo()?;
    let media_bytes = b"\xff\xd8\xff\xe0known-jpeg";
    commit_test_file(
        repo_dir.path(),
        "assets/known.bin",
        media_bytes,
        "add known media",
    )?;
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;

    let error = vault
        .ingest_local_repo_at_commit_with_hosted_media_hash_match_provider(
            "project.alpha",
            &config,
            "HEAD",
            TimeRange { start: 10, end: 10 },
            11,
            &KnownMatchProvider,
        )
        .unwrap_err();

    match error {
        Error::HostedMediaHashMatchKnownMatch {
            provider,
            reference,
            path,
            content_hash,
        } => {
            assert_eq!(&*provider, "unit-provider");
            assert_eq!(&*reference, "case-123");
            assert_eq!(&*path, "assets/known.bin");
            assert_eq!(*content_hash, *blake3::hash(media_bytes).as_bytes());
        }
        other => panic!("unexpected error: {other:?}"),
    }
    Ok(())
}

#[test]
fn codebase_scope_key_clamps_world_set_retrieval() -> Result<()> {
    let repo_dir = create_test_repo()?;
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let config = RepoIngestConfig::new(repo_dir.path(), ["src/lib.rs"])?;
    let ingest = vault.ingest_local_repo_at_commit(
        "project.alpha",
        &config,
        "HEAD",
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    let outside = entity_id(0x58);

    vault.put_entity(
        &outside,
        ENTITY_TYPE_ASSET,
        TimeRange { start: 20, end: 20 },
        21,
        b"outside asset",
    )?;
    vault
        .batch()
        .text(&ingest.code_artifact_id, &[("body", "scopeneedle repo")])
        .text(&outside, &[("body", "scopeneedle outside")])
        .commit()?;

    let all = vault.query().search_text("scopeneedle", 10).run()?;
    assert_eq!(all.len(), 2);

    let scoped = vault
        .query()
        .search_text("scopeneedle", 10)
        .world(WorldScope::WorldSet(ingest.snapshot.scope_key))
        .run()?;
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].id, ingest.code_artifact_id);

    let asset_id = codebase_asset_entity_id(&ingest.snapshot.files[0].content_hash)?;
    let rtxn = vault.store.env.read_txn()?;
    assert!(codebase_candidate_matches_scope_key(
        &vault.store,
        &rtxn,
        &asset_id,
        &ingest.snapshot.scope_key
    )?);
    assert!(!codebase_candidate_matches_scope_key(
        &vault.store,
        &rtxn,
        &outside,
        &ingest.snapshot.scope_key
    )?);
    Ok(())
}

#[test]
fn codebase_filters_apply_before_channel_top_k_limits() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let repo_a = repo_ref();
    let repo_b = repo_ref_b();
    let id_a = entity_id(0x41);
    let id_b = entity_id(0x42);

    vault.put_code_artifact(
        &id_a,
        &code_body(&repo_a),
        TimeRange { start: 10, end: 10 },
        11,
    )?;
    vault.put_codebase_snapshot(&id_a, &snapshot("project.alpha", repo_a)?)?;
    vault.put_code_artifact(
        &id_b,
        &code_body(&repo_b),
        TimeRange { start: 12, end: 12 },
        13,
    )?;
    vault.put_codebase_snapshot(
        &id_b,
        &CodebaseSnapshot::new(
            "project.beta",
            repo_b,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
            vec![file("src/main.rs", 3)],
        )?,
    )?;
    vault
        .batch()
        .text(&id_a, &[("body", "needle needle needle needle")])
        .text(&id_b, &[("body", "needle")])
        .vector(&id_a, &[1.0, 0.0, 0.0, 0.0])
        .vector(&id_b, &[0.0, 1.0, 0.0, 0.0])
        .commit()?;

    let unscoped_text_top = vault.query().search_text("needle", 1).run()?;
    assert_eq!(unscoped_text_top.len(), 1);
    assert_eq!(unscoped_text_top[0].id, id_a);

    let scoped_text_top = vault
        .query()
        .search_text("needle", 1)
        .filter_project_id("project.beta")
        .run()?;
    assert_eq!(scoped_text_top.len(), 1);
    assert_eq!(scoped_text_top[0].id, id_b);

    let scoped_pack = vault
        .context_pack()
        .format(PackFormat::Json)
        .search_text("needle", 1)
        .filter_project_id("project.beta")
        .run()?;
    assert_eq!(scoped_pack.results.len(), 1);
    assert_eq!(scoped_pack.results[0].id, id_b);

    let unscoped_vector_top = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .run()?;
    assert_eq!(unscoped_vector_top.len(), 1);
    assert_eq!(unscoped_vector_top[0].id, id_a);

    let scoped_vector_top = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 1)
        .filter_project_id("project.beta")
        .run()?;
    assert_eq!(scoped_vector_top.len(), 1);
    assert_eq!(scoped_vector_top[0].id, id_b);
    Ok(())
}
