use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::build_cache::{
    ArtifactVersionRef, BuildInputRoot, BuildPlatform, DeclaredOutputPath, FrozenBuildCommand,
};
use crate::codebase::RepoIngestConfig;
use crate::edge::EdgeActorClass;
use crate::write_envelope::WriteActor;
use crate::{TimeRange, VaultConfig};
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success());
}
#[test]
fn independent_views_share_blobs_server_and_build_results() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    std::fs::create_dir(repo.join("src")).unwrap();
    std::fs::write(
        repo.join("src/main.rs"),
        "fn main() { println!(\"view\"); }\n",
    )
    .unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
    );
    let vault = Vault::open(temp.path().join("vault"), VaultConfig::default()).unwrap();
    let at = TimeRange { start: 1, end: 1 };
    let actor = EntityId::now();
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            at,
            1,
            b"builder",
        )
        .unwrap();
    let ingested = vault
        .ingest_local_repo_at_commit(
            "views",
            &RepoIngestConfig::new(&repo, ["src/main.rs"]).unwrap(),
            "HEAD",
            at,
            1,
        )
        .unwrap();
    let mount = vault
        .mount_codebase_snapshot(&ingested.code_artifact_id)
        .unwrap()
        .unwrap();
    let set = CodeViewSet::create(&vault, &temp.path().join("views")).unwrap();
    let policy: VisibleFilePolicy = serde_json::from_str(include_str!(
        "../../../../examples/code-review/visible-files-v1.json"
    ))
    .unwrap();
    assert!(policy.selects("src/main.rs").unwrap());
    assert!(!policy.selects("target/main").unwrap());
    let a = set.materialize(&mount, actor, &policy).unwrap();
    let b = set.materialize(&mount, actor, &policy).unwrap();
    assert_ne!(a.view_id, b.view_id);
    assert_eq!(a.files, b.files);
    assert_eq!(set.receipt(a.view_id).unwrap(), Some(a.clone()));
    assert_eq!(
        std::fs::read_dir(set.root.join("blobs")).unwrap().count(),
        1
    );
    let server = StdioLanguageServer::start(
        Path::new("python3"),
        &[concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/code_view/tests/language_server.py"
        )
        .into()],
        temp.path(),
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let shared = SharedLanguageServer::new(server);
    shared.attach(&set, a.view_id).unwrap();
    shared.attach(&set, b.view_id).unwrap();
    for view in [a.view_id, b.view_id] {
        assert_eq!(
            shared.completions(view, "src/main.rs", 0, 3).unwrap()[0]["label"],
            "main"
        );
        assert_eq!(
            shared.diagnostics(view, "src/main.rs").unwrap()["items"],
            serde_json::json!([])
        );
    }
    shared.restart_view(&set, a.view_id).unwrap();
    assert_eq!(
        shared.completions(b.view_id, "src/main.rs", 0, 3).unwrap()[0]["label"],
        "main"
    );
    let action = BuildAction::new(
        FrozenBuildCommand::new(
            vec![
                "rustc".into(),
                "src/main.rs".into(),
                "-o".into(),
                "target/program".into(),
            ],
            BTreeMap::<String, String>::new(),
        )
        .unwrap(),
        BuildInputRoot {
            repo_ref: ingested.snapshot.repo_ref,
            fork_hash: ingested.snapshot.fork_hash,
            extra_inputs: vec![],
        },
        BuildPlatform::new([("arch", std::env::consts::ARCH)]).unwrap(),
        vec![DeclaredOutputPath::parse("target/program").unwrap()],
    )
    .unwrap();
    let cache = BuildCache::new(&vault);
    let first = set
        .build(
            a.view_id,
            &cache,
            CheckoutTaskClass::Build,
            &action,
            |path, vault| {
                std::fs::create_dir(path.join("target"))?;
                let status = Command::new("rustc")
                    .current_dir(path)
                    .args(["src/main.rs", "-o", "target/program"])
                    .status()?;
                assert!(status.success());
                let bytes = std::fs::read(path.join("target/program"))?;
                let id = EntityId::now();
                vault.put_blob_artifact(
                    &id,
                    &BlobArtifactBody::new("program", "application/octet-stream"),
                    at,
                    1,
                )?;
                let version = vault.append_blob_artifact_version(
                    &id,
                    &bytes,
                    &BlobVersionProvenance::UserUpload,
                    WriteActor::new(actor, EdgeActorClass::Human),
                    at,
                    1,
                )?;
                Ok(ActionResult {
                    exit_code: 0,
                    outputs: BTreeMap::from([(
                        DeclaredOutputPath::parse("target/program")?,
                        ArtifactVersionRef::new(id, version.version)?,
                    )]),
                    stdout_ref: None,
                    stderr_ref: None,
                    produced_at: 1,
                    producer_ref: a.view_id.to_hex(),
                })
            },
        )
        .unwrap();
    let second = set
        .build(
            b.view_id,
            &cache,
            CheckoutTaskClass::Build,
            &action,
            |_, _| panic!("shared hit must skip rustc"),
        )
        .unwrap();
    assert!(!first.receipt.cache_hit);
    assert!(second.receipt.cache_hit);
    assert_eq!(
        std::fs::read(set.view_path(a.view_id).unwrap().join("target/program")).unwrap(),
        std::fs::read(set.view_path(b.view_id).unwrap().join("target/program")).unwrap()
    );
    // A tool that chmods and overwrites its own input must not corrupt another
    // view or the canonical blob, and a build from that input must not hit cache.
    let input = set.view_path(a.view_id).unwrap().join("src/main.rs");
    let original_permissions = std::fs::metadata(repo.join("src/main.rs"))
        .unwrap()
        .permissions();
    std::fs::set_permissions(&input, original_permissions.clone()).unwrap();
    std::fs::write(&input, b"changed by tool").unwrap();
    assert_eq!(
        std::fs::read(set.view_path(b.view_id).unwrap().join("src/main.rs")).unwrap(),
        std::fs::read(repo.join("src/main.rs")).unwrap()
    );
    let c = set.materialize(&mount, actor, &policy).unwrap();
    assert_eq!(c.files, b.files);
    assert!(
        set.build(
            a.view_id,
            &cache,
            CheckoutTaskClass::Build,
            &action,
            |_, _| panic!("changed input must refuse before cache lookup")
        )
        .is_err()
    );
    assert!(shared.restart_view(&set, a.view_id).is_err());

    let mutating_action = BuildAction::new(
        FrozenBuildCommand::new(
            vec!["mutating-tool".into()],
            BTreeMap::<String, String>::new(),
        )
        .unwrap(),
        action.input_root.clone(),
        BuildPlatform::new([("arch", std::env::consts::ARCH)]).unwrap(),
        vec![],
    )
    .unwrap();
    let result = set.build(
        c.view_id,
        &cache,
        CheckoutTaskClass::Build,
        &mutating_action,
        |path, _| {
            let input = path.join("src/main.rs");
            std::fs::set_permissions(&input, original_permissions)?;
            std::fs::write(&input, b"mutated during build")?;
            Ok(ActionResult {
                exit_code: 0,
                outputs: BTreeMap::new(),
                stdout_ref: None,
                stderr_ref: None,
                produced_at: 2,
                producer_ref: c.view_id.to_hex(),
            })
        },
    );
    assert!(matches!(
        result,
        Err(crate::build_cache::BuildCacheError::Store(
            Error::CorruptedIndex(_)
        ))
    ));
    assert!(
        cache
            .get(&mutating_action.action_key().unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        std::fs::read(set.view_path(b.view_id).unwrap().join("src/main.rs")).unwrap(),
        std::fs::read(repo.join("src/main.rs")).unwrap()
    );
}
