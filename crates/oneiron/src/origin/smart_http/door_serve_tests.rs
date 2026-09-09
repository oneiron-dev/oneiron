//! Serve command and door tests: closed env/argv, vetted hook, unlandable names,
//! framed blobs, coordinator, door request parse, repo names, noop seam, dial.

use super::tests::{
    git, hooks_dir, landing_outcome, landing_time, narrow_door_effectors, seeded_repo, temp_vault,
};
use super::*;

#[test]
fn smart_http_serve_command_env_allowlist_is_closed() {
    let (root, hooks) = hooks_dir();
    let repo = root.path().join("demo.git");
    std::fs::create_dir_all(&repo).expect("repo dir");
    let command =
        ServeCommand::http_backend(&repo, root.path(), hooks.path()).expect("build serve command");

    let base = command.env().keys().cloned().collect::<Vec<_>>();
    assert_eq!(base, SERVE_BASE_ENV_KEYS.to_vec(), "closed serve baseline");
    assert_eq!(
        command.env().get("GIT_HTTP_EXPORT_ALL").map(String::as_str),
        Some("1"),
        "export pin"
    );
    assert_eq!(
        command
            .env()
            .get("GIT_NO_REPLACE_OBJECTS")
            .map(String::as_str),
        Some("1"),
        "every git under this serve reads true object bytes"
    );

    let request = ServeRequest {
        method: "POST".to_owned(),
        path_info: "/demo.git/git-receive-pack".to_owned(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: Some(7),
        content_encoding: Some("gzip".to_owned()),
        git_protocol: Some("version=2".to_owned()),
        remote_user: Some("principal:tester".to_owned()),
        remote_addr: None,
    };
    let child_env = command.child_env(&request);
    for key in child_env.keys() {
        let known = SERVE_BASE_ENV_KEYS.contains(&key.as_str())
            || SERVE_REQUEST_ENV_KEYS.contains(&key.as_str());
        assert!(known, "unexpected serve environment key {key}");
    }
    assert!(
        !child_env.contains_key("GIT_CONFIG_PARAMETERS"),
        "the config policy travels in argv, never in the environment"
    );
}

#[test]
fn smart_http_serve_command_argv_pins_door_hooks_path() {
    let (root, hooks) = hooks_dir();
    let repo = root.path().join("demo.git");
    std::fs::create_dir_all(&repo).expect("repo dir");
    let command =
        ServeCommand::http_backend(&repo, root.path(), hooks.path()).expect("build serve command");

    let argv = command.argv();
    let backend = argv
        .iter()
        .position(|arg| arg == "http-backend")
        .expect("serve invokes http-backend");
    let mut args = argv[1..backend]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    args.extend(["config", "--get", "core.hooksPath"]);
    assert_eq!(
        git(&repo, &args),
        hooks.path().display().to_string(),
        "Git resolves the backend configuration to the vetted hooks directory"
    );
}

#[test]
fn smart_http_door_hooks_dir_carries_only_the_vetted_hook() {
    let (_root, hooks) = hooks_dir();
    let entries = std::fs::read_dir(hooks.path())
        .expect("read hooks dir")
        .map(|entry| entry.expect("dir entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "one hook, nothing else");
    assert_eq!(entries[0], DOOR_PRE_RECEIVE_HOOK_NAME);
}

#[test]
fn smart_http_vetted_hook_disables_replacement_lookup_on_every_git() {
    assert!(
        DOOR_PRE_RECEIVE_HOOK.contains("export GIT_NO_REPLACE_OBJECTS"),
        "the hook exports the pin to every git it spawns"
    );
    for invocation in DOOR_PRE_RECEIVE_HOOK
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("git ") || line.contains("$(git "))
    {
        assert!(
            invocation.contains("--no-replace-objects"),
            "this hook git could read substituted bytes: {invocation}"
        );
    }
}

fn proposed(name: &str) -> RefUpdate {
    RefUpdate {
        name: name.to_owned(),
        old_oid: None,
        new_oid: Some(GitOid::parse_hex("a".repeat(40)).expect("oid")),
    }
}

#[test]
fn smart_http_unlandable_ref_names_are_refused_before_anything_moves() {
    assert!(
        unlandable_ref_reasons(&[
            proposed("refs/heads/main"),
            proposed("refs/tags/v1.0"),
            proposed("refs/heads/feature-foo"),
        ])
        .is_empty(),
        "a legal batch is untouched by this rule"
    );

    // Legal to git, unpublishable by GitWire: the landing would parse this
    // name only AFTER the backend had moved it.
    let illegal = unlandable_ref_reasons(&[proposed("refs/heads/feature+foo")]);
    assert_eq!(illegal.len(), 1, "one reason for the one offending name");
    assert!(
        illegal[0].starts_with("refs/heads/feature+foo:"),
        "the refusal names the ref: {}",
        illegal[0]
    );

    let replace = unlandable_ref_reasons(&[proposed(&format!(
        "{ORIGIN_REFUSED_REF_PREFIX}{}",
        "b".repeat(40)
    ))]);
    assert_eq!(replace.len(), 1, "a replacement ref is never served");

    let twice = unlandable_ref_reasons(&[proposed("refs/heads/main"), proposed("refs/heads/main")]);
    assert_eq!(twice.len(), 1, "a name proposed twice cannot be published");

    let batch = (0..=ORIGIN_MAX_REF_UPDATES)
        .map(|index| proposed(&format!("refs/heads/b{index}")))
        .collect::<Vec<_>>();
    assert_eq!(
        unlandable_ref_reasons(&batch).len(),
        1,
        "a batch past the publication bound is refused whole"
    );
    assert!(
        unlandable_ref_reasons(&batch[..ORIGIN_MAX_REF_UPDATES]).is_empty(),
        "exactly the bound is still a batch the landing can journal"
    );
}

/// Frames one record the way the vetted hook does.
fn blob_record(oid: &str, path: &str, content: &[u8]) -> Vec<u8> {
    let mut record = format!("blob {oid} {} {path}\n", content.len()).into_bytes();
    record.extend_from_slice(content);
    record
}

#[test]
fn smart_http_framed_blobs_reach_the_door_whatever_their_bytes_look_like() {
    // Two entries a text patch could never carry past the door: added lines
    // that begin with `++` and `+++ b/...` (a patch grammar would read the
    // second as a file header and drop the first), and a blob whose bytes
    // are binary (a patch carries `Binary files ... differ` and no content
    // at all).
    let text = b"++ let token = \"value\";\n+++ b/decoy\n";
    let binary = [0x89_u8, 0x50, 0x00, 0x01, 0x02];
    let mut framed = blob_record(&"1".repeat(40), "app.rs", text);
    framed.extend_from_slice(&blob_record(&"2".repeat(40), "a dir/logo.png", &binary));

    let blobs = parse_pushed_blobs(&framed).expect("framed records parse");
    assert_eq!(blobs.len(), 2, "every enumerated entry reaches the door");
    assert_eq!(blobs[0].path, "app.rs");
    assert_eq!(
        blobs[0].oid,
        "1".repeat(40),
        "the post-image oid is what the push would make durable"
    );
    assert_eq!(
        blobs[0].added_lines,
        vec![
            b"++ let token = \"value\";".to_vec(),
            b"+++ b/decoy".to_vec()
        ],
        "no line is dropped and no line is reshaped"
    );
    assert_eq!(
        blobs[1].path, "a dir/logo.png",
        "the path field runs to the end of the header, spaces and all"
    );
    assert!(
        blobs[1].added_lines.iter().any(|line| line.contains(&0)),
        "binary bytes reach the door, which is what refuses them"
    );
}

#[test]
fn smart_http_unreadable_blob_stream_is_an_error_never_an_empty_scan() {
    let oid = "1".repeat(40);
    for unusable in [
        format!("blob {oid} 99 app.rs\nshort"),
        format!("blob {oid} 4 app.rs"),
        format!("blob {oid} four app.rs\n"),
        format!("blob {oid} 0 \n"),
        format!("patch {oid} 0 app.rs\n"),
    ] {
        assert!(
            parse_pushed_blobs(unusable.as_bytes()).is_err(),
            "a stream not readable whole is refused, never scanned: {unusable:?}"
        );
    }
    assert!(
        parse_pushed_blobs(b"")
            .expect("an empty stream parses")
            .is_empty(),
        "a push that added no blob enumerates nothing"
    );
}

#[test]
fn smart_http_receive_pack_coordinator_is_the_repositories_common_dir() {
    let (_vault_dir, vault) = temp_vault();
    let (_source_dir, source, oid) = seeded_repo();
    // A bare repository is the shape the origin serves: GIT_DIR is the
    // repository directory itself.
    let dir = tempfile::tempdir().expect("bare tempdir");
    let source_arg = source.to_string_lossy().into_owned();
    git(
        dir.path(),
        &["clone", "--bare", "--", &source_arg, "demo.git"],
    );
    let bare = dir
        .path()
        .join("demo.git")
        .canonicalize()
        .expect("canonical bare repo");

    let repo = local_repo_ref(&bare, &oid).expect("pinned repo ref");
    let wire = GitWire::new(&vault).expect("git wire");
    let handle = wire.open_repo(repo, &bare).expect("open bare repo");
    assert_eq!(
        repo_common_dir(&bare).expect("coordinator key"),
        handle.common_dir(),
        "the coordinator the serve window takes is the coordinator the landing takes"
    );
}

#[test]
fn smart_http_door_request_parses_creations_and_deletions() {
    let zero = "0".repeat(40);
    let oid = "a".repeat(40);
    let raw = format!(
        "quarantine /tmp/quarantine\nref {zero} {oid} refs/heads/main\nref {oid} {zero} refs/heads/old\nend\n"
    );
    let request = parse_door_request(raw.as_bytes()).expect("parse door request");
    assert_eq!(
        request.quarantine_path,
        Some(PathBuf::from("/tmp/quarantine"))
    );
    assert_eq!(request.ref_updates.len(), 2);
    assert!(
        request.ref_updates[0].old_oid.is_none(),
        "the null oid is absence, never a second oid type"
    );
    assert!(request.ref_updates[1].new_oid.is_none());
}

#[test]
fn smart_http_repo_names_are_closed() {
    assert!(validate_repo_name("demo").is_ok());
    assert!(validate_repo_name("demo.core-1_x").is_ok());
    assert!(validate_repo_name("").is_err());
    assert!(validate_repo_name(".door").is_err());
    assert!(validate_repo_name("a/b").is_err());
    assert!(validate_repo_name("../escape").is_err());
}

#[test]
fn smart_http_noop_door_hook_stamps_without_a_credential() {
    let repo = unpinned_repo_ref(Path::new("/tmp/demo.git"));
    let stamp = NoopDoorHook
        .admit_receive_pack(
            None,
            "principal:tester",
            &repo,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            7,
        )
        .expect("noop admission");
    assert_eq!(stamp.principal_ref(), "principal:tester");
    assert_eq!(stamp.method(), "bearer+registered-principal");
    assert!(
        stamp.credential_fingerprint().is_none(),
        "Phase A presents no slip, and the stamp says so"
    );
    assert!(
        matches!(
            NoopDoorHook.pre_receive_scan(&repo, &[]),
            Ok(DoorScanVerdict::Clean)
        ),
        "the no-op default adds no behavior"
    );
}

#[test]
fn smart_http_noop_evidence_never_claims_landed_policy_or_scanning() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let actor = EntityId::now();
    let stamp = NoopDoorHook
        .admit_receive_pack(
            None,
            &actor.to_hex(),
            &unpinned_repo_ref(&root),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            now_secs(),
        )
        .expect("noop stamp");
    vault
        .record_receive_pack_admission(&root, &stamp, DoorSeam::Noop)
        .expect("honest admission");
    let outcome = landing_outcome(&root, &oid);
    let door = DoorWindowReport {
        verdict: DoorWindowVerdict::Clean,
        ref_updates: outcome.ref_updates.clone(),
        lfs_pointers: Vec::new(),
        quarantine_path: None,
    };
    let attribution = vault
        .record_receive_pack_outcome(&stamp, &door, &outcome, 200)
        .expect("honest observation through explicit noop seam");
    let source = vault
        .get_claim(&attribution.provenance_claim_id)
        .expect("read")
        .expect("source");
    assert_eq!(
        receive_pack_field(&source, "scan").expect("scan"),
        &Value::from("not_performed")
    );
    let admission = vault
        .get_claim(&stamp.operation_id())
        .expect("read")
        .expect("admission");
    assert_eq!(
        receive_pack_field(&admission, "effector_check").expect("effector"),
        &Value::from("not_performed")
    );
    assert!(
        vault
            .apply_receive_pack_update_with_attribution(
                &outcome.pinned_repo_ref().expect("repo"),
                &outcome,
                &attribution,
            )
            .is_err(),
        "an unperformed scan cannot authorize publication"
    );
    let wire = GitWire::new(&vault).expect("wire");
    let handle = wire
        .open_repo(outcome.pinned_repo_ref().expect("repo"), &root)
        .expect("handle");
    assert!(
        vault
            .publish_origin_ref(
                &wire,
                OriginPublicationRequest {
                    repo_id: lfs_repo_id(&handle.identity().as_hex()).expect("repo id"),
                    repo: handle,
                    ref_name: GitRefName::parse_full(outcome.ref_updates[0].name.clone())
                        .expect("ref"),
                    expected_old_oid: outcome.ref_updates[0].old_oid.clone(),
                    new_oid: oid,
                    required_objects: Vec::new(),
                    required_lfs_oids: Vec::new(),
                    provenance_claim_id: attribution.provenance_claim_id,
                    actor_id: actor,
                    occurred: landing_time(),
                    learned_at: now_secs(),
                }
            )
            .is_err(),
        "the generic publication door must also refuse noop evidence"
    );
    assert!(
        vault
            .record_receive_pack_intent(&unpinned_repo_ref(&root), &stamp, &door)
            .is_err()
    );
    assert!(
        vault
            .receive_pack_intents(&root)
            .expect("no intent")
            .is_empty()
    );
    assert!(vault.origin_publication_ids(None).expect("rows").is_empty());
}

#[test]
fn smart_http_landed_door_hook_refuses_an_unauthorized_slip() {
    let (_dir, vault) = temp_vault();
    let door = CredentialDoorService::new(Arc::clone(&vault));
    let repo = unpinned_repo_ref(Path::new("/tmp/demo.git"));
    // A slip that was never narrowed authorizes nothing: the wiring block
    // delegates to the door's own evaluator rather than restating it.
    let credential = DoorCredential::verified("slip-1", "principal:tester", 1, 10_000);
    let refused = DoorHook::admit_receive_pack(
        &door,
        Some(&credential),
        "principal:tester",
        &repo,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        10,
    );
    assert!(
        matches!(refused, Err(Error::ReceivePackDoorRejected { .. })),
        "an unnarrowed slip is refused at the door, not at the transport"
    );
}

/// The catastrophe dial must reach the path that carries NO slip.
///
/// Every production push is that path: Phase A presents no capability slip
/// by design, so a receive-pack gate reachable only through a presented
/// credential is a gate no push ever passes through. An operator who empties
/// `secret.door.allowed_effectors` would then shut every lease and injection
/// downstream of the door while leaving the push door itself open.
#[test]
fn smart_http_narrowed_dial_shuts_the_push_door_with_no_slip_presented() {
    let (_dir, vault) = temp_vault();
    let repo_dir = Path::new("/tmp/demo.git");
    let request = ServeRequest {
        method: "POST".to_owned(),
        path_info: "/demo.git/git-receive-pack".to_owned(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: None,
        content_encoding: None,
        git_protocol: None,
        remote_user: Some("principal:tester".to_owned()),
        remote_addr: Some("127.0.0.1".to_owned()),
    };

    let admitted = stamp_admission(&vault, &request, repo_dir, DoorSeam::Landed)
        .expect("the default dial admits the push door")
        .expect("a receive-pack stamps an admission");
    assert!(
        admitted.credential_fingerprint().is_none(),
        "no slip was presented, and the stamp says so"
    );

    narrow_door_effectors(&vault, Vec::new());
    assert!(
        matches!(
            stamp_admission(&vault, &request, repo_dir, DoorSeam::Landed),
            Err(Error::ReceivePackDoorRejected { .. })
        ),
        "an emptied effector set closes the push path itself, not only what is downstream"
    );
    // Refused HERE is refused before anything exists to refuse it at:
    // `stamp_admission` runs ahead of the coordinator and ahead of the
    // backend, so no pushed byte is ever read.
    assert!(
        DoorHook::admit_receive_pack(
            &CredentialDoorService::new(Arc::clone(&vault)),
            None,
            "principal:tester",
            &unpinned_repo_ref(repo_dir),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            10,
        )
        .is_err(),
        "the seam itself carries the gate, not just this one caller"
    );
    assert!(
        stamp_admission(&vault, &request, repo_dir, DoorSeam::Noop).is_ok(),
        "the no-op seam refuses nothing, which is its whole contract"
    );
}
