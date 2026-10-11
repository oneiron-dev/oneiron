//! Serve command and door tests: closed env/argv, vetted hook, unlandable names,
//! framed blobs, coordinator, door request parse, repo names, noop seam, dial.

use super::tests::{git, landing_outcome, landing_time, seeded_repo, temp_vault};
use super::*;
use crate::error::CodeError;

#[cfg(unix)]
#[test]
fn receive_pack_rejects_secret_under_hostile_inherited_git_config() {
    use super::tests::{CapturingSink, commit_file, served_repo};
    use std::os::unix::fs::PermissionsExt;
    const CHILD: &str = "ONEIRON_HOSTILE_GIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let hostile = tempfile::tempdir().unwrap();
        let hook = hostile.path().join("pre-receive");
        std::fs::write(
            &hook,
            b"#!/bin/sh\nprintf invoked > \"$0.invoked\"\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "origin::smart_http::door_serve_tests::receive_pack_rejects_secret_under_hostile_inherited_git_config",
                "--nocapture", "--test-threads=1"])
            .env(CHILD, "1").env("GIT_CONFIG_COUNT", "2")
            .env("GIT_CONFIG_KEY_0", "core.hooksPath")
            .env("GIT_CONFIG_VALUE_0", hostile.path())
            .env("GIT_CONFIG_KEY_1", "receive.fsckObjects")
            .env("GIT_CONFIG_VALUE_1", "false")
            .output().unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        assert!(!hostile.path().join("pre-receive.invoked").exists());
        return;
    }
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, head) = served_repo(&vault);
    let pusher = EntityId::now().to_hex();
    let push = |path: &str, contents: &str, name: &str| {
        let tip = commit_file(source.path(), path, contents);
        // Transfer objects only; the receive-pack below proposes their first new served ref.
        git(
            &repo,
            &["fetch", "--", source.path().to_str().unwrap(), tip.as_str()],
        );
        let pack = std::process::Command::new("git")
            .current_dir(&repo)
            .args(["pack-objects", "--stdout"])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(pack.status.success());
        let command = format!(
            "{} {} {name}\0report-status\n",
            "0".repeat(40),
            tip.as_str()
        );
        let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
        bytes.extend(pack.stdout);
        let request = ServeRequest {
            method: "POST".into(),
            path_info: "/demo.git/git-receive-pack".into(),
            query_string: String::new(),
            content_type: Some("application/x-git-receive-pack-request".into()),
            content_length: Some(bytes.len() as u64),
            content_encoding: None,
            git_protocol: None,
            remote_user: Some(pusher.clone()),
            remote_addr: Some("127.0.0.1".into()),
        };
        let mut sink = CapturingSink::default();
        let mut body = io::Cursor::new(bytes);
        let report = serve(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            &mut body,
            &mut sink,
        )
        .expect("real CGI exchange completes");
        (tip, report)
    };
    // Positive control: under the same hostile config a clean push scans and lands.
    let (clean, report) = push("notes.txt", "plain notes\n", "refs/heads/hostile-clean");
    assert_eq!(report.door.verdict, DoorWindowVerdict::Clean);
    assert!(report.landing.is_some());
    assert_eq!(
        git(&repo, &["rev-parse", "refs/heads/hostile-clean"]),
        clean.as_str()
    );
    let published = vault.origin_publication_ids(None).unwrap();
    let (_, report) = push(
        "secret.txt",
        "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
        "refs/heads/hostile-secret",
    );
    // Refused by detection: the one reason names the secret's path. Unreadable
    // input, a scan that cannot run and a lost intent write name no path.
    let DoorWindowVerdict::Rejected { reasons } = &report.door.verdict else {
        panic!("secret push admitted: {:?}", report.door.verdict);
    };
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(reasons[0].starts_with("secret.txt: "), "{reasons:?}");
    assert!(!reasons[0].contains("ghp_"));
    assert!(report.landing.is_none());
    assert!(git(&repo, &["for-each-ref", "refs/heads/hostile-secret"]).is_empty());
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), head.as_str());
    assert_eq!(vault.origin_publication_ids(None).unwrap(), published);
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
fn smart_http_noop_evidence_never_claims_landed_policy_or_scanning() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let actor = EntityId::now();
    let stamp = NoopDoorHook
        .admit_receive_pack(
            crate::EntityId::now(),
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
        crate::EntityId::now(),
        Some(&credential),
        "principal:tester",
        &repo,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        10,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Code(CodeError::ReceivePackDoorRejected { .. }))
        ),
        "an unnarrowed slip is refused at the door, not at the transport"
    );
}
