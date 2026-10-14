//! The door scans every blob a push makes reachable, not only the tip diff
//! (H263): a secret one commit adds and a later commit reverts or deletes is
//! still durable history once the ref moves.

use std::process::{Command, Stdio};

use super::tests::{CapturingSink, commit_file, git, seeded_repo, served_repo, temp_vault};
use super::*;

/// A credential-shaped line the door's detector flags, built at run time.
fn planted_secret() -> String {
    let body: String = ('a'..='z').chain('0'..='9').collect();
    format!("token=ghp_{body}\n")
}

/// Removes one file on the checked-out branch and returns the new commit.
fn commit_removal(root: &Path, path: &str) -> GitOid {
    git(root, &["rm", "-q", "--", path]);
    git(
        root,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-q",
            "-m",
            "drop a file",
        ],
    );
    GitOid::parse_hex(git(root, &["rev-parse", "--verify", "HEAD"])).expect("commit oid")
}

/// A real pack of everything `tip` reaches that `have` does not, as the
/// client would send it, plus each `extra` object no tip reaches.
fn pack(source: &Path, tip: &GitOid, have: &[&GitOid], extra: &[&GitOid]) -> Vec<u8> {
    let mut revs = format!("{}\n", tip.as_str());
    for oid in extra {
        revs.push_str(&format!("{}\n", oid.as_str()));
    }
    for oid in have {
        revs.push_str(&format!("^{}\n", oid.as_str()));
    }
    let mut child = Command::new("git")
        .current_dir(source)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn pack-objects");
    child
        .stdin
        .take()
        .expect("pack-objects stdin")
        .write_all(revs.as_bytes())
        .expect("write revs");
    let output = child.wait_with_output().expect("pack-objects");
    assert!(output.status.success(), "pack-objects failed");
    output.stdout
}

/// One receive-pack of `name` from `old` to `new` through the landed door.
fn receive_pack(
    vault: &Arc<Vault>,
    source: &Path,
    old: Option<&GitOid>,
    new: &GitOid,
    name: &str,
    have: &[&GitOid],
) -> ServeReport {
    receive_pack_carrying(vault, source, (old, new, name), have, &[])
}

/// [`receive_pack`] whose pack also carries `extra` objects no tip reaches.
fn receive_pack_carrying(
    vault: &Arc<Vault>,
    source: &Path,
    (old, new, name): (Option<&GitOid>, &GitOid, &str),
    have: &[&GitOid],
    extra: &[&GitOid],
) -> ServeReport {
    let old = old.map_or_else(|| "0".repeat(40), |oid| oid.as_str().to_owned());
    let command = format!("{old} {} {name}\0report-status\n", new.as_str());
    let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    bytes.extend(pack(source, new, have, extra));
    let request = ServeRequest {
        method: "POST".into(),
        path_info: "/demo.git/git-receive-pack".into(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".into()),
        content_length: Some(bytes.len() as u64),
        content_encoding: None,
        git_protocol: None,
        remote_user: Some(EntityId::now().to_hex()),
        remote_addr: Some("127.0.0.1".into()),
    };
    let mut sink = CapturingSink::default();
    serve(
        vault,
        "demo",
        &request,
        DoorSeam::Landed,
        &mut io::Cursor::new(bytes),
        &mut sink,
    )
    .expect("real CGI exchange completes")
}

/// Refused by detection, naming `path` and nothing of the value.
fn assert_refused_at(report: &ServeReport, path: &str) {
    let DoorWindowVerdict::Rejected { reasons } = &report.door.verdict else {
        panic!("secret history admitted: {:?}", report.door.verdict);
    };
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(reasons[0].starts_with(&format!("{path}: ")), "{reasons:?}");
    assert!(!reasons[0].contains("ghp_"));
    assert!(report.landing.is_none());
}

#[cfg(unix)]
#[test]
fn receive_pack_scans_every_new_blob_not_the_tip_diff() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, second) = served_repo(&vault);
    let source = source.path();
    let secret = planted_secret();
    let work = || git(&repo, &["rev-parse", "refs/heads/work"]);

    // Positive control: a clean two-commit push creates `work` and lands.
    commit_file(source, "notes.txt", "first clean note\n");
    let clean = commit_file(source, "notes.txt", "second clean note\n");
    let report = receive_pack(&vault, source, None, &clean, "refs/heads/work", &[&second]);
    assert_eq!(report.door.verdict, DoorWindowVerdict::Clean);
    assert!(report.landing.is_some());
    assert_eq!(work(), clean.as_str());

    // A secret added to a tracked file and reverted: the tip diff is empty.
    commit_file(source, "README.md", &format!("base\n{secret}"));
    let reverted = commit_file(source, "README.md", "base\n");
    let report = receive_pack(
        &vault,
        source,
        Some(&clean),
        &reverted,
        "refs/heads/work",
        &[&clean],
    );
    assert_refused_at(&report, "README.md");
    assert_eq!(work(), clean.as_str(), "a refused push moves no ref");

    // A secret file added and then deleted: the tip diff is empty again.
    git(source, &["reset", "-q", "--hard", clean.as_str()]);
    commit_file(source, "deploy.env", &secret);
    let deleted = commit_removal(source, "deploy.env");
    let report = receive_pack(
        &vault,
        source,
        Some(&clean),
        &deleted,
        "refs/heads/work",
        &[&clean],
    );
    assert_refused_at(&report, "deploy.env");
    assert_eq!(work(), clean.as_str());

    // A new ref onto history whose middle commit carries the secret: the
    // creation diffs only the tip tree, which is clean.
    git(source, &["reset", "-q", "--hard", second.as_str()]);
    commit_file(source, "config/app.toml", &secret);
    let topic = commit_file(source, "config/app.toml", "plain = true\n");
    let report = receive_pack(&vault, source, None, &topic, "refs/heads/topic", &[&second]);
    assert_refused_at(&report, "config/app.toml");
    assert!(git(&repo, &["for-each-ref", "refs/heads/topic"]).is_empty());

    // The refusals wedge nothing: a clean update of `work` still lands.
    git(source, &["reset", "-q", "--hard", clean.as_str()]);
    let next = commit_file(source, "notes.txt", "third clean note\n");
    let report = receive_pack(
        &vault,
        source,
        Some(&clean),
        &next,
        "refs/heads/work",
        &[&clean],
    );
    assert_eq!(report.door.verdict, DoorWindowVerdict::Clean);
    assert!(report.landing.is_some());
    assert_eq!(work(), next.as_str());
}

/// Writes `contents` into the source's object store as a blob no commit
/// names, and returns its oid.
fn loose_blob(source: &Path, contents: &str) -> GitOid {
    let file = source.join("loose.tmp");
    fs::write(&file, contents).expect("write loose blob");
    let oid = git(source, &["hash-object", "-w", "--", "loose.tmp"]);
    fs::remove_file(&file).expect("remove loose blob file");
    GitOid::parse_hex(oid).expect("blob oid")
}

/// H263 review r1 (Astra F1). receive-pack migrates the whole quarantine
/// once the hook admits, so a blob the pack carries that no tip reaches is
/// durable too and must be scanned; it has no path, so its oid labels it.
#[cfg(unix)]
#[test]
fn receive_pack_scans_a_quarantined_blob_no_tip_reaches() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, second) = served_repo(&vault);
    let source = source.path();
    let work = || git(&repo, &["rev-parse", "refs/heads/work"]);

    // A clean commit whose pack also carries a blob no commit names.
    let tip = commit_file(source, "notes.txt", "clean note\n");
    let stowaway = loose_blob(source, &planted_secret());
    let report = receive_pack_carrying(
        &vault,
        source,
        (None, &tip, "refs/heads/work"),
        &[&second],
        &[&stowaway],
    );
    assert_refused_at(&report, stowaway.as_str());
    assert!(git(&repo, &["for-each-ref", "refs/heads/work"]).is_empty());
    let kept = Command::new("git")
        .current_dir(&repo)
        .args(["cat-file", "-e", stowaway.as_str()])
        .status()
        .expect("cat-file");
    assert!(!kept.success(), "a refused push must not keep the stowaway");

    // Control: a clean stowaway lands with its commit.
    let clean = loose_blob(source, "an unreferenced clean note\n");
    let report = receive_pack_carrying(
        &vault,
        source,
        (None, &tip, "refs/heads/work"),
        &[&second],
        &[&clean],
    );
    assert_eq!(report.door.verdict, DoorWindowVerdict::Clean);
    assert!(report.landing.is_some());
    assert_eq!(work(), tip.as_str());
}

/// H263 review r1 (Astra F5). A name rev-list cannot pass on whole (blank,
/// or cut at a newline) labels its blob by oid rather than refusing a clean
/// push. Each file is added and then deleted, so only the history stream
/// carries it.
#[cfg(unix)]
#[test]
fn history_blobs_under_names_rev_list_cannot_pass_on_still_land() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, second) = served_repo(&vault);
    let source = source.path();
    let work = || git(&repo, &["rev-parse", "refs/heads/work"]);

    let tip = commit_file(source, "notes.txt", "clean note\n");
    let report = receive_pack(&vault, source, None, &tip, "refs/heads/work", &[&second]);
    assert_eq!(report.door.verdict, DoorWindowVerdict::Clean);
    let mut old = tip;
    for name in ["   ", "\nnote.txt"] {
        commit_file(source, name, "a clean note under an odd name\n");
        let new = commit_removal(source, name);
        let report = receive_pack(&vault, source, Some(&old), &new, "refs/heads/work", &[&old]);
        assert_eq!(report.door.verdict, DoorWindowVerdict::Clean, "{name:?}");
        assert!(report.landing.is_some(), "{name:?}");
        assert_eq!(work(), new.as_str());
        old = new;
    }
}

// The scan caps below are new with the history walk; they have no before.

/// H263 review r2 (Astra F4): the byte cap bounds no memory on its own, since
/// the door holds each line as its own allocation. Blobs under the byte cap
/// whose lines pass the budget across both streams are refused before any
/// line is split; at the budget they still parse whole.
#[test]
fn door_streams_past_the_line_budget_are_refused_before_splitting() {
    let record = |oid: &str, content: &[u8], terminated: bool| {
        let mut record = format!("blob {oid} {} notes.txt\n", content.len()).into_bytes();
        record.extend_from_slice(content);
        if terminated {
            record.push(b'\n');
        }
        record
    };
    let tip = record(&"1".repeat(40), &b"\n".repeat(3), false);
    let history = record(&"2".repeat(40), b"first\nsecond\n", true);
    assert!(parse_door_streams(&tip, &history, 4).is_err());
    let (blobs, tip_blobs) =
        parse_door_streams(&tip, &history, 5).expect("at the budget both streams parse");
    assert_eq!(tip_blobs, 1);
    let lines: Vec<usize> = blobs.iter().map(|blob| blob.added_lines.len()).collect();
    assert_eq!(lines, [3, 2]);
}

#[cfg(unix)]
#[test]
fn hook_refuses_a_push_past_the_scan_cap_before_announcing_it() {
    let (_source_dir, source, _) = seeded_repo();
    let bare_dir = tempfile::tempdir().expect("bare tempdir");
    let source_path = source.to_str().expect("utf-8 source path");
    git(
        bare_dir.path(),
        &["clone", "-q", "--bare", "--", source_path, "cap.git"],
    );
    let bare = bare_dir.path().join("cap.git");
    // Four KiB of clean text one commit adds and the next deletes: only the
    // history walk carries it, so the cap is what refuses.
    commit_file(&source, "bulk.txt", &"clean line\n".repeat(400));
    let tip = commit_removal(&source, "bulk.txt");
    git(&bare, &["fetch", "-q", "--", source_path, tip.as_str()]);
    let hooks_root = tempfile::tempdir().expect("hooks tempdir");
    let run = |cap: u64| {
        let hooks = DoorHooksDir::materialize_with_scan_cap(hooks_root.path(), cap)
            .expect("materialize door hooks");
        // A hook under the cap announces its request, then waits for this.
        hooks.publish_verdict(DOOR_VERDICT_OK).expect("verdict");
        let mut child = Command::new(hooks.path().join(DOOR_PRE_RECEIVE_HOOK_NAME))
            .current_dir(&bare)
            .env("GIT_DIR", &bare)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook");
        let update = format!("{} {} refs/heads/bulk\n", "0".repeat(40), tip.as_str());
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(update.as_bytes())
            .expect("ref update");
        let output = child.wait_with_output().expect("hook exits");
        let history = fs::read(hooks.history_path()).ok();
        (output, hooks.request_path().exists(), history)
    };

    let (refused, announced, history) = run(1024);
    assert!(
        !refused.status.success(),
        "past the cap the push is refused"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("more than 1024 blob bytes"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!announced, "a refused push announces no request");
    assert!(history.is_none(), "and frames no partial history");

    // Control: under a cap that fits, the same push is announced with the
    // deleted blob framed whole.
    let (admitted, announced, history) = run(1 << 20);
    assert!(admitted.status.success());
    assert!(announced);
    let history = history.expect("history stream");
    assert!(history.starts_with(b"blob "));
    assert_eq!(
        history.windows(11).filter(|w| w == b"clean line\n").count(),
        400
    );
}
