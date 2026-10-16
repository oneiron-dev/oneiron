//! The door scans every blob a push makes reachable, not only the tip diff
//! (H263): a secret one commit adds and a later commit reverts or deletes is
//! still durable history once the ref moves.

use std::process::{Command, Stdio};

use super::tests::{
    CapturingSink, commit_file, git, hooks_dir, seeded_repo, served_repo, temp_vault,
};
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

/// Rule 5 (the owner's rate law): the door holds memory per blob, never per
/// push, so an authenticated push is never refused for how much it carries in
/// all. Five files of a million one-character lines, ten MiB together, split
/// into more lines than the per-push budget H263 set (4Mi): that window was
/// refused whole; it now scans clean and lands.
#[cfg(unix)]
#[test]
fn a_push_of_many_short_lines_scans_whole_and_lands() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, second) = served_repo(&vault);
    let source = source.path();
    let column = "7\n".repeat(1 << 20);
    for part in 0..4 {
        commit_file(source, &format!("column-{part}.csv"), &column);
    }
    let tip = commit_file(source, "column-4.csv", &column);
    let report = receive_pack(&vault, source, None, &tip, "refs/heads/bulk", &[&second]);
    assert_eq!(report.door.verdict, DoorWindowVerdict::Clean);
    assert!(report.landing.is_some());
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/bulk"]), tip.as_str());
}

// The bounds below are new with the per-blob scan; they have no before.

/// The door holds one blob at a time, so its memory floor is per blob: a
/// record whose blob is past the bound is refused before its bytes are read,
/// and records up to the bound parse whole, in both streams, however many
/// there are. A record that cannot be read whole is the generic refusal.
#[test]
fn framed_records_past_the_blob_bound_are_refused_before_they_are_read() {
    let record = |oid: &str, content: &[u8], terminated: bool| {
        let mut record = format!("blob {oid} {} notes.txt\n", content.len()).into_bytes();
        record.extend_from_slice(content);
        if terminated {
            record.push(b'\n');
        }
        record
    };
    let read = |mut stream: &[u8], terminated: bool, blob_bytes: u64| {
        let mut lines = Vec::new();
        let bounds = ScanBounds::new(blob_bytes, 1).expect("bounds");
        for_each_framed_blob(&mut stream, terminated, bounds, &mut |blob| {
            lines.push(blob.lines().count());
        })
        .map(|()| lines)
    };
    let mut tip = record(&"1".repeat(40), &b"\n".repeat(3), false);
    tip.extend(record(&"3".repeat(40), b"", false));
    let history = record(&"2".repeat(40), b"first\nsecond\n", true);
    assert_eq!(read(&tip, false, 3).expect("tip at the bound"), [3, 0]);
    assert_eq!(read(&history, true, 13).expect("history at the bound"), [2]);
    assert!(matches!(
        read(&history, true, 12),
        Err(InputRefused::BlobTooLarge)
    ));
    // Declared past the bound, the record is refused before a byte of it is
    // held or reserved: a petabyte header with no content behind it.
    let declared = |bytes: u64| format!("blob {} {bytes} notes.txt\n", "4".repeat(40)).into_bytes();
    assert!(matches!(
        read(&declared(1 << 50), false, 1024),
        Err(InputRefused::BlobTooLarge)
    ));
    assert!(matches!(
        read(&declared(1 << 20), false, 1 << 20),
        Err(InputRefused::Unverified)
    ));
    let unterminated = record(&"2".repeat(40), b"first\n", false);
    assert!(matches!(
        read(&unterminated, true, 1024),
        Err(InputRefused::Unverified)
    ));
}

/// The door's own refusal names the bound and the key that moves it, and
/// nothing of the push; any other unreadable input stays the one generic
/// refusal. Round 1 (Astra, tests 3 and 6): a history stream that breaks after
/// a clean tip refuses the window, a blob the scanner cannot read refuses it,
/// and only tip blobs are read for LFS pointers.
#[test]
fn a_window_past_the_blob_bound_publishes_a_refusal_naming_its_key() {
    let (_vault_dir, vault) = temp_vault();
    let (_repo_dir, root, oid) = seeded_repo();
    let repo = unpinned_repo_ref(&root);
    let window = |blobs: &[u8], history: &[u8], blob_bytes: u64| {
        let (_hook_root, hooks) = hooks_dir();
        let update = format!("ref {} {} refs/heads/bulk\n", "0".repeat(40), oid.as_str());
        fs::write(hooks.request_path(), update).expect("request");
        fs::write(hooks.blobs_path(), blobs).expect("blob stream");
        fs::write(hooks.history_path(), history).expect("history stream");
        let report = serve_door_window(
            &vault,
            &repo,
            &hooks,
            &AtomicBool::new(false),
            Instant::now() + DOOR_WINDOW_TIMEOUT,
            DoorWindowContext {
                seam: DoorSeam::Landed,
                admission: None,
                scan: ScanBounds::new(blob_bytes, 1).expect("bounds"),
            },
        )
        .expect("window answered");
        let published = fs::read_to_string(hooks.verdict_path()).expect("verdict");
        (report, published)
    };
    let record = |oid: char, path: &str, content: &[u8], terminated: bool| {
        let mut record = format!(
            "blob {} {} {path}\n",
            oid.to_string().repeat(40),
            content.len()
        )
        .into_bytes();
        record.extend_from_slice(content);
        if terminated {
            record.push(b'\n');
        }
        record
    };
    let content = "clean line\n".repeat(400);
    let framed = format!(
        "blob {} {} bulk.txt\n{content}",
        "5".repeat(40),
        content.len()
    );
    let (report, published) = window(framed.as_bytes(), b"", 1024);
    assert_eq!(
        report.verdict,
        DoorWindowVerdict::Rejected {
            reasons: vec![DOOR_BLOB_TOO_LARGE.to_owned()]
        }
    );
    assert_eq!(
        published,
        "oneiron door refused this push: a blob is larger than limits.git_scan_blob_bytes"
    );
    let unverified = "oneiron door refused this push: receive-pack input could not be verified";
    let (report, published) = window(&framed.as_bytes()[..100], b"", 1 << 20);
    assert_eq!(published, unverified, "{:?}", report.verdict);
    let clean_tip = record('6', "notes.txt", b"a clean note\n", false);
    let broken_history = &record('7', "old.txt", b"an old note\n", true)[..30];
    let (report, published) = window(&clean_tip, broken_history, 1 << 20);
    assert_eq!(published, unverified, "{:?}", report.verdict);
    let unreadable = record('8', "logo.png", b"\x89PNG\0\x01", false);
    let clean_history = record('7', "old.txt", b"an old note\n", true);
    let (report, _) = window(&unreadable, &clean_history, 1 << 20);
    assert_eq!(
        report.verdict,
        DoorWindowVerdict::Rejected {
            reasons: vec!["receive-pack scan could not complete".to_owned()]
        }
    );
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 12\n",
        "a".repeat(64)
    );
    let (report, _) = window(
        &record('9', "asset.bin", pointer.as_bytes(), false),
        &record('b', "old.bin", pointer.as_bytes(), true),
        1 << 20,
    );
    assert_eq!(
        report
            .lfs_pointers
            .iter()
            .map(|pointer| pointer.path.as_str())
            .collect::<Vec<_>>(),
        ["asset.bin"]
    );
}

/// The hook keeps the same floors before it announces anything: a blob past
/// the per-blob bound, or framed bytes that would take the disk below its
/// floor, refuse the push with a reason naming the key, and frame no partial
/// history. Blobs that each fit land together, however much they add up to.
///
/// Round 1 (Astra F2, Sol F2): the free space is the number before the
/// capacity percentage, so a filesystem name with a space in it is read
/// right, and a `df` that fails refuses the push even when it printed a row.
/// A stand-in `df` sets the free space, so the floor is crossed by the second
/// history record rather than at the start.
#[cfg(unix)]
#[test]
fn hook_refuses_a_blob_past_its_bound_or_the_disk_floor_before_announcing_it() {
    use std::os::unix::fs::PermissionsExt;
    let (_source_dir, source, _) = seeded_repo();
    let bare_dir = tempfile::tempdir().expect("bare tempdir");
    let source_path = source.to_str().expect("utf-8 source path");
    git(
        bare_dir.path(),
        &["clone", "-q", "--bare", "--", source_path, "cap.git"],
    );
    let bare = bare_dir.path().join("cap.git");
    // Two blobs of 4,400 bytes of clean text one commit adds and the next
    // deletes: only the history walk carries them, so the hook's own bounds
    // are what decide.
    let bulk = "clean line\n".repeat(400);
    commit_file(&source, "bulk.txt", &bulk);
    commit_file(&source, "more.txt", &bulk.replace("clean", "plain"));
    commit_removal(&source, "bulk.txt");
    let tip = commit_removal(&source, "more.txt");
    git(&bare, &["fetch", "-q", "--", source_path, tip.as_str()]);
    let hooks_root = tempfile::tempdir().expect("hooks tempdir");
    let fake_bin = tempfile::tempdir().expect("stand-in df directory");
    let fake_df = fake_bin.path().join("df");
    fs::write(
        &fake_df,
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n%s\\n' \"$STAND_IN_DF_ROW\"\nexit \"$STAND_IN_DF_EXIT\"\n",
    )
    .expect("stand-in df");
    fs::set_permissions(&fake_df, fs::Permissions::from_mode(0o755)).expect("executable");
    let path = format!(
        "{}:{}",
        fake_bin.path().display(),
        std::env::var("PATH").expect("PATH")
    );
    // `df`: the stand-in's row and exit status, or the host's own `df`.
    // `updates`: the hook's stdin. It answers the hook's output and the
    // request and blob streams it announced, if any, and its history stream.
    let run_with =
        |blob_bytes: u64, disk_floor_bytes: u64, df: Option<(&str, &str)>, updates: &str| {
            let scan = ScanBounds::new(blob_bytes, disk_floor_bytes).expect("bounds");
            let hooks = DoorHooksDir::materialize_with(hooks_root.path(), scan)
                .expect("materialize door hooks");
            // A hook within its bounds announces its request, then waits for this.
            hooks.publish_verdict(DOOR_VERDICT_OK).expect("verdict");
            let mut hook = Command::new(hooks.path().join(DOOR_PRE_RECEIVE_HOOK_NAME));
            if let Some((row, exit)) = df {
                hook.env("PATH", &path)
                    .env("STAND_IN_DF_ROW", row)
                    .env("STAND_IN_DF_EXIT", exit);
            }
            let mut child = hook
                .current_dir(&bare)
                .env("GIT_DIR", &bare)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn hook");
            child
                .stdin
                .take()
                .expect("hook stdin")
                .write_all(updates.as_bytes())
                .expect("ref update");
            let output = child.wait_with_output().expect("hook exits");
            let request = fs::read(hooks.request_path()).ok();
            let blobs = fs::read(hooks.blobs_path()).ok();
            (output, request, blobs, fs::read(hooks.history_path()).ok())
        };
    let creation = |name: &str| format!("{} {} {name}\n", "0".repeat(40), tip.as_str());
    let run = |blob_bytes: u64, disk_floor_bytes: u64, df: Option<(&str, &str)>| {
        let update = creation("refs/heads/bulk");
        let (output, request, _, history) = run_with(blob_bytes, disk_floor_bytes, df, &update);
        (output, request.is_some(), history)
    };
    let refused_naming = |blob_bytes: u64, disk_floor_bytes: u64, df, key: &str| {
        let (refused, announced, history) = run(blob_bytes, disk_floor_bytes, df);
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{key}: {stderr}");
        assert!(
            stderr.contains("oneiron door refused this push: ") && stderr.contains(key),
            "{stderr}"
        );
        assert!(!stderr.contains("clean line"), "{stderr}");
        assert!(!announced, "a refused push announces no request");
        assert!(history.is_none(), "and frames no partial history");
    };

    refused_naming(4399, 1, None, "limits.git_scan_blob_bytes");
    refused_naming(
        4400,
        ScanBounds::MAX_BYTES,
        None,
        "limits.git_scan_disk_floor_bytes",
    );
    // 6 KiB free under a spaced name, whose used column is near a GiB: the
    // tip and the first history record fit, the second crosses the floor.
    refused_naming(
        4400,
        1,
        Some(("example volume 1000000 999994 6 100% /stand/in", "0")),
        "limits.git_scan_disk_floor_bytes",
    );
    // Every framed byte counts, the tip's and the headers' too. The tip's
    // `README.md` frames 5 + 128 + 9 bytes and each history record 4,400 +
    // 128 + 8: 9,214 in all. A 9,100-byte allowance (9 KiB free, a 116-byte
    // floor) refuses it, where the blob bytes alone or the history alone fit.
    refused_naming(
        4400,
        116,
        Some(("example 1000000 999991 9 100% /stand/in", "0")),
        "limits.git_scan_disk_floor_bytes",
    );
    // A df that fails refuses the push, whatever row it printed, and so does
    // a row whose name could be read as the columns (round 2, both F1), even
    // where df printed its own columns as unknown or negative (round 3, both
    // F1), and a row whose space available is unknown or negative.
    for (row, exit) in [
        ("example 1000000 1 999999 1% /stand/in", "1"),
        (
            "example 1000000 1 999999 1% 1638400 1605632 32768 98% /stand/in",
            "0",
        ),
        ("example 1000000 1 999999 1% 0 0 0 - /stand/in", "0"),
        (
            "example 1000000 1 999999 1% 1048576 1036288 -4096 101% /stand/in",
            "0",
        ),
        (
            "example 1048576 1036288 -4096 101% /stand/in 1000000 1 999999 1%",
            "0",
        ),
        ("example 0 0 0 - /stand/in", "0"),
        ("example 1048576 1036288 -4096 101% /stand/in", "0"),
    ] {
        let (refused, announced, history) = run(4400, 1, Some((row, exit)));
        assert!(!refused.status.success(), "{row}");
        assert!(!announced && history.is_none(), "{row}");
    }

    // Three hundred refs naming one move frame its blobs once (rule-5 review
    // r1, both F3): the tip's README record and the two history records,
    // 9,214 bytes, fit 16 KiB free, where a record per ref would not. The
    // request still names every ref.
    let updates: String = (0..300)
        .map(|n| creation(&format!("refs/heads/alias-{n:03}")))
        .collect();
    let (admitted, request, blobs, _) = run_with(
        4400,
        1,
        Some(("example volume 1000000 999984 16 100% /stand/in", "0")),
        &updates,
    );
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let request = String::from_utf8(request.expect("announced")).expect("request text");
    assert_eq!(
        request
            .lines()
            .filter(|line| line.starts_with("ref "))
            .count(),
        300
    );
    let blobs = blobs.expect("blob stream");
    let records = blobs
        .split(|byte| *byte == b'\n')
        .filter(|line| line.starts_with(b"blob "))
        .count();
    assert_eq!(records, 1, "one README record for three hundred refs");

    // Each blob at the bound, twice the bound together: the push is
    // announced with both deleted blobs framed whole, under the host's df and
    // under 12 KiB free.
    let (admitted, announced, _) = run(
        4400,
        1,
        Some(("example volume 1000000 999988 12 100% /stand/in", "0")),
    );
    assert!(
        admitted.status.success() && announced,
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let (admitted, announced, history) = run(4400, 1, None);
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    assert!(announced);
    let history = history.expect("history stream");
    assert!(history.starts_with(b"blob "));
    assert_eq!(
        history.windows(11).filter(|w| w == b"clean line\n").count(),
        400
    );
    assert_eq!(
        history.windows(11).filter(|w| w == b"plain line\n").count(),
        400
    );
}
