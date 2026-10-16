//! Ticket 7: `git receive-pack` writes a push certificate into the object
//! store as a blob before any hook runs, so no door window ever reads it. The
//! origin offers no signed push and refuses a request that sends one before
//! the backend reads a byte, plain or gzipped (round 1, Sol F2 / Astra F1:
//! JGit gzips its pushes, so a gzipped one is read inflated, not refused).

use std::process::{Command, Stdio};

use super::tests::{CapturingSink, advertise, commit_file, git, served_repo, temp_vault};
use super::*;
use crate::error::CodeError;

fn pkt(payload: &str) -> Vec<u8> {
    format!("{:04x}{payload}", payload.len() + 4).into_bytes()
}

fn receive_pack(
    vault: &Arc<Vault>,
    body: Vec<u8>,
    content_encoding: Option<&str>,
) -> Result<ServeReport> {
    let request = ServeRequest {
        method: "POST".into(),
        path_info: "/demo.git/git-receive-pack".into(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".into()),
        content_length: Some(body.len() as u64),
        content_encoding: content_encoding.map(str::to_owned),
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
        &mut io::Cursor::new(body),
        &mut sink,
    )
}

fn has_object(repo: &Path, oid: &str) -> bool {
    Command::new("git")
        .current_dir(repo)
        .args(["cat-file", "-e", oid])
        .status()
        .expect("cat-file")
        .success()
}

#[cfg(unix)]
#[test]
fn a_push_certificate_never_reaches_the_object_store() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, second) = served_repo(&vault);
    let source = source.path();
    let zero = "0".repeat(40);
    git(&repo, &["branch", "doomed", second.as_str()]);
    let doomed = || git(&repo, &["for-each-ref", "refs/heads/doomed"]);

    // A delete-only push signed with a certificate: no pack, no quarantine,
    // and on main the certificate's bytes stay in the store as a blob.
    let certificate = format!(
        "certificate version 0.1\npusher placeholder 0 +0000\npushee demo\n\n{} {zero} refs/heads/doomed\n",
        second.as_str()
    );
    let certificate_path = repo.join("certificate.probe");
    fs::write(&certificate_path, &certificate).expect("write certificate probe");
    let certificate_oid = git(&repo, &["hash-object", "--", "certificate.probe"]);
    fs::remove_file(&certificate_path).expect("remove certificate probe");
    let mut body = pkt("push-cert\0report-status\n");
    for line in certificate.split_inclusive('\n') {
        body.extend(pkt(line));
    }
    body.extend(pkt("push-cert-end\n"));
    body.extend(b"0000");
    let refused = receive_pack(&vault, body.clone(), None);
    assert!(
        !has_object(&repo, &certificate_oid),
        "the certificate never reaches the object store"
    );
    assert!(
        matches!(
            refused,
            Err(Error::Code(CodeError::ReceivePackDoorRejected { .. }))
        ),
        "{refused:?}"
    );
    assert!(!doomed().is_empty(), "a refused push deletes nothing");

    // Gzipped, as JGit sends a push, the body is read inflated: the same
    // certificate is refused the same way.
    let encoded = receive_pack(&vault, gzip(&body), Some("gzip"));
    assert!(
        matches!(
            encoded,
            Err(Error::Code(CodeError::ReceivePackDoorRejected { .. }))
        ),
        "{encoded:?}"
    );
    assert!(!has_object(&repo, &certificate_oid));

    // The advertisement offers no signed push, even when the repository's
    // config would have git offer one.
    git(
        &repo,
        &["config", "receive.certNonceSeed", "placeholder-seed"],
    );
    let advertised = advertise(&vault, "git-receive-pack");
    assert!(
        !String::from_utf8_lossy(&advertised.body).contains("push-cert"),
        "{}",
        String::from_utf8_lossy(&advertised.body)
    );

    // Control: an ordinary push with a pack still lands, plain or gzipped,
    // its command section read ahead of the backend and handed on intact.
    let mut base = second;
    for (branch, encoding) in [("work", None), ("zipped", Some("gzip"))] {
        let tip = commit_file(source, &format!("{branch}.txt"), "a clean note\n");
        let create = format!(
            "{zero} {} refs/heads/{branch}\0report-status\n",
            tip.as_str()
        );
        let mut body = pkt(&create);
        body.extend(b"0000");
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
            .write_all(format!("{}\n^{}\n", tip.as_str(), base.as_str()).as_bytes())
            .expect("write revs");
        let pack = child.wait_with_output().expect("pack-objects");
        assert!(pack.status.success());
        body.extend(pack.stdout);
        if encoding.is_some() {
            body = gzip(&body);
        }
        let report = receive_pack(&vault, body, encoding).expect("a push with a pack is served");
        assert_eq!(report.door.verdict, DoorWindowVerdict::Clean, "{branch}");
        assert!(report.landing.is_some(), "{branch}");
        assert_eq!(
            git(&repo, &["rev-parse", &format!("refs/heads/{branch}")]),
            tip.as_str()
        );
        base = tip;
    }
}

/// A push names any number of refs (rule 5), so its command section is held
/// whatever its size: past the mebibyte held in memory it is held in an
/// unnamed file in the door root and read whole. 3,699 creations named at the
/// 200-byte ref limit, then a replacement ref, make a section past a mebibyte:
/// the door window refuses the push for that last name alone, which only a
/// backend handed the whole section can report. A push certificate past the
/// mebibyte is still refused before the backend reads a byte. Nothing the
/// sections were held in is left in the door root.
#[cfg(unix)]
#[test]
fn a_command_section_past_a_mebibyte_is_held_and_read_whole() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, repo, _, second) = served_repo(&vault);
    let door_root = origin_door_root(&vault).expect("door root");
    let door_entries = || {
        let mut names: Vec<_> = fs::read_dir(&door_root)
            .expect("door root")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort();
        names
    };
    let before = door_entries();
    let zero = "0".repeat(40);
    let mut names: Vec<String> = (0..3_699)
        .map(|n| format!("refs/heads/{n:04}-{}", "x".repeat(184)))
        .collect();
    names.push(format!("refs/replace/{}", "y".repeat(187)));
    assert!(names.iter().all(|name| name.len() == 200));
    let mut section = Vec::new();
    for (n, name) in names.iter().enumerate() {
        let capabilities = if n == 0 { "\0report-status" } else { "" };
        section.extend(pkt(&format!(
            "{zero} {} {name}{capabilities}\n",
            second.as_str()
        )));
    }
    assert!(section.len() > 1 << 20, "{} section bytes", section.len());
    let pack = Command::new("git")
        .current_dir(&repo)
        .args(["pack-objects", "--stdout"])
        .stdin(Stdio::null())
        .output()
        .expect("pack-objects");
    assert!(pack.status.success() && pack.stdout.starts_with(b"PACK"));

    let mut body = section.clone();
    body.extend(b"0000");
    body.extend(&pack.stdout);
    let report = receive_pack(&vault, body, None).expect("a section of any size is served");
    let DoorWindowVerdict::Rejected { reasons } = &report.door.verdict else {
        panic!(
            "the door refuses the replacement ref: {:?}",
            report.door.verdict
        );
    };
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].starts_with("refs/replace/")
            && reasons[0].ends_with("this origin never serves a replacement ref"),
        "{reasons:?}"
    );
    assert!(git(&repo, &["for-each-ref", "refs/heads/0000-*"]).is_empty());

    let mut signed = section;
    signed.extend(pkt("push-cert\0report-status\n"));
    signed.extend(pkt("certificate version 0.1\n"));
    signed.extend(pkt("push-cert-end\n"));
    signed.extend(b"0000");
    let refused = receive_pack(&vault, signed, None);
    assert!(
        matches!(
            &refused,
            Err(Error::Code(CodeError::ReceivePackDoorRejected { reason }))
                if reason == "the origin accepts no push certificate"
        ),
        "{refused:?}"
    );
    assert_eq!(door_entries(), before);
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body).expect("gzip");
    encoder.finish().expect("gzip")
}
