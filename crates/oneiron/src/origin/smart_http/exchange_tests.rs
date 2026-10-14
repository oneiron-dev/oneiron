//! One exchange's lifetime on the bounded serve path: a push whose client is
//! gone before its response begins ends its backend at once and frees the
//! repository, rather than leaving the door hook waiting on a verdict the
//! door window will never give.

use std::sync::mpsc;

use super::tests::{commit_file, git, served_repo, temp_vault};
use super::*;
use crate::git_wire::try_lock_repository;

/// A response sink whose client hung up before the response began.
struct GoneSink;

impl ServeSink for GoneSink {
    fn begin(&mut self, _: u16, _: &[(String, String)]) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn write_chunk(&mut self, _: &[u8]) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn a_push_whose_client_is_gone_ends_its_backend_and_frees_the_repository() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, _) = served_repo(&vault);
    let tip = commit_file(source.path(), "notes.txt", "plain notes\n");
    // The objects travel ahead, so the push itself is one command and an
    // empty pack: the hook still runs, and still waits on its verdict.
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
        "{} {} refs/heads/gone\0report-status\n",
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
        remote_user: Some(EntityId::now().to_hex()),
        remote_addr: Some("127.0.0.1".into()),
    };

    // Far inside the idle limit: the exchange has failed, so nothing is left
    // to wait for.
    let (ended, served) = mpsc::channel();
    let pushing = Arc::clone(&vault);
    std::thread::spawn(move || {
        let mut body = io::Cursor::new(bytes);
        let outcome = serve_bounded(
            &pushing,
            "demo",
            &request,
            DoorSeam::Landed,
            Duration::from_secs(120),
            &mut body,
            &mut GoneSink,
        );
        let _ = ended.send(outcome.map(|_| ()));
    });
    let outcome = served
        .recv_timeout(Duration::from_secs(30))
        .expect("a push whose client is gone ends at once, not when its hook gives up");
    assert!(outcome.is_err(), "a push nobody hears is no success");

    let coordinator = try_lock_repository(&repo_common_dir(&repo).unwrap()).unwrap();
    assert!(coordinator.is_some(), "the repository is free again");
    assert!(git(&repo, &["for-each-ref", "refs/heads/gone"]).is_empty());
}
