//! One exchange's lifetime: a push whose client is gone before its response
//! begins, or whose exchange unwinds, ends its backend at once and frees the
//! repository, rather than leaving the door hook waiting on a verdict the
//! door window will never give; and a push starts no maintenance that would
//! outlive it.

use std::sync::mpsc;

use super::tests::{CapturingSink, commit_file, git, served_repo, temp_vault};
use super::*;
use crate::error::CodeError;
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

/// A push of a fresh commit onto a new ref: the objects travel ahead, so the
/// body is one command and an empty pack, and the hook still runs and still
/// waits on its verdict.
fn hook_waiting_push(source: &Path, repo: &Path) -> (ServeRequest, Vec<u8>) {
    let tip = commit_file(source, "notes.txt", "plain notes\n");
    git(
        repo,
        &["fetch", "--", source.to_str().unwrap(), tip.as_str()],
    );
    let pack = std::process::Command::new("git")
        .current_dir(repo)
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
    (request, bytes)
}

/// Serves `request` on its own thread with `sink`, far inside the idle
/// limit, and says whether it ended within a deadline: `Some(true)` when it
/// failed or unwound, as an exchange with nothing left to wait for must.
fn ends_soon(
    vault: &Arc<Vault>,
    request: ServeRequest,
    bytes: Vec<u8>,
    mut sink: impl ServeSink + Send + 'static,
) -> bool {
    let (ended, served) = mpsc::channel();
    let pushing = Arc::clone(vault);
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            serve_bounded(
                &pushing,
                "demo",
                &request,
                DoorSeam::Landed,
                ExchangeBounds {
                    idle: Duration::from_secs(120),
                    repository_wait: Duration::ZERO,
                },
                &mut io::Cursor::new(bytes),
                &mut sink,
            )
        }));
        let _ = ended.send(!matches!(outcome, Ok(Ok(_))));
    });
    served
        .recv_timeout(Duration::from_secs(30))
        .expect("the exchange ends at once, not when its hook gives up")
}

#[test]
fn a_push_whose_client_is_gone_ends_its_backend_and_frees_the_repository() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, _) = served_repo(&vault);
    let (request, bytes) = hook_waiting_push(source.path(), &repo);

    assert!(
        ends_soon(&vault, request, bytes, GoneSink),
        "a push nobody hears is no success"
    );
    let coordinator = try_lock_repository(&repo_common_dir(&repo).unwrap()).unwrap();
    assert!(coordinator.is_some(), "the repository is free again");
    assert!(git(&repo, &["for-each-ref", "refs/heads/gone"]).is_empty());
}

/// A response sink that panics as the response begins: the exchange unwinds.
struct PanickingSink;

impl ServeSink for PanickingSink {
    fn begin(&mut self, _: u16, _: &[(String, String)]) -> io::Result<()> {
        panic!("the sink gave way");
    }

    fn write_chunk(&mut self, _: &[u8]) -> io::Result<()> {
        panic!("the sink gave way");
    }
}

#[test]
fn an_exchange_that_unwinds_ends_its_backend_and_frees_the_repository() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, _) = served_repo(&vault);
    let (request, bytes) = hook_waiting_push(source.path(), &repo);

    assert!(ends_soon(&vault, request, bytes, PanickingSink));
    let coordinator = try_lock_repository(&repo_common_dir(&repo).unwrap()).unwrap();
    assert!(coordinator.is_some(), "the repository is free again");
    assert!(git(&repo, &["for-each-ref", "refs/heads/gone"]).is_empty());
}

/// The objects `to` adds over `from`, as one pack.
fn pack_between(source: &Path, from: &GitOid, to: &GitOid) -> Vec<u8> {
    let mut packing = std::process::Command::new("git")
        .current_dir(source)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let revs = format!("{}\n^{}\n", to.as_str(), from.as_str());
    packing
        .stdin
        .take()
        .unwrap()
        .write_all(revs.as_bytes())
        .unwrap();
    let pack = packing.wait_with_output().unwrap();
    assert!(pack.status.success());
    pack.stdout
}

#[test]
fn a_push_starts_no_maintenance_to_outlive_its_exchange() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, head) = served_repo(&vault);
    // One pack already, and a repository whose own config runs maintenance,
    // in the foreground so this test sees it, once a push leaves a second.
    git(&repo, &["repack", "-d"]);
    for (key, value) in [
        ("receive.unpackLimit", "1"),
        ("gc.autoPackLimit", "1"),
        ("gc.autoDetach", "false"),
        ("maintenance.autoDetach", "false"),
    ] {
        git(&repo, &["config", key, value]);
    }
    let tip = commit_file(source.path(), "notes.txt", "plain notes\n");
    let command = format!(
        "{} {} refs/heads/main\0report-status\n",
        head.as_str(),
        tip.as_str()
    );
    let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    bytes.extend(pack_between(source.path(), &head, &tip));
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
    let report = serve(
        &vault,
        "demo",
        &request,
        DoorSeam::Landed,
        &mut io::Cursor::new(bytes),
        &mut CapturingSink::default(),
    )
    .expect("the push is served");
    assert!(report.landing.is_some(), "the push lands");
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), tip.as_str());

    let packs = fs::read_dir(repo.join("objects").join("pack"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "pack")
        })
        .count();
    assert_eq!(packs, 2, "no maintenance ran on the push's behalf");
}

/// A push body that sends `prefix`, then goes quiet for `stall` and fails as
/// a transport whose own wait ran out does.
struct StallingBody {
    prefix: io::Cursor<Vec<u8>>,
    stall: Duration,
}

impl Read for StallingBody {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(out)?;
        if read > 0 || out.is_empty() {
            return Ok(read);
        }
        std::thread::sleep(self.stall);
        Err(io::ErrorKind::TimedOut.into())
    }
}

#[test]
fn a_push_killed_mid_pack_leaves_no_quarantine_behind() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, head) = served_repo(&vault);
    let tip = commit_file(source.path(), "notes.txt", "plain notes\n");
    let command = format!(
        "{} {} refs/heads/main\0report-status\n",
        head.as_str(),
        tip.as_str()
    );
    let pack = pack_between(source.path(), &head, &tip);
    // The pack's header and a little of its first object: git has opened
    // its quarantine and waits inside it for the rest.
    let mut prefix = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    prefix.extend_from_slice(&pack[..pack.len().min(20)]);
    let request = ServeRequest {
        method: "POST".into(),
        path_info: "/demo.git/git-receive-pack".into(),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".into()),
        content_length: Some((prefix.len() + pack.len()) as u64),
        content_encoding: None,
        git_protocol: None,
        remote_user: Some(EntityId::now().to_hex()),
        remote_addr: Some("127.0.0.1".into()),
    };
    let mut body = StallingBody {
        prefix: io::Cursor::new(prefix),
        stall: Duration::from_secs(3),
    };

    let served = serve_bounded(
        &vault,
        "demo",
        &request,
        DoorSeam::Landed,
        ExchangeBounds {
            idle: Duration::from_secs(1),
            repository_wait: Duration::ZERO,
        },
        &mut body,
        &mut CapturingSink::default(),
    );
    assert!(
        matches!(served, Err(Error::Code(CodeError::GitHttpExchangeIdle))),
        "{served:?}"
    );
    let left: Vec<_> = fs::read_dir(repo.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with("tmp_objdir"))
        .collect();
    assert!(left.is_empty(), "a killed push left {left:?}");
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), head.as_str());
}

/// A push body that, as it is first read, makes a quarantine the way another
/// receive-pack on the same object store would, outside this process. Past
/// `bytes` it ends, or with a `stall` goes quiet and fails as a transport
/// whose own wait ran out does.
struct BodyBesideAnotherPush {
    bytes: io::Cursor<Vec<u8>>,
    other: Option<PathBuf>,
    stall: Option<Duration>,
}

impl Read for BodyBesideAnotherPush {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if let Some(other) = self.other.take() {
            fs::create_dir_all(&other)?;
            fs::write(other.join("incoming.pack"), b"another push's objects")?;
        }
        let read = self.bytes.read(out)?;
        match self.stall {
            Some(stall) if read == 0 && !out.is_empty() => {
                std::thread::sleep(stall);
                Err(io::ErrorKind::TimedOut.into())
            }
            _ => Ok(read),
        }
    }
}

/// Round 3 (Sol, Astra): only a backend this exchange killed has its
/// quarantine swept. One that exited by itself removed its own, so a
/// quarantine that appeared beside it belongs to someone else.
#[test]
fn a_push_that_ends_by_itself_leaves_another_quarantine_alone() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, head) = served_repo(&vault);
    let tip = commit_file(source.path(), "notes.txt", "plain notes\n");
    let command = format!(
        "{} {} refs/heads/main\0report-status\n",
        head.as_str(),
        tip.as_str()
    );
    let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    bytes.extend(pack_between(source.path(), &head, &tip));
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
    let other = repo.join("objects").join("tmp_objdir-incoming-another");
    let mut body = BodyBesideAnotherPush {
        bytes: io::Cursor::new(bytes),
        other: Some(other.clone()),
        stall: None,
    };

    let report = serve_bounded(
        &vault,
        "demo",
        &request,
        DoorSeam::Landed,
        ExchangeBounds {
            idle: Duration::from_secs(5),
            repository_wait: Duration::ZERO,
        },
        &mut body,
        &mut CapturingSink::default(),
    )
    .expect("the push is served");
    assert!(report.landing.is_some(), "the push lands");
    assert_eq!(
        fs::read(other.join("incoming.pack")).expect("the other quarantine is still there"),
        b"another push's objects"
    );
}

/// Round 4 (Sol, Astra): a backend that answered and exited before its body
/// came is not one this exchange killed, even when the exchange then fails
/// on that body and ends it.
#[test]
fn a_backend_that_exits_before_its_body_leaves_another_quarantine_alone() {
    let (_vault_dir, vault) = temp_vault();
    let (_source, repo, _, _) = served_repo(&vault);
    // The wrong media type: http-backend answers 415 and exits unread.
    let request = ServeRequest {
        method: "POST".into(),
        path_info: "/demo.git/git-receive-pack".into(),
        query_string: String::new(),
        content_type: Some("text/plain".into()),
        content_length: Some(64),
        content_encoding: None,
        git_protocol: None,
        remote_user: Some(EntityId::now().to_hex()),
        remote_addr: Some("127.0.0.1".into()),
    };
    let other = repo.join("objects").join("tmp_objdir-incoming-another");
    let mut body = BodyBesideAnotherPush {
        bytes: io::Cursor::new(Vec::new()),
        other: Some(other.clone()),
        stall: Some(Duration::from_secs(1)),
    };

    let served = serve_bounded(
        &vault,
        "demo",
        &request,
        DoorSeam::Landed,
        ExchangeBounds {
            idle: Duration::from_secs(5),
            repository_wait: Duration::ZERO,
        },
        &mut body,
        &mut CapturingSink::default(),
    );
    assert!(served.is_err(), "{served:?}");
    assert_eq!(
        fs::read(other.join("incoming.pack")).expect("the other quarantine is still there"),
        b"another push's objects"
    );
}
