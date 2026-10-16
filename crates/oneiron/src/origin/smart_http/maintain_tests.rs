//! Done-means for served repository maintenance: a repository past git's own
//! threshold is maintained; one a push holds, or that no exchange permit is
//! free for, is left for the next run untouched; a push that comes while
//! maintenance runs lands, the maintenance giving the repository up to it and
//! leaving no lock of git's behind; and a command a repository's own
//! configuration names for gc never runs.

use std::cell::Cell;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::exchange_tests::pack_between;
use super::serve::repo_common_dir;
use super::tests::{CapturingSink, commit_file, git, served_repo, temp_vault};
use super::{
    DoorSeam, ExchangeBounds, ScanBounds, ServeRequest, ServedRepositoryMaintenance,
    maintain_served_repositories, serve_bounded,
};
use crate::git_wire::{
    GIT_WIRE_REPO_LOCK_FILE_NAME, GitOid, lock_repository, repository_hold_for_test,
};
use crate::{EntityId, Vault};

fn packs(repo: &Path) -> usize {
    std::fs::read_dir(repo.join("objects").join("pack"))
        .expect("pack directory")
        .filter(|entry| {
            entry
                .as_ref()
                .is_ok_and(|entry| entry.path().extension().is_some_and(|ext| ext == "pack"))
        })
        .count()
}

/// Two packs of reachable objects under a pack limit of one: `gc --auto`
/// has work.
fn past_its_threshold(source: &Path, repo: &Path) {
    git(repo, &["repack", "-d"]);
    commit_file(source, "THIRD.md", "third\n");
    let target = repo.to_str().expect("utf-8 repo path");
    git(source, &["push", "--", target, "main:main"]);
    git(repo, &["repack", "-d"]);
    git(repo, &["config", "gc.autoPackLimit", "1"]);
    assert_eq!(packs(repo), 2);
}

/// A host gate that always has a permit to give.
fn permit() -> impl FnMut() -> Option<Box<dyn Send>> {
    || Some(Box::new(()))
}

#[test]
fn maintenance_packs_a_served_repository_past_its_threshold() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, _) = served_repo(&vault);
    past_its_threshold(&source.path().canonicalize().expect("source"), &repo);

    let run = maintain_served_repositories(&vault, permit(), || false).expect("maintain");
    assert_eq!(
        run,
        ServedRepositoryMaintenance {
            repositories: 1,
            maintained: 1,
            deferred: 0,
            failed: 0,
            refused: 0,
        }
    );
    assert_eq!(packs(&repo), 1, "gc --auto consolidated the packs");
}

#[test]
fn maintenance_leaves_a_repository_a_push_holds_or_no_permit_is_free_for() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, _) = served_repo(&vault);
    past_its_threshold(&source.path().canonicalize().expect("source"), &repo);

    let run = maintain_served_repositories(&vault, || None, || false).expect("maintain");
    assert_eq!((run.deferred, run.maintained), (1, 0));

    // The coordinator is re-entrant on its holder's thread, so the push holds
    // it here and the maintenance runs on another.
    let _push = lock_repository(&repo_common_dir(&repo).expect("common dir")).expect("lock");
    let run = std::thread::scope(|scope| {
        scope
            .spawn(|| maintain_served_repositories(&vault, permit(), || false))
            .join()
            .expect("maintenance thread")
    })
    .expect("maintain");
    assert_eq!((run.deferred, run.maintained), (1, 0));
    assert_eq!(packs(&repo), 2, "nothing ran beside the push");
}

/// A push of `tip` onto `main`, which stands at `head`.
fn push_onto_main(source: &Path, head: &GitOid, tip: &GitOid) -> (ServeRequest, Vec<u8>) {
    let command = format!(
        "{} {} refs/heads/main\0report-status\n",
        head.as_str(),
        tip.as_str()
    );
    let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    bytes.extend(pack_between(source, head, tip));
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

/// Serves `push` on a thread of its own, as an admitted exchange does, and
/// says whether it landed.
fn serve_push(
    vault: &Arc<Vault>,
    push: (ServeRequest, Vec<u8>),
) -> JoinHandle<Result<bool, String>> {
    serve_push_within(vault, push, Duration::ZERO)
}

/// [`serve_push`] that waits for another writer at most `repository_wait`.
fn serve_push_within(
    vault: &Arc<Vault>,
    (request, bytes): (ServeRequest, Vec<u8>),
    repository_wait: Duration,
) -> JoinHandle<Result<bool, String>> {
    let vault = Arc::clone(vault);
    std::thread::spawn(move || {
        serve_bounded(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            ExchangeBounds {
                idle: Duration::from_secs(30),
                repository_wait,
                scan: ScanBounds::default(),
                spill_floor: None,
            },
            &mut io::Cursor::new(bytes),
            &mut CapturingSink::default(),
        )
        .map(|report| report.landing.is_some())
        .map_err(|error| format!("{error:?}"))
    })
}

/// Engine ruling (rule 5): maintenance never turns a push away. A push that
/// comes while maintenance holds its repository asks for it, the maintenance
/// ends its git and gives it up, and the push lands; the repository is left
/// for the next run.
#[test]
fn a_push_during_maintenance_lands_and_the_maintenance_gives_way() {
    let (_vault_dir, vault) = temp_vault();
    let (source_dir, repo, _, _) = served_repo(&vault);
    let source = source_dir.path().canonicalize().expect("source");
    past_its_threshold(&source, &repo);
    let head = GitOid::parse_hex(git(&repo, &["rev-parse", "refs/heads/main"])).expect("head");
    let tip = commit_file(&source, "FOURTH.md", "fourth\n");
    let push = Mutex::new(Some(push_onto_main(&source, &head, &tip)));
    let pushing = Mutex::new(None);
    let common_dir = repo_common_dir(&repo).expect("common dir");

    let run = maintain_served_repositories(&vault, permit(), || {
        // Once the maintenance holds the repository, the push comes, and the
        // maintenance's git runs on until the push has asked for it.
        let (held, _) = repository_hold_for_test(&common_dir);
        let push = held.then(|| push.lock().expect("push").take()).flatten();
        if let Some(push) = push {
            *pushing.lock().expect("pushing") = Some(serve_push(&vault, push));
            let asked_by = Instant::now() + Duration::from_secs(10);
            while !repository_hold_for_test(&common_dir).1 && Instant::now() < asked_by {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        false
    })
    .expect("maintain");
    let pushed = pushing
        .lock()
        .expect("pushing")
        .take()
        .expect("the push came while the maintenance held the repository")
        .join()
        .expect("push thread");

    assert_eq!(pushed, Ok(true), "the push lands");
    assert_eq!(git(&repo, &["rev-parse", "refs/heads/main"]), tip.as_str());
    assert_eq!(
        run,
        ServedRepositoryMaintenance {
            repositories: 1,
            maintained: 0,
            deferred: 1,
            failed: 0,
            refused: 0,
        },
        "the maintenance gave the repository up and left it for the next run"
    );
}

/// #1464 merged with #1456's maintenance hold (Engine bar, arm b): a push
/// that finds another writer holding its repository waits for it until its
/// `repository_wait`, and then is told the repository is busy. Its wait never
/// outlives that deadline, though the writer holds on well past it.
#[test]
fn a_push_behind_another_writer_waits_until_its_deadline_then_is_told_busy() {
    let (_vault_dir, vault) = temp_vault();
    let (source_dir, repo, _, _) = served_repo(&vault);
    let source = source_dir.path().canonicalize().expect("source");
    let head = GitOid::parse_hex(git(&repo, &["rev-parse", "refs/heads/main"])).expect("head");
    let tip = commit_file(&source, "FOURTH.md", "fourth\n");
    let common_dir = repo_common_dir(&repo).expect("common dir");
    let (held, holding) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let guard = lock_repository(&common_dir).expect("the other writer");
        held.send(()).expect("held");
        std::thread::sleep(Duration::from_secs(5));
        drop(guard);
    });
    holding
        .recv()
        .expect("the other writer holds the repository");

    let wait = Duration::from_millis(300);
    let started = Instant::now();
    let pushed = serve_push_within(&vault, push_onto_main(&source, &head, &tip), wait)
        .join()
        .expect("push thread");
    let waited = started.elapsed();
    writer.join().expect("the other writer");

    let refused = pushed.expect_err("a push past its repository wait does not land");
    assert!(
        refused.contains("GitHttpRepositoryBusy"),
        "the push is told the repository is busy: {refused}"
    );
    assert!(
        waited >= wait,
        "the push waited for the writer first: {waited:?}"
    );
    assert!(
        waited < Duration::from_secs(4),
        "the push's wait ended at its deadline, not when the writer let go: {waited:?}"
    );
    assert_ne!(git(&repo, &["rev-parse", "refs/heads/main"]), tip.as_str());
}

/// Runs git in `repo` with `input` on its standard input.
fn git_with_input(repo: &Path, args: &[&str], input: &str) {
    let mut child = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("git");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write");
    assert!(child.wait().expect("git").success(), "git {args:?}");
}

/// Every lock file of git's in `dir` and below: all but the coordinator's
/// own, which stays for the repository's life.
fn locks_in(dir: &Path) -> Vec<PathBuf> {
    let mut locks = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            locks.extend(locks_in(&path));
        } else if path.extension().is_some_and(|ext| ext == "lock")
            && path.file_name() != Some(std::ffi::OsStr::new(GIT_WIRE_REPO_LOCK_FILE_NAME))
        {
            locks.push(path);
        }
    }
    locks
}

/// Sol R3 F1: a gc ended while git holds a ref lock leaves the lock to no
/// one. It is terminated, git removes its own lock files, and the
/// repository is given up only once every git it started is gone, so the
/// writer it gave way to finds no stale lock.
#[test]
fn maintenance_that_gives_way_while_git_holds_a_lock_leaves_none_behind() {
    let (_vault_dir, vault) = temp_vault();
    let (source_dir, repo, _, _) = served_repo(&vault);
    past_its_threshold(&source_dir.path().canonicalize().expect("source"), &repo);
    // gc packs the loose refs under packed-refs.lock, and enough of them
    // that `pack-refs --auto` has work.
    git(&repo, &["config", "gc.packRefs", "true"]);
    let head = git(&repo, &["rev-parse", "refs/heads/main"]);
    let refs: String = (0..100)
        .map(|n| format!("create refs/heads/load/{n} {head}\n"))
        .collect();
    git_with_input(&repo, &["update-ref", "--stdin"], &refs);
    // packed-refs as a fifo no one writes to: once pack-refs holds the lock
    // it opens the file to read it, and waits there until it is ended. The
    // run gives way to a lock known to be held, on any host's speed.
    let packed = repo.join("packed-refs");
    if let Err(error) = std::fs::remove_file(&packed) {
        assert_eq!(
            error.kind(),
            io::ErrorKind::NotFound,
            "packed-refs: {error}"
        );
    }
    let fifo = std::process::Command::new("mkfifo")
        .arg(&packed)
        .status()
        .expect("mkfifo");
    assert!(fifo.success(), "mkfifo");
    let lock = repo.join("packed-refs.lock");
    let gave_way = Cell::new(false);
    // A git that never takes the lock fails the test in a minute, not at
    // the maintenance's own timeout.
    let deadline = Instant::now() + Duration::from_secs(60);

    let run = maintain_served_repositories(&vault, permit(), || {
        if lock.exists() {
            gave_way.set(true);
        }
        gave_way.get() || Instant::now() >= deadline
    })
    .expect("maintain");

    assert!(gave_way.get(), "the run was ended while git held the lock");
    assert_eq!((run.deferred, run.maintained), (1, 0));
    assert_eq!(locks_in(&repo), Vec::<PathBuf>::new(), "no lock is left");
}

/// Sol R3 F2: `gc.recentObjectsHook` is a list of shell commands gc runs
/// while it prunes, and no later setting clears it. A repository whose own
/// configuration names one is left unmaintained, and the command never runs.
#[test]
fn maintenance_runs_no_command_a_repository_configuration_names() {
    let (_vault_dir, vault) = temp_vault();
    let (source_dir, repo, _, _) = served_repo(&vault);
    past_its_threshold(&source_dir.path().canonicalize().expect("source"), &repo);
    // An object nothing reaches, which gc's prune asks the command about.
    git_with_input(&repo, &["hash-object", "-w", "--stdin"], "unreachable\n");
    let marker_dir = tempfile::tempdir().expect("marker dir");
    let marker = marker_dir.path().join("ran");
    let command = format!("touch {}", marker.to_str().expect("utf-8 marker"));
    git(&repo, &["config", "gc.recentObjectsHook", command.as_str()]);

    let run = maintain_served_repositories(&vault, permit(), || false).expect("maintain");

    assert!(!marker.exists(), "the configured command ran");
    assert_eq!(
        run,
        ServedRepositoryMaintenance {
            repositories: 1,
            maintained: 0,
            deferred: 0,
            failed: 0,
            refused: 1,
        }
    );
    assert_eq!(packs(&repo), 2, "the repository is left as it was");
}
