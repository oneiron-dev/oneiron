//! Done-means for served repository maintenance: a repository past git's own
//! threshold is maintained; one a push holds, or that no exchange permit is
//! free for, is left for the next run untouched; and a push that comes while
//! maintenance runs lands, the maintenance giving the repository up to it.

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::exchange_tests::pack_between;
use super::serve::repo_common_dir;
use super::tests::{CapturingSink, commit_file, git, served_repo, temp_vault};
use super::{
    DoorSeam, ServeRequest, ServedRepositoryMaintenance, maintain_served_repositories,
    serve_bounded,
};
use crate::git_wire::{GitOid, lock_repository, repository_hold_for_test};
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

fn permit() -> Option<Box<dyn Send>> {
    Some(Box::new(()))
}

#[test]
fn maintenance_packs_a_served_repository_past_its_threshold() {
    let (_vault_dir, vault) = temp_vault();
    let (source, repo, _, _) = served_repo(&vault);
    past_its_threshold(&source.path().canonicalize().expect("source"), &repo);

    let run = maintain_served_repositories(&vault, permit, || false).expect("maintain");
    assert_eq!(
        run,
        ServedRepositoryMaintenance {
            repositories: 1,
            maintained: 1,
            deferred: 0,
            failed: 0,
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
            .spawn(|| maintain_served_repositories(&vault, permit, || false))
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
    (request, bytes): (ServeRequest, Vec<u8>),
) -> JoinHandle<Result<bool, String>> {
    let vault = Arc::clone(vault);
    std::thread::spawn(move || {
        serve_bounded(
            &vault,
            "demo",
            &request,
            DoorSeam::Landed,
            Duration::from_secs(30),
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

    let run = maintain_served_repositories(&vault, permit, || {
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
        },
        "the maintenance gave the repository up and left it for the next run"
    );
}
