//! Done-means for served repository maintenance: a repository past git's own
//! threshold is maintained; one a push holds, or that no exchange permit is
//! free for, is left for the next run untouched.

use std::path::Path;

use super::serve::repo_common_dir;
use super::tests::{commit_file, git, served_repo, temp_vault};
use super::{ServedRepositoryMaintenance, maintain_served_repositories};
use crate::git_wire::lock_repository;

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
