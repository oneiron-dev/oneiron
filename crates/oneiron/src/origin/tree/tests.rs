use super::*;
use crate::{
    Vault, VaultConfig,
    codebase::RepoRef,
    git_wire::{GitTreeEntry, GitWirePlan},
};

#[test]
fn repeated_tree_paths_consume_a_cumulative_budget() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    assert!(
        std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(&root)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("git")
            .arg("-C")
            .arg(&root)
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "initial"
            ])
            .status()
            .unwrap()
            .success()
    );
    let head = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(head.status.success());
    let commit = String::from_utf8(head.stdout).unwrap().trim().to_owned();
    let vault = Vault::open(temp.path().join("vault"), VaultConfig::default()).unwrap();
    let git = GitWire::new(&vault).unwrap();
    let repo = git
        .open_repo(
            RepoRef::LocalFolder {
                path: root.to_str().unwrap().into(),
                commit,
            },
            &root,
        )
        .unwrap();
    let write_tree = |entries| {
        let mut plan = GitWirePlan::new();
        plan.write_tree(entries).unwrap();
        git.write_objects(&repo, &plan, 1).unwrap().pop().unwrap()
    };
    let leaf = write_tree(Vec::new());
    let branch = write_tree(vec![GitTreeEntry {
        mode: 0o040000,
        name: b"child".to_vec(),
        oid: leaf,
    }]);
    let tree = write_tree(
        ["a", "b", "c"]
            .into_iter()
            .map(|name| GitTreeEntry {
                mode: 0o040000,
                name: name.as_bytes().to_vec(),
                oid: branch.clone(),
            })
            .collect(),
    );
    // Seven projected directories, only three distinct objects; DFS frontier
    // never exceeds three. Repeated OIDs cannot bypass the cumulative limit.
    assert!(
        read_tree_files_bounded(&git, &repo, &tree, 7)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        read_tree_files_bounded(&git, &repo, &tree, 6),
        Err(Error::IndexOverflow(_))
    ));
}
