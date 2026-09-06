use std::ffi::OsStr;
use std::fs;

use tempfile::TempDir;

use super::*;
use crate::VaultConfig;
use crate::checkout::lease::{CheckoutId, CheckoutLeaseState, CheckoutTaskClass};
use crate::entity_id::EntityId;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn open_test_vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn run_git(root: &Path, args: &[&str]) -> Vec<u8> {
    let owned = args.iter().copied().map(String::from).collect::<Vec<_>>();
    let output = run_bridged_git_argv(root, &owned).expect("git command");
    assert!(
        output.success,
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn trimmed(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .expect("git output must be UTF-8")
        .trim()
        .to_owned()
}

const TEST_IDENTITY: [&str; 4] = [
    "-c",
    "user.name=Oneiron",
    "-c",
    "user.email=oneiron@example.invalid",
];

struct TestRepo {
    dir: TempDir,
    repo_ref: RepoRef,
    head: GitOid,
    tree: GitOid,
    branch: GitRefName,
}

impl TestRepo {
    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn init_repo() -> TestRepo {
    let dir = tempfile::tempdir().expect("repo tempdir");
    init_repo_at(dir)
}

fn init_repo_at(dir: TempDir) -> TestRepo {
    run_git(dir.path(), &["init"]);
    fs::write(dir.path().join("README.md"), "base\n").expect("write readme");
    run_git(dir.path(), &["add", "--", "README.md"]);
    let mut commit = TEST_IDENTITY.to_vec();
    commit.extend_from_slice(&["commit", "-m", "initial"]);
    run_git(dir.path(), &commit);
    run_git(dir.path(), &["branch", "-M", "work"]);
    let head = trimmed(run_git(dir.path(), &["rev-parse", "--verify", "HEAD"]));
    let tree = trimmed(run_git(
        dir.path(),
        &["rev-parse", "--verify", "HEAD^{tree}"],
    ));
    let repo_ref = RepoRef::LocalFolder {
        path: dir.path().to_string_lossy().into_owned(),
        commit: head.clone(),
    };
    TestRepo {
        dir,
        repo_ref,
        head: GitOid::parse_hex(head).expect("head oid"),
        tree: GitOid::parse_hex(tree).expect("tree oid"),
        branch: GitRefName::parse_full("refs/heads/work").expect("branch ref"),
    }
}

fn open(wire: &GitWire<'_>, repo: &TestRepo) -> GitWireRepo {
    wire.open_repo(repo.repo_ref.clone(), repo.path())
        .expect("open repo")
}

fn new_wire(vault: &Vault) -> GitWire<'_> {
    GitWire::new(vault).expect("git wire")
}

fn commit_request(repo: &TestRepo, message: &str) -> GitCommitRequest {
    GitCommitRequest {
        tree: repo.tree.clone(),
        parents: vec![repo.head.clone()],
        author_name: "Oneiron".to_owned(),
        author_email: "oneiron@example.invalid".to_owned(),
        authored_at: 1_700_000_000,
        message: message.as_bytes().to_vec(),
        extra_headers: Vec::new(),
    }
}

/// A plan built through the public builders only. It is the load-bearing proof
/// that the two-phase API is usable from outside the module: no private field
/// is touched anywhere in this function.
fn commit_plan(repo: &TestRepo, message: &str) -> GitWirePlan {
    let mut plan = GitWirePlan::new();
    let commit = plan
        .write_commit(commit_request(repo, message))
        .expect("plan commit");
    plan.publish(
        repo.branch.clone(),
        GitRefExpectation::Value(repo.head.clone()),
        commit,
    )
    .expect("plan publish");
    plan
}

fn rival_commit(repo: &TestRepo) -> GitOid {
    let mut args = TEST_IDENTITY.to_vec();
    args.extend_from_slice(&[
        "commit-tree",
        repo.tree.as_str(),
        "-p",
        repo.head.as_str(),
        "-m",
        "rival",
    ]);
    GitOid::parse_hex(trimmed(run_git(repo.path(), &args))).expect("rival oid")
}

fn set_ref_externally(repo: &TestRepo, name: &GitRefName, oid: &GitOid) {
    run_git(repo.path(), &["update-ref", name.as_str(), oid.as_str()]);
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create destination");
    for entry in fs::read_dir(source).expect("read source") {
        let entry = entry.expect("dir entry");
        let target = destination.join(entry.file_name());
        let kind = entry.file_type().expect("file type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, body).expect("write script");
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("script mode");
}

// ---------------------------------------------------------------------------
// M8 — closed subprocess policy
// ---------------------------------------------------------------------------

#[test]
fn git_wire_pins_the_executable_and_the_closed_config_policy() {
    let process_env = GitWireProcessEnv::capture().expect("process env");
    assert!(process_env.git_binary().is_absolute());
    assert!(process_env.git_binary().exists());

    let env = child_env(&process_env);
    let keys = env.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
    for key in &keys {
        let inherited = GIT_WIRE_INHERITED_ENV_KEYS.contains(&key.as_str());
        let fixed = GIT_WIRE_FIXED_ENV.iter().any(|(name, _)| name == key);
        let policy = key.starts_with("GIT_CONFIG_KEY_")
            || key.starts_with("GIT_CONFIG_VALUE_")
            || key == "GIT_CONFIG_COUNT";
        assert!(
            inherited || fixed || policy,
            "unexpected child env key: {key}"
        );
    }
    for (key, value) in [
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ] {
        assert!(
            env.contains(&(key.to_owned(), OsString::from(value))),
            "missing pinned env pair {key}"
        );
    }
    // The executable-program keys the finding named must all be pinned.
    let policy_keys = GIT_WIRE_CONFIG_POLICY
        .iter()
        .map(|(key, _)| *key)
        .collect::<Vec<_>>();
    for key in [
        "core.hooksPath",
        "core.fsmonitor",
        "credential.helper",
        "gpg.program",
        "commit.gpgSign",
        "diff.external",
        "uploadpack.packObjectsHook",
        "protocol.allow",
    ] {
        assert!(policy_keys.contains(&key), "config policy is missing {key}");
    }
}

#[test]
fn git_wire_never_inherits_a_hostile_parent_environment() {
    let process_env = GitWireProcessEnv::capture().expect("process env");
    let hostile = |key: &str| match key {
        "GIT_CONFIG_NOSYSTEM" => Some(OsString::from("0")),
        "GIT_TERMINAL_PROMPT" => Some(OsString::from("1")),
        "GIT_NO_LAZY_FETCH" => Some(OsString::from("0")),
        "GIT_CONFIG_GLOBAL" => Some(OsString::from("/tmp/oneiron-evil.gitconfig")),
        "GIT_DIR" => Some(OsString::from("/tmp/oneiron-evil")),
        "GIT_SSH_COMMAND" => Some(OsString::from("/tmp/oneiron-evil-ssh")),
        "HOME" => Some(OsString::from("/tmp/oneiron-evil-home")),
        "LANG" => Some(OsString::from("C")),
        _ => None,
    };
    let env = child_env_from(&process_env, hostile);
    for key in ["GIT_DIR", "GIT_SSH_COMMAND", "HOME", "LC_ALL"] {
        assert!(
            !env.iter().any(|(name, _)| name == key),
            "ambient {key} reached the child"
        );
    }
    // The forced values win: the hostile ones are never even read.
    assert!(env.contains(&("GIT_CONFIG_NOSYSTEM".to_owned(), OsString::from("1"))));
    assert!(env.contains(&("GIT_NO_LAZY_FETCH".to_owned(), OsString::from("1"))));
    assert!(!env.contains(&(
        "GIT_CONFIG_GLOBAL".to_owned(),
        OsString::from("/tmp/oneiron-evil.gitconfig")
    )));
    assert!(env.contains(&("LANG".to_owned(), OsString::from("C"))));
}

#[cfg(unix)]
#[test]
fn git_wire_ignores_hostile_repository_configuration() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let marker_dir = tempfile::tempdir().expect("marker dir");
    let marker = marker_dir.path().join("executed");
    let script = marker_dir.path().join("evil");
    write_executable(
        &script,
        &format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()),
    );
    let script_arg = script.to_string_lossy().into_owned();
    for key in [
        "core.fsmonitor",
        "core.askPass",
        "core.editor",
        "core.pager",
        "core.sshCommand",
        "credential.helper",
        "diff.external",
        "gpg.program",
        "uploadpack.packObjectsHook",
    ] {
        run_git(repo.path(), &["config", key, script_arg.as_str()]);
    }
    let hooks_arg = marker_dir.path().to_string_lossy().into_owned();
    run_git(
        repo.path(),
        &["config", "core.hooksPath", hooks_arg.as_str()],
    );
    run_git(repo.path(), &["config", "commit.gpgSign", "true"]);

    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("read ref"),
        Some(repo.head.clone())
    );
    let prepared = wire
        .stage(&bound, &commit_plan(&repo, "hostile config\n"), 10)
        .expect("stage");
    let outcome = wire.commit_prepared(&bound, &prepared, 20).expect("commit");
    assert!(outcome.is_applied());
    // The repo-mutation bridge runs a porcelain commit under the same policy,
    // so a local `commit.gpgSign=true` plus a hostile `gpg.program` must not
    // reach a signer either.
    fs::write(repo.path().join("README.md"), "hostile\n").expect("write readme");
    run_git(repo.path(), &["add", "--", "README.md"]);
    let mut commit = TEST_IDENTITY.to_vec();
    commit.extend_from_slice(&["commit", "-m", "under hostile config"]);
    run_git(repo.path(), &commit);

    assert!(
        !marker.exists(),
        "repository-configured program was executed by the boundary"
    );
}

#[cfg(unix)]
#[test]
fn git_wire_bounds_child_runtime_and_output() {
    let dir = tempfile::tempdir().expect("fake git dir");
    let slow = dir.path().join("slow-git");
    write_executable(&slow, "#!/bin/sh\nsleep 30\n");
    let loud = dir.path().join("loud-git");
    write_executable(&loud, "#!/bin/sh\nhead -c 400000 /dev/zero\n");
    let args: Vec<OsString> = Vec::new();

    let slow_env = GitWireProcessEnv::capture()
        .expect("process env")
        .with_binary_for_test(slow)
        .with_limits(Duration::from_millis(200), 4096)
        .expect("limits");
    let timed_out = spawn_git(&slow_env, dir.path(), &args, None).expect("spawn slow git");
    assert!(timed_out.timed_out);
    assert!(!timed_out.success);
    assert_eq!(
        classify_failure(&timed_out).class(),
        GitWireFailureClass::Timeout
    );

    let loud_env = GitWireProcessEnv::capture()
        .expect("process env")
        .with_binary_for_test(loud)
        .with_limits(Duration::from_secs(30), 1024)
        .expect("limits");
    let oversize = spawn_git(&loud_env, dir.path(), &args, None).expect("spawn loud git");
    assert!(oversize.truncated);
    assert!(!oversize.success);
    assert!(oversize.stdout.len() <= 1024);
    assert_eq!(
        classify_failure(&oversize).class(),
        GitWireFailureClass::OutputOverflow
    );
}

#[cfg(unix)]
#[test]
fn git_wire_redacts_credentials_and_paths_out_of_failures() {
    let dir = tempfile::tempdir().expect("fake git dir");
    let leaky = dir.path().join("leaky-git");
    write_executable(
        &leaky,
        "#!/bin/sh\necho 'fatal: unable to access \
         https://oneiron:s3cr3t-token@example.invalid/repo.git/: \
         /home/someone/private/keys' >&2\nexit 128\n",
    );
    let env = GitWireProcessEnv::capture()
        .expect("process env")
        .with_binary_for_test(leaky);
    let args: Vec<OsString> = Vec::new();
    let output = spawn_git(&env, dir.path(), &args, None).expect("spawn leaky git");
    let failure = classify_failure(&output);
    let message = failure.message(GitWireOperation::PublishRefs);
    for secret in ["s3cr3t-token", "://", "/home/someone", "example.invalid"] {
        assert!(
            !message.contains(secret),
            "redacted failure leaked {secret}: {message}"
        );
    }
    assert!(message.contains("diag=blake3:"));
    assert!(message.contains("class="));
    assert!(failure.is_uncertain());
}

// ---------------------------------------------------------------------------
// M5 — effect classification and durable payloads
// ---------------------------------------------------------------------------

#[test]
fn git_wire_effect_classes_are_total_and_enforced_in_both_directions() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    // The classification is total and both phase guards obey it for every
    // operation, so a new operation cannot slip into the wrong phase. The argv
    // is empty on purpose: a correctly classified operation is refused before a
    // child could ever be spawned.
    for operation in GIT_WIRE_ALL_OPERATIONS {
        let argv = FrozenGitArgv::frozen(operation, Vec::new());
        let name = operation.as_str();
        let (phase, refused) = if operation.effect_class().is_read() {
            ("mutation", wire.run_mutation(&bound, &argv))
        } else {
            ("read", wire.run_read(&bound, &argv))
        };
        match refused {
            Err(Error::InvalidRepoMutationRecord(message)) => {
                assert!(
                    message.contains("refuses"),
                    "{name} was rejected by the {phase} phase for the wrong reason"
                );
            }
            other => panic!("{name} was not refused by the {phase} phase: {other:?}"),
        }
    }
    assert_eq!(
        GitWireOperation::WorktreeRemove.effect_class(),
        GitWireEffectClass::WorktreeWrite
    );
    assert_eq!(
        GitWireOperation::NotesAdd.effect_class(),
        GitWireEffectClass::ObjectAndRefWrite
    );

    // A destructive worktree removal is not a read. This is the exact trigger
    // the finding named: a "read" that removes a worktree.
    let drop_argv = FrozenGitArgv::worktree_remove(repo.path()).expect("worktree remove argv");
    assert!(wire.run_read(&bound, &drop_argv).is_err());
    assert!(repo.path().exists());

    // A read is not a mutation either, so a read can never be laundered into a
    // durable mutation record.
    let read_argv = FrozenGitArgv::read_refs(std::slice::from_ref(&repo.branch));
    assert!(wire.run_mutation(&bound, &read_argv).is_err());

    // The publication phase refuses both mixed and object-producing writers.
    let blob_argv = FrozenGitArgv::write_blob(b"nope");
    assert!(wire.run_publication(&bound, &blob_argv).is_err());
    let notes_argv = FrozenGitArgv::frozen(
        GitWireOperation::NotesAdd,
        os_args(&[
            "notes",
            "--ref",
            "refs/notes/x",
            "add",
            "-f",
            "-m",
            "n",
            "HEAD",
        ]),
    );
    assert!(wire.run_publication(&bound, &notes_argv).is_err());
}

#[test]
fn git_wire_durable_rows_carry_no_payload_secret_or_path() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    let secret = "oneiron-durable-row-secret-value";
    let mut plan = GitWirePlan::new();
    let blob = plan
        .write_blob(format!("token = {secret}\n").into_bytes())
        .expect("plan blob");
    let name = GitRefName::parse_full("refs/oneiron/test/secret").expect("ref");
    plan.publish(name, GitRefExpectation::Absent, blob)
        .expect("plan publish");
    let prepared = wire.stage(&bound, &plan, 10).expect("stage");
    assert!(
        wire.commit_prepared(&bound, &prepared, 20)
            .expect("commit")
            .is_applied()
    );
    // A direct ref effect writes a record of its own, so both row shapes are
    // covered by the scan below.
    assert!(
        wire.set_ref(&bound, &repo.branch, &rival_commit(&repo), 30)
            .expect("set ref")
            .is_applied()
    );

    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut rows = 0;
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, GIT_WIRE_RECORD_KEY_PREFIX)
        .expect("prefix iter")
    {
        let (_, bytes) = row.expect("row");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        rows += 1;
        for forbidden in [
            secret,
            repo.path().to_string_lossy().as_ref(),
            std::env::temp_dir().to_string_lossy().as_ref(),
            "fatal:",
        ] {
            assert!(
                !text.contains(forbidden),
                "durable git wire row leaked {forbidden}"
            );
        }
    }
    assert!(rows > 0, "expected durable git wire rows");
}

// ---------------------------------------------------------------------------
// M6 — absence, mismatch, and fatal failure are three different things
// ---------------------------------------------------------------------------

#[test]
fn git_wire_reads_absence_positively_and_keeps_fatal_failures_typed() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    let absent = GitRefName::parse_full("refs/heads/not-here").expect("ref");
    assert_eq!(wire.read_ref(&bound, &absent).expect("absent ref"), None);
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("present ref"),
        Some(repo.head.clone())
    );
    // A prefix of a real ref must not answer for the exact name.
    let prefix = GitRefName::parse_full("refs/heads").expect("prefix ref");
    assert_eq!(wire.read_ref(&bound, &prefix).expect("prefix ref"), None);

    let missing = GitOid::parse_hex("1234567890abcdef1234567890abcdef12345678").expect("oid");
    assert!(
        !wire
            .object_exists(&bound, &missing)
            .expect("missing object")
    );
    assert!(wire.object_exists(&bound, &repo.head).expect("present"));

    // A destroyed repository is a failure, never an absence.
    fs::remove_dir_all(repo.path().join(".git")).expect("destroy repository");
    assert!(wire.read_ref(&bound, &repo.branch).is_err());
    assert!(wire.object_exists(&bound, &repo.head).is_err());
}

#[cfg(unix)]
#[test]
fn git_wire_ref_lock_is_uncertainty_and_preserves_recovery_intent() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let rival = rival_commit(&repo);

    // Hold the ref lock the way a competing writer would.
    let lock_path = repo.path().join(".git").join("refs").join("heads");
    fs::create_dir_all(&lock_path).expect("ref dir");
    fs::write(lock_path.join("work.lock"), b"").expect("hold ref lock");

    let error = wire
        .update_ref_cas(&bound, &repo.branch, Some(&repo.head), &rival, 10)
        .expect_err("a held ref lock is a failure, not an absence or a success");
    let message = error.to_string();
    assert!(message.contains("class=ref_locked") || message.contains("class=unknown"));
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );

    // The intent survives: recovery finishes it once the lock is released.
    fs::remove_file(lock_path.join("work.lock")).expect("release ref lock");
    let receipts = wire.recover(&bound, 20).expect("recover");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, GitWireRecordState::Applied);
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(rival)
    );
}

// ---------------------------------------------------------------------------
// M1 — replay must prove the current ref postcondition
// ---------------------------------------------------------------------------

#[test]
fn git_wire_does_not_replay_an_aba_ref_cycle() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let name = GitRefName::parse_full("refs/oneiron/test/aba").expect("ref");
    let a = repo.head.clone();
    let b = rival_commit(&repo);

    let first = wire.set_ref(&bound, &name, &a, 10).expect("set A");
    assert!(matches!(first, GitWireCommitOutcome::Applied(_)));
    let second = wire.set_ref(&bound, &name, &b, 20).expect("set B");
    assert!(matches!(second, GitWireCommitOutcome::Applied(_)));

    // The trigger: repeating the first request must not answer from the first
    // receipt while the ref reads B.
    let third = wire.set_ref(&bound, &name, &a, 30).expect("set A again");
    assert!(
        !third.is_replayed(),
        "an ABA cycle replayed a stale receipt"
    );
    assert_eq!(wire.read_ref(&bound, &name).expect("ref"), Some(a.clone()));

    // Repeating a request whose postcondition still holds is a genuine replay:
    // the effect is not re-run and no git write happens.
    let fourth = wire
        .set_ref(&bound, &name, &a, 40)
        .expect("set A once more");
    assert!(!fourth.is_replayed(), "a new decision is not a replay");
    let fifth = wire.set_ref(&bound, &name, &a, 50).expect("set A again");
    assert!(fifth.is_replayed());
    assert_eq!(wire.read_ref(&bound, &name).expect("ref"), Some(a));
}

#[test]
fn git_wire_keep_ref_write_delete_write_lifecycle_is_exact() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let keep = object_keep_ref_name(&repo.tree).expect("keep ref name");

    assert!(
        wire.write_keep_ref(&bound, &repo.tree, 10)
            .expect("write")
            .is_applied()
    );
    assert_eq!(
        wire.read_ref(&bound, &keep).expect("keep ref"),
        Some(repo.tree.clone())
    );
    assert!(
        wire.delete_keep_ref(&bound, &repo.tree, 20)
            .expect("delete")
            .is_applied()
    );
    assert_eq!(wire.read_ref(&bound, &keep).expect("keep ref"), None);

    // The second write must actually re-create the ref rather than replay the
    // first write's receipt onto an absent ref.
    let rewritten = wire
        .write_keep_ref(&bound, &repo.tree, 30)
        .expect("write again");
    assert!(!rewritten.is_replayed());
    assert_eq!(
        wire.read_ref(&bound, &keep).expect("keep ref"),
        Some(repo.tree)
    );
}

// ---------------------------------------------------------------------------
// M2 — identity binds the verified object store
// ---------------------------------------------------------------------------

#[test]
fn git_wire_binds_records_to_the_object_store_that_was_mutated() {
    let (_vault_dir, vault) = open_test_vault();
    let origin = init_repo();
    let clone_dir = tempfile::tempdir().expect("clone dir");
    copy_tree(origin.path(), clone_dir.path());

    // One RepoRef, two object stores: exactly the cross-clone trigger.
    let shared = RepoRef::GitHubAtCommit {
        owner: "oneiron".to_owned(),
        repo: "fixture".to_owned(),
        commit: origin.head.as_str().to_owned(),
    };
    let wire = new_wire(&vault);
    let left = wire
        .open_repo(shared.clone(), origin.path())
        .expect("open origin");
    let right = wire
        .open_repo(shared, clone_dir.path())
        .expect("open clone");
    assert_ne!(left.identity(), right.identity());

    let plan = commit_plan(&origin, "cross clone\n");
    let prepared = wire.stage(&left, &plan, 10).expect("stage left");
    assert!(
        wire.commit_prepared(&left, &prepared, 20)
            .expect("commit left")
            .is_applied()
    );

    // The clone must not see the origin's record at all, and must do the work.
    assert!(
        wire.receipt(&right, prepared.record_key())
            .expect("clone receipt")
            .is_none()
    );
    let clone_prepared = wire.stage(&right, &plan, 30).expect("stage right");
    let clone_outcome = wire
        .commit_prepared(&right, &clone_prepared, 40)
        .expect("commit right");
    assert!(matches!(clone_outcome, GitWireCommitOutcome::Applied(_)));
    assert!(!clone_outcome.is_replayed());
    let advanced = wire
        .read_ref(&right, &origin.branch)
        .expect("clone ref")
        .expect("clone ref present");
    assert!(wire.object_exists(&right, &advanced).expect("clone object"));
}

#[cfg(unix)]
#[test]
fn git_wire_normalizes_path_aliases_to_one_identity() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let direct = open(&wire, &repo);

    let alias_dir = tempfile::tempdir().expect("alias dir");
    let alias = alias_dir.path().join("alias");
    std::os::unix::fs::symlink(repo.path(), &alias).expect("symlink alias");
    let through_symlink = wire
        .open_repo(repo.repo_ref.clone(), &alias)
        .expect("open through symlink");
    assert_eq!(direct.identity(), through_symlink.identity());

    // A linked worktree shares the object store, so it shares the identity.
    let worktree_parent = tempfile::tempdir().expect("worktree parent");
    let worktree = worktree_parent.path().join("linked");
    run_git(
        repo.path(),
        &[
            "worktree",
            "add",
            "--detach",
            "--",
            worktree.to_string_lossy().as_ref(),
            repo.head.as_str(),
        ],
    );
    let linked = wire
        .open_repo(repo.repo_ref, &worktree)
        .expect("open linked worktree");
    assert_eq!(direct.identity(), linked.identity());
}

#[test]
fn git_wire_refuses_a_repo_ref_that_does_not_match_the_store() {
    let (_vault_dir, vault) = open_test_vault();
    let left = init_repo();
    let right = init_repo();
    let wire = new_wire(&vault);

    // The repo_ref names one repository, the working root another.
    assert!(wire.open_repo(left.repo_ref.clone(), right.path()).is_err());

    // The repo_ref pins a commit this store does not have.
    let absent = RepoRef::LocalFolder {
        path: left.path().to_string_lossy().into_owned(),
        commit: "1234567890abcdef1234567890abcdef12345678".to_owned(),
    };
    assert!(wire.open_repo(absent, left.path()).is_err());
}

// ---------------------------------------------------------------------------
// M3 — one usable receipted two-phase protocol
// ---------------------------------------------------------------------------

#[test]
fn git_wire_public_plan_stages_objects_then_publishes_refs() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    let plan = commit_plan(&repo, "staged commit\n");
    let prepared = wire.stage(&bound, &plan, 10).expect("stage");

    // Phase one moved no advertised ref, but the object is durable and pinned.
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
    let record = wire
        .receipt(&bound, prepared.record_key())
        .expect("record")
        .expect("record present");
    assert_eq!(record.state, GitWireRecordState::Prepared);
    let published = record.publications[0].next().expect("target").clone();
    assert!(
        wire.object_exists(&bound, &published)
            .expect("staged object")
    );
    let keep = keep_refs_of(&wire, &bound, prepared.record_key());
    assert_eq!(
        keep.len(),
        1,
        "phase one must protect the staged object set"
    );

    let outcome = wire.commit_prepared(&bound, &prepared, 20).expect("commit");
    assert!(matches!(outcome, GitWireCommitOutcome::Applied(_)));
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(published)
    );
    assert!(
        keep_refs_of(&wire, &bound, prepared.record_key()).is_empty(),
        "publication must release the keep-refs it held"
    );

    let replay = wire.commit_prepared(&bound, &prepared, 30).expect("replay");
    assert!(replay.is_replayed());
}

fn keep_refs_of(wire: &GitWire<'_>, repo: &GitWireRepo, key: &[u8; 32]) -> Vec<ObservedGitRef> {
    let scope = hex_lower(key);
    let name = GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}stage/{scope}/0"))
        .expect("keep ref name");
    wire.read_refs(repo, &[name])
        .expect("keep refs")
        .into_iter()
        .filter(|entry| entry.oid.is_some())
        .collect()
}

#[test]
fn git_wire_restaging_claims_the_stage_key_instead_of_repeating_the_effect() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let plan = commit_plan(&repo, "claimed\n");

    let first = wire.stage(&bound, &plan, 10).expect("stage once");
    let second = wire.stage(&bound, &plan, 20).expect("stage twice");
    assert_eq!(first, second, "an identical plan must claim one stage key");
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
}

#[test]
fn git_wire_plan_refuses_ambiguous_and_engine_owned_publications() {
    let repo = init_repo();
    let mut plan = GitWirePlan::new();
    let blob = plan.write_blob(b"payload".to_vec()).expect("plan blob");

    // A publication must state what it was decided against.
    assert!(
        plan.publish(repo.branch.clone(), GitRefExpectation::Any, blob)
            .is_err()
    );
    // Engine keep-refs are protection, not publication.
    let keep = GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}object/x")).expect("keep");
    assert!(plan.publish(keep, GitRefExpectation::Absent, blob).is_err());
    // One ref may not be named twice in one transaction.
    plan.publish(repo.branch.clone(), GitRefExpectation::Absent, blob)
        .expect("first publication");
    assert!(
        plan.publish(repo.branch, GitRefExpectation::Absent, blob)
            .is_err()
    );
    // An empty plan publishes nothing and is refused.
    assert!(GitWirePlan::new().validate().is_err());
}

#[test]
fn git_wire_recovers_every_journaled_operation_class_after_a_crash() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    // Crash point 1: staged objects, prepared record, ref never advanced.
    let staged = wire
        .stage(&bound, &commit_plan(&repo, "recovered stage\n"), 10)
        .expect("stage");
    let target = wire
        .receipt(&bound, staged.record_key())
        .expect("record")
        .expect("record present")
        .publications[0]
        .next()
        .expect("target")
        .clone();
    let receipts = wire.recover(&bound, 20).expect("recover stage");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, GitWireRecordState::Applied);
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(target.clone())
    );
    assert!(wire.recover(&bound, 30).expect("second recover").is_empty());

    // Crash point 2: a worktree effect journaled but interrupted before the
    // record was cleared. Recovery reconciles registration and settles it.
    let worktree_parent = tempfile::tempdir().expect("worktree parent");
    let worktree = worktree_parent.path().join("journaled");
    run_git(
        repo.path(),
        &[
            "worktree",
            "add",
            "--detach",
            "--",
            worktree.to_string_lossy().as_ref(),
            target.as_str(),
        ],
    );
    let scope = worktree_scope(&worktree);
    let key = worktree_record_key(bound.identity(), GitWireOperation::WorktreeAdd, &scope);
    let mut record = new_record(&bound, key, GitWireOperation::WorktreeAdd, &[], &[], 40);
    record.worktree_scope = Some(scope);
    wire.put_record(&bound, &record).expect("journal worktree");
    let settled = wire.recover(&bound, 50).expect("recover worktree");
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0].state, GitWireRecordState::Applied);
    assert!(wire.recover(&bound, 60).expect("third recover").is_empty());
}

// ---------------------------------------------------------------------------
// M4 — unforgeable prepared state and atomic recovery
// ---------------------------------------------------------------------------

#[test]
fn git_wire_refuses_a_forged_or_stale_prepared_capability() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let prepared = wire
        .stage(&bound, &commit_plan(&repo, "capability\n"), 10)
        .expect("stage");

    // A capability with no durable record behind it.
    let forged = GitWirePrepared {
        record_key: [7; 32],
        repo_identity: bound.identity(),
        capability_hash: [7; 32],
    };
    assert!(wire.commit_prepared(&bound, &forged, 20).is_err());

    // A capability whose bound intent no longer matches the durable row.
    let stale = GitWirePrepared {
        capability_hash: [0; 32],
        ..prepared
    };
    assert!(wire.commit_prepared(&bound, &stale, 20).is_err());

    // A capability minted against another repository.
    let other = init_repo();
    let other_bound = open(&wire, &other);
    assert!(wire.commit_prepared(&other_bound, &prepared, 20).is_err());

    // None of the refusals moved anything, and the real capability still works.
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
    assert!(
        wire.commit_prepared(&bound, &prepared, 30)
            .expect("commit")
            .is_applied()
    );
}

#[test]
fn git_wire_terminal_records_cannot_be_overwritten() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    let key = [11_u8; 32];
    let record = new_record(&bound, key, GitWireOperation::PublishRefs, &[], &[], 10);
    let failed = {
        let mut failed = finish_state(record, GitWireRecordState::Failed, Vec::new(), 20);
        failed.failure = Some(GitWireFailureClass::RefMismatch.as_str().to_owned());
        failed
    };
    wire.put_record(&bound, &failed).expect("store failed row");

    let applied = finish_state(failed, GitWireRecordState::Applied, Vec::new(), 30);
    let settled = wire.transition(&bound, applied).expect("transition");
    assert_eq!(settled.state, GitWireRecordState::Failed.as_str());
    let receipt = wire
        .receipt(&bound, &key)
        .expect("receipt")
        .expect("receipt present");
    assert_eq!(receipt.state, GitWireRecordState::Failed);
}

#[test]
fn git_wire_verifies_the_whole_reachable_graph_not_just_the_tip() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let prepared = wire
        .stage(&bound, &commit_plan(&repo, "incomplete graph\n"), 10)
        .expect("stage");

    // The commit itself survives; a tree it needs does not. Tip presence alone
    // would certify an unusable ref.
    remove_loose_object(&repo, &repo.tree);
    assert!(
        !wire
            .reachable_objects_present(&bound, &repo.head, &[])
            .expect("reachability")
    );
    let outcome = wire.commit_prepared(&bound, &prepared, 20).expect("commit");
    assert!(matches!(
        outcome,
        GitWireCommitOutcome::Rejected {
            reason: GitWireRejection::ObjectsUnavailable,
            ..
        }
    ));
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
}

fn remove_loose_object(repo: &TestRepo, oid: &GitOid) {
    let hex = oid.as_str();
    let path = repo
        .path()
        .join(".git")
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..]);
    fs::remove_file(&path).expect("remove loose object");
}

#[test]
fn git_wire_never_certifies_a_partial_multi_ref_publication() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let rival = rival_commit(&repo);
    let second = GitRefName::parse_full("refs/oneiron/test/second").expect("ref");

    // The second publication's expectation is already false, so the whole
    // transaction must be terminally rejected and no ref may move.
    let publications = vec![
        GitRefPublication::update(
            repo.branch.clone(),
            GitRefExpectation::Value(repo.head.clone()),
            rival.clone(),
        ),
        GitRefPublication::update(
            second.clone(),
            GitRefExpectation::Value(repo.head.clone()),
            rival.clone(),
        ),
    ];
    let outcome = wire
        .publish_refs(&bound, publications, 10)
        .expect("publish two refs");
    assert!(matches!(
        outcome,
        GitWireCommitOutcome::Rejected {
            reason: GitWireRejection::RefMoved,
            ..
        }
    ));
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
    assert_eq!(wire.read_ref(&bound, &second).expect("ref"), None);

    // With both expectations true, both refs move in one transaction.
    let publications = vec![
        GitRefPublication::update(
            repo.branch.clone(),
            GitRefExpectation::Value(repo.head.clone()),
            rival.clone(),
        ),
        GitRefPublication::update(second.clone(), GitRefExpectation::Absent, rival.clone()),
    ];
    assert!(
        wire.publish_refs(&bound, publications, 20)
            .expect("publish two refs")
            .is_applied()
    );
    assert_eq!(
        wire.read_ref(&bound, &repo.branch).expect("ref"),
        Some(rival.clone())
    );
    assert_eq!(wire.read_ref(&bound, &second).expect("ref"), Some(rival));
}

#[test]
fn git_wire_does_not_skip_availability_when_a_ref_already_advanced() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let prepared = wire
        .stage(&bound, &commit_plan(&repo, "already advanced\n"), 10)
        .expect("stage");
    let target = wire
        .receipt(&bound, prepared.record_key())
        .expect("record")
        .expect("record present")
        .publications[0]
        .next()
        .expect("target")
        .clone();

    // The ref advanced out of band, and then the graph it needs was damaged.
    set_ref_externally(&repo, &repo.branch, &target);
    remove_loose_object(&repo, &repo.tree);
    let error = wire
        .commit_prepared(&bound, &prepared, 20)
        .expect_err("an advanced ref is not a licence to skip availability");
    assert!(matches!(error, Error::RepoMutationFailed(_)));
    assert!(
        wire.receipt(&bound, prepared.record_key())
            .expect("record")
            .expect("record present")
            .state
            == GitWireRecordState::Prepared,
        "an uncertain result must preserve the recovery intent"
    );
}

#[test]
fn git_wire_serializes_concurrent_recoverers() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let prepared = wire
        .stage(&bound, &commit_plan(&repo, "one recoverer wins\n"), 10)
        .expect("stage");

    let total = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..4 {
            handles.push(scope.spawn(|| {
                let wire = new_wire(&vault);
                let bound = wire
                    .open_repo(repo.repo_ref.clone(), repo.path())
                    .expect("open repo");
                wire.recover(&bound, 20).expect("recover").len()
            }));
        }
        let mut resolved = 0;
        for handle in handles {
            resolved += handle.join().expect("recoverer thread");
        }
        resolved
    });
    assert_eq!(total, 1, "exactly one recoverer may resolve a record");
    let receipt = wire
        .receipt(&bound, prepared.record_key())
        .expect("record")
        .expect("record present");
    assert_eq!(receipt.state, GitWireRecordState::Applied);
}

// ---------------------------------------------------------------------------
// M9 — journal before the effect, serialize every writer
// ---------------------------------------------------------------------------

#[test]
fn git_wire_recovers_a_ref_effect_that_crashed_after_git() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let rival = rival_commit(&repo);

    // The journal is written before git, so a crash after the ref moved but
    // before the record settled still leaves a prepared row to reconcile.
    let publications = vec![GitRefPublication::update(
        repo.branch.clone(),
        GitRefExpectation::Value(repo.head.clone()),
        rival.clone(),
    )];
    let key = ref_record_key(bound.identity(), &publications);
    let observed = wire
        .read_refs(&bound, std::slice::from_ref(&repo.branch))
        .expect("observe");
    let record = new_record(
        &bound,
        key,
        GitWireOperation::PublishRefs,
        &publications,
        &observed,
        10,
    );
    wire.put_record(&bound, &record).expect("journal intent");
    set_ref_externally(&repo, &repo.branch, &rival);

    let receipts = wire.recover(&bound, 20).expect("recover");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, GitWireRecordState::Applied);
    assert_eq!(receipts[0].observed_after[0].oid.as_ref(), Some(&rival));
}

#[cfg(unix)]
#[test]
fn git_wire_and_repo_mutation_share_one_repository_coordinator() {
    use std::os::fd::AsRawFd;

    let repo = init_repo();
    let common_dir = repo.path().join(".git").canonicalize().expect("common dir");
    let lock_path = common_dir.join(GIT_WIRE_REPO_LOCK_FILE_NAME);

    let guard = lock_repository(&common_dir).expect("hold the repository lock");
    assert!(lock_path.exists(), "the lock lives in the git common dir");

    // Re-entrant on this thread: a nested writer must not deadlock itself.
    let nested = lock_repository(&common_dir).expect("re-entrant acquisition");
    drop(nested);

    // A second open file description is exactly what a second process holds,
    // and it must be refused while the guard lives.
    let contender = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open contender");
    // SAFETY: `contender.as_raw_fd()` is a live descriptor owned by this scope,
    // and `LOCK_NB` makes the call return instead of blocking.
    let blocked = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(blocked, -1, "a second writer acquired the repository lock");

    drop(guard);
    // SAFETY: the same live descriptor; the lock is now free.
    let granted = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(granted, 0, "the lock was not released");
    // SAFETY: the same live descriptor, releasing what was just granted.
    unsafe {
        libc::flock(contender.as_raw_fd(), libc::LOCK_UN);
    }
}

// ---------------------------------------------------------------------------
// M7 — pinned checkout custody
// ---------------------------------------------------------------------------

fn test_lease(repo: &TestRepo, epoch: u64) -> CheckoutLeaseAct {
    CheckoutLeaseAct {
        checkout_id: CheckoutId::from_bytes(*EntityId::now().as_bytes()).expect("checkout id"),
        task_ref: EntityId::now(),
        repo_ref: repo.repo_ref.clone(),
        holder_ref: "oneiron-test".to_owned(),
        epoch,
        task_class: CheckoutTaskClass::Build,
        state: CheckoutLeaseState::Active,
        claimed_at: 1,
        lease_expires_at: None,
        updated_at: 1,
    }
}

#[test]
fn git_wire_checkout_materializes_the_pinned_commit_not_a_moving_head() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let lease = test_lease(&repo, 1);

    // HEAD moves after the lease pinned its commit. The checkout must still
    // carry the pinned commit.
    let rival = rival_commit(&repo);
    set_ref_externally(&repo, &repo.branch, &rival);

    wire.materialize(&lease).expect("materialize");
    let tree = wire.checkout_worktree_path(&lease).expect("worktree path");
    assert!(tree.exists());
    let observed = trimmed(run_git(&tree, &["rev-parse", "--verify", "HEAD"]));
    assert_eq!(observed, repo.head.as_str());
    assert_ne!(observed, rival.as_str());

    // The repository head itself was never touched.
    assert_eq!(
        wire.read_ref(&open(&wire, &repo), &repo.branch)
            .expect("ref"),
        Some(rival)
    );
    wire.materialize(&lease).expect("materialize is idempotent");
}

#[test]
fn git_wire_checkout_refuses_a_preexisting_handle_path() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let lease = test_lease(&repo, 1);
    let handle = wire.checkout_handle_dir(&lease).expect("handle dir");

    // An attacker who guesses the path and creates it must not be trusted.
    fs::create_dir_all(handle.join("tree")).expect("precreate handle");
    fs::write(handle.join("tree").join("planted"), b"planted\n").expect("plant content");
    let error = wire
        .materialize(&lease)
        .expect_err("a preexisting handle must be refused, not adopted");
    assert!(matches!(error, CheckoutError::RepoOps(_)));
    assert!(handle.join("tree").join("planted").exists());
}

#[test]
fn git_wire_checkout_handles_are_repository_and_epoch_bound() {
    let (_vault_dir, vault) = open_test_vault();
    let left = init_repo();
    let right = init_repo();
    let wire = new_wire(&vault);
    let lease = test_lease(&left, 1);
    let next_epoch = CheckoutLeaseAct {
        epoch: 2,
        ..lease.clone()
    };
    let elsewhere = CheckoutLeaseAct {
        repo_ref: right.repo_ref,
        ..lease.clone()
    };

    let base = wire.checkout_handle_dir(&lease).expect("handle");
    let later = wire.checkout_handle_dir(&next_epoch).expect("handle");
    let other = wire.checkout_handle_dir(&elsewhere).expect("handle");
    assert_ne!(base, later, "epochs must not share a handle");
    assert_ne!(
        base.parent(),
        other.parent(),
        "repositories must not share a checkout root"
    );
    // The root is private to GitWire, not a shared temp namespace.
    assert!(
        base.starts_with(std::env::temp_dir().join(GIT_WIRE_CHECKOUT_ROOT_NAME)),
        "checkout roots must live under the private GitWire root"
    );
}

#[test]
fn git_wire_collect_removes_only_a_proven_handle_and_reconciles_registration() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);
    let lease = test_lease(&repo, 1);

    wire.materialize(&lease).expect("materialize");
    let tree = wire.checkout_worktree_path(&lease).expect("worktree path");
    let handle = wire.checkout_handle_dir(&lease).expect("handle");
    assert!(wire.worktree_registered(&bound, &tree).expect("registered"));

    let receipt = PushedHeadReceipt {
        receipt_ref: "receipt:1".to_owned(),
        observed_ref: repo.branch.as_str().to_owned(),
        pushed_head: repo.head.as_str().to_owned(),
        checkout_id: lease.checkout_id,
        epoch: lease.epoch,
    };
    let inspection = wire
        .inspect_teardown(&lease, &receipt)
        .expect("inspect teardown");
    assert_eq!(inspection.receipt_match, TeardownReceiptMatch::Match);
    assert!(!inspection.dirty);
    // Inspection is side-effect free: it must not leave an index lock behind.
    assert!(!repo.path().join(".git").join("index.lock").exists());

    fs::write(tree.join("README.md"), "dirty\n").expect("dirty worktree");
    assert!(
        wire.inspect_teardown(&lease, &receipt)
            .expect("inspect")
            .dirty
    );

    wire.collect(&lease).expect("collect");
    assert!(!handle.exists());
    assert!(!wire.worktree_registered(&bound, &tree).expect("registered"));
    wire.collect(&lease).expect("collect is idempotent");

    let gone = wire
        .inspect_teardown(&lease, &receipt)
        .expect("inspect a collected checkout");
    assert_eq!(gone.receipt_match, TeardownReceiptMatch::Uncertain);
}

// ---------------------------------------------------------------------------
// Typed input validation and the single-constructor control
// ---------------------------------------------------------------------------

#[test]
fn git_wire_ref_and_oid_parsing_is_frozen() {
    assert!(GitRefName::parse_full("refs/heads/work").is_ok());
    assert!(GitRefName::parse_full("refs/oneiron/keep/object/x").is_ok());
    // HEAD is not a publishable ref: GitWire never compare-and-sets the head.
    assert!(GitRefName::parse_full("HEAD").is_err());
    assert!(GitRefName::parse_full("work").is_err());
    assert!(GitRefName::parse_full("refs/heads/../evil").is_err());
    assert!(GitRefName::parse_full("refs/heads/work.lock").is_err());
    assert!(GitRefName::parse_full("refs/heads/wo rk").is_err());
    assert!(GitRefName::parse_full("refs/heads/wo\"rk").is_err());
    assert!(GitRefName::parse_full("refs/heads/wo~rk").is_err());
    assert!(GitRefName::parse_full("refs/heads/.hidden").is_err());
    assert!(GitRefName::parse_full("refs/heads/").is_err());
    assert!(GitRefName::parse_full("refs").is_err());
    assert!(GitRefName::parse_full("--upload-pack=evil").is_err());

    assert!(GitOid::parse_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    assert!(GitOid::parse_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    assert!(GitOid::parse_hex("0".repeat(40)).is_err());
    assert!(GitOid::parse_hex("abc").is_err());
}

#[test]
fn git_wire_object_payloads_round_trip_exactly() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = new_wire(&vault);
    let bound = open(&wire, &repo);

    // A newline in a path name is legal under mktree's NUL framing.
    let mut plan = GitWirePlan::new();
    let blob = plan.write_blob(b"typed\n".to_vec()).expect("plan blob");
    let name = GitRefName::parse_full("refs/oneiron/test/blob").expect("ref");
    plan.publish(name.clone(), GitRefExpectation::Absent, blob)
        .expect("publish");
    let prepared = wire.stage(&bound, &plan, 10).expect("stage");
    assert!(
        wire.commit_prepared(&bound, &prepared, 20)
            .expect("commit")
            .is_applied()
    );
    let blob_oid = wire.read_ref(&bound, &name).expect("ref").expect("present");
    assert_eq!(
        wire.read_object(&bound, &blob_oid).expect("read"),
        b"typed\n"
    );

    let entries = vec![GitTreeEntry {
        mode: 0o100_644,
        name: b"line\none.txt".to_vec(),
        oid: blob_oid,
    }];
    let tree = wire
        .run_mutation(&bound, &FrozenGitArgv::write_tree(&entries).expect("argv"))
        .expect("write tree");
    let tree_oid = parse_oid_output(&tree.stdout).expect("tree oid");
    assert_eq!(
        wire.read_tree(&bound, &tree_oid).expect("read tree"),
        entries
    );

    // Extra commit headers ride the object body byte-exactly.
    let mut request = commit_request(&repo, "conflicted\n");
    request.extra_headers = vec![
        GitCommitHeader::parse("jj:trees", repo.tree.as_str()).expect("jj:trees"),
        GitCommitHeader::parse("jj:conflict-labels", "side-1 side-2").expect("labels"),
    ];
    let written = wire
        .run_mutation(
            &bound,
            &FrozenGitArgv::write_commit(&request).expect("argv"),
        )
        .expect("write commit");
    let commit_oid = parse_oid_output(&written.stdout).expect("commit oid");
    let raw = wire.read_object(&bound, &commit_oid).expect("read commit");
    let text = String::from_utf8(raw).expect("commit object must be UTF-8");
    assert!(text.contains(&format!("jj:trees {}\n", repo.tree.as_str())));
    assert!(text.contains("jj:conflict-labels side-1 side-2\n"));
    assert!(text.ends_with("\nconflicted\n"));

    assert!(GitCommitHeader::parse("tree", "x").is_err());
    assert!(GitCommitHeader::parse("committer", "x").is_err());
    assert!(GitCommitHeader::parse("Jj:Trees", "x").is_err());
    assert!(GitCommitHeader::parse("jj:trees", "a\nb").is_err());
    assert!(GitCommitHeader::parse("jj:trees", vec![0_u8]).is_err());
}

#[test]
fn git_wire_bridge_rejects_forbidden_and_unfrozen_argv() {
    let owned = |args: &[&str]| args.iter().copied().map(String::from).collect::<Vec<_>>();
    for args in [
        vec!["clean", "-fd"],
        vec!["reset", "--hard", "HEAD"],
        vec!["checkout", "--", "."],
        vec!["-c", "core.hooksPath=/tmp/hooks", "commit"],
        vec!["-c", "credential.helper=evil", "fetch"],
        vec!["-c", "user.name", "commit"],
        vec!["--exec-path=/tmp"],
        vec![],
    ] {
        assert!(
            bridged_argv(&owned(&args)).is_err(),
            "expected a rejected argv: {args:?}"
        );
    }
    let mut accepted = TEST_IDENTITY.to_vec();
    accepted.extend_from_slice(&["commit", "-m", "message"]);
    let argv = bridged_argv(&owned(&accepted)).expect("identity argv");
    assert_eq!(argv.len(), accepted.len());
}

#[cfg(unix)]
#[test]
fn git_wire_never_runs_repository_hooks() {
    let repo = init_repo();
    let hooks = repo.path().join(".git").join("hooks");
    fs::create_dir_all(&hooks).expect("hooks dir");
    write_executable(&hooks.join("pre-commit"), "#!/bin/sh\nexit 1\n");
    fs::write(repo.path().join("README.md"), "changed\n").expect("write readme");
    run_git(repo.path(), &["add", "--", "README.md"]);
    let mut commit = TEST_IDENTITY.to_vec();
    commit.extend_from_slice(&["commit", "-m", "the hook must not run"]);
    run_git(repo.path(), &commit);
}

#[test]
fn git_wire_is_the_only_production_git_subprocess_constructor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    // Literal-text guard only: dynamic constructors, including
    // ServeCommand::spawn, are not covered by this scan.
    let needle = format!("Command::new({}git{})", '"', '"');
    let allowed = ["codebase/tests.rs", "artifact_hosting/tests.rs"];
    let mut offenders = Vec::new();
    scan_for_needle(&root, &root, &needle, &allowed, &mut offenders);
    assert!(
        offenders.is_empty(),
        "literal git subprocess constructors must stay in git_wire.rs: {offenders:?}"
    );
}

fn contains_production_needle(text: &str, needle: &str) -> bool {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust scanner language");
    let tree = parser.parse(text, None).expect("Rust scanner parse");
    assert!(
        !tree.root_node().has_error(),
        "production scanner requires valid Rust syntax"
    );
    let mut test_ranges = Vec::new();
    collect_test_only_ranges(tree.root_node(), text, &mut test_ranges);
    text.match_indices(needle)
        .any(|(offset, _)| !test_ranges.iter().any(|range| range.contains(&offset)))
}

fn collect_test_only_ranges(
    node: tree_sitter::Node<'_>,
    text: &str,
    ranges: &mut Vec<std::ops::Range<usize>>,
) {
    let mut cursor = node.walk();
    let mut test_only = false;
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "attribute_item" => {
                // Only explicit cfg(test) excludes an item. Other cfg predicates
                // stay visible; each exclusion ends at the parsed item boundary.
                test_only |= text[child.byte_range()]
                    .split_whitespace()
                    .collect::<String>()
                    == "#[cfg(test)]";
            }
            "line_comment" | "block_comment" => {}
            _ => {
                if test_only {
                    ranges.push(child.byte_range());
                } else {
                    collect_test_only_ranges(child, text, ranges);
                }
                test_only = false;
            }
        }
    }
}

#[test]
fn production_git_constructor_scan_excludes_only_test_scopes() {
    let needle = format!("Command::new({}git{})", '"', '"');
    let test_scopes = r##"
        #[cfg(test)]
        #[allow(dead_code)]
        // An intervening comment must not detach the test attribute.
        mod fixtures {
            fn git() {
                let braces = r#"} mod fake {"#;
                /* } */
                StdGIT_CALL;
            }
            mod nested { fn git() { GIT_CALL; } }
        }
        mod production {
            #[cfg ( test )]
            fn test_helper() { GIT_CALL; }
        }
    "##
    .replace("GIT_CALL", &needle);
    assert!(!contains_production_needle(&test_scopes, &needle));

    // Production before, after, and inside a surrounding module stays visible.
    // A module name or a different cfg is not permission to hide a constructor.
    for source in [
        format!("fn before() {{ {needle}; }} {test_scopes}"),
        format!("{test_scopes} fn after() {{ Std{needle}; }}"),
        format!("mod outer {{ {test_scopes} fn after() {{ {needle}; }} }}"),
        format!("#[cfg(test)] fn helper() {{ {needle}; }} fn after() {{ {needle}; }}"),
        format!("#[cfg(not(test))] fn production() {{ {needle}; }}"),
        format!("#[cfg(any(test, feature = \"sync\"))] fn production() {{ {needle}; }}"),
        format!("mod tests {{ fn production() {{ {needle}; }} }}"),
    ] {
        assert!(
            contains_production_needle(&source, &needle),
            "production constructor was hidden: {source}"
        );
    }
}

fn scan_for_needle(
    dir: &Path,
    root: &Path,
    needle: &str,
    allowed: &[&str],
    offenders: &mut Vec<String>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_for_needle(&path, root, needle, allowed, offenders);
            continue;
        }
        if path.extension().and_then(OsStr::to_str) != Some("rs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if !text.contains(needle) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map(|suffix| suffix.to_string_lossy().into_owned())
            .unwrap_or_default();
        if allowed.contains(&relative.as_str()) {
            continue;
        }
        if contains_production_needle(&text, needle) {
            offenders.push(relative);
        }
    }
}
