use std::ffi::OsStr;
use std::fs;

use tempfile::TempDir;

use super::*;
use crate::VaultConfig;
use crate::checkout::lease::{CheckoutId, CheckoutLeaseState, CheckoutTaskClass};

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
    repo: GitWireRepo,
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
    let repo = GitWireRepo::new(repo_ref, dir.path().to_path_buf());
    TestRepo {
        dir,
        repo,
        head: GitOid::parse_hex(head).expect("head oid"),
        tree: GitOid::parse_hex(tree).expect("tree oid"),
        branch: GitRefName::parse_full("refs/heads/work").expect("branch ref"),
    }
}

fn commit_request(
    repo: &TestRepo,
    message: &str,
    extra_headers: Vec<GitCommitHeader>,
) -> GitCommitRequest {
    GitCommitRequest {
        tree: repo.tree.clone(),
        parents: vec![repo.head.clone()],
        author_name: "Oneiron".to_owned(),
        author_email: "oneiron@example.invalid".to_owned(),
        authored_at: 1_700_000_000,
        message: message.as_bytes().to_vec(),
        extra_headers,
    }
}

fn stage_commit(wire: &GitWire<'_>, repo: &TestRepo, message: &str) -> GitWireStagedObjects {
    let argv = FrozenGitArgv::write_commit(&commit_request(repo, message, Vec::new()))
        .expect("commit argv")
        .with_guarded_ref(repo.branch.clone());
    let observed = ObservedGitRef {
        name: repo.branch.clone(),
        oid: Some(repo.head.clone()),
    };
    let request = GitWireRequest::new(repo.repo.clone(), argv, 10).with_observed_ref(observed);
    wire.stage_objects(request).expect("stage objects")
}

#[test]
fn git_wire_child_env_is_cleared_and_pinned() {
    let process_env = GitWireProcessEnv::capture();
    let env = child_env(&process_env);
    let keys = env.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    for key in &keys {
        let inherited = GIT_WIRE_INHERITED_ENV_KEYS.contains(key);
        let fixed = GIT_WIRE_FIXED_ENV.iter().any(|(name, _)| name == key);
        assert!(inherited || fixed, "unexpected child env key: {key}");
    }
    // The two pinned pairs are never inherited: they are assigned after the
    // baseline, so an ambient `GIT_CONFIG_NOSYSTEM=0` can never reach a child.
    assert!(!GIT_WIRE_INHERITED_ENV_KEYS.contains(&"GIT_CONFIG_NOSYSTEM"));
    assert!(!GIT_WIRE_INHERITED_ENV_KEYS.contains(&"GIT_TERMINAL_PROMPT"));
    let pinned = env
        .iter()
        .filter(|(key, _)| key.starts_with("GIT_"))
        .map(|(key, value)| (*key, value.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        pinned,
        vec![
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            ("GIT_TERMINAL_PROMPT", OsString::from("0")),
        ]
    );
}

/// A hostile parent environment cannot reach a GitWire child.
///
/// The ambient lookup is injected rather than installed with `std::env::set_var`
/// on purpose: the test binary runs these cases in parallel with tests that read
/// the environment, and mutating the process environment under them is exactly
/// the data race `set_var` is `unsafe` for. `child_env_from` is the whole of the
/// child's environment, so deciding it here decides what the child receives.
#[test]
fn git_wire_pins_the_env_over_a_hostile_parent() {
    let process_env = GitWireProcessEnv::capture();
    let hostile = |key: &str| match key {
        // The values GitWire must never honour.
        "GIT_CONFIG_NOSYSTEM" => Some(OsString::from("0")),
        "GIT_TERMINAL_PROMPT" => Some(OsString::from("1")),
        // Keys that must never be inherited at all.
        "GIT_CONFIG_GLOBAL" => Some(OsString::from("/tmp/oneiron-evil.gitconfig")),
        "GIT_DIR" => Some(OsString::from("/tmp/oneiron-evil")),
        "GIT_SSH_COMMAND" => Some(OsString::from("/tmp/oneiron-evil-ssh")),
        "HOME" => Some(OsString::from("/tmp/oneiron-evil-home")),
        "LANG" => Some(OsString::from("C")),
        _ => None,
    };
    let env = child_env_from(&process_env, hostile);
    let keys = env.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    for key in [
        "GIT_CONFIG_GLOBAL",
        "GIT_DIR",
        "GIT_SSH_COMMAND",
        "HOME",
        "LC_ALL",
    ] {
        assert!(!keys.contains(&key), "ambient {key} reached the child");
    }
    // `Command::env` resolves by key with the last assignment winning, so the
    // forced pairs must be the final ones and must carry the fixed values.
    let tail = env[env.len() - GIT_WIRE_FIXED_ENV.len()..].to_vec();
    assert_eq!(
        tail,
        vec![
            ("GIT_CONFIG_NOSYSTEM", OsString::from("1")),
            ("GIT_TERMINAL_PROMPT", OsString::from("0")),
        ]
    );
    let forced = env
        .iter()
        .filter(|(key, _)| *key == "GIT_CONFIG_NOSYSTEM")
        .count();
    assert_eq!(forced, 1);
    // The locale keys are the ones the parent is allowed to contribute.
    assert!(env.contains(&("LANG", OsString::from("C"))));
}

#[test]
fn git_wire_frozen_argv_pins_hooks_and_credentials() {
    let name = GitRefName::parse_full("refs/heads/work").expect("ref");
    let oid = GitOid::parse_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("oid");
    let observed = ObservedGitRef {
        name: name.clone(),
        oid: None,
    };
    let argvs = vec![
        FrozenGitArgv::read_ref(name.clone()),
        FrozenGitArgv::rev_parse("HEAD").expect("rev-parse"),
        FrozenGitArgv::merge_base("HEAD", "HEAD").expect("merge-base"),
        FrozenGitArgv::update_ref(observed, oid.clone()),
        FrozenGitArgv::set_ref(name.clone(), &oid),
        FrozenGitArgv::delete_ref(name.clone(), Some(&oid)),
        FrozenGitArgv::object_exists(&oid),
        FrozenGitArgv::read_tree(&oid),
        FrozenGitArgv::write_blob(b"payload"),
        FrozenGitArgv::status_porcelain(),
        FrozenGitArgv::worktree_list(),
        FrozenGitArgv::receive_pack_stage(),
        FrozenGitArgv::worktree_add(PathBuf::from("/tmp/oneiron-frozen"), name.clone())
            .expect("worktree add"),
        FrozenGitArgv::worktree_drop(PathBuf::from("/tmp/oneiron-frozen")).expect("worktree drop"),
        FrozenGitArgv::notes_add(name, &oid, "{}").expect("notes add"),
    ];
    let policy = policy_argv();
    assert!(policy.contains(&OsString::from("core.hooksPath=/dev/null")));
    assert!(policy.contains(&OsString::from("credential.helper=")));
    for argv in &argvs {
        assert_eq!(&argv.args()[..policy.len()], policy.as_slice());
    }
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
    let policy = policy_argv();
    assert_eq!(&argv[..policy.len()], policy.as_slice());
    assert_eq!(argv.len(), policy.len() + accepted.len());
}

#[test]
fn git_wire_ref_and_oid_parsing_is_frozen() {
    assert!(GitRefName::parse_full("refs/heads/work").is_ok());
    assert!(GitRefName::parse_full("HEAD").is_ok());
    assert!(GitRefName::parse_full("work").is_err());
    assert!(GitRefName::parse_full("refs/heads/../evil").is_err());
    assert!(GitRefName::parse_full("refs/heads/work.lock").is_err());
    assert!(GitRefName::parse_full("refs/heads/wo rk").is_err());
    assert!(GitRefName::parse_full("--upload-pack=evil").is_err());
    assert!(GitOid::parse_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    assert!(GitOid::parse_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
    assert!(GitOid::parse_hex(GIT_WIRE_NULL_OID).is_err());
    assert!(GitOid::parse_hex("abc").is_err());
}

#[test]
fn git_wire_idempotency_key_binds_payload_and_observation() {
    let repo = GitWireRepo::new(
        RepoRef::LocalFolder {
            path: "/tmp/oneiron-key".to_owned(),
            commit: "a".repeat(40),
        },
        PathBuf::from("/tmp/oneiron-key"),
    );
    let one = FrozenGitArgv::write_blob(b"one");
    let two = FrozenGitArgv::write_blob(b"two");
    assert_eq!(one.argv_hash(), two.argv_hash());
    assert_ne!(one.stdin_hash(), two.stdin_hash());
    let key_one = git_wire_idempotency_key(&GitWireRequest::new(repo.clone(), one, 1));
    let key_two = git_wire_idempotency_key(&GitWireRequest::new(repo.clone(), two, 1));
    assert_ne!(key_one, key_two);

    let name = GitRefName::parse_full("refs/heads/work").expect("ref");
    let next = GitOid::parse_hex("b".repeat(40)).expect("next oid");
    let observed = ObservedGitRef {
        name: name.clone(),
        oid: Some(GitOid::parse_hex("c".repeat(40)).expect("observed oid")),
    };
    let argv = FrozenGitArgv::set_ref(name.clone(), &next);
    let unobserved = git_wire_idempotency_key(&GitWireRequest::new(repo.clone(), argv.clone(), 1));
    let request = GitWireRequest::new(repo, argv, 1).with_observed_ref(observed);
    assert_ne!(unobserved, git_wire_idempotency_key(&request));
}

#[cfg(unix)]
#[test]
fn git_wire_never_runs_repository_hooks() {
    let repo = init_repo();
    let hooks = repo.path().join(".git").join("hooks");
    fs::create_dir_all(&hooks).expect("hooks dir");
    let hook = hooks.join("pre-commit");
    fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("write hook");
    let mut permissions = fs::metadata(&hook).expect("hook metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    fs::set_permissions(&hook, permissions).expect("hook mode");
    fs::write(repo.path().join("README.md"), "changed\n").expect("write readme");
    run_git(repo.path(), &["add", "--", "README.md"]);
    let mut commit = TEST_IDENTITY.to_vec();
    commit.extend_from_slice(&["commit", "-m", "the hook must not run"]);
    run_git(repo.path(), &commit);
}

#[test]
fn git_wire_replays_a_durable_receipt_without_launching_git() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let first = wire
        .write_blob(&repo.repo, b"payload\n", 10)
        .expect("write blob");
    assert!(!first.is_replayed());
    let oid = first.value().clone();
    assert!(wire.object_exists(&repo.repo, &oid).expect("object exists"));

    // The repository is removed: a second identical write can only answer from
    // the durable receipt row, never from a git child.
    fs::remove_dir_all(repo.path()).expect("remove repo");
    let second = wire
        .write_blob(&repo.repo, b"payload\n", 20)
        .expect("replayed blob");
    assert!(second.is_replayed());
    assert_eq!(second.value(), &oid);
    assert_eq!(
        second.receipt().disposition,
        GitWireReceiptDisposition::Applied
    );
    assert_eq!(
        second.receipt().idempotency_key,
        first.receipt().idempotency_key
    );
}

#[test]
fn git_wire_write_commit_round_trips_extra_headers() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let headers = vec![
        GitCommitHeader::parse("jj:trees", repo.tree.as_str()).expect("jj:trees"),
        GitCommitHeader::parse("jj:conflict-labels", "side-1 side-2").expect("labels"),
    ];
    let request = commit_request(&repo, "conflicted\n", headers);
    let outcome = wire
        .write_commit(&repo.repo, &request, 10)
        .expect("write commit");
    let raw = wire
        .read_object(&repo.repo, outcome.value())
        .expect("read commit object");
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
fn git_wire_typed_object_ops_round_trip() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let blob = wire
        .write_blob(&repo.repo, b"typed\n", 10)
        .expect("write blob");
    let entries = vec![GitTreeEntry {
        mode: 0o100_644,
        name: b"typed.txt".to_vec(),
        oid: blob.value().clone(),
    }];
    let tree = wire
        .write_tree(&repo.repo, &entries, 11)
        .expect("write tree");
    let read = wire.read_tree(&repo.repo, tree.value()).expect("read tree");
    assert_eq!(read, entries);
    let keep = wire
        .write_keep_ref(&repo.repo, tree.value(), 12)
        .expect("write keep ref");
    let keep_name = keep.value().clone();
    assert!(keep_name.as_str().starts_with(GIT_WIRE_KEEP_REF_PREFIX));
    assert_eq!(
        wire.read_ref(&repo.repo, &keep_name).expect("keep ref"),
        Some(tree.value().clone())
    );
    let dropped = wire
        .delete_keep_ref(&repo.repo, tree.value(), 13)
        .expect("delete keep ref");
    assert_eq!(dropped.value().as_ref(), Some(&keep_name));
    assert_eq!(
        wire.read_ref(&repo.repo, &keep_name).expect("keep ref"),
        None
    );
}

#[test]
fn git_wire_update_ref_cas_reports_a_mismatch_instead_of_forcing() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let rival = rival_commit(&repo);
    let stale = GitOid::parse_hex("d".repeat(40)).expect("stale oid");
    let outcome = wire
        .update_ref_cas(&repo.repo, &repo.branch, Some(&stale), &rival, 10)
        .expect("cas");
    assert!(matches!(outcome.value(), GitRefCasOutcome::Mismatch { .. }));
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
    let applied = wire
        .update_ref_cas(&repo.repo, &repo.branch, Some(&repo.head), &rival, 11)
        .expect("cas");
    assert!(matches!(applied.value(), GitRefCasOutcome::Updated { .. }));
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(rival)
    );
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

#[test]
fn git_wire_stages_objects_before_it_commits_refs() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let staged = stage_commit(&wire, &repo, "staged commit\n");
    assert_eq!(staged.proposed_refs.len(), 1);
    assert!(staged.quarantine_path.ends_with("objects"));
    let proposed = staged.proposed_refs[0].1.clone();

    // Phase one is durable in the object store and nothing has moved yet.
    assert!(
        wire.object_exists(&repo.repo, &proposed)
            .expect("staged object")
    );
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
    assert!(
        wire.receipt(&staged.idempotency_key)
            .expect("receipt")
            .is_none()
    );

    let outcome = wire
        .commit_staged_refs(staged.clone(), 20)
        .expect("commit staged refs");
    assert!(!outcome.is_replayed());
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(proposed)
    );
    let receipt = wire
        .receipt(&staged.idempotency_key)
        .expect("receipt")
        .expect("receipt row");
    assert_eq!(receipt.disposition, GitWireReceiptDisposition::Applied);
    assert_eq!(receipt.operation, GitWireOperation::StageObjects);
    let replay = wire
        .commit_staged_refs(staged, 30)
        .expect("replayed commit");
    assert!(replay.is_replayed());
}

#[test]
fn git_wire_commit_staged_refs_fails_stale_when_the_guarded_ref_moves() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let staged = stage_commit(&wire, &repo, "staged commit\n");
    let rival = rival_commit(&repo);
    run_git(
        repo.path(),
        &["update-ref", repo.branch.as_str(), rival.as_str()],
    );
    let error = wire
        .commit_staged_refs(staged, 20)
        .expect_err("stale guarded ref");
    assert!(matches!(error, Error::ConcurrentWrite(_)));
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(rival)
    );
}

#[test]
fn git_wire_refuses_a_ref_advance_onto_an_unavailable_object_set() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let mut staged = stage_commit(&wire, &repo, "unavailable\n");
    staged.idempotency_key = [7; 32];
    staged.proposed_refs = vec![(
        repo.branch.clone(),
        GitOid::parse_hex("1234567890abcdef1234567890abcdef12345678").expect("absent oid"),
    )];
    let error = wire
        .commit_staged_refs(staged, 20)
        .expect_err("unavailable object set");
    assert!(matches!(error, Error::RepoMutationFailed(_)));
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
}

#[test]
fn git_wire_recovery_completes_a_prepared_ref_advance() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    // Crash point: objects staged and the prepared row is durable, but the
    // ref advance never ran.
    let staged = stage_commit(&wire, &repo, "prepared commit\n");
    let receipts = wire
        .recover_prepared_refs(&repo.repo, 40)
        .expect("recover prepared");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].disposition, GitWireReceiptDisposition::Applied);
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(staged.proposed_refs[0].1.clone())
    );
    assert!(
        wire.receipt(&staged.idempotency_key)
            .expect("receipt")
            .is_some()
    );
    assert!(
        wire.recover_prepared_refs(&repo.repo, 50)
            .expect("second recovery")
            .is_empty()
    );
}

#[test]
fn git_wire_recovery_rolls_an_advanced_ref_forward_to_its_receipt() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let staged = stage_commit(&wire, &repo, "advanced commit\n");
    let proposed = staged.proposed_refs[0].1.clone();
    // Crash point: the ref advanced but the receipt never committed.
    run_git(
        repo.path(),
        &["update-ref", repo.branch.as_str(), proposed.as_str()],
    );
    let receipts = wire
        .recover_prepared_refs(&repo.repo, 40)
        .expect("recover prepared");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].disposition, GitWireReceiptDisposition::Applied);
    assert!(
        wire.receipt(&staged.idempotency_key)
            .expect("receipt")
            .is_some()
    );
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(proposed)
    );
}

#[test]
fn git_wire_recovery_discards_a_prepared_row_with_an_unavailable_object_set() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    // Crash point: the prepared row is durable but its staged object set never
    // reached the object store (an interrupted or garbage-collected staging).
    let absent =
        GitOid::parse_hex("1234567890abcdef1234567890abcdef12345678").expect("absent commit");
    let staged = GitWireStagedObjects {
        idempotency_key: [9; 32],
        repo: repo.repo.clone(),
        quarantine_path: repo.path().join(".git").join("objects"),
        object_set_hash: [0; 32],
        observed_refs: vec![ObservedGitRef {
            name: repo.branch.clone(),
            oid: Some(repo.head.clone()),
        }],
        proposed_refs: vec![(repo.branch.clone(), absent)],
        staged_at: 10,
    };
    wire.put_prepared(&staged, GitWireOperation::WriteCommit)
        .expect("prepared row");

    let receipts = wire
        .recover_prepared_refs(&repo.repo, 40)
        .expect("recover prepared");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].disposition, GitWireReceiptDisposition::Failed);
    // The load-bearing assertion: recovery moved no ref, so no ref points at an
    // unavailable staged object set.
    assert_eq!(
        wire.read_ref(&repo.repo, &repo.branch).expect("ref"),
        Some(repo.head.clone())
    );
    assert!(
        wire.recover_prepared_refs(&repo.repo, 50)
            .expect("second recovery")
            .is_empty()
    );
}

#[test]
fn git_wire_phase_guards_refuse_misrouted_operations() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);

    // A read may never carry an object-writing or ref-moving effect.
    let blob = GitWireRequest::new(repo.repo.clone(), FrozenGitArgv::write_blob(b"nope"), 10);
    assert!(wire.execute_read(blob).is_err());
    let advance = GitWireRequest::new(
        repo.repo.clone(),
        FrozenGitArgv::set_ref(repo.branch.clone(), &repo.head),
        10,
    );
    assert!(wire.execute_read(advance).is_err());

    // Staging is only for object-producing effects.
    let read = GitWireRequest::new(
        repo.repo.clone(),
        FrozenGitArgv::read_ref(repo.branch.clone()),
        10,
    );
    assert!(wire.stage_objects(read).is_err());

    // The transactional ref-commit phase refuses to launch one at all, so
    // `commit_staged_refs` cannot produce objects inside an LMDB write txn.
    let object_producing = FrozenGitArgv::write_blob(b"nope");
    assert!(object_producing.operation().may_write_objects());
    let error = wire
        .run_ref_only(&repo.repo, &object_producing)
        .expect_err("the ref-commit phase must refuse object-producing work");
    assert!(matches!(error, Error::InvariantViolation(_)));
}

fn test_lease(repo: &TestRepo) -> CheckoutLeaseAct {
    CheckoutLeaseAct {
        checkout_id: CheckoutId::from_bytes(*EntityId::now().as_bytes()).expect("checkout id"),
        task_ref: EntityId::now(),
        repo_ref: repo.repo.repo_ref.clone(),
        holder_ref: "oneiron-test".to_owned(),
        epoch: 1,
        task_class: CheckoutTaskClass::Build,
        state: CheckoutLeaseState::Active,
        claimed_at: 1,
        lease_expires_at: None,
        updated_at: 1,
    }
}

#[test]
fn git_wire_serves_the_checkout_repo_ops_port() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let wire = GitWire::new(&vault);
    let lease = test_lease(&repo);
    let path = checkout_worktree_path(&lease);

    wire.materialize(&lease).expect("materialize");
    assert!(path.exists());
    wire.materialize(&lease).expect("materialize is idempotent");

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
    let observed_head = inspection.observed_head.expect("observed head");
    assert_eq!(observed_head.to_string(), repo.head.as_str());

    fs::write(path.join("README.md"), "dirty\n").expect("dirty worktree");
    let dirty = wire
        .inspect_teardown(&lease, &receipt)
        .expect("inspect teardown");
    assert!(dirty.dirty);

    wire.collect(&lease).expect("collect");
    assert!(!path.exists());
    wire.collect(&lease).expect("collect is idempotent");

    let mismatched = PushedHeadReceipt {
        pushed_head: "e".repeat(40),
        ..receipt
    };
    let gone = wire
        .inspect_teardown(&lease, &mismatched)
        .expect("inspect a collected checkout");
    assert_eq!(gone.receipt_match, TeardownReceiptMatch::Uncertain);
}

#[test]
fn git_wire_is_the_only_production_git_subprocess_constructor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needle = format!("Command::new({}git{})", '"', '"');
    let allowed = ["codebase/tests.rs", "artifact_hosting/tests.rs"];
    let mut offenders = Vec::new();
    scan_for_needle(&root, &root, &needle, &allowed, &mut offenders);
    assert!(
        offenders.is_empty(),
        "git subprocesses must be constructed only in git_wire.rs: {offenders:?}"
    );
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
        offenders.push(relative);
    }
}
