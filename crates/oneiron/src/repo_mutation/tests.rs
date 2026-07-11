use std::sync::{Arc, Barrier};
use std::thread;

use tempfile::TempDir;

use super::*;
use crate::registry::ENTITY_TYPE_TASK;
use crate::{ErrorKind, VaultConfig};

fn open_test_vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn init_repo() -> TempDir {
    let dir = tempfile::tempdir().expect("repo tempdir");
    run_git_at_path(dir.path(), &["init".to_owned()]).expect("git init");
    fs::write(dir.path().join("README.md"), "base\n").expect("write readme");
    run_git_at_path(
        dir.path(),
        &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
    )
    .expect("git add");
    run_git_at_path(
        dir.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "initial".to_owned(),
        ],
    )
    .expect("git commit");
    dir
}

fn repo_ref(repo: &TempDir) -> RepoRef {
    RepoRef::LocalFolder {
        path: repo.path().to_string_lossy().into_owned(),
        commit: current_head_commit(repo.path()).expect("repo head commit"),
    }
}

fn commit_file_at(repo: &TempDir, branch: &str, path: &str, content: &str, message: &str) {
    run_git_at_path(repo.path(), &["checkout".to_owned(), branch.to_owned()])
        .expect("checkout branch");
    fs::write(repo.path().join(path), content).expect("write branch file");
    run_git_at_path(
        repo.path(),
        &["add".to_owned(), "--".to_owned(), path.to_owned()],
    )
    .expect("git add branch file");
    run_git_at_path(
        repo.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            message.to_owned(),
        ],
    )
    .expect("git commit branch file");
}

fn create_conflicting_branches(repo: &TempDir) {
    let base = current_head_commit(repo.path()).expect("base commit");
    run_git_at_path(
        repo.path(),
        &[
            "checkout".to_owned(),
            "-B".to_owned(),
            "left".to_owned(),
            base.clone(),
        ],
    )
    .expect("checkout left from base");
    fs::write(repo.path().join("README.md"), "left branch\n").expect("write left");
    run_git_at_path(
        repo.path(),
        &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
    )
    .expect("add left");
    run_git_at_path(
        repo.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "left edit".to_owned(),
        ],
    )
    .expect("commit left");

    run_git_at_path(
        repo.path(),
        &[
            "checkout".to_owned(),
            "-B".to_owned(),
            "right".to_owned(),
            base,
        ],
    )
    .expect("checkout right from base");
    fs::write(repo.path().join("README.md"), "right branch\n").expect("write right");
    run_git_at_path(
        repo.path(),
        &["add".to_owned(), "--".to_owned(), "README.md".to_owned()],
    )
    .expect("add right");
    run_git_at_path(
        repo.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "right edit".to_owned(),
        ],
    )
    .expect("commit right");
    run_git_at_path(repo.path(), &["checkout".to_owned(), "left".to_owned()]).expect("return left");
}

fn add_side_branch_with_message(repo: &TempDir, branch: &str, message: &[u8]) -> String {
    let message_path = repo.path().join(format!("{branch}-message.bin"));
    fs::write(&message_path, message).expect("write commit message");
    let parent = current_head_commit(repo.path()).expect("side branch parent");
    let tree = utf8_trimmed(
        run_git_at_path(
            repo.path(),
            &["rev-parse".to_owned(), "HEAD^{tree}".to_owned()],
        )
        .expect("head tree"),
        "git tree sha must be UTF-8",
    )
    .expect("head tree utf8");
    let commit = utf8_trimmed(
        run_git_at_path(
            repo.path(),
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit-tree".to_owned(),
                tree,
                "-p".to_owned(),
                parent,
                "-F".to_owned(),
                path_arg(&message_path).expect("message path"),
            ],
        )
        .expect("commit tree"),
        "git commit-tree output must be UTF-8",
    )
    .expect("commit sha");
    run_git_at_path(
        repo.path(),
        &[
            "update-ref".to_owned(),
            format!("refs/heads/{branch}"),
            commit.clone(),
        ],
    )
    .expect("update side branch");
    commit
}

fn put_branch_subject(vault: &Vault) -> EntityId {
    let branch_subject = EntityId::now();
    vault
        .put_entity(
            &branch_subject,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
        )
        .expect("branch subject");
    branch_subject
}

fn repo_provenance_claim_value() -> Value {
    Value::Map(vec![
        (Value::from("actor"), Value::from("agent:oneiron-test")),
        (Value::from("model"), Value::from("oneiron/test-model@1")),
        (
            Value::from("prompt_hash"),
            Value::from("sha256:test-prompt"),
        ),
        (
            Value::from("derivation_envelope"),
            Value::Map(vec![
                (
                    Value::from("content_hash"),
                    Value::from("sha256:test-content"),
                ),
                (Value::from("model_id"), Value::from("oneiron/test-model@1")),
                (Value::from("version"), Value::from("1")),
                (
                    Value::from("params_hash"),
                    Value::from("sha256:test-params"),
                ),
            ]),
        ),
        (
            Value::from("diff_lineage_receipt"),
            Value::Map(vec![
                (Value::from("base_tree"), Value::from("base-tree")),
                (Value::from("result_tree"), Value::from("result-tree")),
            ]),
        ),
    ])
}

fn put_repo_provenance_claim(vault: &Vault) -> EntityId {
    put_repo_provenance_claim_with_value(vault, repo_provenance_claim_value())
}

fn put_repo_provenance_claim_with_value(vault: &Vault, value: Value) -> EntityId {
    let subject = put_branch_subject(vault);
    let claim_id = EntityId::now();
    let body = ClaimBody::new(
        REPO_PROVENANCE_PREDICATE,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let data = encode_claim_body(&body).expect("encode repo provenance claim");
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_CLAIM);
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&1_u64.to_be_bytes());
    payload.extend_from_slice(&data);
    let mut wtxn = vault.store.env.write_txn().expect("claim write txn");
    vault
        .store
        .entities
        .put(&mut wtxn, claim_id.as_bytes(), &payload)
        .expect("put repo provenance claim");
    wtxn.commit().expect("commit repo provenance claim");
    claim_id
}

#[test]
fn repo_mutation_commit_file_wires_provenance_trailer_to_claim() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let claim_id = put_repo_provenance_claim(&vault);

    vault
        .apply_repo_mutation(
            RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "agent.txt".to_owned(),
                    content: b"agent edit\n".to_vec(),
                    message: "agent edit".to_owned(),
                },
            )
            .with_provenance_claim_id(claim_id),
        )
        .expect("repo mutation with provenance");

    let head = current_head_commit(repo.path()).expect("head commit");
    let message = String::from_utf8(
        run_git_at_path(
            repo.path(),
            &[
                "show".to_owned(),
                "-s".to_owned(),
                "--format=%B".to_owned(),
                head.clone(),
            ],
        )
        .expect("git show commit message"),
    )
    .expect("commit message utf8");
    let expected_trailer = format!("{REPO_PROVENANCE_TRAILER_KEY}: {}", claim_id.to_hex());
    assert!(message.lines().any(|line| line == expected_trailer));
    assert_eq!(
        message
            .lines()
            .filter(|line| line.starts_with(REPO_PROVENANCE_TRAILER_PREFIX))
            .count(),
        1
    );
    assert!(!message.contains("private payload"));

    let provenance = repo_commit_provenance(repo.path(), &head)
        .expect("commit provenance lookup")
        .expect("trailer provenance");
    assert_eq!(provenance.commit_sha, head);
    assert_eq!(provenance.claim_id, claim_id);

    let commit =
        repo_commit_for_provenance_claim(repo.path(), &claim_id).expect("claim provenance lookup");
    assert_eq!(commit, Some(head));
}

#[test]
fn repo_provenance_parser_reads_only_final_trailer_block() {
    let claim_id = EntityId::now();
    let diagnostic = format!(
        "subject\n\nExample output:\n{REPO_PROVENANCE_TRAILER_KEY}: not-a-claim\n\nSigned-off-by: Tester <test@example.invalid>\n"
    );
    assert_eq!(
        parse_repo_provenance_trailer(&diagnostic).expect("body diagnostic ignored"),
        None
    );

    let trailer = format!(
        "subject\n\nbody\n\nSigned-off-by: Tester <test@example.invalid>\n{REPO_PROVENANCE_TRAILER_KEY}: {}\n",
        claim_id.to_hex()
    );
    assert_eq!(
        parse_repo_provenance_trailer(&trailer).expect("final trailer parsed"),
        Some(claim_id)
    );
}

#[test]
fn repo_provenance_trailer_appends_to_existing_trailer_block() {
    let claim_id = EntityId::now();
    let message = commit_message_with_provenance_trailer(
        "subject\n\nSigned-off-by: Tester <test@example.invalid>",
        Some(claim_id),
    )
    .expect("append provenance");

    assert!(message.contains(&format!(
        "Signed-off-by: Tester <test@example.invalid>\n{REPO_PROVENANCE_TRAILER_KEY}: {}",
        claim_id.to_hex()
    )));
    assert!(!message.contains("Signed-off-by: Tester <test@example.invalid>\n\nOneiron-Claim:"));
}

#[test]
fn repo_provenance_git_notes_export_round_trips_on_demand() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let claim_id = put_repo_provenance_claim(&vault);
    vault
        .apply_repo_mutation(
            RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "notes.txt".to_owned(),
                    content: b"notes\n".to_vec(),
                    message: "notes edit".to_owned(),
                },
            )
            .with_provenance_claim_id(claim_id),
        )
        .expect("repo mutation with provenance");
    let head = current_head_commit(repo.path()).expect("head commit");
    let note = format!(
        r#"{{"commit":"{}","claim_id":"{}","trailer":"{}"}}"#,
        head,
        claim_id.to_hex(),
        REPO_PROVENANCE_TRAILER_KEY
    );

    export_repo_provenance_git_note(repo.path(), &head, &claim_id).expect("export git note");

    let stored = repo_provenance_git_note(repo.path(), &head)
        .expect("read git note")
        .expect("note exists");
    assert_eq!(stored, note);

    let note_provenance = repo_commit_provenance_from_git_note(repo.path(), &head)
        .expect("resolve git note")
        .expect("note provenance");
    let trailer_provenance = repo_commit_provenance(repo.path(), &head)
        .expect("resolve trailer")
        .expect("trailer provenance");
    assert_eq!(note_provenance, trailer_provenance);
}

#[test]
fn repo_mutation_rejects_non_claim_provenance_id_before_commit() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let non_claim = put_branch_subject(&vault);
    let head_before = current_head_commit(repo.path()).expect("head before");

    let error = vault
        .apply_repo_mutation(
            RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "bad.txt".to_owned(),
                    content: b"bad\n".to_vec(),
                    message: "bad edit".to_owned(),
                },
            )
            .with_provenance_claim_id(non_claim),
        )
        .expect_err("non-claim provenance id must fail");

    assert_eq!(error.kind(), ErrorKind::InvalidRepoMutationRecord);
    assert_eq!(
        current_head_commit(repo.path()).expect("head after"),
        head_before
    );
}

#[test]
fn repo_mutation_rejects_incomplete_repo_provenance_claim_before_commit() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let claim_id = put_repo_provenance_claim_with_value(&vault, Value::from("private payload"));
    let head_before = current_head_commit(repo.path()).expect("head before");

    let error = vault
        .apply_repo_mutation(
            RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "bad-provenance.txt".to_owned(),
                    content: b"bad\n".to_vec(),
                    message: "bad provenance".to_owned(),
                },
            )
            .with_provenance_claim_id(claim_id),
        )
        .expect_err("incomplete provenance claim must fail");

    assert_eq!(error.kind(), ErrorKind::InvalidRepoMutationRecord);
    assert_eq!(
        current_head_commit(repo.path()).expect("head after"),
        head_before
    );
}

#[test]
fn repo_claim_lookup_errors_when_claim_maps_to_multiple_commits() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let claim_id = put_repo_provenance_claim(&vault);

    for (path, content, message) in [
        ("one.txt", b"one\n".to_vec(), "one edit"),
        ("two.txt", b"two\n".to_vec(), "two edit"),
    ] {
        vault
            .apply_repo_mutation(
                RepoMutationRequest::new(
                    repo_ref(&repo),
                    RepoMutationOperation::CommitFile {
                        path: path.to_owned(),
                        content,
                        message: message.to_owned(),
                    },
                )
                .with_provenance_claim_id(claim_id),
            )
            .expect("repo mutation with reused provenance");
    }

    let error = repo_commit_for_provenance_claim(repo.path(), &claim_id)
        .expect_err("reused claim id must be ambiguous");
    assert_eq!(error.kind(), ErrorKind::InvalidRepoMutationRecord);
}

#[test]
fn repo_claim_lookup_ignores_body_matches_and_unreadable_unrelated_messages() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let claim_id = put_repo_provenance_claim(&vault);
    let body_match = format!(
        "diagnostic\n\nExample:\n{REPO_PROVENANCE_TRAILER_KEY}: {}\n\nSigned-off-by: Tester <test@example.invalid>\n",
        claim_id.to_hex()
    );
    add_side_branch_with_message(&repo, "body-match", body_match.as_bytes());
    add_side_branch_with_message(&repo, "non-utf8", b"non utf8 side branch \xff\n");

    vault
        .apply_repo_mutation(
            RepoMutationRequest::new(
                repo_ref(&repo),
                RepoMutationOperation::CommitFile {
                    path: "real.txt".to_owned(),
                    content: b"real\n".to_vec(),
                    message: "real edit".to_owned(),
                },
            )
            .with_provenance_claim_id(claim_id),
        )
        .expect("real provenance mutation");
    let head = current_head_commit(repo.path()).expect("head commit");

    assert_eq!(
        repo_commit_for_provenance_claim(repo.path(), &claim_id)
            .expect("claim lookup survives side branches"),
        Some(head)
    );
}

#[test]
fn repo_mutation_queue_serializes_concurrent_commits() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let vault = Arc::new(vault);
    let barrier = Arc::new(Barrier::new(3));

    let mut handles = Vec::new();
    for name in ["a", "b"] {
        let vault = Arc::clone(&vault);
        let barrier = Arc::clone(&barrier);
        let repo_ref = repo_ref(&repo);
        handles.push(thread::spawn(move || {
            barrier.wait();
            vault.apply_repo_mutation(RepoMutationRequest::new(
                repo_ref,
                RepoMutationOperation::CommitFile {
                    path: format!("{name}.txt"),
                    content: format!("{name}\n").into_bytes(),
                    message: format!("commit {name}"),
                },
            ))
        }));
    }

    barrier.wait();
    let mut seqs = Vec::new();
    for handle in handles {
        let outcome = handle.join().expect("thread join").expect("commit");
        assert_eq!(outcome.entry.status, RepoMutationStatus::Applied);
        seqs.push(outcome.entry.seq);
    }
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2]);

    let log = vault.repo_mutation_oplog(&repo_ref(&repo)).expect("oplog");
    assert_eq!(log.len(), 2);
    assert!(log.iter().all(|entry| entry.failure.is_none()));
    assert_eq!(log[0].status, RepoMutationStatus::Applied);
    assert_eq!(log[1].status, RepoMutationStatus::Applied);

    let commits = run_git_at_path(
        repo.path(),
        &[
            "log".to_owned(),
            "--format=%s".to_owned(),
            "--".to_owned(),
            "a.txt".to_owned(),
            "b.txt".to_owned(),
        ],
    )
    .expect("git log");
    let commits = String::from_utf8(commits).expect("utf8 log");
    assert!(commits.contains("commit a"));
    assert!(commits.contains("commit b"));
}

#[cfg(unix)]
#[test]
fn repo_mutation_file_lock_uses_git_common_dir() {
    let repo = init_repo();
    let common_dir = git_common_dir(repo.path()).expect("main common dir");
    let worktree_parent = tempfile::tempdir().expect("worktree parent");
    let worktree_path = worktree_parent.path().join("linked-worktree");
    run_git_at_path(
        repo.path(),
        &[
            "worktree".to_owned(),
            "add".to_owned(),
            "--detach".to_owned(),
            "--".to_owned(),
            worktree_path.to_string_lossy().into_owned(),
            "HEAD".to_owned(),
        ],
    )
    .expect("create linked worktree");

    assert_eq!(
        git_common_dir(&worktree_path).expect("worktree common dir"),
        common_dir
    );
    let _guard = repo_mutation_file_lock(&common_dir).expect("lock common dir");
    assert!(common_dir.join(REPO_MUTATION_LOCK_FILE_NAME).exists());
}

#[test]
fn repo_mutation_recovery_remounts_pre_action_snapshot() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let tracked = repo.path().join("README.md");
    fs::write(&tracked, "dirty before\n").expect("dirty write");
    let before = fs::read_to_string(&tracked).expect("read before");

    let outcome = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: b"mutated\n".to_vec(),
                message: "mutate readme".to_owned(),
            },
        ))
        .expect("mutate");
    let pre_head = run_git_at_path(
        repo.path(),
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD^".to_owned(),
        ],
    )
    .expect("pre mutation head");
    assert_eq!(
        fs::read_to_string(&tracked).expect("read mutated"),
        "mutated\n"
    );

    let recovery = vault
        .recover_repo_snapshot(&repo_ref(&repo), outcome.entry.pre_action_fork_hash)
        .expect("recover");
    assert_eq!(recovery.entry.operation_kind, "recover_snapshot");
    assert_eq!(
        fs::read_to_string(&tracked).expect("read recovered"),
        before
    );
    let recovered_head = run_git_at_path(
        repo.path(),
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )
    .expect("recovered head");
    assert_eq!(recovered_head, pre_head);
}

#[test]
fn repo_mutation_prepared_recovery_rolls_forward_after_action_crash() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let tracked = repo.path().join("README.md");
    let input_ref = repo_ref(&repo);
    let before_head = current_head_commit(repo.path()).expect("head before mutation");

    INJECT_REPO_MUTATION_CRASH
        .with(|cell| cell.set(RepoMutationCrashPoint::AfterActionBeforeApplied));
    let error = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            input_ref.clone(),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: b"mutated\n".to_vec(),
                message: "mutate readme".to_owned(),
            },
        ))
        .expect_err("injected crash after git action");
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    let applied_head = current_head_commit(repo.path()).expect("applied head");
    assert_ne!(applied_head, before_head);
    assert_eq!(
        fs::read_to_string(&tracked).expect("read applied content"),
        "mutated\n"
    );

    let prepared = vault.repo_mutation_oplog(&input_ref).expect("prepared row");
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].status, RepoMutationStatus::Prepared);
    assert_ne!(
        prepared[0].expected_post_action_fork_hash,
        Some(prepared[0].pre_action_fork_hash)
    );

    let recovered = vault
        .recover_prepared_repo_mutations(&input_ref)
        .expect("roll forward prepared mutation");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].entry.seq, prepared[0].seq);
    assert_eq!(recovered[0].entry.operation_kind, "commit_file");
    assert_eq!(recovered[0].entry.status, RepoMutationStatus::Applied);
    assert_eq!(
        current_head_commit(repo.path()).expect("head after recovery"),
        applied_head
    );
    assert_eq!(
        fs::read_to_string(&tracked).expect("read recovered content"),
        "mutated\n"
    );
    let log = vault.repo_mutation_oplog(&input_ref).expect("oplog");
    assert_eq!(log.len(), 1, "roll-forward must not create a restore row");
    assert_eq!(log[0].status, RepoMutationStatus::Applied);
}

#[test]
fn repo_mutation_prepared_recovery_restores_after_pre_action_crash() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let tracked = repo.path().join("README.md");
    fs::write(&tracked, "dirty before\n").expect("dirty pre-action worktree");
    let before = fs::read_to_string(&tracked).expect("read before");
    let input_ref = repo_ref(&repo);
    let before_head = current_head_commit(repo.path()).expect("head before mutation");

    INJECT_REPO_MUTATION_CRASH
        .with(|cell| cell.set(RepoMutationCrashPoint::AfterPreparedBeforeAction));
    let error = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            input_ref.clone(),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: b"mutated\n".to_vec(),
                message: "mutate readme".to_owned(),
            },
        ))
        .expect_err("injected crash before git action");
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    assert_eq!(
        current_head_commit(repo.path()).expect("head after crash"),
        before_head
    );
    assert_eq!(
        fs::read_to_string(&tracked).expect("read after crash"),
        before
    );

    let recovered = vault
        .recover_prepared_repo_mutations(&input_ref)
        .expect("restore pre-action snapshot");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].entry.operation_kind, "recover_snapshot");
    assert_eq!(recovered[0].entry.status, RepoMutationStatus::Applied);
    assert_eq!(
        current_head_commit(repo.path()).expect("head after recovery"),
        before_head
    );
    assert_eq!(
        fs::read_to_string(&tracked).expect("read recovered"),
        before
    );
    let log = vault.repo_mutation_oplog(&input_ref).expect("oplog");
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].status, RepoMutationStatus::Failed);
    assert_eq!(log[1].operation_kind, "recover_snapshot");
    assert_eq!(log[1].status, RepoMutationStatus::Applied);
}

#[test]
fn repo_mutation_prepared_recovery_halts_on_diverged_repo_state() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let tracked = repo.path().join("README.md");
    let input_ref = repo_ref(&repo);

    INJECT_REPO_MUTATION_CRASH
        .with(|cell| cell.set(RepoMutationCrashPoint::AfterActionBeforeApplied));
    let error = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            input_ref.clone(),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: b"mutated\n".to_vec(),
                message: "mutate readme".to_owned(),
            },
        ))
        .expect_err("injected crash after git action");
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    let applied_head = current_head_commit(repo.path()).expect("applied head");
    fs::write(&tracked, "foreign touch\n").expect("foreign worktree touch");

    let error = vault
        .recover_prepared_repo_mutations(&input_ref)
        .expect_err("diverged state must halt recovery");
    assert_eq!(error.kind(), ErrorKind::RepoMutationRecoveryDiverged);
    let Error::RepoMutationRecoveryDiverged {
        pre_action_fork_hash,
        expected_post_action_fork_hash,
        actual_fork_hash,
        ..
    } = error
    else {
        unreachable!("error kind checked above")
    };
    assert!(expected_post_action_fork_hash.is_some());
    assert_ne!(actual_fork_hash, pre_action_fork_hash);
    assert_ne!(Some(actual_fork_hash), expected_post_action_fork_hash);
    assert_eq!(
        current_head_commit(repo.path()).expect("head after halted recovery"),
        applied_head
    );
    assert_eq!(
        fs::read_to_string(&tracked).expect("foreign content remains"),
        "foreign touch\n"
    );
    let log = vault.repo_mutation_oplog(&input_ref).expect("oplog");
    assert_eq!(log.len(), 1, "halt must not add a recovery row");
    assert_eq!(log[0].status, RepoMutationStatus::Prepared);
    assert!(log[0].finished_at_ms.is_none());
}

#[test]
fn repo_mutation_auto_recovers_prepared_rows() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let tracked = repo.path().join("README.md");
    let before = fs::read_to_string(&tracked).expect("read before");
    let canonical = repo_ref(&repo);
    INJECT_REPO_MUTATION_CRASH
        .with(|cell| cell.set(RepoMutationCrashPoint::AfterPreparedBeforeAction));
    let error = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            canonical.clone(),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: b"mutated\n".to_vec(),
                message: "mutate readme".to_owned(),
            },
        ))
        .expect_err("injected crash before git action");
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);

    let recovered = vault
        .recover_prepared_repo_mutations(&canonical)
        .expect("recover prepared");

    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read_to_string(&tracked).expect("read recovered"),
        before
    );
    let log = vault.repo_mutation_oplog(&canonical).expect("oplog");
    assert_eq!(log[0].status, RepoMutationStatus::Failed);
    assert_eq!(log[1].operation_kind, "recover_snapshot");
    assert_eq!(log[1].status, RepoMutationStatus::Applied);
}

#[cfg(unix)]
#[test]
fn repo_mutation_rejects_symlink_write_escape() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let outside = tempfile::tempdir().expect("outside tempdir");
    std::os::unix::fs::symlink(outside.path(), repo.path().join("escape")).expect("repo symlink");
    run_git_at_path(
        repo.path(),
        &["add".to_owned(), "--".to_owned(), "escape".to_owned()],
    )
    .expect("git add symlink");
    run_git_at_path(
        repo.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "add symlink".to_owned(),
        ],
    )
    .expect("git commit symlink");

    let err = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::CommitFile {
                path: "escape/pwned".to_owned(),
                content: b"owned\n".to_vec(),
                message: "attempt escape".to_owned(),
            },
        ))
        .expect_err("symlink escape rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    assert!(!outside.path().join("pwned").exists());
}

#[cfg(unix)]
#[test]
fn repo_mutation_rejects_leaf_symlink_write_escape() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let outside = tempfile::tempdir().expect("outside tempdir");
    let outside_target = outside.path().join("secret");
    fs::write(&outside_target, "original\n").expect("write outside target");
    std::os::unix::fs::symlink(&outside_target, repo.path().join("link"))
        .expect("repo leaf symlink");
    run_git_at_path(
        repo.path(),
        &["add".to_owned(), "--".to_owned(), "link".to_owned()],
    )
    .expect("git add leaf symlink");
    run_git_at_path(
        repo.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "add leaf symlink".to_owned(),
        ],
    )
    .expect("git commit leaf symlink");

    let err = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::CommitFile {
                path: "link".to_owned(),
                content: b"owned\n".to_vec(),
                message: "attempt leaf escape".to_owned(),
            },
        ))
        .expect_err("leaf symlink escape rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    assert_eq!(
        fs::read_to_string(&outside_target).expect("read outside target"),
        "original\n"
    );
}

#[test]
fn repo_mutation_commit_file_preserves_unrelated_staged_paths() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    fs::write(repo.path().join("unrelated.txt"), "staged\n").expect("write staged");
    run_git_at_path(
        repo.path(),
        &[
            "add".to_owned(),
            "--".to_owned(),
            "unrelated.txt".to_owned(),
        ],
    )
    .expect("stage unrelated");

    vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::CommitFile {
                path: "owned.txt".to_owned(),
                content: b"owned\n".to_vec(),
                message: "commit owned".to_owned(),
            },
        ))
        .expect("commit owned");

    let staged = run_git_at_path(
        repo.path(),
        &[
            "diff".to_owned(),
            "--cached".to_owned(),
            "--name-only".to_owned(),
            "--".to_owned(),
            "unrelated.txt".to_owned(),
        ],
    )
    .expect("cached diff");
    assert_eq!(
        String::from_utf8(staged).expect("utf8 staged"),
        "unrelated.txt\n"
    );
    let unrelated_log = run_git_at_path(
        repo.path(),
        &[
            "log".to_owned(),
            "--format=%s".to_owned(),
            "--".to_owned(),
            "unrelated.txt".to_owned(),
        ],
    )
    .expect("unrelated log");
    assert!(
        !String::from_utf8(unrelated_log)
            .expect("utf8 log")
            .contains("commit owned")
    );
}

#[test]
fn repo_mutation_recovery_rejects_snapshot_from_other_repo() {
    let (_vault_dir, vault) = open_test_vault();
    let repo_a = init_repo();
    let repo_b = init_repo();
    fs::write(repo_a.path().join("repo-a-only.txt"), "repo a only\n")
        .expect("write repo a unique file");
    run_git_at_path(
        repo_a.path(),
        &[
            "add".to_owned(),
            "--".to_owned(),
            "repo-a-only.txt".to_owned(),
        ],
    )
    .expect("git add repo a unique file");
    run_git_at_path(
        repo_a.path(),
        &[
            "-c".to_owned(),
            "user.name=Oneiron".to_owned(),
            "-c".to_owned(),
            "user.email=oneiron@example.invalid".to_owned(),
            "commit".to_owned(),
            "-m".to_owned(),
            "make repo a unique".to_owned(),
        ],
    )
    .expect("git commit repo a unique file");
    let b_readme = repo_b.path().join("README.md");
    let before_b = fs::read_to_string(&b_readme).expect("read repo b");

    let outcome = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo_a),
            RepoMutationOperation::CommitFile {
                path: "a.txt".to_owned(),
                content: b"a\n".to_vec(),
                message: "commit a".to_owned(),
            },
        ))
        .expect("mutate repo a");
    let err = vault
        .recover_repo_snapshot(&repo_ref(&repo_b), outcome.entry.pre_action_fork_hash)
        .expect_err("foreign snapshot rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    assert_eq!(
        fs::read_to_string(&b_readme).expect("read repo b after"),
        before_b
    );
}

#[test]
fn repo_conflict_record_keeps_branches_mountable_and_queryable() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    create_conflicting_branches(&repo);
    let branch_subject = put_branch_subject(&vault);

    let outcome = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::RecordConflict {
                branch_subject,
                branch_name: "left".to_owned(),
                ours_ref: "left".to_owned(),
                theirs_ref: "right".to_owned(),
            },
        ))
        .expect("record conflict");
    assert_eq!(outcome.entry.status, RepoMutationStatus::Applied);
    let claim_id = outcome
        .repo_conflict_claim_id
        .expect("record conflict claim id");

    let conflicts = vault
        .repo_conflict_claims(&branch_subject)
        .expect("conflict claims");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].claim_id, claim_id);
    assert_eq!(conflicts[0].branch, "left");
    assert_eq!(conflicts[0].conflicted_paths, vec!["README.md"]);
    assert_eq!(conflicts[0].base_tree.len(), CODEBASE_COMMIT_HASH_HEX_LEN);
    assert_eq!(conflicts[0].ours_tree.len(), CODEBASE_COMMIT_HASH_HEX_LEN);
    assert_eq!(conflicts[0].theirs_tree.len(), CODEBASE_COMMIT_HASH_HEX_LEN);

    let worktree_parent = tempfile::tempdir().expect("worktree parent");
    let left_mount = worktree_parent.path().join("left");
    let right_mount = worktree_parent.path().join("right");
    run_git_at_path(
        repo.path(),
        &[
            "worktree".to_owned(),
            "add".to_owned(),
            "--detach".to_owned(),
            "--".to_owned(),
            left_mount.to_string_lossy().into_owned(),
            "left".to_owned(),
        ],
    )
    .expect("mount left");
    run_git_at_path(
        repo.path(),
        &[
            "worktree".to_owned(),
            "add".to_owned(),
            "--detach".to_owned(),
            "--".to_owned(),
            right_mount.to_string_lossy().into_owned(),
            "right".to_owned(),
        ],
    )
    .expect("mount right");
    assert_eq!(
        fs::read_to_string(left_mount.join("README.md")).expect("left readme"),
        "left branch\n"
    );
    assert_eq!(
        fs::read_to_string(right_mount.join("README.md")).expect("right readme"),
        "right branch\n"
    );

    commit_file_at(
        &repo,
        "left",
        "left.txt",
        "left descendant\n",
        "left descendant",
    );
    commit_file_at(
        &repo,
        "right",
        "right.txt",
        "right descendant\n",
        "right descendant",
    );
    let left_log = run_git_at_path(
        repo.path(),
        &[
            "log".to_owned(),
            "--format=%s".to_owned(),
            "left".to_owned(),
        ],
    )
    .expect("left log");
    let right_log = run_git_at_path(
        repo.path(),
        &[
            "log".to_owned(),
            "--format=%s".to_owned(),
            "right".to_owned(),
        ],
    )
    .expect("right log");
    assert!(
        String::from_utf8(left_log)
            .expect("utf8 left log")
            .contains("left descendant")
    );
    assert!(
        String::from_utf8(right_log)
            .expect("utf8 right log")
            .contains("right descendant")
    );
}

#[test]
fn repo_conflict_resolution_supersedes_open_claim_and_writes_clean_tree() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    create_conflicting_branches(&repo);
    let branch_subject = put_branch_subject(&vault);
    let open = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::RecordConflict {
                branch_subject,
                branch_name: "left".to_owned(),
                ours_ref: "left".to_owned(),
                theirs_ref: "right".to_owned(),
            },
        ))
        .expect("record conflict")
        .repo_conflict_claim_id
        .expect("open claim id");

    run_git_at_path(repo.path(), &["checkout".to_owned(), "left".to_owned()])
        .expect("checkout left");
    let resolved = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::ResolveConflictFile {
                branch_subject,
                open_conflict_claim_id: open,
                branch_name: "left".to_owned(),
                path: "README.md".to_owned(),
                content: b"resolved branch\n".to_vec(),
                message: "resolve readme conflict".to_owned(),
            },
        ))
        .expect("resolve conflict")
        .repo_conflict_claim_id
        .expect("resolution claim id");

    let status = run_git_at_path(
        repo.path(),
        &["status".to_owned(), "--porcelain".to_owned()],
    )
    .expect("git status");
    assert_eq!(String::from_utf8(status).expect("utf8 status"), "");
    assert_eq!(
        fs::read_to_string(repo.path().join("README.md")).expect("resolved file"),
        "resolved branch\n"
    );
    assert!(
        vault
            .repo_conflict_claims(&branch_subject)
            .expect("active open conflicts")
            .is_empty()
    );
    let open_body = vault
        .get_claim(&open)
        .expect("get open claim")
        .expect("open claim exists");
    assert_eq!(open_body.lifecycle, ClaimLifecycleStatus::Superseded);
    let resolutions = vault
        .repo_conflict_resolution_claims(&branch_subject)
        .expect("resolution claims");
    assert_eq!(resolutions.len(), 1);
    assert_eq!(resolutions[0].claim_id, resolved);
    assert_eq!(resolutions[0].open_conflict_claim_id, open);
    assert_eq!(resolutions[0].resolved_paths, vec!["README.md"]);
    assert_eq!(
        resolutions[0].resolved_tree,
        tree_hash_for_ref(repo.path(), "HEAD").expect("resolved tree")
    );
}

#[test]
fn repo_mutation_api_has_no_forbidden_raw_git_operations() {
    assert_eq!(
        REPO_MUTATION_ALLOWED_OPERATION_KINDS,
        [
            "commit_file",
            "create_worktree",
            "record_conflict",
            "remove_worktree",
            "recover_snapshot",
            "resolve_conflict_file"
        ]
    );
    for forbidden in REPO_MUTATION_FORBIDDEN_GIT_COMMANDS {
        assert!(
            !REPO_MUTATION_ALLOWED_OPERATION_KINDS.contains(&forbidden),
            "{forbidden} must not be an allowed queue operation"
        );
    }
    let err = validate_relative_repo_path(".git/index").expect_err("reject .git path");
    assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    let err = validate_relative_repo_path("../outside").expect_err("reject parent path");
    assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    let err = validate_base_ref("-q").expect_err("reject option-like base ref");
    assert_eq!(err.kind(), ErrorKind::InvalidRepoMutationRecord);
    let truncated = truncate_failure(&format!("{}é{}", "a".repeat(4095), "b".repeat(16)));
    assert!(truncated.ends_with("..."));
}

#[test]
fn repo_mutation_worktree_lifecycle_is_queued_and_logged() {
    let (_vault_dir, vault) = open_test_vault();
    let repo = init_repo();
    let worktree = tempfile::tempdir().expect("worktree parent");
    let worktree_path = worktree.path().join("agent-worktree");

    let created = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::CreateWorktree {
                worktree_path: worktree_path.clone(),
                base_ref: "HEAD".to_owned(),
            },
        ))
        .expect("create worktree");
    assert!(worktree_path.join("README.md").exists());

    let removed = vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(&repo),
            RepoMutationOperation::RemoveWorktree {
                worktree_path: worktree_path.clone(),
            },
        ))
        .expect("remove worktree");
    assert!(!worktree_path.exists());
    assert_eq!(created.entry.seq, 1);
    assert_eq!(removed.entry.seq, 2);
}
