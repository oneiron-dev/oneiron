//! [RUNNER-FENCE-MASKED-CHECKOUT] (OPUS-CENSUS-L8, Sol review F1): a
//! masked copy's checkout is a self-contained repository outside the
//! vault, so git in a fenced seat can read its repository while the
//! runner fence removes the vault's whole data tree.
//!
//! Before the fix the checkout was a linked worktree of the copy store
//! at `<vault>/repo-secret-projections/<store>/<graph>/repo.git`, inside
//! the data tree the fence removes: its git common directory was that
//! store, and a fenced git in the tree could not read HEAD or the
//! objects. The fixture stands a canonical repo and a bare copy store
//! in a "data" tree (with a "control" tree beside it, as a vault
//! holds), binds a lease of the canonical original to the copy, and
//! materializes through the masked-checkout test door. There is no
//! hole in the fence for the copy store: the probe read of each removed
//! tree still fails under it.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test runner_fence_masked_checkout`
#![cfg(all(unix, oneiron_test_support))]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use oneiron::checkout::{
    CheckoutId, CheckoutLeaseAct, CheckoutLeaseState, CheckoutTaskClass, PushedHeadReceipt,
    TeardownReceiptMatch,
};
use oneiron::codebase::RepoRef;
use oneiron::git_wire::{GIT_WIRE_CHECKOUT_ROOT_NAME, GitOid, GitWire, GitWireProcessEnv};
use oneiron::test_doors::masked_checkout as door;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_container::{RunnerFence, RunnerFenceMechanism};

// ---------------------------------------------------------------------------
// Stock git, as `tests/git_smart_http.rs` runs it.
// ---------------------------------------------------------------------------

fn git_output(cwd: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Oneiron")
        .env("GIT_AUTHOR_EMAIL", "oneiron@example.invalid")
        .env("GIT_COMMITTER_NAME", "Oneiron")
        .env("GIT_COMMITTER_EMAIL", "oneiron@example.invalid")
        .args(args)
        .output()
        .expect("run git")
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = git_output(cwd, args);
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn commit_file(root: &Path, name: &str, body: &str, message: &str) -> String {
    std::fs::write(root.join(name), body).expect("write file");
    git(root, &["add", "--", name]);
    git(root, &["commit", "-m", message]);
    git(root, &["rev-parse", "--verify", "HEAD"])
}

// ---------------------------------------------------------------------------
// The runner fence, as `oneiron-container/tests/runner_fence.rs` drives it.
// ---------------------------------------------------------------------------

/// Whether this host applies the fence; a host without Landlock ABI 3 or
/// Seatbelt must then prove nothing.
fn applied(fence: &RunnerFence) -> bool {
    eprintln!("runner_fence: mechanism {:?}", fence.mechanism());
    if fence.mechanism() == RunnerFenceMechanism::Unavailable {
        assert!(
            !fence.prove().proven,
            "a host with no mechanism never proves the fence"
        );
        return false;
    }
    true
}

/// What `cat` under the fence read from `path`, or `None` where it failed.
fn reads(fence: &RunnerFence, path: &Path) -> Option<String> {
    let output = fence
        .command("/bin/cat")
        .expect("fenced command")
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .expect("the runner started");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn fenced_git(fence: &RunnerFence, git_binary: &Path, tree: &Path, args: &[&str]) -> Output {
    fence
        .command(git_binary)
        .expect("fenced command")
        .current_dir(tree)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the fenced git started")
}

fn fenced_git_stdout(fence: &RunnerFence, git_binary: &Path, tree: &Path, args: &[&str]) -> String {
    let output = fenced_git(fence, git_binary, tree, args);
    assert!(
        output.status.success(),
        "fenced git {args:?} failed in {}:\n{}",
        tree.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

// ---------------------------------------------------------------------------
// Fixture: a canonical repo and a bare copy store inside a removed tree.
// ---------------------------------------------------------------------------

struct Fixture {
    // `vault` is declared before its temp dir so it drops first.
    vault: Vault,
    _vault_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
    data: PathBuf,
    control: PathBuf,
    copy_root: PathBuf,
    original: String,
    copy: String,
    copy_parent: String,
    lease: CheckoutLeaseAct,
}

fn fixture(id_byte: u8) -> Fixture {
    let vault_dir = tempfile::tempdir().expect("vault tempdir");
    let vault = Vault::open(vault_dir.path(), VaultConfig::default()).expect("open vault");

    let root = tempfile::tempdir().expect("fixture root");
    let data = root.path().join("vault").join("data");
    let control = root.path().join("vault").join("control");
    std::fs::create_dir_all(&data).expect("data tree");
    std::fs::create_dir_all(&control).expect("control tree");
    std::fs::write(data.join("probe"), "data-secret").expect("data probe");
    std::fs::write(control.join("probe"), "control-secret").expect("control probe");

    // The canonical repo the lease pins, in the data tree.
    let canonical = data.join("canonical");
    std::fs::create_dir_all(&canonical).expect("canonical dir");
    git(&canonical, &["init", "--initial-branch=main"]);
    let original = commit_file(&canonical, "app.txt", "original\n", "original");

    // The masked copy: two commits of other bytes, pushed to a bare
    // store laid out as a projection copy store is.
    let copy_source = root.path().join("copy-source");
    std::fs::create_dir_all(&copy_source).expect("copy source dir");
    git(&copy_source, &["init", "--initial-branch=main"]);
    let copy_parent = commit_file(&copy_source, "app.txt", "masked base\n", "masked base");
    let copy = commit_file(&copy_source, "app.txt", "masked\n", "masked");
    let copy_root = data
        .join("repo-secret-projections")
        .join("store")
        .join("graph")
        .join("repo.git");
    std::fs::create_dir_all(copy_root.parent().expect("graph dir")).expect("graph dir");
    let copy_root_text = copy_root.to_string_lossy().into_owned();
    git(
        root.path(),
        &["init", "--bare", "--initial-branch=main", &copy_root_text],
    );
    git(
        &copy_source,
        &["push", &copy_root_text, "HEAD:refs/heads/main"],
    );

    let lease = CheckoutLeaseAct {
        checkout_id: CheckoutId::from_bytes([id_byte; 16]).expect("checkout id"),
        task_ref: EntityId::from_bytes([3; 16]).expect("task id"),
        repo_ref: RepoRef::LocalFolder {
            path: canonical.to_string_lossy().into_owned(),
            commit: original.clone(),
        },
        holder_ref: "masked-holder".to_owned(),
        epoch: 1,
        task_class: CheckoutTaskClass::Build,
        state: CheckoutLeaseState::Active,
        claimed_at: 1,
        lease_expires_at: None,
        updated_at: 1,
        bound_attempt: None,
    };
    Fixture {
        vault,
        _vault_dir: vault_dir,
        _root: root,
        data,
        control,
        copy_root,
        original,
        copy,
        copy_parent,
        lease,
    }
}

impl Fixture {
    fn receipt(&self) -> PushedHeadReceipt {
        PushedHeadReceipt {
            receipt_ref: "receipt:masked-checkout".to_owned(),
            observed_ref: "refs/heads/main".to_owned(),
            pushed_head: self.copy.clone(),
            checkout_id: self.lease.checkout_id,
            epoch: self.lease.epoch,
        }
    }

    fn inspect(&self) -> oneiron::checkout::CheckoutTeardownInspection {
        door::inspect_masked_copy_checkout(
            &self.vault,
            &self.lease,
            &self.copy_root,
            &self.original,
            &self.copy,
            &self.receipt(),
        )
        .expect("inspect the masked checkout")
    }
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|_| panic!("{} resolves", path.display()))
}

fn git_common_dir(tree: &Path) -> PathBuf {
    PathBuf::from(git(
        tree,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    ))
}

#[test]
fn a_masked_copys_checkout_is_self_contained_and_runs_git_under_the_fence() {
    let fixture = fixture(41);
    let tree = door::materialize_masked_copy_checkout(
        &fixture.vault,
        &fixture.lease,
        &fixture.copy_root,
        &fixture.original,
        &fixture.copy,
    )
    .expect("materialize the masked checkout");
    let handle = tree.parent().expect("checkout handle").to_path_buf();

    // The copy commit's files, and its whole history, are in the tree.
    assert_eq!(
        std::fs::read_to_string(tree.join("app.txt")).expect("checked-out file"),
        "masked\n"
    );
    assert_eq!(
        git(&tree, &["rev-parse", "--verify", "HEAD^{commit}"]),
        fixture.copy
    );
    assert_eq!(
        git(&tree, &["log", "--format=%H"]),
        format!("{}\n{}", fixture.copy, fixture.copy_parent)
    );

    // The repository the tree reads is its own, in the handle outside
    // the removed trees — never the copy store in the data tree. Before
    // the fix this was the copy store itself.
    let common = canonical(&git_common_dir(&tree));
    assert!(
        common.starts_with(canonical(&handle)),
        "git common dir {} is in the checkout handle {}",
        common.display(),
        handle.display()
    );
    assert!(
        !common.starts_with(canonical(&fixture.data)),
        "git common dir {} is outside the removed data tree",
        common.display()
    );

    // Teardown inspection sees a clean tree at the copy commit, then a
    // dirty one, through the checkout's own store.
    let inspection = fixture.inspect();
    assert_eq!(
        inspection.observed_head.map(|head| head.to_string()),
        Some(fixture.copy.clone())
    );
    assert!(!inspection.dirty, "a fresh checkout is clean");
    assert_eq!(inspection.receipt_match, TeardownReceiptMatch::Match);
    std::fs::write(tree.join("scratch.txt"), "work\n").expect("scratch file");
    assert!(fixture.inspect().dirty, "uncommitted work is dirty");
    std::fs::remove_file(tree.join("scratch.txt")).expect("remove scratch file");

    // A second materialize finds the same checkout standing.
    let again = door::materialize_masked_copy_checkout(
        &fixture.vault,
        &fixture.lease,
        &fixture.copy_root,
        &fixture.original,
        &fixture.copy,
    )
    .expect("materialize the standing masked checkout");
    assert_eq!(again, tree);
    assert_eq!(
        git(&tree, &["rev-parse", "--verify", "HEAD^{commit}"]),
        fixture.copy
    );

    // Under the fence that removes both vault trees, git in the tree
    // still reads its repository, and nothing of the removed trees is
    // readable: no carve-out was made for the copy store.
    let fence = RunnerFence::for_host([fixture.data.clone(), fixture.control.clone()])
        .expect("runner fence");
    if applied(&fence) {
        let git_binary = GitWireProcessEnv::capture()
            .expect("git process env")
            .git_binary()
            .to_path_buf();
        assert_eq!(
            fenced_git_stdout(
                &fence,
                &git_binary,
                &tree,
                &["rev-parse", "--verify", "HEAD^{commit}"]
            ),
            fixture.copy
        );
        assert_eq!(
            fenced_git_stdout(
                &fence,
                &git_binary,
                &tree,
                &["--no-optional-locks", "status", "--porcelain"]
            ),
            ""
        );
        assert_eq!(
            fenced_git_stdout(&fence, &git_binary, &tree, &["show", "HEAD:app.txt"]),
            "masked"
        );
        assert_eq!(
            reads(&fence, &fixture.data.join("probe")),
            None,
            "data tree read under the fence"
        );
        assert_eq!(
            reads(&fence, &fixture.control.join("probe")),
            None,
            "control tree read under the fence"
        );
        assert_eq!(
            reads(&fence, &fixture.copy_root.join("config")),
            None,
            "copy store read under the fence"
        );
    }

    // Collection removes the whole handle, its own store included, and
    // a second collection is a no-op. The copy store stands.
    door::collect_masked_copy_checkout(
        &fixture.vault,
        &fixture.lease,
        &fixture.copy_root,
        &fixture.original,
        &fixture.copy,
    )
    .expect("collect the masked checkout");
    assert!(!handle.exists(), "the handle is collected");
    assert!(fixture.copy_root.exists(), "the copy store stands");
    door::collect_masked_copy_checkout(
        &fixture.vault,
        &fixture.lease,
        &fixture.copy_root,
        &fixture.original,
        &fixture.copy,
    )
    .expect("collect the masked checkout again");
}

#[test]
fn a_linked_checkout_made_before_the_store_moved_still_inspects_and_collects() {
    let fixture = fixture(42);

    // Build the old on-disk shape by hand: a linked worktree of the
    // copy store, in the handle the lease's checkout uses.
    let wire = GitWire::new(&fixture.vault).expect("git wire");
    let copy_repo = wire
        .open_repo(
            RepoRef::LocalFolder {
                path: fixture.copy_root.to_string_lossy().into_owned(),
                commit: fixture.copy.clone(),
            },
            &fixture.copy_root,
        )
        .expect("open the copy store");
    let identity = copy_repo.identity().as_hex();
    let handle = std::env::temp_dir()
        .join(GIT_WIRE_CHECKOUT_ROOT_NAME)
        .join(&identity[..32])
        .join(format!(
            "{}-{}",
            fixture.lease.checkout_id, fixture.lease.epoch
        ));
    let tree = handle.join("tree");
    std::fs::create_dir_all(&handle).expect("checkout handle");
    let copy_oid = GitOid::parse_hex(fixture.copy.as_str()).expect("copy oid");
    wire.add_worktree(&copy_repo, &tree, &copy_oid, fixture.lease.updated_at)
        .expect("add the linked worktree");
    assert_eq!(
        canonical(&git_common_dir(&tree)),
        canonical(&fixture.copy_root),
        "the hand-built checkout is linked to the copy store"
    );

    // Inspection still reads it through the copy store.
    let inspection = fixture.inspect();
    assert_eq!(
        inspection.observed_head.map(|head| head.to_string()),
        Some(fixture.copy.clone())
    );
    assert!(!inspection.dirty, "the linked checkout is clean");
    assert_eq!(inspection.receipt_match, TeardownReceiptMatch::Match);

    // Collection removes it and reconciles the copy store's
    // registration, and a second collection is a no-op.
    door::collect_masked_copy_checkout(
        &fixture.vault,
        &fixture.lease,
        &fixture.copy_root,
        &fixture.original,
        &fixture.copy,
    )
    .expect("collect the linked checkout");
    assert!(!handle.exists(), "the handle is collected");
    let leaf = format!("{}-{}/tree", fixture.lease.checkout_id, fixture.lease.epoch);
    assert!(
        wire.list_worktrees(&copy_repo)
            .expect("list the copy store's worktrees")
            .iter()
            .all(|path| !path.ends_with(&leaf)),
        "the copy store no longer registers the collected tree"
    );
    door::collect_masked_copy_checkout(
        &fixture.vault,
        &fixture.lease,
        &fixture.copy_root,
        &fixture.original,
        &fixture.copy,
    )
    .expect("collect the linked checkout again");
}
