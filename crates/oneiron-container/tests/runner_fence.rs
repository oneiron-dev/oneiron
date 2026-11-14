//! The runner fence (canon `#runner-fence`, row L8-27): a runner the daemon
//! starts cannot read or write the vault's data and control trees, and keeps
//! its checkout and the rest of the host; the fence proves itself and its
//! proof goes on the session manifest; a host without a mechanism still runs
//! the runner, unproven (canon `#fence-unproven`).
#![cfg(unix)]

use oneiron_container::{GuestSeccomp, RunnerFence, RunnerFenceMechanism};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

/// A vault's two trees, a checkout beside them, a file beside the trees
/// inside the vault, and a link into the data tree.
struct Layout {
    _root: tempfile::TempDir,
    data: PathBuf,
    control: PathBuf,
    checkout: PathBuf,
    beside: PathBuf,
    link: PathBuf,
}

fn layout() -> Layout {
    let root = tempfile::tempdir().expect("temp root");
    let vault = root.path().join("vault");
    let data = vault.join("data");
    let control = vault.join("control");
    let checkout = root.path().join("checkout");
    for dir in [&data, &control, &checkout] {
        fs::create_dir_all(dir).expect("layout directory");
    }
    fs::write(data.join("probe"), "data-secret").expect("data probe");
    fs::write(control.join("probe"), "control-secret").expect("control probe");
    fs::write(checkout.join("probe"), "checkout-file").expect("checkout probe");
    let beside = vault.join("notes.txt");
    fs::write(&beside, "beside-the-trees").expect("file beside the trees");
    let link = root.path().join("data-link");
    std::os::unix::fs::symlink(&data, &link).expect("link into the data tree");
    Layout {
        _root: root,
        data,
        control,
        checkout,
        beside,
        link,
    }
}

fn vault_fence(layout: &Layout) -> RunnerFence {
    RunnerFence::for_host([layout.data.clone(), layout.control.clone()]).expect("runner fence")
}

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

fn run(fence: &RunnerFence, program: &str, args: &[&OsString]) -> Output {
    fence
        .command(program)
        .expect("fenced command")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the runner started")
}

/// What `cat` under the fence read from `path`, or `None` where it failed.
fn reads(fence: &RunnerFence, path: &Path) -> Option<String> {
    let output = run(fence, "/bin/cat", &[&path.as_os_str().to_owned()]);
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether `sh` under the fence wrote `text` into a new file at `path`.
fn writes(fence: &RunnerFence, path: &Path, text: &str) -> bool {
    let script = OsString::from("printf %s \"$1\" > \"$2\"");
    let output = run(
        fence,
        "/bin/sh",
        &[
            &OsString::from("-c"),
            &script,
            &OsString::from("sh"),
            &OsString::from(text),
            &path.as_os_str().to_owned(),
        ],
    );
    output.status.success()
}

#[test]
fn a_fenced_runner_cannot_read_or_write_the_vault_trees() {
    let layout = layout();
    let fence = vault_fence(&layout);
    if !applied(&fence) {
        return;
    }
    assert_eq!(
        reads(&fence, &layout.data.join("probe")),
        None,
        "data tree read"
    );
    assert_eq!(
        reads(&fence, &layout.control.join("probe")),
        None,
        "control tree read"
    );
    assert_eq!(
        reads(&fence, &layout.link.join("probe")),
        None,
        "data tree read through a link beside it"
    );
    let planted = layout.data.join("planted");
    assert!(!writes(&fence, &planted, "planted"), "data tree written");
    assert!(!planted.exists(), "a file appeared in the data tree");
    let listed = run(&fence, "/bin/ls", &[&layout.control.as_os_str().to_owned()]);
    assert!(!listed.status.success(), "control tree listed");
}

#[test]
fn a_fenced_runner_keeps_its_checkout_and_the_rest_of_the_host() {
    let layout = layout();
    let fence = vault_fence(&layout);
    if !applied(&fence) {
        return;
    }
    assert_eq!(
        reads(&fence, &layout.checkout.join("probe")).as_deref(),
        Some("checkout-file")
    );
    assert_eq!(
        reads(&fence, &layout.beside).as_deref(),
        Some("beside-the-trees"),
        "a file beside the trees stays the runner's"
    );
    let made = layout.checkout.join("made");
    assert!(writes(&fence, &made, "made"), "checkout write refused");
    assert_eq!(fs::read_to_string(made).expect("made file"), "made");
    assert_eq!(
        reads(&fence, Path::new("/etc/hosts")).is_some(),
        Path::new("/etc/hosts").is_file(),
        "a system file outside the vault"
    );
}

#[test]
fn the_fence_proves_itself_and_its_proof_goes_on_the_session_manifest() {
    let layout = layout();
    let fence = vault_fence(&layout);
    if !applied(&fence) {
        return;
    }
    let outcome = fence.prove();
    assert!(outcome.proven, "proof failed: {outcome:?}");
    assert_eq!(outcome.mechanism, fence.mechanism());
    assert_eq!(outcome.ruleset_hash, fence.ruleset_hash());
    let argv = [OsString::from("claude"), OsString::from("-p")];
    let manifest = outcome.session_manifest("runner:seat", "claude", &argv);
    assert_eq!(manifest.backend, "runner:seat");
    assert_eq!(manifest.network, "host");
    assert_eq!(manifest.seccomp, GuestSeccomp::Unfiltered);
    assert!(!manifest.fence_unproven);
    let proof = manifest
        .fence_proof
        .expect("a proven session carries its proof");
    assert_eq!(proof.ruleset_hash, fence.ruleset_hash());
    assert_eq!(proof.ruleset_hash.len(), 64);
    assert!(proof.ruleset_hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(proof.sandbox_generation, outcome.sandbox_generation);
    assert_ne!(
        manifest.generation,
        outcome
            .session_manifest("runner:seat", "claude", &argv)
            .generation,
        "each session has its own generation"
    );
}

#[test]
fn the_ruleset_hash_names_the_removed_trees() {
    let layout = layout();
    let one = vault_fence(&layout).ruleset_hash();
    let reordered = RunnerFence::for_host([layout.control.clone(), layout.data.clone()])
        .expect("runner fence")
        .ruleset_hash();
    let other = RunnerFence::for_host([layout.data.clone(), layout.checkout.clone()])
        .expect("runner fence")
        .ruleset_hash();
    assert_eq!(one, reordered, "the hash names the rule, not the order");
    assert_ne!(one, other, "another tree is another rule");
    assert_eq!(one.len(), 64);
}

#[test]
fn a_host_without_the_fence_runs_the_runner_unproven() {
    let layout = layout();
    let fence = RunnerFence::unavailable([layout.data.clone(), layout.control.clone()])
        .expect("runner fence");
    assert_eq!(fence.mechanism(), RunnerFenceMechanism::Unavailable);
    assert_eq!(
        reads(&fence, &layout.data.join("probe")).as_deref(),
        Some("data-secret"),
        "the run goes on, unfenced"
    );
    let outcome = fence.prove();
    assert!(!outcome.proven);
    let manifest = outcome.session_manifest("runner:seat", "claude", &[OsString::from("claude")]);
    assert!(manifest.fence_unproven);
    assert!(
        manifest.fence_proof.is_none(),
        "no ruleset hash is recorded"
    );
    let receipt = serde_json::to_value(&manifest).expect("manifest json");
    assert_eq!(receipt["fence_unproven"], serde_json::Value::Bool(true));
    assert!(receipt.get("fence_proof").is_none());
}

#[test]
fn a_relative_or_missing_tree_is_refused() {
    let relative = RunnerFence::for_host([PathBuf::from("vault/data")]).expect_err("relative");
    assert_eq!(relative.kind(), std::io::ErrorKind::InvalidInput);
    let none = RunnerFence::for_host(Vec::<PathBuf>::new()).expect_err("no tree");
    assert_eq!(none.kind(), std::io::ErrorKind::InvalidInput);
}
