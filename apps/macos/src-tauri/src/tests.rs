//! The recorder's own vault door.

/// Set when `a_panic_after_the_recorder_opens_its_vault_prints_no_payload`
/// starts this test binary as its child.
const PANIC_CHILD_ENV: &str = "ONEIRON_TEST_MACOS_PANIC_CHILD";

/// The child half of `a_panic_after_the_recorder_opens_its_vault_prints_no_payload`:
/// opens a vault through the recorder's door, then panics with row text. A
/// no-op unless that check started it.
#[test]
fn recorder_panic_child() {
    if std::env::var_os(PANIC_CHILD_ENV).is_none() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = super::open_vault_at(&dir.path().join(super::VAULT_DIR)).expect("open vault");
    let caught =
        std::panic::catch_unwind(|| panic!("could not parse segment: sentinel-world-text-5c2a"));
    assert!(caught.is_err());
    drop(vault);
    eprintln!("recorder panic child: done");
}

/// Owner ruling 2026-10-14 (fix 6): crash output never carries world text.
/// The recorder embeds the engine, so its vault door installs the engine's
/// panic hook. The hook is process-global and stderr is the sink, so the
/// panic runs in a child.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "a test starts its own binary as a child to read its stderr"
)]
fn a_panic_after_the_recorder_opens_its_vault_prints_no_payload() {
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "tests::recorder_panic_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PANIC_CHILD_ENV, "1")
        .output()
        .expect("the child test runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for shown in [&stdout, &stderr] {
        assert!(!shown.contains("sentinel-world-text-5c2a"), "{shown}");
    }
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("recorder panic child: done"), "{stderr}");
    assert!(stderr.contains("payload withheld"), "{stderr}");
}
