//! The code-mode refusals of the `self.desktop.*` and `self.browser.*` rows,
//! through the composed call `McpCodeModeVerbs` serves a run's guest: the
//! binding admission, the credential gate, then the run-guest admission, in
//! that order, before any guest acts.
//!
//! A credential that binds an unrelated name answers `mcp_verb_not_bound` on
//! every row; a bound read-only credential answers `mcp_auth_required` on the
//! Write rows, and its Read rows reach the pack gate; a bound write-scoped
//! credential with no guest answers `browser_pack_not_installed` on a fresh
//! vault, and with the pack seed marker removed answers `browser_unbound` on
//! desktop rows and `browser_connection_unchecked` on browser rows. A bound
//! write-scoped credential on a run with a desktop guest configured passes
//! every gate. The composed answer keeps the refusal code only; the two
//! gateway messages are pinned through the gates, which also prove the
//! control stops before any guest starts. No QuickJS host, model, or guest
//! starts: the door resolves the credential and drives the production door,
//! and the guest is only ever checked for, never started.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! code_mode_host_verb_refusals`.
//!
//! Canon: the program calls the browser host verbs ("A mid planner tier writes
//! one batched code-mode program for each subgoal. The program calls the
//! browser host verbs, and decide() for routine choices."
//! `/Users/olety/Desktop/code/oneiron-docs/generated/llms-full.txt:328717`);
//! a run row needs its own binding ("A run row needs its own binding on the
//! credential, or it gets `mcp_verb_not_bound`."
//! `/Users/olety/Desktop/code/oneiron-docs/generated/llms-full.txt:344746`);
//! without browser config the verbs return `browser_unbound` ("Without browser
//! config, the verbs return `browser_unbound`."
//! `/Users/olety/Desktop/code/oneiron-docs/generated/llms-full.txt:49076`).
//! No canon line names `browser_pack_not_installed` or
//! `browser_connection_unchecked`, or the desktop rows; the nearest desktop
//! line is the code-mode execution doc's screenshot trigger
//! (`llms-full.txt` carries `eiri-arch-0002-code-mode-execution.md:171`: "or a
//! desktop step has no accessibility tree.").
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_browser::{DesktopGuest, GuestLimits, SendPolicy};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::code_mode_verbs::{
    TestCredential, admit_host_verb, admits_guest, call_verb, gate_host_verb, register_credential,
};

/// The twenty desktop rows (`scripts/sdk/verbs/self.desktop.*.json`).
const DESKTOP_ROWS: [&str; 20] = [
    "self.desktop.batch",
    "self.desktop.click",
    "self.desktop.click_at",
    "self.desktop.crop",
    "self.desktop.expect",
    "self.desktop.find",
    "self.desktop.handover",
    "self.desktop.hotkey",
    "self.desktop.key",
    "self.desktop.observe",
    "self.desktop.open",
    "self.desktop.screenshot",
    "self.desktop.scroll",
    "self.desktop.select",
    "self.desktop.type",
    "self.desktop.view",
    "self.desktop.wait_for",
    "self.desktop.window",
    "self.desktop.windows",
    "self.desktop.zoom",
];

/// The twenty-four browser rows (`scripts/sdk/verbs/self.browser.*.json`).
const BROWSER_ROWS: [&str; 24] = [
    "self.browser.batch",
    "self.browser.click",
    "self.browser.click_at",
    "self.browser.crop",
    "self.browser.demonstration.start",
    "self.browser.demonstration.stop",
    "self.browser.expect",
    "self.browser.find",
    "self.browser.handover",
    "self.browser.library.draft",
    "self.browser.library.find",
    "self.browser.library.propose",
    "self.browser.library.retired",
    "self.browser.library.retire",
    "self.browser.library.run",
    "self.browser.observe",
    "self.browser.open",
    "self.browser.screenshot",
    "self.browser.select",
    "self.browser.switch_engine",
    "self.browser.type",
    "self.browser.view",
    "self.browser.wait_for",
    "self.browser.zoom",
];

/// The Write rows among both families (`"scope": "Write"` at each json `:7`):
/// 9 desktop + 13 browser. Only these meet the Write grant check.
const WRITE_ROWS: [&str; 22] = [
    "self.desktop.batch",
    "self.desktop.click",
    "self.desktop.click_at",
    "self.desktop.handover",
    "self.desktop.hotkey",
    "self.desktop.key",
    "self.desktop.open",
    "self.desktop.select",
    "self.desktop.type",
    "self.browser.batch",
    "self.browser.click",
    "self.browser.click_at",
    "self.browser.demonstration.start",
    "self.browser.demonstration.stop",
    "self.browser.handover",
    "self.browser.library.propose",
    "self.browser.library.retire",
    "self.browser.library.run",
    "self.browser.open",
    "self.browser.select",
    "self.browser.switch_engine",
    "self.browser.type",
];

/// The Read rows among both families: 11 desktop + 11 browser. A read-only
/// credential passes the gate on these, so the composed call reaches the
/// guest admission with them.
const READ_ROWS: [&str; 22] = [
    "self.desktop.crop",
    "self.desktop.expect",
    "self.desktop.find",
    "self.desktop.observe",
    "self.desktop.screenshot",
    "self.desktop.scroll",
    "self.desktop.view",
    "self.desktop.wait_for",
    "self.desktop.window",
    "self.desktop.windows",
    "self.desktop.zoom",
    "self.browser.crop",
    "self.browser.expect",
    "self.browser.find",
    "self.browser.library.draft",
    "self.browser.library.find",
    "self.browser.library.retired",
    "self.browser.observe",
    "self.browser.screenshot",
    "self.browser.view",
    "self.browser.wait_for",
    "self.browser.zoom",
];

/// A device vault with a fresh server that configures no guest.
struct DoorFixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
}

async fn door_fixture(secret: &str) -> DoorFixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in BEFORE the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(secret.into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    DoorFixture {
        _dir: dir,
        vault,
        server,
    }
}

/// A desktop guest configuration that is never started: the admission checks
/// only that one is configured.
fn idle_desktop_config() -> DesktopGuest {
    DesktopGuest {
        runtime: PathBuf::from("/nonexistent"),
        image: "never-pulled".to_owned(),
        limits: GuestLimits {
            memory_mib: 512,
            cpu_millis: 500,
            pids: 64,
            tmpfs_mib: 64,
        },
        wait_cap: Duration::from_secs(1),
        policy: SendPolicy::default(),
    }
}

async fn bound_write_credential(fixture: &DoorFixture, seed: u8) -> TestCredential {
    register_credential(&fixture.server, seed, &["read", "write"], None)
        .await
        .expect("a bound write credential registers")
}

/// A credential that binds an unrelated name answers `mcp_verb_not_bound` on
/// the composed call, on every desktop and browser row. The gateway's message
/// is pinned through the admission: the composed answer drops it.
#[tokio::test]
async fn unbound_credential_is_refused_before_any_gate() {
    let fixture = door_fixture("code-mode-unbound").await;
    let outsider = register_credential(
        &fixture.server,
        0xA1,
        &["read", "write"],
        Some(&["vault.recall"]),
    )
    .await
    .expect("the narrow credential registers");
    let run = EntityId::now();
    for verb in DESKTOP_ROWS.into_iter().chain(BROWSER_ROWS) {
        let refused = call_verb(&fixture.server, &outsider, run, verb)
            .await
            .expect("the composed call runs")
            .expect_err("an unbound row is refused");
        assert_eq!(refused.code, "mcp_verb_not_bound", "{verb}");
        assert_eq!(refused.hook_notice, None, "{verb}");
        let dropped = admit_host_verb(&fixture.server, &outsider, verb)
            .await
            .expect("admission runs")
            .expect_err("an unbound row is refused");
        assert_eq!(
            dropped.message,
            format!("{verb} is not bound to this connector credential"),
            "{verb}"
        );
    }
}

/// A bound read-only credential answers `mcp_auth_required` on the composed
/// call, on every Write row; its Read rows pass both gates and reach the pack
/// gate. The gateway's message is pinned through the gate: the composed
/// answer drops it.
#[tokio::test]
async fn read_only_credential_is_refused_on_write_rows() {
    let fixture = door_fixture("code-mode-read-only").await;
    let reader = register_credential(&fixture.server, 0xB2, &["read"], None)
        .await
        .expect("the read-only credential registers");
    let run = EntityId::now();
    for verb in WRITE_ROWS {
        let refused = call_verb(&fixture.server, &reader, run, verb)
            .await
            .expect("the composed call runs")
            .expect_err("a Write row needs Write");
        assert_eq!(refused.code, "mcp_auth_required", "{verb}");
        assert_eq!(refused.hook_notice, None, "{verb}");
        let dropped = gate_host_verb(&fixture.server, &reader, verb)
            .await
            .expect("the gate runs")
            .expect_err("a Write row needs Write");
        assert_eq!(
            dropped.message, "the registered connector requires its live paired holder proof",
            "{verb}"
        );
    }
    for verb in READ_ROWS {
        let refused = call_verb(&fixture.server, &reader, run, verb)
            .await
            .expect("the composed call runs")
            .expect_err("a Read row passes the gates");
        assert_eq!(refused.code, "browser_pack_not_installed", "{verb}");
        assert_eq!(refused.hook_notice, None, "{verb}");
    }
}

/// A bound write-scoped credential with no guest answers
/// `browser_pack_not_installed` on the composed call, on every row of a fresh
/// vault. Reaching the guest code proves both gates passed, in order.
#[tokio::test]
async fn bound_write_credential_without_guest_hits_pack_gate_on_fresh_vault() {
    let fixture = door_fixture("code-mode-pack").await;
    let writer = bound_write_credential(&fixture, 0xC3).await;
    let run = EntityId::now();
    for verb in DESKTOP_ROWS.into_iter().chain(BROWSER_ROWS) {
        let refused = call_verb(&fixture.server, &writer, run, verb)
            .await
            .expect("the composed call runs")
            .expect_err("no pack is installed");
        assert_eq!(refused.code, "browser_pack_not_installed", "{verb}");
        assert_eq!(refused.hook_notice, None, "{verb}");
    }
}

/// With the pack seed marker removed and still no guest, the composed call
/// answers `browser_unbound` on desktop rows and
/// `browser_connection_unchecked` on browser rows. Reaching the guest codes
/// proves both gates passed, in order.
#[tokio::test]
async fn without_pack_seed_desktop_is_unbound_and_browser_needs_its_connection() {
    let fixture = door_fixture("code-mode-unbound").await;
    oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&fixture.vault)
        .expect("the seed marker is removed");
    let writer = bound_write_credential(&fixture, 0xD4).await;
    let run = EntityId::now();
    for verb in DESKTOP_ROWS {
        let refused = call_verb(&fixture.server, &writer, run, verb)
            .await
            .expect("the composed call runs")
            .expect_err("no desktop guest is configured");
        assert_eq!(refused.code, "browser_unbound", "{verb}");
        assert_eq!(refused.hook_notice, None, "{verb}");
    }
    for verb in BROWSER_ROWS {
        let refused = call_verb(&fixture.server, &writer, run, verb)
            .await
            .expect("the composed call runs")
            .expect_err("no browser connection is checked");
        assert_eq!(refused.code, "browser_connection_unchecked", "{verb}");
        assert_eq!(refused.hook_notice, None, "{verb}");
    }
}

/// A bound write-scoped credential on a run with a desktop guest configured
/// passes the binding admission, the credential gate, and the guest admission
/// on every desktop row. The guest is never started: the test stops at the
/// admission, before any guest call. Browser rows have no such control: their
/// admission also needs a verified pack connection, which no test seam marks.
#[tokio::test]
async fn bound_write_credential_with_desktop_guest_passes_every_gate() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("code-mode-guest".into()),
                ..Default::default()
            },
        )
        .expect("create server")
        .with_desktop_guest(Some(idle_desktop_config())),
    );
    oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&vault)
        .expect("the seed marker is removed");
    let writer = register_credential(&server, 0xE5, &["read", "write"], None)
        .await
        .expect("a bound write credential registers");
    let run = EntityId::now();
    for verb in DESKTOP_ROWS {
        admit_host_verb(&server, &writer, verb)
            .await
            .expect("admission runs")
            .expect("a bound row passes admission");
        gate_host_verb(&server, &writer, verb)
            .await
            .expect("the gate runs")
            .expect("a write credential passes the gate");
        admits_guest(&server, run, verb)
            .expect("admission runs")
            .expect("a configured guest admits the run");
    }
}
