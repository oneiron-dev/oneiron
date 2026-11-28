//! Row OWNER-CONFIRM-SHEET, PR 4b-5: a vault the embedded client opens in
//! its caller's own process takes the process's presence gate beside its
//! keystore, so an important owner act asks through this device's own
//! unlock prompt. A handle attached to a host's vault installs nothing: it
//! keeps what its host installed, and a serving host installs no gate.

use std::sync::Arc;

use oneiron::{Vault, VaultConfig};
use oneiron_remote::{OneironClient, OpenOptions};

/// The open needs the platform's default keystore: on Linux a key directory
/// under `XDG_STATE_HOME` or `HOME`, as every embedded open of this crate's
/// tests does.
#[test]
fn an_embedded_open_leaves_a_presence_gate_beside_its_keystore() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let client =
        OneironClient::open(Some(dir.path()), &OpenOptions::default()).expect("an embedded open");
    assert_eq!(
        client.vault_holds_presence_gate(),
        Some(true),
        "an embedded open with the platform's default keystore installed"
    );
}

/// The host's vault holds a keystore and no gate, as a serving host's does:
/// an attach that installed the gate beside a keystore, as the open does,
/// would show here. It needs the platform's default keystore too.
#[test]
fn a_handle_attached_to_a_host_vault_installs_no_gate() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let vault =
        Arc::new(Vault::open_owned(dir.path(), VaultConfig::default()).expect("the host's vault"));
    vault.install_default_keystore(dir.path());
    assert!(
        vault.device_keystore_assurance().is_some(),
        "the host's vault holds the platform's default keystore"
    );
    assert!(vault.presence_gate().is_none());
    let client = OneironClient::attach(dir.path(), Arc::clone(&vault), &OpenOptions::default())
        .expect("a handle on the host's vault");
    assert_eq!(client.vault_holds_presence_gate(), Some(false));
    assert!(vault.presence_gate().is_none());
}
