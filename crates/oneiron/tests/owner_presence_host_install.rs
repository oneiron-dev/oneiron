//! Row OWNER-CONFIRM-SHEET, PR 4b-5: a host whose caller is at the device
//! puts the process's one presence gate on its vault handle, so an important
//! owner act asks through the device's own unlock prompt. Every handle of
//! the process takes the same gate, a gate installed before stays, and the
//! default keystore install leaves the gate beside the keystore. A host
//! whose handle also answers other machines installs the keystore with no
//! gate.
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::world_keys::{OwnerActImportance, OwnerPresenceBasis};
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::{ManualPresenceClock, PresenceGate, PresenceWindow, ScriptedPresence};
use tempfile::TempDir;

const REASON: &str = "confirm a change to your vault";

fn open_vault() -> (Vault, TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (vault, dir)
}

/// A gate over a prompt that says yes once, as a host with a prompt of its
/// own installs it.
fn install_scripted_gate(vault: &Vault) -> (Arc<PresenceGate>, Arc<ScriptedPresence>) {
    let presence = Arc::new(ScriptedPresence::new([Ok(())]));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = Arc::new(PresenceGate::new(presence.clone(), window));
    vault.install_presence_gate(Arc::clone(&gate));
    (gate, presence)
}

fn installed_gate(vault: &Vault) -> Arc<PresenceGate> {
    vault.presence_gate().expect("the handle holds a gate")
}

#[test]
fn a_handle_holds_no_gate_until_its_host_installs_one() {
    let (vault, _dir) = open_vault();
    assert!(vault.presence_gate().is_none());
    vault.install_process_presence_gate();
    assert!(Arc::ptr_eq(
        &installed_gate(&vault),
        &PresenceGate::process_wide()
    ));
}

#[test]
fn two_handles_take_the_one_gate_of_the_process() {
    let (first, _first_dir) = open_vault();
    let (second, _second_dir) = open_vault();
    first.install_process_presence_gate();
    second.install_process_presence_gate();
    assert!(Arc::ptr_eq(
        &installed_gate(&first),
        &installed_gate(&second)
    ));
}

#[test]
fn a_second_install_keeps_the_same_gate() {
    let (vault, _dir) = open_vault();
    vault.install_process_presence_gate();
    let before = installed_gate(&vault);
    vault.install_process_presence_gate();
    assert!(Arc::ptr_eq(&before, &installed_gate(&vault)));
}

/// A host with a prompt of its own installed its gate first: the process's
/// gate does not take its place, and an important act asks the host's prompt.
#[test]
fn a_gate_installed_before_stays() {
    let (vault, _dir) = open_vault();
    let (gate, _presence) = install_scripted_gate(&vault);
    vault.install_process_presence_gate();
    assert!(Arc::ptr_eq(&gate, &installed_gate(&vault)));
    let witness = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("the host's own prompt says yes");
    assert_eq!(witness.basis(), OwnerPresenceBasis::Prompted);
}

/// The call of a host that opens the vault in its own process (the embedded
/// clients, the C ABI, the macOS recorder). It needs a platform keystore:
/// on Linux a key directory under `XDG_STATE_HOME` or `HOME`.
#[test]
fn the_default_keystore_install_leaves_the_process_gate_beside_the_keystore() {
    let (vault, dir) = open_vault();
    vault.install_default_keystore(dir.path());
    assert!(
        vault.device_keystore_assurance().is_some(),
        "this test needs the platform's default keystore: on Linux, XDG_STATE_HOME or HOME"
    );
    assert!(Arc::ptr_eq(
        &installed_gate(&vault),
        &PresenceGate::process_wide()
    ));
}

#[test]
fn the_default_keystore_install_keeps_a_gate_installed_before() {
    let (vault, dir) = open_vault();
    let (gate, _presence) = install_scripted_gate(&vault);
    vault.install_default_keystore(dir.path());
    assert!(Arc::ptr_eq(&gate, &installed_gate(&vault)));
}

/// The call of a host whose handle also answers other machines (the macOS
/// recorder's device link): the same keystore, and no gate, so a caller on
/// another machine raises no prompt on this device.
#[test]
fn the_default_keystore_install_without_a_gate_leaves_none() {
    let (vault, dir) = open_vault();
    vault.install_default_keystore_without_presence_gate(dir.path());
    assert!(
        vault.device_keystore_assurance().is_some(),
        "this test needs the platform's default keystore: on Linux, XDG_STATE_HOME or HOME"
    );
    assert!(vault.presence_gate().is_none());
}

/// On a platform with no prompt the process's gate answers as a device that
/// cannot ask, so an important act stands as it does on a handle with no
/// gate: installing the gate changes nothing there.
#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn an_important_act_stands_on_a_platform_without_a_prompt() {
    let (vault, _dir) = open_vault();
    vault.install_process_presence_gate();
    let witness = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("the act stands");
    assert_eq!(witness.basis(), OwnerPresenceBasis::DeviceCannotAsk);
}
