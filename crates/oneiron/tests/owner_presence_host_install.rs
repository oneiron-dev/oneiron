//! Row OWNER-CONFIRM-SHEET, PR 4b-5: a host whose caller is at the device
//! puts the process's one presence gate on its vault handle
//! (`Vault::install_process_presence_gate`), so an important owner act asks
//! through the device's own unlock prompt. Every handle of the process takes
//! the same gate, and a gate installed before stays.
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

/// On a platform with no prompt the process's gate answers as a device that
/// cannot ask, so an important act stands as it does on a handle with no
/// gate: installing the gate changes nothing there.
#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn an_important_act_stands_on_a_platform_without_a_prompt() {
    let (vault, _dir) = open_vault();
    vault.install_process_presence_gate();
    // The answer below is also a handle's with no gate: this one holds the
    // process's gate, so it is the gate's own answer.
    assert!(Arc::ptr_eq(
        &installed_gate(&vault),
        &PresenceGate::process_wide()
    ));
    let witness = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("the act stands");
    assert_eq!(witness.basis(), OwnerPresenceBasis::DeviceCannotAsk);
}
