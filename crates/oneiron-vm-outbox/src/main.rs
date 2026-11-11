//! `oneiron-vm-outbox`: a vault VM's root outbox companion, started by
//! `oneiron-vm-init` beside the engine (`managed::run_vm_outbox`, FIX 5235).
//! Linux only: it is the guest's.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    oneiron_server::logging::install_panic_hook();
    oneiron_server::managed::run_vm_outbox()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("oneiron-vm-outbox runs only inside a Linux vault VM");
    std::process::ExitCode::FAILURE
}
