//! `oneiron-vm-init`: a vault VM's root bootstrap, run by the image's init
//! before the engine (`managed::run_vm_init`). Linux only: it is the guest's.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    oneiron_server::logging::install_panic_hook();
    oneiron_server::managed::run_vm_init()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("oneiron-vm-init runs only inside a Linux vault VM");
    std::process::ExitCode::FAILURE
}
