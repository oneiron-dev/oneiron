//! The seal organ's process: serves the host on the socket it passes.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    oneiron_organ_protocol::serve(oneiron_seal::organ::SealOrgan)
}

#[cfg(not(unix))]
fn main() {}
