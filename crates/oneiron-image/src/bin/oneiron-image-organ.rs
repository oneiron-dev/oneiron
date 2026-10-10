//! The image organ's process: serves the host on the socket it passes.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    oneiron_organ_protocol::serve(oneiron_image::ImageOrgan::default())
}

#[cfg(not(unix))]
fn main() {}
