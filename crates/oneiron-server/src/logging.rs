//! What the binaries write to their log sinks, and the panic hook.
//!
//! Logs and crash reports never carry world text (owner ruling 2026-10-14).
//! Both sinks (the normal one and managed mode's) build their subscriber here,
//! so a check run through `subscriber` is a check of what production writes.
//!
//! Rust's default panic hook prints the panic payload, and a payload is
//! arbitrary text. [`install_panic_hook`] is the engine's content-free report
//! (`oneiron::panic_report`): where the panic happened and a stable kind,
//! never the payload.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The engine's content-free panic report; every binary installs it first.
pub use oneiron::panic_report::{PANIC_KIND, install_panic_hook};

/// The subscriber both log sinks install.
pub(crate) fn subscriber<W>(filter: EnvFilter, writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .finish()
}

/// The engine's stable kind for an `anyhow` chain, when one of its causes is
/// an engine error. Logged in place of the chain, whose text can echo input.
pub(crate) fn engine_kind(error: &anyhow::Error) -> Option<oneiron::ErrorKind> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<oneiron::Error>())
        .map(oneiron::Error::kind)
}

#[cfg(test)]
pub(crate) mod tests;
