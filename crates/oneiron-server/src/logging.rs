//! What the binaries write to their log sinks, and the panic hook.
//!
//! Logs and crash reports never carry world text (owner ruling 2026-10-14).
//! Both sinks (the normal one and managed mode's) build their subscriber here,
//! so a check run through [`subscriber`] is a check of what production writes.
//!
//! Rust's default panic hook prints the panic payload, and a payload is
//! arbitrary text: an `expect` on a parsed body, a `{row:?}` in an assert, a
//! provider response echoed into a message. [`install_panic_hook`] replaces it
//! with a report of where the panic happened and a stable kind. The payload is
//! never read, so nothing has to be scrubbed out of it.

use std::backtrace::{Backtrace, BacktraceStatus};
use std::panic::PanicHookInfo;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// The kind every panic report carries.
pub const PANIC_KIND: &str = "panic";

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

/// Replaces the process panic hook. Every binary calls this first.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(report_panic));
}

fn report_panic(info: &PanicHookInfo<'_>) {
    let location = info.location().map_or_else(
        || "unknown".to_owned(),
        |at| format!("{}:{}:{}", at.file(), at.line(), at.column()),
    );
    let thread = std::thread::current();
    let thread = thread.name().unwrap_or("unnamed");
    // Frames name code, not data. Captured only when RUST_BACKTRACE asks.
    let backtrace = Backtrace::capture();
    let backtrace = (backtrace.status() == BacktraceStatus::Captured).then_some(backtrace);
    let subscribed = tracing::dispatcher::get_default(|dispatch| {
        !dispatch.is::<tracing::subscriber::NoSubscriber>()
    });
    if subscribed {
        tracing::error!(
            target: "oneiron::panic",
            kind = PANIC_KIND,
            %location,
            thread,
            backtrace = backtrace.as_ref().map(tracing::field::display),
            "thread panicked; payload withheld"
        );
    } else {
        // Before a subscriber is up (argument parsing, config load), or in a
        // binary that has none, the report still has to land somewhere.
        eprintln!("{PANIC_KIND} at {location} on thread {thread}; payload withheld");
        if let Some(backtrace) = backtrace {
            eprintln!("{backtrace}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
