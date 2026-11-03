//! The content-free panic report a host installs before it opens a vault.
//!
//! Rust's default panic hook prints the panic payload, and a payload is
//! arbitrary text: an `expect` on a parsed body, a `{row:?}` in an assert, a
//! provider response echoed into a message. Crash reports never carry world
//! text (owner ruling 2026-10-14), so [`install_panic_hook`] replaces the hook
//! with a report of where the panic happened and a stable kind. The payload is
//! never read, so nothing has to be scrubbed out of it.
//!
//! The hook runs before any `catch_unwind` returns, so a caught panic (a
//! Dreamer executor's, for one) still reaches it. The library never installs
//! it on its own: the hook is process-global and belongs to the host. Every
//! first-party host (the server binaries, the broker, the bindings, the bench)
//! installs it before it opens a vault, and an embedder should do the same.

use std::backtrace::{Backtrace, BacktraceStatus};
use std::panic::PanicHookInfo;

/// The kind every panic report carries.
pub const PANIC_KIND: &str = "panic";

/// Replaces the process panic hook with the content-free report. A host calls
/// it before it opens a vault; calling it again installs the same report.
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
        // host that has none, the report still has to land somewhere.
        eprintln!("{PANIC_KIND} at {location} on thread {thread}; payload withheld");
        if let Some(backtrace) = backtrace {
            eprintln!("{backtrace}");
        }
    }
}
