//! Builds an awaited future in its own stack frame and boxes it.
//!
//! At opt-level 0 an async fn's poll function gives every future it awaits
//! its own stack slot, and those slots do not overlap, so a poll frame is
//! about the sum of the futures it awaits; every enclosing future also holds
//! its children inline. A Dreamer wake pass nests a whole consolidation under
//! the driver's pass loop, and in a dev build a turn wake's micro
//! consolidation overflowed a default 2 MiB thread (FIX
//! DREAMER-MICRO-CONSOLIDATION-DEV-STACK-DEPTH; production polls engine
//! futures on 32 MiB threads). Awaiting the box [`build_boxed_future`]
//! returns keeps only the closure's captures and one pointer in the caller's
//! frame and state: the concrete future is built in the helper's own frame,
//! which returns before the future is first polled. The same shape as the
//! engine window's boxed helpers (`executor/partition_window.rs`, FIX 21927)
//! and the generated dispatch's outlined rows
//! (docs/ops/generated-dispatch-stack.md), written once for any callee.

use std::future::Future;
use std::pin::Pin;

/// Runs `build` in this function's own, never inlined, stack frame and
/// returns the future it builds, boxed. The box keeps the future's auto
/// traits, so a `Send` future stays `Send`.
#[inline(never)]
pub(crate) fn build_boxed_future<F: Future>(build: impl FnOnce() -> F) -> Pin<Box<F>> {
    Box::pin(build())
}
