//! Drives facade-touching lib tests on the engine's stack.
//!
//! The generated facade dispatch's poll frame is over 11 MiB in a dev build,
//! which a libtest test thread's default 2 MiB stack (plain `#[tokio::test]`)
//! or a default tokio worker's does not hold: a test that polls the facade
//! on either overflows before any request is answered. Production serves on
//! threads with [`crate::ENGINE_THREAD_STACK_BYTES`], and the standalone
//! integration tests share that shape through
//! `tests/support/engine_stack.rs` (#7320); this module is the same shape
//! for the lib tests, which cannot use that file. [`on_engine_stack`] hops
//! one request future onto a process-wide runtime whose workers have the
//! engine stack; [`run_on_engine_stack`] runs a whole test body on a named
//! engine-stack thread under such a runtime.

use std::future::Future;
use std::sync::OnceLock;

/// The process-wide runtime whose workers have the engine's stack.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_stack_size(crate::ENGINE_THREAD_STACK_BYTES)
            .thread_name("engine-test-worker")
            .enable_all()
            .build()
            .expect("engine-sized test runtime")
    })
}

/// Polls `future` on the engine's stack and answers its output. A failed
/// assertion fails the test with its own message.
pub(crate) async fn on_engine_stack<F>(future: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match runtime().spawn(future).await {
        Ok(output) => output,
        // A failed assertion fails the test with its own message.
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => panic!("engine-stack test task failed: {error}"),
    }
}

/// Runs `test` on the engine's stack, on a thread named `name`. `test`
/// builds its future inside the thread, so the future itself need not be
/// `Send`. A failed assertion fails the test with its own message.
pub(crate) fn run_on_engine_stack<F, Fut>(name: &str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(crate::ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(crate::ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test())
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}
