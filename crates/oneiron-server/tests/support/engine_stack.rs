//! Runs a server test as the server's binary runs its app: on a multi-thread
//! runtime whose threads have the engine's stack, driven from a thread that
//! has it too. The generated facade dispatch's poll frame alone is over
//! 11 MiB in a dev build (`ENGINE_THREAD_STACK_BYTES`, FIX 16372 and 19837),
//! which a test thread's default stack does not hold, so a test that drives
//! `build_app`'s facade in process under `#[tokio::test]` overflows its stack
//! before any request is answered. Test-only: shared by the crate's
//! integration tests through `#[path = "support/engine_stack.rs"]`.
// Each including test binary uses one of the two drivers.
#![allow(dead_code)]

use std::future::Future;

use oneiron_server::ENGINE_THREAD_STACK_BYTES;

/// Runs `test` on the engine's stack and answers its result. `test` builds
/// its future inside the thread, so the future itself need not be `Send`; an
/// error crosses back as its text.
pub(crate) fn on_engine_stack<F, Fut>(test: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
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
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
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
