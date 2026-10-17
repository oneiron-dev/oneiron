//! Polling an engine future whose decisions run on the host's ladder. A
//! generated rung's first read is async, but the ladder closes and climbs
//! synchronously, and its System One and Big rungs block on the server's
//! runtime. A runtime `block_on` around the future would mark the thread as
//! inside the runtime, so those rungs could not; poll it here, on a blocking
//! thread, instead.
use std::future::Future;
use std::sync::Arc;

/// Polls `future` to its end on this thread. Call it on a blocking thread
/// (`spawn_blocking`): the thread keeps the runtime's handle for the I/O the
/// future does, but is not inside the runtime.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::park();
    }
}
