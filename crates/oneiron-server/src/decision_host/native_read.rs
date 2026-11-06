//! Blocking bridge for private reads on the server's multi-thread runtime.

use oneiron::llm::run_admission::RunAdmission;
use tokio::runtime::{Handle, RuntimeFlavor};

/// Keeps borrowed call state and thread-local context on the caller's thread.
/// On the served app's multi-thread runtime, callers must be outside a `LocalSet`.
/// Other runtime contexts retain their original direct-call behavior. The native
/// read's own deadline bounds its work; outer cancellation cannot interrupt it.
pub(crate) fn run_native_read<R>(run: &RunAdmission, read: impl FnOnce() -> R) -> R {
    if run.is_unrecorded()
        && Handle::try_current()
            .is_ok_and(|runtime| runtime.runtime_flavor() == RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(read)
    } else {
        read()
    }
}
