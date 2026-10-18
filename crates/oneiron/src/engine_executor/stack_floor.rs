//! The native stack a callable skill's call leaves its thread (FIX 600).
//!
//! A callable that calls another re-enters the host loop on the calling
//! thread, so each level's frames stay on that thread's stack until its
//! inner step ends. A call that would start with less than
//! [`STACK_FLOOR_BYTES`] left answers `skills_call_stack_floor` instead:
//! an overflow would abort the process for every caller. The stack is
//! memory, so this is the memory floor the `[limits]` nest row leaves to
//! stop a runaway.

/// The stack a callable call keeps free below its own frame before it
/// starts a step: room for one more level's host loop and its callbacks.
pub(super) const STACK_FLOOR_BYTES: usize = 1 << 20;

/// Whether the calling thread has less than [`STACK_FLOOR_BYTES`] of stack
/// left. A platform that names no stack bounds is never below it.
pub(super) fn below_stack_floor() -> bool {
    stack_remaining().is_some_and(|left| left < STACK_FLOOR_BYTES)
}

/// Bytes of stack below this frame on the calling thread. The stack grows
/// down on every target the engine builds for.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn stack_remaining() -> Option<usize> {
    let marker = 0_u8;
    let here = std::ptr::addr_of!(marker).addr();
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    // SAFETY: `attr` is valid for writes; on success the call initializes it
    // with the calling thread's attributes.
    if unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) } != 0 {
        return None;
    }
    let mut low = std::ptr::null_mut();
    let mut size = 0;
    // SAFETY: `attr` was initialized above, and `low` and `size` are valid
    // for writes.
    let read = unsafe { libc::pthread_attr_getstack(attr.as_ptr(), &mut low, &mut size) };
    // SAFETY: `attr` was initialized above and is destroyed once.
    unsafe { libc::pthread_attr_destroy(attr.as_mut_ptr()) };
    (read == 0).then(|| here.saturating_sub(low.addr()))
}

/// Bytes of stack below this frame on the calling thread. The stack grows
/// down on every target the engine builds for.
#[cfg(target_vendor = "apple")]
fn stack_remaining() -> Option<usize> {
    let marker = 0_u8;
    let here = std::ptr::addr_of!(marker).addr();
    // SAFETY: both read the calling thread's own stack bounds, which hold
    // for as long as the thread runs.
    let (top, size) = unsafe {
        let this = libc::pthread_self();
        (
            libc::pthread_get_stackaddr_np(this).addr(),
            libc::pthread_get_stacksize_np(this),
        )
    };
    top.checked_sub(size).map(|low| here.saturating_sub(low))
}

/// No stack bounds are read on this platform.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn stack_remaining() -> Option<usize> {
    None
}
