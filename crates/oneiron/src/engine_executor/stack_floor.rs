//! Native stack space for a callable skill's host loop (FIX 600).
//!
//! Nested callables re-enter the host on the same OS thread. On supported
//! targets, a call near the stack floor runs on a temporary stack segment,
//! keeping its borrowed host and runtime on that thread. Other targets keep
//! their native stack-floor check.

/// Stack space left free before starting another callable's host loop.
pub(super) const STACK_FLOOR_BYTES: usize = 1 << 20;

/// One floor for the callable's frames and one left below them.
#[cfg(any(
    all(unix, any(target_arch = "x86_64", target_arch = "aarch64")),
    windows
))]
const STACK_SEGMENT_BYTES: usize = STACK_FLOOR_BYTES * 2;

/// Runs the callable without moving its borrowed host or runtime to a thread.
#[cfg(any(
    all(unix, any(target_arch = "x86_64", target_arch = "aarch64")),
    windows
))]
pub(super) fn on_callable_stack<T>(call: impl FnOnce() -> T) -> Option<T> {
    Some(stacker::maybe_grow(
        STACK_FLOOR_BYTES,
        STACK_SEGMENT_BYTES,
        call,
    ))
}

/// Targets without stack switching retain the original stack-floor refusal.
#[cfg(not(any(
    all(unix, any(target_arch = "x86_64", target_arch = "aarch64")),
    windows
)))]
pub(super) fn on_callable_stack<T>(call: impl FnOnce() -> T) -> Option<T> {
    if native::below_stack_floor() {
        None
    } else {
        Some(call())
    }
}

#[cfg(not(any(
    all(unix, any(target_arch = "x86_64", target_arch = "aarch64")),
    windows
)))]
mod native {
    use super::STACK_FLOOR_BYTES;

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

    /// Bytes of stack below this frame on the calling thread.
    #[cfg(target_os = "windows")]
    fn stack_remaining() -> Option<usize> {
        let marker = 0_u8;
        let here = std::ptr::addr_of!(marker).addr();
        let (mut low, mut high) = (0_usize, 0_usize);
        // SAFETY: both pointers are valid for writes; the function returns the
        // calling thread's own stack limits and retains neither pointer.
        unsafe {
            windows_sys::Win32::System::Threading::GetCurrentThreadStackLimits(&mut low, &mut high);
        }
        Some(here.saturating_sub(low))
    }

    /// No stack bounds are read on this platform.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "windows"
    )))]
    fn stack_remaining() -> Option<usize> {
        None
    }
}
