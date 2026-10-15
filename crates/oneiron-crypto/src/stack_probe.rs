//! Test-only stack probe. It paints the stack just below its own frame, runs a
//! computation there, and copies out what the computation left, so a test can see how
//! deep a secret computation reached and which secret bytes it left behind. Painting
//! and copying are inline asm, so no Rust call touches the region between the two.
//!
//! Linux and macOS only: their thread stacks are mapped up front, so the first write may
//! land anywhere in the span. Windows commits stack pages through a moving guard page,
//! which a write far below it skips, faulting instead of growing the stack.

const PAINT: u8 = 0xA5;

/// The `span` bytes below the probe's frame after the computation returned, lowest
/// address first.
pub(crate) struct Below {
    bytes: Vec<u8>,
}

impl Below {
    /// How far below the probe's frame the computation wrote: the distance to the
    /// deepest byte that no longer holds the paint. Equal to the span when it ran
    /// deeper than the probe looked.
    pub(crate) fn depth(&self) -> usize {
        self.bytes
            .iter()
            .position(|&b| b != PAINT)
            .map_or(0, |deepest| self.bytes.len() - deepest)
    }

    /// How far below the probe's frame the deepest copy of `secret` starts, if any
    /// copy is left in the region.
    pub(crate) fn depth_of(&self, secret: &[u8]) -> Option<usize> {
        self.bytes
            .windows(secret.len())
            .position(|w| w == secret)
            .map(|deepest| self.bytes.len() - deepest)
    }
}

/// Paints `span` bytes below this frame, runs `f`, and copies the same bytes out.
/// `span` must fit in the test thread's stack. `f` is called through a vtable, so it
/// cannot be inlined into this frame: everything it does lands below it.
#[inline(never)]
pub(crate) fn run(span: usize, f: &mut dyn FnMut()) -> Below {
    assert!(span > 0);
    let mut bytes = vec![0u8; span];
    let out = bytes.as_mut_ptr();
    // SAFETY: writes `span` bytes just below the stack pointer, inside the thread's
    // stack (callers keep `span` far under its size). No live value is there: the asm
    // is not `nostack`, so the compiler keeps nothing in a red zone across it.
    unsafe { paint(span) };
    f();
    // SAFETY: reads the same `span` bytes below the stack pointer (the frame is fixed,
    // so it is the same region) into `bytes`, which owns `span` bytes at `out`.
    unsafe { copy_out(out, span) };
    Below { bytes }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn paint(span: usize) {
    // SAFETY: the caller's contract; `rep stosb` fills [rsp - span, rsp).
    unsafe {
        core::arch::asm!(
            "mov rdi, rsp",
            "sub rdi, rcx",
            "rep stosb",
            inout("rcx") span => _,
            out("rdi") _,
            in("al") PAINT,
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn copy_out(out: *mut u8, span: usize) {
    // SAFETY: the caller's contract; `rep movsb` copies [rsp - span, rsp) to `out`.
    unsafe {
        core::arch::asm!(
            "mov rsi, rsp",
            "sub rsi, rcx",
            "rep movsb",
            inout("rcx") span => _,
            inout("rdi") out => _,
            out("rsi") _,
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn paint(span: usize) {
    // SAFETY: the caller's contract; the loop fills [sp - span, sp).
    unsafe {
        core::arch::asm!(
            "mov {at}, sp",
            "sub {at}, {at}, {n}",
            "2:",
            "strb {v:w}, [{at}], #1",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            at = out(reg) _,
            n = inout(reg) span => _,
            v = in(reg) u32::from(PAINT),
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn copy_out(out: *mut u8, span: usize) {
    // SAFETY: the caller's contract; the loop copies [sp - span, sp) to `out`.
    unsafe {
        core::arch::asm!(
            "mov {at}, sp",
            "sub {at}, {at}, {n}",
            "2:",
            "ldrb {b:w}, [{at}], #1",
            "strb {b:w}, [{to}], #1",
            "subs {n}, {n}, #1",
            "b.ne 2b",
            at = out(reg) _,
            b = out(reg) _,
            to = inout(reg) out => _,
            n = inout(reg) span => _,
        );
    }
}
