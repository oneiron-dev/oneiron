//! Allocation-boundary teardown observer for session-owned buffers.
//! Tracks one allocation on the calling test thread. No freed-memory reads,
//! process-global mutable state, or sampling another test's allocations.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static WATCH: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static SCRUBBED: Cell<Option<bool>> = const { Cell::new(None) };
    static PATTERN: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static DIRTY_PATTERN: Cell<usize> = const { Cell::new(0) };
    static CLEAN_PATTERN: Cell<usize> = const { Cell::new(0) };
    static REPLAY_OBSERVING: Cell<bool> = const { Cell::new(false) };
}

struct ObservedAllocator;

// SAFETY: all allocations/deallocations delegate to System with the original
// layout; the observer reads only a registered allocation before dealloc.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding the caller's layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            if let Some((expected, len)) = watch.get()
                && expected == ptr as usize
                && layout.size() >= len
            {
                // SAFETY: this is the registered, initialized byte allocation;
                // System.dealloc has not run yet and layout covers len bytes.
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                let _ = SCRUBBED.try_with(|result| {
                    result.set(Some(bytes.iter().all(|byte| *byte == 0)));
                });
                watch.set(None);
            }
        });
        let _ = PATTERN.try_with(|pattern| {
            if let Some((source, len)) = pattern.get()
                && layout.size() == len
            {
                // SAFETY: the source is borrowed from an owner held live for
                // the whole observe_pattern call; ptr is live until dealloc.
                let expected = unsafe { std::slice::from_raw_parts(source as *const u8, len) };
                // SAFETY: ptr is the allocation being deallocated, and the
                // exact-sized layout still owns these initialized bytes.
                let candidate = unsafe { std::slice::from_raw_parts(ptr, len) };
                if candidate == expected {
                    let _ = DIRTY_PATTERN.try_with(|count| count.set(count.get() + 1));
                } else if candidate.iter().all(|byte| *byte == 0) {
                    let _ = CLEAN_PATTERN.try_with(|count| count.set(count.get() + 1));
                }
            }
        });
        // SAFETY: forwarding the caller's pointer and layout unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

/// Call while `bytes` is still owned. Observe only this exact allocation
/// during `action`, then assert whether it was freed after being zeroed.
pub(crate) fn allocation(bytes: &[u8]) -> (usize, usize) {
    assert!(!bytes.is_empty());
    (bytes.as_ptr() as usize, bytes.len())
}

pub(crate) fn observe_drop((ptr, len): (usize, usize), should_drop: bool, action: impl FnOnce()) {
    assert!(len > 0);
    WATCH.with(|watch| {
        assert!(watch.get().is_none(), "nested allocation observer");
        watch.set(Some((ptr, len)));
    });
    SCRUBBED.with(|result| result.set(None));
    action();
    let observed = SCRUBBED.with(|result| result.replace(None));
    WATCH.with(|watch| watch.set(None));
    if should_drop {
        assert_eq!(
            observed,
            Some(true),
            "owned allocation was not scrubbed before dealloc"
        );
    } else {
        assert_eq!(observed, None, "live COW allocation was freed early");
    }
}

/// Observe clones of a caller-held payload whose pointer is not available
/// before a production function creates them. No allocation with equal bytes
/// may be freed unchanged during this call. At least one equal-sized buffer
/// must be scrubbed before deallocation. Keep `pattern` live through `action`.
pub(crate) fn observe_pattern<T>(pattern: &[u8], action: impl FnOnce() -> T) -> T {
    assert!(!pattern.is_empty() && pattern.iter().any(|byte| *byte != 0));
    PATTERN.with(|slot| {
        assert!(slot.get().is_none(), "nested pattern observer");
        slot.set(Some((pattern.as_ptr() as usize, pattern.len())));
    });
    DIRTY_PATTERN.with(|count| count.set(0));
    CLEAN_PATTERN.with(|count| count.set(0));
    let result = action();
    PATTERN.with(|slot| slot.set(None));
    let dirty = DIRTY_PATTERN.with(Cell::get);
    let clean = CLEAN_PATTERN.with(Cell::get);
    assert_eq!(dirty, 0, "private scratch freed unchanged");
    assert!(clean > 0, "no scrubbed scratch allocation observed");
    result
}

/// Follow the actual promotion builder's owned Put buffer through success or
/// failure. Registration occurs inside its production constructor, after the
/// clone, so this observes that exact allocation rather than a helper copy.
pub(crate) fn observe_replay_copy<T>(action: impl FnOnce() -> T) -> T {
    REPLAY_OBSERVING.with(|active| {
        assert!(!active.get(), "nested replay observer");
        active.set(true);
    });
    SCRUBBED.with(|result| result.set(None));
    let outcome = action();
    REPLAY_OBSERVING.with(|active| active.set(false));
    let scrubbed = SCRUBBED.with(|result| result.replace(None));
    WATCH.with(|watch| watch.set(None));
    assert_eq!(
        scrubbed,
        Some(true),
        "promotion replay copy was not scrubbed before dealloc"
    );
    outcome
}

#[cfg(test)]
pub(crate) fn register_replay_copy(ops: &[crate::batch::BatchOp]) {
    if !REPLAY_OBSERVING.with(Cell::get) {
        return;
    }
    if let Some(crate::batch::BatchOp::Put { data, .. }) = ops
        .iter()
        .find(|op| matches!(op, crate::batch::BatchOp::Put { .. }))
    {
        WATCH.with(|watch| {
            assert!(watch.get().is_none(), "multiple replay builder owners");
            watch.set(Some((data.as_ptr() as usize, data.len())));
        });
        SCRUBBED.with(|result| result.set(None));
    }
}
