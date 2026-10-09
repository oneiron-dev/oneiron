//! Allocation-boundary teardown observer for session-owned buffers.
//! Only an owner's explicitly registered initialized byte allocation is read,
//! immediately before its deallocation, on the calling test thread.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static WATCH: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static SCRUBBED: Cell<Option<bool>> = const { Cell::new(None) };
    static REPLAY_OBSERVING: Cell<bool> = const { Cell::new(false) };
    static SHORT_ID_TARGET: Cell<Option<ShortIdScratch>> = const { Cell::new(None) };
}

/// The separately owned scratch allocation to observe at the short-id door.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShortIdScratch {
    Alias,
    StaleForwardKey,
    NewForwardKey,
}

struct ObservedAllocator;

// SAFETY: all allocations/deallocations delegate to System with the original
// layout; the observer reads only a specific registered initialized allocation
// before forwarding its deallocation. It does not scan by allocation size.
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
                // SAFETY: the owner registered these initialized bytes at
                // this exact address; System.dealloc has not run yet. For the
                // watched Vec<u8>/String, zeroize writes the full original
                // length before shortening it, so the byte span remains valid.
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
                let _ = SCRUBBED.try_with(|result| {
                    result.set(Some(bytes.iter().all(|byte| *byte == 0)));
                });
                watch.set(None);
            }
        });
        // SAFETY: forwarding the caller's pointer and layout unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

// Every observation scope restores the thread-local registration on normal
// exit AND unwind, before a borrowed owner can be freed after a panic.
struct ObservationGuard;

impl ObservationGuard {
    fn new() -> Self {
        WATCH.with(|slot| assert!(slot.get().is_none(), "nested allocation observer"));
        REPLAY_OBSERVING.with(|slot| assert!(!slot.get(), "nested replay observer"));
        SHORT_ID_TARGET.with(|slot| assert!(slot.get().is_none(), "nested short-id observer"));
        SCRUBBED.with(|slot| slot.set(None));
        Self
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        let _ = WATCH.try_with(|slot| slot.set(None));
        let _ = SCRUBBED.try_with(|slot| slot.set(None));
        let _ = REPLAY_OBSERVING.try_with(|slot| slot.set(false));
        let _ = SHORT_ID_TARGET.try_with(|slot| slot.set(None));
    }
}

/// Obtain an address only while `bytes` is still initialized and owned.
pub(crate) fn allocation(bytes: &[u8]) -> (usize, usize) {
    assert!(!bytes.is_empty());
    (bytes.as_ptr() as usize, bytes.len())
}

fn register(bytes: &[u8]) {
    let address = allocation(bytes);
    WATCH.with(|slot| {
        assert!(slot.get().is_none(), "multiple allocations registered");
        slot.set(Some(address));
    });
}

pub(crate) fn observe_drop((ptr, len): (usize, usize), should_drop: bool, action: impl FnOnce()) {
    assert!(len > 0);
    let _guard = ObservationGuard::new();
    WATCH.with(|slot| slot.set(Some((ptr, len))));
    action();
    let observed = SCRUBBED.with(Cell::get);
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

/// A short-ID function registers its own exact scratch allocation. No byte
/// comparison or uninitialized unrelated allocation is touched.
pub(crate) fn observe_short_id_scratch<T>(target: ShortIdScratch, action: impl FnOnce() -> T) -> T {
    let _guard = ObservationGuard::new();
    SHORT_ID_TARGET.with(|slot| slot.set(Some(target)));
    let result = action();
    assert_eq!(
        SCRUBBED.with(Cell::get),
        Some(true),
        "short-id scratch was not scrubbed"
    );
    result
}

pub(crate) fn register_short_id_buffer(target: ShortIdScratch, bytes: &[u8]) {
    if SHORT_ID_TARGET.with(Cell::get) == Some(target) {
        register(bytes);
    }
}

/// Follow the actual promotion builder's owned Put buffer through success or
/// failure. Registration occurs inside its production constructor, after the
/// clone, so this observes that exact allocation rather than a helper copy.
pub(crate) fn observe_replay_copy<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ObservationGuard::new();
    REPLAY_OBSERVING.with(|slot| slot.set(true));
    let outcome = action();
    assert_eq!(
        SCRUBBED.with(Cell::get),
        Some(true),
        "promotion replay copy was not scrubbed"
    );
    outcome
}

pub(crate) fn register_replay_copy(ops: &[crate::batch::BatchOp]) {
    if !REPLAY_OBSERVING.with(Cell::get) {
        return;
    }
    if let Some(crate::batch::BatchOp::Put { data, .. }) = ops
        .iter()
        .find(|op| matches!(op, crate::batch::BatchOp::Put { .. }))
    {
        register(data);
    }
}
