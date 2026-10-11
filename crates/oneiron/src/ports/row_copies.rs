//! The row-copy hook, so a test can see that no entity read on a path copied a
//! row holding a value into a buffer freed unwiped. A copy through
//! [`port_entity_raw_wiped`](super::EntityStoreRead::port_entity_raw_wiped)
//! is wiped when it drops, and is not counted.

use std::cell::RefCell;

thread_local! {
    // Per thread: a put reads its prior rows on the thread that writes.
    static WATCH: RefCell<Option<(Vec<u8>, Vec<String>)>> = const { RefCell::new(None) };
}

/// Records, from now on, each plain copy this thread makes of a row that
/// holds `needle`.
pub(crate) fn watch(needle: &[u8]) {
    WATCH.with_borrow_mut(|watch| *watch = Some((needle.to_vec(), Vec::new())));
}

pub(super) fn saw(row: &[u8]) {
    WATCH.with_borrow_mut(|watch| {
        let Some((needle, sites)) = watch else {
            return;
        };
        if row
            .windows(needle.len())
            .any(|window| window == needle.as_slice())
        {
            sites.push(reader());
        }
    });
}

/// The engine frames that asked for the copy, nearest first.
fn reader() -> String {
    std::backtrace::Backtrace::force_capture()
        .to_string()
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("oneiron::") && !line.contains("oneiron::ports::"))
        .take(3)
        .collect::<Vec<_>>()
        .join(" < ")
}

/// Where this thread copied a row holding the watched bytes unwiped.
pub(crate) fn sites() -> Vec<String> {
    WATCH.with_borrow(|watch| {
        watch
            .as_ref()
            .map_or_else(Vec::new, |(_, sites)| sites.clone())
    })
}
