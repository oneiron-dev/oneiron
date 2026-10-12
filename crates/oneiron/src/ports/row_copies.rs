//! The row-copy hook, so a test can see that no entity read on a path copied a
//! row holding a value into a buffer freed unwiped. A copy through
//! [`port_entity_raw_wiped`](super::EntityStoreRead::port_entity_raw_wiped)
//! is wiped when it drops, and is counted apart ([`wiped_sites`]), for a path
//! that must copy no such row at all.

use std::cell::RefCell;

/// The watched bytes, then the readers that copied a row holding them: plain
/// copies, then wiped ones.
type Watch = (Vec<u8>, Vec<String>, Vec<String>);

thread_local! {
    // Per thread: a put reads its prior rows on the thread that writes.
    static WATCH: RefCell<Option<Watch>> = const { RefCell::new(None) };
}

/// Records, from now on, each copy this thread makes of a row that holds
/// `needle`.
pub(crate) fn watch(needle: &[u8]) {
    WATCH.with_borrow_mut(|watch| *watch = Some((needle.to_vec(), Vec::new(), Vec::new())));
}

pub(super) fn saw(row: &[u8]) {
    record(row, false);
}

pub(super) fn saw_wiped(row: &[u8]) {
    record(row, true);
}

fn record(row: &[u8], wiped: bool) {
    WATCH.with_borrow_mut(|watch| {
        let Some((needle, plain, wiped_sites)) = watch else {
            return;
        };
        if row
            .windows(needle.len())
            .any(|window| window == needle.as_slice())
        {
            let sites = if wiped { wiped_sites } else { plain };
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
            .map_or_else(Vec::new, |(_, plain, _)| plain.clone())
    })
}

/// Where this thread copied a row holding the watched bytes into a wiped
/// buffer.
pub(crate) fn wiped_sites() -> Vec<String> {
    WATCH.with_borrow(|watch| {
        watch
            .as_ref()
            .map_or_else(Vec::new, |(_, _, wiped)| wiped.clone())
    })
}
