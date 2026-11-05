//! A vault's Clipboard world and its masked text records.
//!
//! Hosts classify private pasteboard types before calling the ordinary text
//! door. Private copies belong in secret custody, never in these claims.

mod erase;
mod intake;
mod purpose;
mod retention;
mod world;

pub use erase::{ClipboardErase, ClipboardEraseReport};
pub use intake::{ClipboardEntry, PREDICATE_CLIPBOARD_CAPTURED};
pub use retention::{CLIPBOARD_LOW_DISK_FREE_BYTES, ClipboardCleanupReport, ClipboardRetention};
pub use world::{CLIPBOARD_WORLD_NAME, ClipboardWorld, clipboard_world_id};
