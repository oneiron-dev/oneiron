pub use crate::clipboard::erase::ClipboardErase;
pub use crate::clipboard::erase::ClipboardEraseReport;
pub use crate::clipboard::intake::ClipboardEntry;
pub use crate::clipboard::retention::ClipboardCleanupReport;
pub use crate::clipboard::retention::ClipboardRetention;
pub use crate::clipboard::world::ClipboardWorld;

pub mod erase;
pub mod intake;
pub mod retention;
pub mod world;
