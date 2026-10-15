mod facade;
mod headerless;
mod markers;
mod outcome;
#[cfg(all(test, feature = "sync"))]
mod pierced_tests;
mod preview;

pub use self::outcome::{DeleteEntityOptions, DeleteEntityOutcome};
pub use self::preview::{DeleteEntityPreview, DeleteHeldBytes, DeleteOtherVersion};
