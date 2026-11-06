//! Value-free file-mask paths, read visibility, and byte-span transformations.

pub use oneiron_store::file_secret_marks::SecretSight;
pub(crate) use oneiron_store::file_secret_marks::{
    FILLER, HANDLE_TEXT_OPEN, KeyPlaces, KeySpan, MemberStep, PlaceHandles, as_text, filled,
    filled_with, masked_copy_withheld, unmask_value,
};
