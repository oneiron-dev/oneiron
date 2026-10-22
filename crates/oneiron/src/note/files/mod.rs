//! The Files world (FIX 6942; ARCH-0027 #files-world): an opt-in,
//! device-local world over folders the owner chooses, extending the attached
//! folder source (OF-554).
//!
//! One Files world per install. The owner opts in by attaching a folder to
//! it; the world is born then, read on this install only and with no sealed
//! copies, before any file lands in it. A Files source is an attached folder
//! with a placement: its notes, their parts and their links are born in the
//! world in the write that lands them, and their ids derive from the
//! source's identity (its install, its world and its folder), never from a
//! host path. A file the source reads no text from is held by its name
//! only. The same ledger and the same rescans serve both kinds of source.

mod metadata;
mod source;

pub use metadata::{
    FILES_TEXT_EXTENSIONS, FileFacts, FileMeta, FileReadiness, NameOnlyFile, NameOnlyReason,
};
pub(in crate::note) use source::namespace;
pub use source::{
    DEFAULT_FILES_EXCLUDE, FILES_DEFAULT_KIND, FILES_WORLD_NAME, FileHandle, FilesPlacement,
    FilesWorld,
};
