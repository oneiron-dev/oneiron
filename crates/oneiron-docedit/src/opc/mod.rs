//! OPC inspection and retained editing; no-op writes preserve the entire archive.
mod archive;
mod retained;
pub use archive::{CONTENT_TYPES_PART, OpcPackage, OpcPart, PartClass, classify, read, write};
pub use retained::{Limits, Package};
