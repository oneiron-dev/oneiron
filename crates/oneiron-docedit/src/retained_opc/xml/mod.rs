//! Bounded source-indexed XML part, with checked semantic patches.
mod ffi;
mod patch;
mod retained;

pub(in crate::retained_opc) use retained::ValidatedXmlPart;
pub use retained::XmlLimits;
