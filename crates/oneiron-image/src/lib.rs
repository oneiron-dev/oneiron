//! The image organ (ART-1, the first slice): still PNG, JPEG and WebP images
//! as a native `image` kind, behind the organ host.
//!
//! It runs as its own process (`oneiron-image-organ`) and speaks the open
//! organ protocol; the engine never links it. The body is non-destructive:
//! the source by content hash, then crop and resize steps and editable
//! overlays. Only `image.export` makes pixels.
//!
//! The first promise is a single frame, eight bits a channel, in sRGB.
//! Sixteen-bit, animated and non-sRGB sources are refused before any pixel
//! buffer exists; untagged sources are read as sRGB and the notes say so.

mod body;
mod decode;
mod ops;
#[cfg(unix)]
mod organ;
mod render;

pub use body::{
    Filter, Format, Icc, ImageBody, KIND, MAX_OVERLAYS, MAX_POINTS, MAX_SIDE, MAX_STEPS,
    MAX_STROKE_WIDTH, MAX_TOTAL_POINTS, Overlay, Point, SCHEMA, Shape, Size, Source, Step, Stroke,
};
pub use decode::{Header, Profile, read_header};
pub use ops::overlay_locator;
#[cfg(unix)]
pub use organ::{
    ImageOrgan, VERB_ANNOTATE, VERB_CROP, VERB_EXPORT, VERB_INSPECT, VERB_OPEN, VERB_RESIZE,
};
