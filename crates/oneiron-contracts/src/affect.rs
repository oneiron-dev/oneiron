//! Core VAD value types. `oneiron::affect` re-exports them next to the affect records.

mod vad;

pub use self::vad::{DerivationFreshness, Vad, VadAnnotation, VadAnnotationSource, VadComponent};
