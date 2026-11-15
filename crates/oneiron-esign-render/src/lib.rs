//! One shared e-sign field renderer for the pre-seal burn-in.
//!
//! Canon ARCH-0064 [SGN-07]: the engine and the seal organ draw the burn-in
//! with this drawing program rather than a second drawing path. The code is
//! the organ's port with each ledger call replaced by an [`Admission`] hook
//! call at the same place: the organ admits against its operation ledger
//! through its own admission, and the engine runs the same program through
//! [`NoAdmission`], which never refuses. A move, not a behaviour change: for
//! every input each side draws the same bytes and reports the same error as
//! before.

pub mod admit;
pub mod appearance;
pub mod burn;
pub mod error;
pub mod present;

pub use admit::Admission;
pub use appearance::flatten;
pub use burn::{burn_field, op, resource, stamp_rejected, text};
pub use error::BurnError;
pub use present::{
    FieldGeometry, FieldMark, ImageCache, LeafValue, PageGeometry, PdfFieldRect, RasterView,
    encoded_text, marks, render_field_geometry,
};

/// The engine's admission: every hook succeeds and grows natively, exactly
/// as the engine's drawing program always did. It never refuses, never adds
/// a bound, and never touches a ledger.
pub struct NoAdmission;

impl Admission for NoAdmission {
    type Error = std::convert::Infallible;

    fn admit_len<T>(&self, _len: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn release_admitted(&self, _bytes: u64) {}

    fn alloc_failed(_bytes: usize) -> Self::Error {
        unreachable!("the engine overrides never fail, so this is never called")
    }

    fn reserve<T>(&self, output: &mut Vec<T>, additional: usize) -> Result<(), Self::Error> {
        output.reserve(additional);
        Ok(())
    }

    fn push<T>(&self, output: &mut Vec<T>, value: T) -> Result<(), Self::Error> {
        output.push(value);
        Ok(())
    }

    fn admit_dict_entry(&self, _key_len: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn admit_object(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn admit_image_entry(&self, _key_len: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn admit_image_dict(
        &self,
        _entries: usize,
        _keys: usize,
        _names: usize,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
