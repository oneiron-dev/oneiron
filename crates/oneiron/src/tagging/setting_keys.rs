//! The tag linker's learned knobs (ARCH-0003 #learning-settings; Setting stage 3): catalogue
//! keys a fit learns under the owner's seeds and pins. The crate's build script places each row in the
//! setting catalogue.

use crate::setting::{Kind, LEARNED_SCOPES};

crate::setting::setting_keys! {
    /// How far the nearest candidate's cosine must lead the next one's before
    /// the vector rung puts it first: an owner-steered catalog row over a cosine
    /// difference, 0 to 1.
    pub LINKER_VECTOR_MARGIN: f64 = "linker.vector.margin" {
        kind: Kind::new(|| 0.05).learned(0.0, 1.0),
        scopes: &LEARNED_SCOPES,
        on_change: Some(crate::learning_setting::refold_fits_on_change),
    };
}
