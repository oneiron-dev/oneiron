//! The adopted-fold door (FIX [ADOPTED-FOLD-GATE-TEST] and
//! [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]): one vault's log folded past an
//! image of a prefix of it on a cold install, beside the vault's own whole
//! fold, live and image-grade, so a test shows where the fold past an image
//! answers and that its answer is the whole fold's; past an image that
//! dropped its residence bodies too (FIX 11400). Compiled only under
//! `--cfg oneiron_test_support`; never API.

pub use crate::authority::adopted_door::{
    AdoptedFoldComparison, ImageGradeFold, PastImage, fold_past_overflow_prefix_image,
    fold_past_prefix_image,
};
