//! The fold state encoding door (row [ROSTER-KEY-LOG-FLOOD], PR 2): every
//! row's folded state of one log, and their merge, as the named MessagePack
//! a checkpoint image stores, so a test compares one build's bytes with
//! another's. Compiled only under `--cfg oneiron_test_support`; never API.

pub use crate::authority::fold_encoding_door::{StateEncodings, reencoded, state_encodings};
