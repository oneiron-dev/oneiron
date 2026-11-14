//! The shipped act table (ARCH-0082 #act-table and #catastrophe-floor).

use serde::{Deserialize, Serialize};

use crate::consent::CatastropheClass;

#[doc(hidden)]
pub use oneiron_records::check_in::act_class::{
    ACT_CLASS, ActClass, ActClassRow, ModelCheck, ProofKind, UndoClass,
};
#[doc(hidden)]
use oneiron_records::check_in::act_class::{
    CONFIRM_KEY_DELAY, CONFIRM_KEY_QUORUM, CONFIRM_OR_KEY, EVERY_PROOF, NO_PROOF, catastrophe, row,
};

use ProofKind::{DelayWindow, HumanConfirm, Key, Quorum};
