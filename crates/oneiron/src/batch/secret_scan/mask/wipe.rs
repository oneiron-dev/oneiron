//! Core half of `batch::secret_scan::mask::wipe`: its store-layer items live in `oneiron_store::batch::secret_scan::mask::wipe` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::mask::wipe::*;

use super::side_row::SidePart;
use crate::batch::BatchOp;
use rmpv::Value;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Every byte of one row part that can hold a secret.
pub(super) fn wipe_part(part: &mut SidePart) {
    match part {
        SidePart::Body(bytes) => bytes.zeroize(),
        SidePart::Text(text) => text.zeroize(),
        SidePart::Value(value) => wipe_value(value),
    }
}

/// A plan's copy of a row's parts, wiped when it drops.
pub(super) struct PlanParts(Vec<SidePart>);

impl PlanParts {
    pub(super) fn of(parts: &[SidePart]) -> Self {
        Self(parts.to_vec())
    }
}

impl Deref for PlanParts {
    type Target = [SidePart];

    fn deref(&self) -> &[SidePart] {
        &self.0
    }
}

impl DerefMut for PlanParts {
    fn deref_mut(&mut self) -> &mut [SidePart] {
        &mut self.0
    }
}

impl Drop for PlanParts {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(wipe_part);
    }
}
