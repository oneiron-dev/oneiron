//! Moved from `crates/oneiron/src/lens/inspection.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::lens::mediation::mediation_backing::LensBackingTargetKind;
use serde::Deserialize;
use serde::Serialize;

/// The version tag every inspection handle starts with.
pub const INSPECTION_HANDLE_VERSION: &str = "i1";

/// An inspection handle's exact length: version, kind, 32-hex id.
pub const INSPECTION_HANDLE_LEN: usize = INSPECTION_HANDLE_VERSION.len() + 1 + 32;

pub const fn kind_tag(kind: LensBackingTargetKind) -> char {
    match kind {
        LensBackingTargetKind::Entity => 'e',
        LensBackingTargetKind::Claim => 'c',
    }
}

/// `vault.inspection.resolve`'s input: a handle a host took from a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectionResolveRequest {
    pub handle: String,
}
