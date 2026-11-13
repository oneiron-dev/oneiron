//! The served weave Admin rows' inputs (OF-499 A3, FIX 11694). Each names
//! the one Admin membership grant the call stands on beside the request a
//! person's own weave row takes. The step-up is never an input: the door
//! reads the one recorded on the request's own slip.

use serde::{Deserialize, Serialize};

use crate::claim::{
    WeaveDigestRequest, WeaveReportRequest, WeaveWrongItemRequest, WeaveWrongLinkRequest,
};
use crate::lens::WeaveLensRequest;

#[doc(hidden)]
pub use oneiron_verb_wire::authority::step_up::admin_inputs::{
    WeaveAdminDigestRequest, WeaveAdminLensRequest, WeaveAdminLinkWrongRequest,
    WeaveAdminReportRequest,
};

/// `vault.weave.admin.item.wrong`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveAdminItemWrongRequest {
    /// The Admin membership grant the label stands on (32 hex).
    pub membership_grant: String,
    pub request: WeaveWrongItemRequest,
}
