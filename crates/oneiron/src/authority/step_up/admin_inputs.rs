//! The served weave Admin rows' inputs (OF-499 A3, FIX 11694). Each names
//! the one Admin membership grant the call stands on beside the request a
//! person's own weave row takes. The step-up is never an input: the door
//! reads the one recorded on the request's own slip.

use serde::{Deserialize, Serialize};

use crate::claim::{WeaveReportRequest, WeaveWrongItemRequest};
use crate::lens::WeaveLensRequest;

/// `vault.weave.admin.report`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveAdminReportRequest {
    /// The Admin membership grant the read stands on: its 32-hex id, as
    /// `vault.members.projection` lists it.
    pub membership_grant: String,
    #[serde(default)]
    pub request: WeaveReportRequest,
}

/// `vault.weave.admin.lens`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveAdminLensRequest {
    /// The Admin membership grant the read stands on (32 hex).
    pub membership_grant: String,
    #[serde(default)]
    pub request: WeaveLensRequest,
}

#[doc(hidden)]
pub use oneiron_verb_wire::authority::step_up::admin_inputs::{
    WeaveAdminDigestRequest, WeaveAdminLinkWrongRequest,
};

/// `vault.weave.admin.item.wrong`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveAdminItemWrongRequest {
    /// The Admin membership grant the label stands on (32 hex).
    pub membership_grant: String,
    pub request: WeaveWrongItemRequest,
}
