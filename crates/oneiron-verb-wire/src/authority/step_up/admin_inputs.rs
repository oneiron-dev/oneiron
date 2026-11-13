//! Moved from `crates/oneiron/src/authority/step_up/admin_inputs.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::claim::scoped_read::weave_serve::WeaveDigestRequest;
use crate::claim::scoped_read::weave_serve::WeaveWrongLinkRequest;
use crate::lens::sdk::WeaveLensRequest;
use serde::Deserialize;
use serde::Serialize;

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

/// `vault.weave.admin.digest`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveAdminDigestRequest {
    /// The Admin membership grant the read stands on (32 hex).
    pub membership_grant: String,
    #[serde(default)]
    pub request: WeaveDigestRequest,
}

/// `vault.weave.admin.link.wrong`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveAdminLinkWrongRequest {
    /// The Admin membership grant the label stands on (32 hex).
    pub membership_grant: String,
    pub request: WeaveWrongLinkRequest,
}
