//! A session's private, lease-bound live port, distinct from artifact publication.

use serde::{Deserialize, Serialize};

use crate::UnixTs;

/// The process identity is assigned by the session host, not an OS pid supplied
/// by an HTTP caller. The host resolves it inside that session's sandbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPortDeclaration {
    pub process_ref: String,
    pub port: u16,
}

/// The preview part of the host-authenticated session manifest. There is one
/// private preview per lease; this is neither a codebase export nor a publish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewSessionManifest {
    pub session_ref: String,
    pub lease_ref: String,
    pub owner_ref: String,
    pub expires_at: UnixTs,
    pub preview: PreviewPortDeclaration,
}

impl PreviewSessionManifest {
    pub fn validate(&self, now: UnixTs) -> Result<(), &'static str> {
        for reference in [
            &self.session_ref,
            &self.lease_ref,
            &self.owner_ref,
            &self.preview.process_ref,
        ] {
            validate_preview_ref(reference)?;
        }
        if self.preview.port == 0 {
            return Err("preview port must be nonzero");
        }
        if self.expires_at <= now {
            return Err("preview lease has ended");
        }
        Ok(())
    }
}

/// A preview never acquires a published state or a public audience.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewStage {
    Draft,
}

/// No credential is embedded in this displayable endpoint. A host may carry
/// the same private listener over the vault's existing transport to a phone;
/// an adapter must not create a public tunnel for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewEndpoint {
    pub session_ref: String,
    pub lease_ref: String,
    pub local_url: String,
    pub stage: PreviewStage,
    pub expires_at: UnixTs,
}

pub fn validate_preview_ref(reference: &str) -> Result<(), &'static str> {
    if reference.is_empty() || reference.len() > 256 || reference.chars().any(char::is_control) {
        return Err("invalid preview reference");
    }
    Ok(())
}
