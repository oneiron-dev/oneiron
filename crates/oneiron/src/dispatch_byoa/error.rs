//! Error enum, literal refusal reasons, result alias, and the invalid() constructor.

use crate::code_sandbox::SandboxCredentialHandle;
use crate::error::{ArtifactError, Error};
// ---------------------------------------------------------------------------
// Door validators
// ---------------------------------------------------------------------------

pub(super) fn invalid(message: &'static str) -> ByoaError {
    ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        message,
    )))
}

pub(super) const ERR_UNKNOWN_MODEL_SLUG: &str =
    "model slug is not bound by this endpoint connector";

pub(super) const ERR_ENDPOINT_PROTOCOL: &str = "endpoint protocol label is not a v1 protocol";

pub(super) const ERR_ATTACH_KIND: &str = "protocol attach kind is not implemented in v1";

pub(super) const ERR_DISPOSITION: &str = "byoa terminal disposition label is not recognized";

pub(super) const ERR_PAYLOAD_ENCODE: &str = "byoa connector payload failed to encode";

pub(super) const ERR_PAYLOAD_DECODE: &str = "byoa connector payload failed to decode";

pub(super) const ERR_PAYLOAD_SCHEMA: &str =
    "byoa connector payload schema version is not supported";

pub(super) const ERR_BASE_URL: &str = "endpoint base_url must be a bare http(s) URL";

pub(super) const ERR_SLUG_MAP_EMPTY: &str = "endpoint must bind at least one model slug";

pub(super) const ERR_SLUG_MAP_TOO_LARGE: &str = "endpoint binds too many model slugs";

pub(super) const ERR_MODEL_SLUG: &str = "model slug must be non-empty, bounded, and printable";

pub(super) const ERR_SERVER_REF: &str = "protocol attach server_ref must be non-empty and bounded";

pub(super) const ERR_PROGRAM: &str =
    "cli sandbox program must be a bare executable, not a command line";

pub(super) const ERR_ARGV_ENTRY: &str = "cli sandbox argv entry must be bounded and printable";

pub(super) const ERR_ARGV_TOO_LONG: &str = "cli sandbox argv has too many entries";

pub(super) const ERR_EGRESS_PROFILE_REF: &str =
    "cli sandbox egress_profile_ref must be non-empty and bounded";

pub(super) const ERR_CREDENTIAL_HANDLES: &str =
    "cli sandbox references too many credential handles";

pub(super) const ERR_EXHAUST_ENCODE: &str = "byoa exhaust failed to encode";

pub(super) const ERR_EXHAUST_EMPTY: &str = "byoa exhaust must carry at least one stream";

pub(super) const ERR_EXHAUST_TOO_LARGE: &str = "byoa exhaust exceeds its byte budget";

pub(super) const ERR_ATTEMPT_KIND: &str = "operation requires a valid BYOA attempt";

pub(super) const ERR_EXECUTION_SHAPE: &str = "execution does not match the persisted connector";

pub(super) const ERR_EXECUTION_BUDGET: &str = "byoa execution requires a bounded budget";

pub(super) const ERR_EXECUTION_CHECKOUT: &str = "byoa execution requires a live matching checkout";

pub(super) const ERR_ARTIFACT_COLLISION: &str =
    "byoa exhaust artifact is not owned by this capture";

pub(super) const ERR_RUNTIME_ACTOR_COLLISION: &str =
    "byoa runtime actor is not the canonical identity";

pub(super) const ERR_CAPTURE_CONFLICT: &str = "byoa capture conflicts with the canonical result";

pub(super) const ERR_STOP_REASON_EMPTY: &str = "failure reason must not be empty";

pub(super) const ERR_STOP_REASON_TOO_LONG: &str = "failure reason exceeds 2048 bytes";

pub(super) const ERR_CHECKPOINT_FRONTIER: &str =
    "byoa checkpoint frontier entry is unbounded or unprintable";

pub(super) const ERR_ATTEMPT_MISSING: &str = "missing";

pub(super) const ERR_RESULT_REF_SHAPE: &str =
    "byoa result reference is not artifact@version shaped";

pub(super) const ERR_LEASE_PROFILE_MISMATCH: &str = "egress lease names a different profile";

pub(super) const ERR_LEASE_EXPIRED: &str = "egress lease is already expired";

pub(super) const ERR_LEASE_UNBOUNDED: &str = "egress lease grants no bounded host scope";

pub(super) const ERR_LEASE_HOST_DENIED: &str = "egress lease does not admit the requested host";

pub(super) const ERR_LEASE_ID_ZERO: &str = "egress lease carries no lease id";

/// Every way a foreign-agent door can refuse.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ByoaError {
    /// Network was attempted without a lease that admits it. This is the
    /// refusal a direct-socket attempt lands on: there is no other door.
    #[error("byoa egress denied for profile {profile_ref}: {reason}")]
    EgressDenied { profile_ref: String, reason: String },
    /// A custody handle could not be opened. Carries the HANDLE, which is a
    /// reference; it can never carry the material behind it.
    #[error("byoa credential unavailable: {}", .0.as_str())]
    CredentialUnavailable(SandboxCredentialHandle),
    /// The host-owned backend seam refused.
    #[error("byoa backend refused: {0}")]
    Backend(String),
    /// Any crate-level refusal raised beneath this module — a queue door, a
    /// vault write, or a connector validator.
    #[error(transparent)]
    Store(#[from] Error),
}

/// Result alias for every door in this module.
pub type ByoaResult<T> = Result<T, ByoaError>;
