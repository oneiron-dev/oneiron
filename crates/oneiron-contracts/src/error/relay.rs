//! Relay-domain errors: relay attestation refusals, vault-receipt trust, and
//! the hosted policy manifest and verdict doors.
//!
//! Reached from the root as `Error::Relay(..)`, a transparent wrapper: Display
//! and `source()` are the leaf's, so every message string is what it was when
//! these variants sat flat on `Error`.

use super::ErrorKind;

/// Relay-domain error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// A connector-edge service identity failed relay attestation validation
    /// (B11-2b / ONE-1572): it must carry the `connector-edge:<name>` grammar
    /// and name a service present in the caller-supplied edge service
    /// registry. Fail-closed — an unregistered or malformed identity can
    /// never mint an attested relay domain.
    #[error("invalid connector-edge service identity `{service_identity}`: {reason}")]
    RelayAttestationInvalidServiceIdentity {
        service_identity: String,
        reason: &'static str,
    },
    /// A CloudVault receipt was missing or did not verify against local policy state.
    #[error("cloud vault receipt is untrusted: {reason}")]
    RelayVaultReceiptUntrusted { reason: &'static str },
    /// A verdict handed to `Vault::enforce_policy_model_verdict` is not the
    /// verdict for the request beside it, or the manifest has moved since it
    /// was decided. Either way it cannot be pinned to the policy in force, so
    /// the door refuses instead of enforcing it.
    #[error("policy verdict is not bound to this request under the policy in force")]
    PolicyVerdictNotInForce,
    /// A connector-edge identity claimed a connection class other than the
    /// one its service identity is registered for (B11-2b / ONE-1572) — e.g.
    /// a hosted connector claiming cloud-vault peer standing, which would
    /// skip the relay floor. Rejected before any witness is minted.
    #[error(
        "connector-edge service `{service_identity}` claimed connection class `{claimed}` but is registered as `{registered}`"
    )]
    RelayAttestationClassMismatch {
        service_identity: String,
        claimed: &'static str,
        registered: &'static str,
    },
    /// A connector-edge service registration conflicted with an existing
    /// registration under a different connection class (B11-2b / ONE-1572).
    /// Fail-closed: a deployment manifest can never silently re-register an
    /// edge service to a stronger (or weaker) class.
    #[error(
        "connector-edge service `{service}` is already registered as `{registered}`; conflicting registration as `{claimed}` rejected"
    )]
    RelayAttestationEdgeServiceConflict {
        service: String,
        registered: &'static str,
        claimed: &'static str,
    },
    /// A hosted legal policy was rejected at registration because one of its
    /// attribution fields cannot survive the gate-notice ledger's bounds.
    /// Caught here rather than at receipt-append time, so a policy that would
    /// make every hosted `Warn`/`Block` fail to receipt never registers.
    #[error("hosted legal policy for connector-edge service `{service}`: {field} {reason}")]
    RelayHostedLegalPolicyInvalid {
        service: String,
        field: &'static str,
        reason: &'static str,
    },
    /// The vault's own policy manifest cannot be read as written, named by
    /// the manifest key at fault. The owner plane's twin of
    /// [`Self::RelayHostedLegalPolicyInvalid`]: a defect the substrate owner
    /// fixes in the manifest, not a fault of the request that tripped it, so
    /// the key and the reason stay `'static` and machine-readable rather than
    /// formatted into prose.
    #[error("policy manifest: {field} {reason}")]
    PolicyManifestInvalid {
        field: &'static str,
        reason: &'static str,
    },
}

impl RelayError {
    /// Returns the stable category for this error.
    #[must_use]
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            Self::RelayAttestationInvalidServiceIdentity { .. } => {
                ErrorKind::RelayAttestationInvalidServiceIdentity
            }
            Self::RelayVaultReceiptUntrusted { .. } => ErrorKind::RelayVaultReceiptUntrusted,
            Self::PolicyVerdictNotInForce => ErrorKind::PolicyVerdictNotInForce,
            Self::RelayAttestationClassMismatch { .. } => ErrorKind::RelayAttestationClassMismatch,
            Self::RelayAttestationEdgeServiceConflict { .. } => {
                ErrorKind::RelayAttestationEdgeServiceConflict
            }
            Self::RelayHostedLegalPolicyInvalid { .. } => ErrorKind::RelayHostedLegalPolicyInvalid,
            Self::PolicyManifestInvalid { .. } => ErrorKind::PolicyManifestInvalid,
        }
    }
}
