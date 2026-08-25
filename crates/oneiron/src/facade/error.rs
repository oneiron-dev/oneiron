//! Facade error vocabulary: [`FacadeError`], the stable `FACADE_CODE_*` strings,
//! and the central engine-error mapping. Split from the flat `facade.rs`;
//! surface re-exported by [`super`] (the `facade` module).

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind};

/// Stable facade error codes, mirroring the `oneiron-server`
/// `ApiErrorDetails` code vocabulary (S8).
pub const FACADE_CODE_BAD_REQUEST: &str = "BAD_REQUEST";

/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_NOT_FOUND: &str = "NOT_FOUND";

/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_FORBIDDEN: &str = "FORBIDDEN";

/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_INVALID_STATE: &str = "INVALID_STATE";

/// See [`FACADE_CODE_BAD_REQUEST`].
pub const FACADE_CODE_INTERNAL: &str = "INTERNAL_SERVER_ERROR";

/// `recall(Deep)` called without a budget lease (W4/C4 lease rule).
pub const FACADE_CODE_LEASE_REQUIRED: &str = "LEASE_REQUIRED";

/// The canonical door was asked to witness into a conversation owned by a live
/// off-record session (ARCH-0052 D2 backstop (a), ONE-1728 K7). Distinct from
/// `FORBIDDEN`: the write was not refused on policy grounds — the room is only
/// reachable through the session handle.
pub const FACADE_CODE_OFF_RECORD_SESSION_DOOR: &str = "OFF_RECORD_SESSION_DOOR";

/// Typed facade error: stable `code` + human `message` + remediation
/// `suggestions` (never empty). The central `From<Error>` impl is the one
/// engine→binding error mapping (S8); the HTTP mapping stays server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacadeError {
    /// One of the `FACADE_CODE_*` strings.
    pub code: String,
    /// Human-readable description of the failure.
    pub message: String,
    /// Remediation hints for clients; always non-empty.
    pub suggestions: Vec<String>,
    /// The current lifecycle head's `short_id:content_hash` ref, present only
    /// on the `INVALID_STATE` refusal a stale write-verb target produces
    /// (ONE-1936). A client re-gets THIS ref and issues a new decision; the
    /// value is a typed field precisely so no client has to parse it back out
    /// of `message`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_short_id: Option<String>,
}

impl FacadeError {
    pub(super) fn new(code: &str, message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            suggestions: suggestions.iter().map(|s| (*s).to_owned()).collect(),
            successor_short_id: None,
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(
            FACADE_CODE_BAD_REQUEST,
            message,
            &["Fix the request shape and retry."],
        )
    }

    pub(crate) fn bad_request_with(message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self::new(FACADE_CODE_BAD_REQUEST, message, suggestions)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(
            FACADE_CODE_NOT_FOUND,
            message,
            &["Verify the identifier and retry."],
        )
    }
}

impl std::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for FacadeError {}

impl From<Error> for FacadeError {
    fn from(err: Error) -> Self {
        let message = err.to_string();
        // ONE-1936: the successor ref travels as a FIELD, not as prose. A
        // stale target is an INVALID_STATE refusal like the rest of the
        // refresh-and-retry family, but this one names exactly what to
        // refresh TO.
        if let Error::WriteVerbTargetStale {
            successor_short_id, ..
        } = err
        {
            return Self {
                successor_short_id: Some(successor_short_id),
                ..Self::new(
                    FACADE_CODE_INVALID_STATE,
                    message,
                    &[
                        "The claim you named is no longer the current head; read successor_short_id.",
                        "Re-get that claim, decide again, and issue the verb against the new head.",
                    ],
                )
            };
        }
        match err.kind() {
            ErrorKind::EntityNotFound | ErrorKind::EdgeNotFound => Self::new(
                FACADE_CODE_NOT_FOUND,
                message,
                &["Verify the identifier and retry."],
            ),
            // FORBIDDEN like the gate family beside it, but with its OWN
            // remedies: the generic arm points at pending consents and at
            // resubmitting as proposed, and both are exactly what this error
            // means is unavailable. Advice a caller cannot take is worse than
            // no advice.
            // FORBIDDEN with the gate family — it is a policy/authority denial,
            // not a bad request — but with the remedies THIS denial has. The
            // generic arm's advice (review pending consents, resubmit as
            // proposed) is about a gate that parked a write; nothing was
            // parked here, and the actor's standing is what has to change.
            ErrorKind::ActorLacksClaimAuthority => Self::new(
                FACADE_CODE_FORBIDDEN,
                message,
                &[
                    "Check the ref: this may not be the claim you meant.",
                    "Retract as the actor that authored it.",
                    "Acting over another actor's claim needs an active owner binding.",
                ],
            ),
            ErrorKind::FamilyRequiresAutoGrant => Self::new(
                FACADE_CODE_FORBIDDEN,
                message,
                &[
                    "This vault's policy will not grant auto for this family, and the family has no review path.",
                    "Loosen the policy for this predicate prefix, or write as an actor the policy admits.",
                ],
            ),
            ErrorKind::GateWriteRejected
            | ErrorKind::SourceNotTrustedForAuto
            | ErrorKind::GateConsentStale
            | ErrorKind::MaintenanceKindNotWritable
            | ErrorKind::ActorClassMismatch => Self::new(
                FACADE_CODE_FORBIDDEN,
                message,
                &[
                    "The gate refused this write; review pending consents via pending_writes.",
                    "Submit the claim as proposed or adjust the actor/scope.",
                ],
            ),
            // K7 (ONE-1728): distinct from the FORBIDDEN gate family above —
            // nothing was refused on policy grounds. The room is simply not
            // reachable through this door, and the remedy is a different door,
            // not a different actor or scope.
            ErrorKind::OffRecordWitnessDoorRejected => Self::new(
                FACADE_CODE_OFF_RECORD_SESSION_DOOR,
                message,
                &[
                    "This conversation belongs to a live off-record session; witness it through the session handle.",
                    "Close the session first if the turn belongs on the record.",
                ],
            ),
            ErrorKind::ClaimAlreadyClosed
            | ErrorKind::ClaimSelfSupersession
            | ErrorKind::CompanionRecordAlreadyExists
            | ErrorKind::ConcurrentWrite
            | ErrorKind::EntityTypeImmutable => Self::new(
                FACADE_CODE_INVALID_STATE,
                message,
                &["Refresh the resource, merge local changes, then retry."],
            ),
            ErrorKind::Storage
            | ErrorKind::Io
            | ErrorKind::CorruptedIndex
            | ErrorKind::InvariantViolation
            | ErrorKind::MapFull
            | ErrorKind::IndexOverflow
            | ErrorKind::MissingPostingEntry => Self::new(
                FACADE_CODE_INTERNAL,
                message,
                &["Retry; if the failure persists, inspect vault store health."],
            ),
            _ => Self::new(
                FACADE_CODE_BAD_REQUEST,
                message,
                &["Fix the request shape and retry."],
            ),
        }
    }
}

/// Facade result alias.
pub type FacadeResult<T> = std::result::Result<T, FacadeError>;
