//! Memory error vocabulary: [`MemoryError`], the stable `MEMORY_CODE_*` strings,
//! and the central engine-error mapping. Split from the flat `facade.rs`;
//! surface re-exported by [`super`] (the `memory` module).

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, GateDenialOutcome, GateDenialReason};

/// Stable facade error codes, mirroring the `oneiron-server`
/// `ApiErrorDetails` code vocabulary (S8).
pub const MEMORY_CODE_BAD_REQUEST: &str = "BAD_REQUEST";

/// See [`MEMORY_CODE_BAD_REQUEST`].
pub const MEMORY_CODE_NOT_FOUND: &str = "NOT_FOUND";

/// See [`MEMORY_CODE_BAD_REQUEST`].
pub const MEMORY_CODE_FORBIDDEN: &str = "FORBIDDEN";

/// See [`MEMORY_CODE_BAD_REQUEST`].
pub const MEMORY_CODE_INVALID_STATE: &str = "INVALID_STATE";

/// See [`MEMORY_CODE_BAD_REQUEST`].
pub const MEMORY_CODE_INTERNAL: &str = "INTERNAL_SERVER_ERROR";

/// `recall(Deep)` called without a budget lease (W4/C4 lease rule).
pub const MEMORY_CODE_LEASE_REQUIRED: &str = "LEASE_REQUIRED";

/// The canonical door was asked to witness into a conversation owned by a live
/// off-record session (ARCH-0052 D2 backstop (a), ONE-1728 K7). Distinct from
/// `FORBIDDEN`: the write was not refused on policy grounds — the room is only
/// reachable through the session handle.
pub const MEMORY_CODE_OFF_RECORD_SESSION_DOOR: &str = "OFF_RECORD_SESSION_DOOR";

/// Typed facade error: stable `code` + human `message` + remediation
/// `suggestions` (never empty). The central `From<Error>` impl is the one
/// engine→binding error mapping (S8); the HTTP mapping stays server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryError {
    /// One of the `MEMORY_CODE_*` strings.
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
    /// The typed Gate denial behind a `FORBIDDEN` refusal, present only when
    /// the engine error was [`Error::GateWriteRejected`] (ONE-1686).
    ///
    /// The facade's job is to render a stable code and message, but a caller
    /// INSIDE the engine — the off-record executor adapter — needs the denial
    /// back as the typed error it was, not as prose it would have to parse.
    /// Carried as a field for the same reason `successor_short_id` is: a
    /// refusal's machine-readable half must not have to survive a round trip
    /// through `message`.
    ///
    /// BOXED, and not for style: `MemoryError` is the `Err` half of
    /// [`MemoryResult`], which hundreds of facade signatures return by value.
    /// An inline `MemoryGateDenial` (a `String` plus a `Vec`) pushes this
    /// struct past clippy's large-error threshold and taxes every one of those
    /// returns with 48 bytes that are `None` on all but the gate-refusal path.
    /// The box is invisible on the wire — `Option<Box<T>>` and `Option<T>`
    /// serialize identically — so the stable payload is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_denial: Option<Box<MemoryGateDenial>>,
}

/// The stable Gate rejection strings behind a [`MemoryError`] whose engine
/// cause was [`Error::GateWriteRejected`]: the outcome (`pending`/`deny`) and
/// the `gate.*` reason codes, exactly as the engine spelled them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGateDenial {
    /// `pending` or `deny`.
    pub outcome: String,
    /// Stable `gate.*` reason codes.
    pub reason_codes: Vec<String>,
}

impl MemoryError {
    pub(super) fn new(code: &str, message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            suggestions: suggestions.iter().map(|s| (*s).to_owned()).collect(),
            successor_short_id: None,
            gate_denial: None,
        }
    }

    /// Rebuilds the typed engine denial this refusal carries, when it carries
    /// one (ONE-1686).
    ///
    /// Only reason codes and outcomes the engine's own taxonomy still knows are
    /// rebuilt, so an unknown string cannot be laundered into a typed error;
    /// an unrecognized one answers `None` and the caller keeps its own
    /// fail-closed handling.
    #[must_use]
    pub fn gate_denial_error(&self) -> Option<Error> {
        let denial = self.gate_denial.as_deref()?;
        let outcome = GateDenialOutcome::parse(&denial.outcome)?.as_str();
        let mut reason_codes = Vec::with_capacity(denial.reason_codes.len());
        for reason_code in &denial.reason_codes {
            reason_codes.push(GateDenialReason::from_code(reason_code)?.as_str());
        }
        Some(Error::GateWriteRejected {
            outcome,
            reason_codes,
        })
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(
            MEMORY_CODE_BAD_REQUEST,
            message,
            &["Fix the request shape and retry."],
        )
    }

    pub(crate) fn bad_request_with(message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self::new(MEMORY_CODE_BAD_REQUEST, message, suggestions)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(
            MEMORY_CODE_NOT_FOUND,
            message,
            &["Verify the identifier and retry."],
        )
    }
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for MemoryError {}

impl From<Error> for MemoryError {
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
                    MEMORY_CODE_INVALID_STATE,
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
                MEMORY_CODE_NOT_FOUND,
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
                MEMORY_CODE_FORBIDDEN,
                message,
                &[
                    "Check the ref: this may not be the claim you meant.",
                    "Retract as the actor that authored it.",
                    "Acting over another actor's claim needs an active owner binding.",
                ],
            ),
            ErrorKind::FamilyRequiresAutoGrant => Self::new(
                MEMORY_CODE_FORBIDDEN,
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
            | ErrorKind::ActorClassMismatch => {
                let forbidden = Self::new(
                    MEMORY_CODE_FORBIDDEN,
                    message,
                    &[
                        "The gate refused this write; review pending consents via pending_writes.",
                        "Submit the claim as proposed or adjust the actor/scope.",
                    ],
                );
                // ONE-1686: the denial's machine-readable half rides as a
                // FIELD. Everything above renders it for a client; an
                // engine-internal adapter needs it back as the typed error.
                match err {
                    Error::GateWriteRejected {
                        outcome,
                        reason_codes,
                    } => Self {
                        gate_denial: Some(Box::new(MemoryGateDenial {
                            outcome: outcome.to_owned(),
                            reason_codes: reason_codes
                                .iter()
                                .map(|reason| (*reason).to_owned())
                                .collect(),
                        })),
                        ..forbidden
                    },
                    _ => forbidden,
                }
            }
            // K7 (ONE-1728): distinct from the FORBIDDEN gate family above —
            // nothing was refused on policy grounds. The room is simply not
            // reachable through this door, and the remedy is a different door,
            // not a different actor or scope.
            ErrorKind::OffRecordWitnessDoorRejected => Self::new(
                MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
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
                MEMORY_CODE_INVALID_STATE,
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
                MEMORY_CODE_INTERNAL,
                message,
                &["Retry; if the failure persists, inspect vault store health."],
            ),
            _ => Self::new(
                MEMORY_CODE_BAD_REQUEST,
                message,
                &["Fix the request shape and retry."],
            ),
        }
    }
}

/// Facade result alias.
pub type MemoryResult<T> = std::result::Result<T, MemoryError>;
