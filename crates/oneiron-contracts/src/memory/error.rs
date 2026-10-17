//! Memory error vocabulary: [`MemoryError`], the stable `MEMORY_CODE_*` strings,
//! and the central engine-error mapping. Split from the flat `facade.rs`;
//! surface re-exported by [`super`] (the `memory` module).

use serde::{Deserialize, Serialize};

use crate::error::{
    ClaimError, Error, ErrorKind, GateDenialOutcome, GateDenialReason, GateError, VerbHookStop,
};

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

/// An effect named a person through a mention that is not settled yet
/// (OF-123). The caller settles it with `self.identity.settle`, then acts.
pub const MEMORY_CODE_IDENTITY_UNSETTLED: &str = "IDENTITY_UNSETTLED";

/// A paid call's budget line cannot cover it: the line the host admitted the
/// request on is spent, or the vault's budget policy refuses the call. Distinct
/// from `LEASE_REQUIRED`: the caller held a lease, and the line ran out.
pub const MEMORY_CODE_BUDGET_SPENT: &str = "BUDGET_SPENT";

/// The model a request needs gave no usable answer: its route refused the
/// call, the call failed, or its answer did not fit the call. Nothing stands
/// in for it.
pub const MEMORY_CODE_MODEL_UNAVAILABLE: &str = "MODEL_UNAVAILABLE";

/// The canonical door was asked to witness into a conversation owned by a live
/// off-record session (ARCH-0052 D2 backstop (a), ONE-1728 K7). Distinct from
/// `FORBIDDEN`: the write was not refused on policy grounds — the room is only
/// reachable through the session handle.
pub const MEMORY_CODE_OFF_RECORD_SESSION_DOOR: &str = "OFF_RECORD_SESSION_DOOR";

/// An owner verb was attempted by an actor holding no ACTIVE human-class owner
/// binding in the vault's authority log (S-AUTH3 T9/T11).
///
/// Distinct from `FORBIDDEN` because the remedy differs: the generic arm's
/// advice is about a gate that parked a write (review pending consents,
/// resubmit as proposed) and the actor-class arms are about writing as a
/// different actor. Neither applies here. Nothing was parked and no scope
/// change helps — the authority log has to gain a `BindActor` entry signed by
/// an owner device before ANY owner verb (`put_structural` mints,
/// cross-actor `claim_retract`, `safe_delete`) authorizes.
///
/// It is also the only refusal that separates "the authority log denied this
/// actor" from a Gate denial on the same verb: `safe_delete` can refuse with
/// `FORBIDDEN` from either door, and only this code tells a caller which one
/// it hit.
pub const MEMORY_CODE_OWNER_BINDING_REQUIRED: &str = "OWNER_BINDING_REQUIRED";

/// An embedded vault directory is already owned by another process holding the
/// single-writer lease (ONE-1441 WIRE-P1).
///
/// Distinct from `INVALID_STATE`, which is the refresh-and-retry family: this
/// refusal is about WHO holds the writer lease on a directory, not about a
/// stale target or a version conflict, and no retry loop resolves it. The
/// remedies are to connect to the owning process or to stop it — never to
/// re-read and write again.
///
/// Emitted by the SDK's embedded constructor when
/// `oneiron::VaultWriterLease::acquire` refuses, and only when the refusal is
/// lease contention (`Error::ConcurrentWrite` carrying
/// `oneiron::VAULT_WRITER_LEASE_HELD`). The central `From<Error>` impl below is
/// deliberately NOT amended: every other `ConcurrentWrite` keeps its
/// `INVALID_STATE` mapping.
pub const MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER: &str = "VAULT_LOCKED_SINGLE_WRITER";

/// An SDK call named a verb under the wrong root (`tools.`, `connectors.`, a
/// shared verb under `self.memory`, ...). The call is refused before any
/// effect and never corrected and run: the caller issues a fresh call to the
/// `replacement` the error carries (EIRI-ARCH-0002 §The contract).
pub const MEMORY_CODE_WRONG_ROOT: &str = "WRONG_ROOT";

/// A verb hook asked before the verb ran (ARCH-0080 §3): the verb waits on an
/// open ask, and the refusal's `hook` names the invocation and the ask. A
/// retry with the same invocation answers the same ask, never a second one.
/// Distinct from `FORBIDDEN`: nothing was refused, the verb is only waiting,
/// like a gate's pending write.
pub const MEMORY_CODE_PENDING_ASK: &str = "PENDING_ASK";
/// A write named a record ref that does not resolve under its writer's own
/// scoped read (OF-063): invented, missing and unreadable are this one
/// refusal. The message names the field pointer, never the ref. The write
/// never ran, and the refusal was receipted on its own write before this
/// error left the engine.
pub const MEMORY_CODE_INVENTED_REFERENCE: &str = "INVENTED_REFERENCE";

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
    /// the engine error was [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected) (ONE-1686).
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
    /// The mandatory receipt of the scoped read that produced this refusal,
    /// present when a read verb answers `NOT_FOUND`: an absent row and a row
    /// this actor may not read are both `NOT_FOUND`, and only the receipt
    /// says which axes narrowed (DEC-0005: a read never silently narrows).
    ///
    /// On the wire it is `narrowing`, the one name every read result uses
    /// for its receipt. Boxed for the same reason `gate_denial` is.
    #[serde(default, rename = "narrowing", skip_serializing_if = "Option::is_none")]
    pub read_receipt: Option<Box<crate::claim::ScopedReadReceipt>>,
    /// Policy refusal facts, addressable without parsing prose. Absent for
    /// errors that did not refuse an act under a scoped manifest row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_denial: Option<Box<MemoryPolicyDenial>>,
    /// The correction a `WRONG_ROOT` refusal carries. Flattened, so the wire
    /// shape is `{code, attempted, replacement, schemaRef, ...}`; boxed for
    /// the same reason `gate_denial` is.
    #[serde(flatten)]
    pub wrong_root: Option<Box<MemoryWrongRoot>>,
    /// The verb hook's stop behind this refusal (ARCH-0080 §3): skipped,
    /// pending on an ask, or hidden. Boxed for the same reason `gate_denial`
    /// is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<Box<VerbHookStop>>,
}

/// A wrong-root refusal's correction: the name the caller wrote, the
/// canonical name to call instead, and where that verb's schema lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWrongRoot {
    pub attempted: String,
    pub replacement: String,
    #[serde(rename = "schemaRef")]
    pub schema_ref: String,
}

/// The stable Gate rejection strings behind a [`MemoryError`] whose engine
/// cause was [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected): the outcome (`pending`/`deny`) and
/// the `gate.*` reason codes, exactly as the engine spelled them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGateDenial {
    /// `pending` or `deny`.
    pub outcome: String,
    /// Stable `gate.*` reason codes.
    pub reason_codes: Vec<String>,
}

/// Typed provenance and exception door for a refused policy-controlled act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPolicyDenial {
    pub level: String,
    pub row_ref: String,
    pub role: String,
    pub exception_proposal: MemoryPolicyExceptionProposal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryPolicyExceptionProposal {
    pub action: String,
    pub row_ref: String,
    pub required_role: String,
}

impl MemoryError {
    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn new(code: &str, message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            suggestions: suggestions.iter().map(|s| (*s).to_owned()).collect(),
            successor_short_id: None,
            gate_denial: None,
            read_receipt: None,
            policy_denial: None,
            wrong_root: None,
            hook: None,
        }
    }

    /// The `WRONG_ROOT` refusal for `attempted`, naming its canonical
    /// `replacement` and that verb's `schema_ref`.
    #[must_use]
    pub fn wrong_root(
        attempted: impl Into<String>,
        replacement: impl Into<String>,
        schema_ref: impl Into<String>,
    ) -> Self {
        let (attempted, replacement) = (attempted.into(), replacement.into());
        let mut error = Self::new(
            MEMORY_CODE_WRONG_ROOT,
            format!("`{attempted}` is not an SDK verb; the verb is `{replacement}`"),
            &["Call the replacement verb; a wrong root is never run."],
        );
        error.wrong_root = Some(Box::new(MemoryWrongRoot {
            attempted,
            replacement,
            schema_ref: schema_ref.into(),
        }));
        error
    }

    /// The same refusal carrying the receipt of the read that produced it.
    #[must_use]
    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn with_read_receipt(mut self, receipt: crate::claim::ScopedReadReceipt) -> Self {
        self.read_receipt = Some(Box::new(receipt));
        self
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
        Some(Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }))
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(
            MEMORY_CODE_BAD_REQUEST,
            message,
            &["Fix the request shape and retry."],
        )
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn bad_request_with(message: impl Into<String>, suggestions: &[&str]) -> Self {
        Self::new(MEMORY_CODE_BAD_REQUEST, message, suggestions)
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(
            MEMORY_CODE_NOT_FOUND,
            message,
            &["Verify the identifier and retry."],
        )
    }
}

impl MemoryError {
    /// A verb hook's stop as the refusal a caller reads: a skip is the
    /// `INVALID_STATE` family with the hook's reason, an ask is
    /// `PENDING_ASK`, a hidden result is `FORBIDDEN`. A call settlement
    /// already ran is `INVALID_STATE` at a door that cannot answer with its
    /// result, and its own code when it failed. The typed stop rides in
    /// `hook`.
    fn verb_hook(stop: VerbHookStop) -> Self {
        if let VerbHookStop::CompletedWithError { code, message, .. } = &stop {
            return Self {
                hook: Some(Box::new(stop.clone())),
                ..Self::new(
                    code,
                    message.clone(),
                    &[
                        "This invocation already ran once its hook's ask was answered; call again with a new invocation.",
                    ],
                )
            };
        }
        let (code, suggestion) = match &stop {
            VerbHookStop::Skipped { .. } => (
                MEMORY_CODE_INVALID_STATE,
                "A verb hook skipped this call for the reason given; change the call, or ask the vault owner about the hook.",
            ),
            VerbHookStop::Pending { .. } => (
                MEMORY_CODE_PENDING_ASK,
                "Wait for the ask to be answered, then retry with the same invocation id.",
            ),
            VerbHookStop::Hidden { .. } => (
                MEMORY_CODE_FORBIDDEN,
                "A blocking verb hook failed, so this result stays hidden; retry later or ask the vault owner.",
            ),
            VerbHookStop::Completed { .. } | VerbHookStop::CompletedWithError { .. } => (
                MEMORY_CODE_INVALID_STATE,
                "This invocation already ran once its hook's ask was answered; its result rides in `hook`.",
            ),
        };
        Self {
            hook: Some(Box::new(stop.clone())),
            ..Self::new(code, stop.to_string(), &[suggestion])
        }
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
        if let Error::Claim(ClaimError::ScopedReadOwnerNotLive(refusal)) = err {
            return *refusal;
        }
        if let Error::VerbHook(stop) = err {
            return Self::verb_hook(*stop);
        }
        let message = err.to_string();
        // ONE-1936: the successor ref travels as a FIELD, not as prose. A
        // stale target is an INVALID_STATE refusal like the rest of the
        // refresh-and-retry family, but this one names exactly what to
        // refresh TO.
        if let Error::Claim(ClaimError::WriteVerbTargetStale {
            successor_short_id, ..
        }) = err
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
        // The hold is a valid write parked on the parties it names, not a
        // bad request: INVALID_STATE, filed by the join it names.
        if matches!(
            err,
            Error::Record(crate::error::RecordError::RoomJoinHeld(_))
        ) {
            return Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "File the join with vault.rooms.join and the intent_key named here; the write goes through once those parties consent.",
                ],
            );
        }
        if matches!(
            err,
            Error::Record(crate::error::RecordError::InvalidTaskBody(
                "tasks.ask.option"
            ))
        ) {
            return Self::bad_request_with(
                message,
                &[
                    "Name one of the question's option ids (or omit the option if the question has none).",
                ],
            );
        }
        match err.kind() {
            ErrorKind::IdentityUnsettled => Self::new(
                MEMORY_CODE_IDENTITY_UNSETTLED,
                message,
                &[
                    "Call self.identity.settle with the person's name and this effect, then act again.",
                    "If it answers needs_person, wait for the person's choice on the card before acting.",
                ],
            ),
            ErrorKind::KeyValueWriteRequiresOwnedDoor => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "Use the actor-bound key_value API for keyed facts; generic claims and imports cannot overwrite keyed revisions.",
                ],
            ),
            ErrorKind::OffRecordTalkOnly => Self::new(
                MEMORY_CODE_FORBIDDEN,
                message,
                &["This session cannot retain this action. Start a separate on-record session."],
            ),
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
            // Only the vault's owner records a guest's consent; no change to
            // the request makes this ask admissible.
            // A policy refusal, not a bad request: the member's choice is
            // what has to change.
            ErrorKind::WorkCompanionRequired => Self::new(
                MEMORY_CODE_FORBIDDEN,
                message,
                &["Start a work companion in this workspace; its policy refuses a brought one."],
            ),
            ErrorKind::ConsentGuestNotRecorded => Self::new(
                MEMORY_CODE_FORBIDDEN,
                message,
                &["Ask the vault's owner to record this guest's consent, then ask again."],
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
                    Error::Gate(GateError::GateWriteRejected {
                        outcome,
                        reason_codes,
                    }) => Self {
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
            // Both are off-record ROOM STATE, not request shape: the caller's
            // turn is well formed and the generic `_` arm's "fix the request
            // shape and retry" is advice it cannot act on. They are the
            // refresh-and-retry family (`INVALID_STATE`, already a 409
            // server-side) with the remedy each one actually has.
            ErrorKind::OffRecordOverlayLeaseClosed => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "The room flipped mode after this write route was minted; mint a fresh route and retry.",
                    "A route is generation-stamped on purpose: a stale one refuses before staging anything.",
                ],
            ),
            ErrorKind::OffRecordSavingStopped => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "Nothing of this write was kept, and the stretch is off record again.",
                    "Witness the turn again to say it off record; only the vault's owner, in the room, puts it back on record.",
                ],
            ),
            ErrorKind::OffRecordCopyConflict => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "Nothing of this save was kept; what was said stays in the room until it closes.",
                    "Export the talk to keep a copy of it.",
                ],
            ),
            // One answer for "no such stretch" and "not in its room", as the
            // HTTP boundary gives, so a stranger learns nothing of a room's
            // stretches here either.
            ErrorKind::OffRecordSessionNotFound | ErrorKind::OffRecordNotInRoom => Self::new(
                MEMORY_CODE_NOT_FOUND,
                message,
                &["Verify the room and the stretch, and join the room before acting in it."],
            ),
            ErrorKind::OffRecordOverlayFull => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "This private room is full; witness a smaller turn, or enter the session with a larger byte budget.",
                    "Promote the room's turns to the durable vault, or close it, to stop holding the bytes.",
                ],
            ),
            ErrorKind::ClaimAlreadyClosed
            | ErrorKind::ClaimSelfSupersession
            | ErrorKind::ConcurrentWrite
            | ErrorKind::EntityTypeImmutable => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &["Refresh the resource, merge local changes, then retry."],
            ),
            // The vault holds too little authority history to fold (OF-469):
            // an import of what it names closes the gap; no request changes.
            ErrorKind::AuthorityHistoryRequired => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "Fetch the authority history this vault names (its history request), import it, then retry.",
                ],
            ),
            // The vault no longer holds the bytes a restore needs; the
            // request itself was sound.
            ErrorKind::SkillPackageUnavailable => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &["Restore the revision's package (re-import it), or edit the skill by hand."],
            ),
            // The host skipped a setup step, so neither the request nor the
            // caller's standing is what has to change.
            ErrorKind::EngineIdentitiesNotProvisioned => Self::new(
                MEMORY_CODE_INTERNAL,
                message,
                &[
                    "The host must provision the engine's machine identities after it opens the vault, then retry.",
                ],
            ),
            ErrorKind::Storage
            | ErrorKind::Io
            | ErrorKind::CorruptedIndex
            | ErrorKind::SideTableRow
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
