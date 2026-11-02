//! Memory error vocabulary: [`MemoryError`], the stable `MEMORY_CODE_*` strings,
//! and the central engine-error mapping. Split from the flat `facade.rs`;
//! surface re-exported by [`super`] (the `memory` module).

use serde::{Deserialize, Serialize};

use crate::error::{
    ClaimError, Error, ErrorKind, GateDenialOutcome, GateDenialReason, GateError, VerbHookStop,
};

mod engine;
mod gate_denial;
pub use self::gate_denial::MemoryGateDenial;

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

/// The owner pinned a spawn's model and no offered seat serves it (FIX 10011).
pub const MEMORY_CODE_MODEL_PIN_UNAVAILABLE: &str = "MODEL_PIN_UNAVAILABLE";

/// The canonical door was asked to witness into a conversation owned by a live
/// off-record session (ARCH-0052 D2 backstop (a), ONE-1728 K7). Distinct from
/// `FORBIDDEN`: the write was not refused on policy grounds — the room is only
/// reachable through the session handle.
pub const MEMORY_CODE_OFF_RECORD_SESSION_DOOR: &str = "OFF_RECORD_SESSION_DOOR";

/// A session row asked to manage a room's whole off-record stretch: read
/// everyone's overlay at once, write or run in it, or discard it for the
/// room (WILL-PLAN L13 row 03, Engine ruling 2026-10-19). The caller is on
/// the room's roster, so this is no `NOT_FOUND`; nor a `FORBIDDEN` a scope or
/// actor change admits. It is a missing consent record, not a location
/// limit: no record holds the room audience's consent to that management,
/// so every host refuses it alike, hosted, self-hosted or embedded. The
/// members' own bounded acts (status, witness, save, export) stay open.
pub const MEMORY_CODE_ROOM_MANAGEMENT: &str = "OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE";

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

/// The vault's persisted authority clock floor is damaged (FIX 10106): no
/// authority reading stands on it until the owner repairs it.
pub const MEMORY_CODE_AUTHORITY_CLOCK_CORRUPT: &str = "AUTHORITY_CLOCK_CORRUPT";

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

/// A host credential asked to act as the vault's owner where no host acts
/// as a person: a hosted operator's root, or any vault that is not
/// self-hosted (FIX 2222, owner ruling "A + support"). Distinct from
/// `FORBIDDEN` and `OWNER_BINDING_REQUIRED`: no scope, actor or binding the
/// caller can change admits it. The operator's own admin commands need no
/// owner; an owner act inside the vault takes the customer's support grant.
pub const MEMORY_CODE_HOST_ACTION_REFUSED: &str = "HOST_ACTION_REQUIRES_SUPPORT_GRANT";

/// The owner's world recipient choice keeps a row the call reads from where
/// its answer goes (FIX 7463a): the message names his choice (one named
/// machine, or machines marked his) and why this destination is not one it
/// admits, never the world. Distinct from `NOT_FOUND`: the row is there,
/// and the world's read setting is what keeps it. It is no location limit
/// on the caller: the same call reads it where the owner's choice admits.
pub const MEMORY_CODE_WORLD_RECIPIENT_LIMIT: &str = "WORLD_RECIPIENT_LIMIT";

/// The world placement of a row the call reads, or the rows a result was
/// derived from, or the vault root, cannot be verified, so nothing is
/// released (FIX 7463a): an integrity hold, never the owner's choice.
/// Content-free, like `WORLD_RECIPIENT_LIMIT`.
pub const MEMORY_CODE_WORLD_PLACEMENT_UNVERIFIABLE: &str = "WORLD_PLACEMENT_UNVERIFIABLE";

/// A foreign guest's proposal spool append would cross the host's disk floor
/// (FIX 7650): the message names the measured bytes needed and free and the
/// reserve, never the file's contents. The host's storage refuses, not the
/// request; the run proposed nothing and goes through once the disk has room.
pub const MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR: &str = "SANDBOX_PROPOSAL_DISK_FLOOR";

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
    /// When to call again, in seconds, on a refusal no provider answered
    /// (FIX 3194): nothing keeps the call, so its caller sends it again.
    /// Absent on every other refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// Each time the refused call's limit resets, as Unix seconds in the
    /// order its source said them (FIX 8190); empty where it said none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resets_at: Vec<u64>,
    /// The stable reason codes behind this refusal, in the order and
    /// spelling its producer gave them (FIX 7398): a room's upkeep voice
    /// refusal names its `gate.rooms.upkeep.*` code here, so no client parses
    /// it out of `message`. Empty, and absent on the wire, where the producer
    /// named none. A Gate write rejection's codes stay in `gate_denial`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    /// The typed legal-hold notice behind this refusal, when its producer supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_hold: Option<Box<crate::error::LegalHoldNotice>>,
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
            retry_after: None,
            resets_at: Vec::new(),
            reason_codes: Vec::new(),
            legal_hold: None,
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

/// Facade result alias.
pub type MemoryResult<T> = std::result::Result<T, MemoryError>;
