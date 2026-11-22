//! The reason codes, words and next steps of an owner-key refusal of a
//! membership move ([`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused)):
//! one constant for each step's code, refusal text and suggestion, and the
//! device-confirm words a client shows before it signs the move.

/// The prefix of the reason code that names what a client offers next after
/// an owner-key refusal of a membership move
/// ([`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused)), followed by the
/// step itself.
pub const OWNER_KEY_NEXT_STEP_REASON_PREFIX: &str = "next_step:";

/// The next step [`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused)
/// names where no install
/// of this vault can prove the move and no device confirm reaches it (row
/// HOSTED-ROOT-REVOKES-OWNER-KEY): an operator's or a proof-of-control
/// recovery, so a client offers no retry. A hosted server holds no owner key,
/// and a device holds no host issuer to make the move with.
pub const OWNER_KEY_MOVE_NEXT_STEP: &str = "owner_device_proof_unavailable";

/// The next step of a refused shared act whose executor holds a live owner
/// key on a device of theirs (row HOSTED-OWNER-MOVE-TWO-PHASE): the act stays
/// pending, and that device confirms it.
pub const OWNER_KEY_MOVE_CONFIRM_STEP: &str = "confirm_on_owner_device";

/// The next step of a refused shared act whose executor holds no live owner
/// key (row HOSTED-OWNER-MOVE-TWO-PHASE): the act stays pending until they
/// enrol an owner key on a device of theirs and confirm it there.
pub const OWNER_KEY_MOVE_ENROL_STEP: &str = "enrol_owner_device";

/// The prefix of the reason code that names the member whose owner keys a
/// refused membership move would end
/// ([`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused)),
/// followed by their id in hex.
pub const OWNER_KEY_MEMBER_REASON_PREFIX: &str = "member:";

/// The prefix of the reason code that names the pending shared act a refused
/// membership move ran for
/// ([`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused)), followed
/// by its id: the act a device confirms.
pub const OWNER_KEY_ACT_REASON_PREFIX: &str = "act:";

/// The engine's words for
/// [`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused) with
/// [`OWNER_KEY_MOVE_NEXT_STEP`], kept in this one place with each step's
/// suggestion (the lead, 15 Nov 21:42: the text stays easy to change). They
/// say plainly that the move needs a device that holds an owner key (Engine
/// RULING OWNERKEY-HOSTED-MOVE-NEXT-STEP = A, 16 Nov 19:53).
pub const OWNER_KEY_MOVE_REFUSAL_TEXT: &str = "This move ends a member's owner keys, so it needs a device that holds your owner key, and this install holds none: nothing was changed.";

/// What [`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused) suggests with
/// [`OWNER_KEY_MOVE_NEXT_STEP`].
pub const OWNER_KEY_MOVE_SUGGESTION: &str = "This move needs a device that holds your owner key, and none can confirm it here: the member keeps their owner standing until then.";

/// The engine's words with [`OWNER_KEY_MOVE_CONFIRM_STEP`] (Engine RULING
/// OWNERKEY-HOSTED-MOVE-NEXT-STEP = A: "confirm this on one of your
/// devices").
pub const OWNER_KEY_MOVE_CONFIRM_TEXT: &str = "This move ends a member's owner keys: confirm this on one of your devices. Nothing was changed yet.";

/// What [`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused) suggests with
/// [`OWNER_KEY_MOVE_CONFIRM_STEP`].
pub const OWNER_KEY_MOVE_CONFIRM_SUGGESTION: &str =
    "Confirm this on one of your devices that holds your owner key; the move waits until then.";

/// The engine's words with [`OWNER_KEY_MOVE_ENROL_STEP`].
pub const OWNER_KEY_MOVE_ENROL_TEXT: &str = "This move ends a member's owner keys, so you confirm it on a device that holds your owner key, and you hold none yet. Nothing was changed.";

/// What [`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused) suggests with
/// [`OWNER_KEY_MOVE_ENROL_STEP`].
pub const OWNER_KEY_MOVE_ENROL_SUGGESTION: &str =
    "Add an owner key on one of your devices, then confirm this there; the move waits until then.";

/// The words the Owner's device shows before it signs a move's owner-key
/// revokes (Engine ANSWER OWNERKEY-TWO-PHASE-MEMBER-CONFIRM = A). The client
/// fills `{member}` with the member's name from the device's own copy, never
/// from the server's plan, and passes that member to
/// `vault.shared.owner_key_move_sign`.
pub const OWNER_KEY_MOVE_DEVICE_CONFIRM_TEXT: &str =
    "End {member}'s owner keys on this vault? They will no longer be an Owner.";

/// [`OWNER_KEY_MOVE_DEVICE_CONFIRM_TEXT`] for an Owner's own leave.
pub const OWNER_KEY_MOVE_DEVICE_CONFIRM_OWN_TEXT: &str =
    "End your own owner keys on this vault? You will no longer be an Owner.";

/// What a client offers after
/// [`RecordError::OwnerKeyMoveRefused`](super::RecordError::OwnerKeyMoveRefused): its
/// next step, each with one constant for its code, its words and its
/// suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKeyMoveStep {
    /// No device confirm reaches the move ([`OWNER_KEY_MOVE_NEXT_STEP`]).
    Unavailable,
    /// The executor's device confirms the pending act
    /// ([`OWNER_KEY_MOVE_CONFIRM_STEP`]).
    ConfirmOnOwnerDevice,
    /// The executor enrols an owner key on a device first
    /// ([`OWNER_KEY_MOVE_ENROL_STEP`]).
    EnrolOwnerDevice,
}

impl OwnerKeyMoveStep {
    /// The step's code, after [`OWNER_KEY_NEXT_STEP_REASON_PREFIX`].
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => OWNER_KEY_MOVE_NEXT_STEP,
            Self::ConfirmOnOwnerDevice => OWNER_KEY_MOVE_CONFIRM_STEP,
            Self::EnrolOwnerDevice => OWNER_KEY_MOVE_ENROL_STEP,
        }
    }

    /// The refusal's words with this step.
    #[must_use]
    pub const fn refusal_text(self) -> &'static str {
        match self {
            Self::Unavailable => OWNER_KEY_MOVE_REFUSAL_TEXT,
            Self::ConfirmOnOwnerDevice => OWNER_KEY_MOVE_CONFIRM_TEXT,
            Self::EnrolOwnerDevice => OWNER_KEY_MOVE_ENROL_TEXT,
        }
    }

    /// The refusal's suggestion with this step.
    #[must_use]
    pub const fn suggestion(self) -> &'static str {
        match self {
            Self::Unavailable => OWNER_KEY_MOVE_SUGGESTION,
            Self::ConfirmOnOwnerDevice => OWNER_KEY_MOVE_CONFIRM_SUGGESTION,
            Self::EnrolOwnerDevice => OWNER_KEY_MOVE_ENROL_SUGGESTION,
        }
    }
}

impl std::fmt::Display for OwnerKeyMoveStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.refusal_text())
    }
}
