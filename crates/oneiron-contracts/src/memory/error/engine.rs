use super::*;

impl From<Error> for MemoryError {
    fn from(err: Error) -> Self {
        if let Error::Claim(ClaimError::ScopedReadOwnerNotLive(refusal)) = err {
            return *refusal;
        }
        if let Error::VerbHook(stop) = err {
            return Self::verb_hook(*stop);
        }
        let message = err.to_string();
        // FIX 3194: an outage keeps when to call again as its field.
        if let Error::ProviderUnavailable { retry_after } = err {
            return Self {
                retry_after: Some(retry_after),
                ..Self::new(
                    MEMORY_CODE_MODEL_UNAVAILABLE,
                    message,
                    &["Call again once retry_after seconds have passed."],
                )
            };
        }
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
        // The hold names the live call a room's assembly waits on: refresh
        // that call's roster and speaker entries, then assemble again.
        if matches!(
            err,
            Error::Record(crate::error::RecordError::RoomLiveSpeakersIncomplete(_))
        ) {
            return Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "A voice call live in this room has no stored roster, or a speaker it must place is not entered yet; its host records them on its next roster refresh. Assemble again after that.",
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
            // FIX 2222: its own code, so a client tells it from a gate's or
            // the owner binding's refusal; the remedy is the customer's.
            ErrorKind::HostActionRequiresSupportGrant => Self::new(
                MEMORY_CODE_HOST_ACTION_REFUSED,
                message,
                &[
                    "Ask the customer for a support grant; the operator's own admin commands (status, backup, restore, repair, move) need none.",
                ],
            ),
            // FIX 7463a: a world's read setting keeps a row the call reads,
            // named as that setting rather than as a row that is not there.
            ErrorKind::WorldRecipientLimit => Self::new(
                MEMORY_CODE_WORLD_RECIPIENT_LIMIT,
                message,
                &[
                    "The owner's read setting for the row's world keeps it from where this answer goes; read it where his choice admits, or ask him to change that setting.",
                ],
            ),
            ErrorKind::WorldPlacementUnverifiable => Self::new(
                MEMORY_CODE_WORLD_PLACEMENT_UNVERIFIABLE,
                message,
                &[
                    "Nothing was released: the world placement or policy named here cannot be verified now. No change to the request helps; retry once the vault has settled it.",
                ],
            ),
            ErrorKind::ConsentGuestNotRecorded => Self::new(
                MEMORY_CODE_FORBIDDEN,
                message,
                &["Ask the vault's owner to record this guest's consent, then ask again."],
            ),
            // FIX 10917: a lapsed owner proof is a refusal, not a malformed
            // request: the owner re-authenticates, then acts again.
            ErrorKind::ConsentOwnerNotAuthenticated => Self::new(
                MEMORY_CODE_FORBIDDEN,
                message,
                &["Re-authenticate as the vault's owner, then retry."],
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
                            ask_ref: None,
                            approval_digest: None,
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
                    "Witness the turn again to say it off record; a participant in the room holding this vault's write grant can save from here.",
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
            // FIX 12023 W0: the process that serves the vault spends its
            // request nonces; no change to the request helps here.
            ErrorKind::VaultServedElsewhere => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &["Send the request to the process that serves this vault."],
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
            ErrorKind::AuthorityClockCorrupt => Self::new(
                MEMORY_CODE_AUTHORITY_CLOCK_CORRUPT,
                message,
                &["The owner runs vault.authority.clock.repair, then retries."],
            ),
            // The vault cannot prove how its decision seals stand (FIX 5248):
            // the message names the seal or image that failed.
            ErrorKind::SealStandingUnverifiable => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[crate::error::SEAL_STANDING_RECONCILE_TEXT],
            ),
            // The vault no longer holds the bytes a restore needs; the
            // request itself was sound.
            ErrorKind::SkillPackageUnavailable => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &["Restore the revision's package (re-import it), or edit the skill by hand."],
            ),
            ErrorKind::ModelPinUnavailable => Self::new(
                MEMORY_CODE_MODEL_PIN_UNAVAILABLE,
                message,
                &["Offer a seat for the pinned model, or clear or change the owner's model pin."],
            ),
            // The request was sound; the refusal names the bound that has to
            // change first (a scope to fund, a seat to bind), and is the
            // whole answer.
            ErrorKind::Refused => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &["Do what the message names (fund, bind or configure it), then ask again."],
            ),
            // A legal order binding the host keeps the record (WILL-PLAN L01
            // rows 01 and 03): the record's state refuses, not the request,
            // and the message names the order's bound.
            ErrorKind::LegalHold => {
                let legal_hold = match err {
                    Error::LegalHold(notice) => Some(notice),
                    _ => None,
                };
                Self {
                    legal_hold,
                    ..Self::new(
                        MEMORY_CODE_INVALID_STATE,
                        message,
                        &[crate::error::LEGAL_HOLD_SUGGESTION],
                    )
                }
            }
            // An erase of a code run's actor took the reply this read names
            // (FIX 5718): the record's state, never the request's shape. What
            // the call did stands, and no retry brings the reply back.
            ErrorKind::ResponseErased => Self::new(
                MEMORY_CODE_INVALID_STATE,
                message,
                &[
                    "An erase took this reply: what the call did stands, and no call sends it again.",
                ],
            ),
            ErrorKind::HoldTargetErased => Self::hold_target_erased(message),
            // A credential's custody key does not open, or custody could not
            // take a new one (KS-6): the vault's state, never the request's
            // shape, and the message names the credential and its way out.
            ErrorKind::CredentialLeafUnreadable | ErrorKind::CredentialCustodyUnavailable => {
                Self::new(
                    MEMORY_CODE_INVALID_STATE,
                    message,
                    &["Do what the message names: retry, or re-enter or reissue that credential."],
                )
            }
            // A foreign guest's proposal spool met the host's disk floor
            // (FIX 7650): the host's storage, never the request's shape.
            ErrorKind::SandboxProposalDiskFloor => Self::new(
                MEMORY_CODE_SANDBOX_PROPOSAL_DISK_FLOOR,
                message,
                &["The host disk is at its free-space floor; run again once it has room."],
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
