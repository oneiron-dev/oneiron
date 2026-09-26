//! The one witness program: request checks, one plan, the ONE-1686 ceiling door and the
//! ONE-1767 mint contract in one transaction, landing in base or in a session overlay.

use super::super::support::*;
use super::super::*;
use super::base::BaseSink;
use super::codec::{encode_witness_turn_body, incoming_turn_speaker, session_short_ref_string};
use super::session::OverlaySink;
use super::validation::{
    validate_existing_witness_message, validate_existing_witness_message_orders,
    validate_existing_witness_turn,
};
use super::{distinct_message_orders, witness_message_envelope};

use std::collections::HashSet;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{
    WitnessMessageAuthorization, WitnessMessageEnvelope, check_witness_message_ceiling,
    resolve_policy_manifest,
};
use crate::off_record::OffRecordSession;
use crate::ports::EntityRecord;
use crate::session_overlay::{RouteTarget, SessionWriteRoute, TxnSegmentGuard};
use crate::store::ManifestDbs;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Where a witness is asked to land. The session is the one parameter the two
/// landings differ by.
pub(super) enum WitnessTarget<'a, 'v> {
    /// Durable base. `route` is `Some` only when a session's on-record
    /// continuation carries the turn (K10): it is the sole evidence the room
    /// was ON RECORD when the turn was admitted, so the program revalidates it
    /// as the last statement of the write transaction.
    Base {
        route: Option<&'a SessionWriteRoute>,
    },
    /// A session (ARCH-0052 §7, ONE-1728): the room's overlay while it is off
    /// record, the base continuation shell after a flip to on record. The
    /// summary is overlay-only (see [`Memory::witness_into_session`]).
    Session {
        session: &'a OffRecordSession<'v>,
        summary: Option<&'a str>,
    },
}

/// Who holds the door, and which turn-id capability they carry.
#[derive(Clone, Copy)]
pub(super) enum WitnessDoor {
    /// A guest caller: its `turn_ref`, if any, is create-or-get at base.
    Guest,
    /// The host executor at base; only it may write report-blocked receipts.
    HostExecutor,
    /// The host executor in a session, with a TURN id derived from its run
    /// identity. A separate capability from the guest `turn_ref`, so keeping a
    /// deterministic retry target cannot weaken the guest refusal.
    HostTurn(EntityId),
}

impl WitnessDoor {
    const fn is_host(self) -> bool {
        !matches!(self, Self::Guest)
    }
}

/// A target resolved against the session's current mode.
enum Landing<'a, 'v> {
    Base {
        route: Option<&'a SessionWriteRoute>,
        continuation: Option<EntityId>,
    },
    Overlay {
        session: &'a OffRecordSession<'v>,
        route: &'a SessionWriteRoute,
        summary: Option<&'a str>,
    },
}

/// One MESSAGE as the plan holds it. The envelope the door authorizes and the
/// canonical body it proves come from ONE value ([`witness_message_envelope`]).
pub(super) struct PlannedMessage<'t> {
    pub(super) message: &'t WitnessMessage,
    pub(super) id: EntityId,
    envelope: WitnessMessageEnvelope<'t>,
    body: Vec<u8>,
}

/// Everything the program decides before its write transaction.
pub(super) struct WitnessPlan<'t> {
    pub(super) turn: &'t WitnessTurn,
    /// Every row carries the witness's own stamps, never the wall clock:
    /// promote replays them, and a restamped row would land in the wrong
    /// month window (ARCH-0052 D4).
    pub(super) occurred: TimeRange,
    pub(super) learned_at: u64,
    pub(super) conversation_id: EntityId,
    /// Base only: the conversation did not resolve before the transaction.
    pub(super) conversation_is_new: bool,
    pub(super) conversation_body: Vec<u8>,
    pub(super) turn_id: EntityId,
    /// The pre-transaction "this TURN does not exist yet" answer. ADVISORY:
    /// the transaction re-reads the row, so a concurrent mint takes the append
    /// path; only a turn expected present and gone is refused.
    pub(super) turn_is_new: bool,
    /// The call's one non-system speaker; `None` is system interleave only.
    speaker: Option<&'static str>,
    pub(super) messages: Vec<PlannedMessage<'t>>,
}

impl WitnessPlan<'_> {
    pub(super) fn message_ids(&self) -> Vec<EntityId> {
        self.messages.iter().map(|planned| planned.id).collect()
    }
}

/// The TURN as the transaction found it.
pub(super) enum AdmittedTurn {
    /// Absent: this witness mints it (ONE-1767), with the one additive
    /// `speaker` entry and a `ChildOf` edge to its conversation.
    Mint { body: Vec<u8> },
    /// Stored and verified: same conversation, same speaker.
    Existing(EntityRecord),
}

/// What the transaction proved, in one pass for both landings.
pub(super) struct WitnessAdmission<'p> {
    pub(super) turn: AdmittedTurn,
    /// The door's own value per message, in plan order. A sink stages a
    /// MESSAGE from this value only, never from a body handed alongside it.
    pub(super) authorized: Vec<WitnessMessageAuthorization<'p>>,
    /// Per message, in plan order: an exact retry of a stored row, which
    /// stages nothing.
    pub(super) message_exists: Vec<bool>,
}

impl WitnessAdmission<'_> {
    pub(super) fn has_new_messages(&self) -> bool {
        self.message_exists.iter().any(|exists| !exists)
    }
}

/// The landing's own staging state, prepared before the transaction.
enum WitnessSink<'a, 'v> {
    Base(BaseSink<'a>),
    Overlay(OverlaySink<'a, 'v>),
}

enum Landed {
    Base,
    HardDeleted(EntityId),
    Overlay {
        segment: TxnSegmentGuard,
        aliases: Vec<(String, u8)>,
    },
}

impl Memory<'_> {
    /// The witness program. Every witness verb is this function with a target
    /// and a door; the target's session is the only thing that decides where
    /// the rows land.
    ///
    /// Order, for both landings: request shape, target resolution, the plan
    /// (containers, speaker, message ids and bodies), the landing's pre-write
    /// state, `before_txn`, then ONE write transaction that runs the landing's
    /// guards, the ceiling door on every envelope, the create-or-verify checks,
    /// the landing's staging, `effect`, and the route revalidation.
    ///
    /// `before_txn` runs in the window between the ADVISORY container
    /// create-or-get and the transaction, which is the race the in-transaction
    /// TURN re-read closes; production callers pass a no-op. `effect` shares
    /// the transaction (stream sidecars, EntityDoc birth): its error rolls back
    /// every row, index and receipt.
    pub(super) fn run_witness(
        &self,
        turn: &WitnessTurn,
        target: WitnessTarget<'_, '_>,
        door: WitnessDoor,
        before_txn: impl FnOnce(),
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        validate_witness_origin(turn, door.is_host())?;
        if turn.messages.is_empty() {
            return Err(MemoryError::bad_request("witness turn carries no messages"));
        }
        if matches!(door, WitnessDoor::HostTurn(_)) && turn.turn_ref.is_some() {
            return Err(Error::InvariantViolation(
                "host-bound session witness also carried a guest turn ref",
            )
            .into());
        }
        distinct_message_orders(&turn.messages)?;
        let session_route;
        let landing = match target {
            WitnessTarget::Base { route } => Landing::Base {
                route,
                continuation: None,
            },
            WitnessTarget::Session { session, summary } => {
                session_route = session.write_route()?;
                // WitnessReceipt promises materialized turns and messages.
                // Anonymous sessions cannot fulfill that promise, so refuse
                // before shell reservation, transaction acquisition, or policy
                // receipt creation.
                session_route.require_recording(session.session_ref())?;
                if session_route.target() == RouteTarget::Base {
                    // Post-flip: the room is on record, so the witness lands in
                    // base under the continuation shell. It never reuses the
                    // overlay conversation id, so K4 sees no overlay refs and
                    // K7 does not fire (the shell is not an overlay member).
                    // The route rides INTO the base transaction: the base half
                    // is the one that publishes durably, so it is the half
                    // that most needs the refusal.
                    Landing::Base {
                        route: Some(&session_route),
                        continuation: Some(session.on_record_continuation_shell()?),
                    }
                } else {
                    Landing::Overlay {
                        session,
                        route: &session_route,
                        summary,
                    }
                }
            }
        };

        let plan = self.plan_witness(turn, &landing, door)?;
        let sink = match landing {
            Landing::Base { route, .. } => WitnessSink::Base(self.base_sink(&plan, route)?),
            Landing::Overlay {
                session,
                route,
                summary,
            } => WitnessSink::Overlay(self.overlay_sink(session, route, summary)?),
        };
        before_txn();

        let landed = self.with_verified_actor_write_txn(|wtxn| {
            let admission = match &sink {
                WitnessSink::Base(_) => {
                    if let Some(id) = self.base_guards_in_txn(&plan, wtxn)? {
                        return Ok(Landed::HardDeleted(id));
                    }
                    self.admit_witness_in_txn(&plan, &self.vault.store, wtxn)?
                }
                // Host-derived ids are create-or-verify in the COMPOSED
                // overlay/base snapshot. The view is dropped before the
                // overlay segment installs, and a divergent body or parent
                // leaves no journal or index delta.
                WitnessSink::Overlay(overlay) => {
                    self.admit_witness_in_txn(&plan, &overlay.read_view()?, wtxn)?
                }
            };
            let landed = match &sink {
                WitnessSink::Base(base) => {
                    self.stage_in_base(&plan, &admission, base, wtxn)?;
                    Landed::Base
                }
                WitnessSink::Overlay(overlay) => {
                    let (segment, aliases) =
                        self.stage_in_overlay(&plan, &admission, overlay, wtxn)?;
                    Landed::Overlay { segment, aliases }
                }
            };
            effect(wtxn)?;
            // LAST statement in the transaction, deliberately: a witness
            // admitted on record must not commit base rows once the room has
            // flipped back off record (K10). Every earlier row rolls back with
            // this `Err`. The overlay route is revalidated by every staged
            // entry instead.
            //
            // The check cannot hold the session state lock: the session
            // mutators hold that lock ACROSS their own write transactions
            // (state -> writer), so a base writer taking it (writer -> state)
            // would invert the order. `revalidate` takes only the overlay's
            // own lifecycle lock, which no holder ever blocks on the base
            // writer for. What remains uncovered is the instant between this
            // check and `wtxn.commit()`; closing that would require the flip
            // to drain base writers the way `seal_writes` drains overlay
            // segments.
            if let WitnessSink::Base(base) = &sink
                && let Some(route) = base.route
            {
                route.revalidate()?;
            }
            Ok(landed)
        })?;

        match landed {
            Landed::HardDeleted(id) => Err(hard_deleted_refusal(&id)),
            Landed::Base => self.base_receipt(&plan),
            Landed::Overlay { segment, aliases } => {
                // The overlay segment and the base txn commit together: the
                // segment applies staged rows only now, so a failure anywhere
                // in staging left the room byte-unchanged.
                segment.commit()?;
                if let WitnessSink::Overlay(overlay) = sink {
                    overlay.commit_shell();
                }
                overlay_receipt(&plan, aliases)
            }
        }
    }

    fn plan_witness<'t>(
        &self,
        turn: &'t WitnessTurn,
        landing: &Landing<'_, '_>,
        door: WitnessDoor,
    ) -> MemoryResult<WitnessPlan<'t>> {
        let ((conversation_id, conversation_is_new), (turn_id, turn_is_new)) = match landing {
            Landing::Base { continuation, .. } => {
                self.resolve_base_containers(turn, *continuation, door)?
            }
            // The room's one shell; the TURN is fresh, or the host's
            // deterministic id, create-or-verified in the transaction.
            Landing::Overlay { session, .. } => {
                let shell = session.overlay_conversation_shell()?;
                let turn_id = match door {
                    WitnessDoor::HostTurn(id) => id,
                    WitnessDoor::Guest | WitnessDoor::HostExecutor => {
                        self.vault.store.clock.entity_id()?
                    }
                };
                ((shell, false), (turn_id, true))
            }
        };

        // The turn-level grouping fact, derived BEFORE the transaction: a call
        // carrying two non-system speakers is a bad request whatever the store
        // holds. `None` means system/tooling interleave only.
        let speaker = incoming_turn_speaker(&turn.messages)?;
        // ONE-1767 binds the overlay door exactly as it binds the base one,
        // and an overlay witness always mints its TURN (or create-or-verifies
        // the host's), so the call must carry the speaker that mint stamps.
        // Promote (ONE-1730) replays the stamped mint into base.
        if matches!(landing, Landing::Overlay { .. }) && speaker.is_none() {
            return Err(MemoryError::bad_request(
                "a new witnessed turn needs one non-system speaker",
            ));
        }

        let mut messages = Vec::with_capacity(turn.messages.len());
        for message in &turn.messages {
            let id = id_from_optional_hex(self.vault, message.id.as_deref())?;
            let envelope = witness_message_envelope(message);
            let body = envelope.encode_body()?;
            messages.push(PlannedMessage {
                message,
                id,
                envelope,
                body,
            });
        }
        Ok(WitnessPlan {
            turn,
            occurred: TimeRange {
                start: turn.occurred_at,
                end: turn.occurred_at,
            },
            learned_at: turn.occurred_at,
            conversation_id,
            conversation_is_new,
            conversation_body: encode_rmpv(&Value::Map(Vec::new()))?,
            turn_id,
            turn_is_new,
            speaker,
            messages,
        })
    }

    /// The in-transaction half both landings share: the ONE-1686 door on every
    /// envelope, then the create-or-verify checks against `dbs` (base for a
    /// base landing, the composed room view for an overlay one).
    fn admit_witness_in_txn<'p>(
        &self,
        plan: &'p WitnessPlan<'_>,
        dbs: &impl ManifestDbs,
        wtxn: &heed::RoTxn<'_>,
    ) -> MemoryResult<WitnessAdmission<'p>> {
        // ONE-1686 (RT-04): the approval-ceiling door, before ANY row stages.
        // The policy manifest is resolved from THIS transaction's snapshot, so
        // the ceiling that authorizes the rows is the one the commit lands
        // under, and a refusal on any message rolls the whole turn back. The
        // room is not a weaker door: promote replays its journal into base
        // verbatim, so an envelope the base boundary refuses is refused at
        // staging too, before the overlay segment installs.
        let policy = resolve_policy_manifest(&self.vault.store, wtxn)?;
        let write_actor = WriteActor::new(self.actor, self.actor_class);
        let mut authorized = Vec::with_capacity(plan.messages.len());
        for planned in &plan.messages {
            authorized.push(check_witness_message_ceiling(
                &self.vault.store,
                wtxn,
                write_actor,
                &planned.envelope,
                &planned.body,
                &policy,
            )?);
        }

        // The pre-transaction create-or-get answer is ADVISORY: a concurrent
        // witness can commit this TURN between that resolve and this
        // transaction. Re-reading the row HERE makes the mint-versus-append
        // decision, and the speaker check that rides it,
        // transaction-authoritative, so a same-id race takes the append path
        // instead of overwriting the committed turn.
        let existing_turn = validate_existing_witness_turn(
            dbs,
            wtxn,
            &plan.turn_id,
            &plan.conversation_id,
            plan.speaker,
        )?;
        // Expected present and gone (a concurrent delete). Recreating it here
        // would silently mint the turn the caller asked to append to.
        if existing_turn.is_none() && !plan.turn_is_new {
            return Err(MemoryError::not_found(
                "the witnessed turn no longer exists",
            ));
        }
        let mut message_exists = Vec::with_capacity(plan.messages.len());
        for planned in &plan.messages {
            message_exists.push(validate_existing_witness_message(
                dbs,
                wtxn,
                &planned.id,
                &planned.body,
                &plan.turn_id,
                &plan.conversation_id,
                planned.message.author,
                &self.actor,
            )?);
        }
        let turn = match existing_turn {
            Some(record) => {
                let existing_message_ids = plan
                    .messages
                    .iter()
                    .zip(&message_exists)
                    .filter_map(|(planned, exists)| exists.then_some(planned.id))
                    .collect::<HashSet<_>>();
                validate_existing_witness_message_orders(
                    dbs,
                    wtxn,
                    &plan.turn_id,
                    &plan.turn.messages,
                    &existing_message_ids,
                )?;
                AdmittedTurn::Existing(record)
            }
            None if message_exists.iter().any(|exists| *exists) => {
                return Err(MemoryError::bad_request(
                    "an existing witnessed message cannot mint its missing turn",
                ));
            }
            // A minted TURN carries exactly one grouping speaker; an all-system
            // call has none to stamp, and the scanner reads this key to score
            // the turn's role.
            None => match plan.speaker {
                Some(speaker) => AdmittedTurn::Mint {
                    body: encode_witness_turn_body(speaker)?,
                },
                None => {
                    return Err(MemoryError::bad_request(
                        "a new witnessed turn needs one non-system speaker",
                    ));
                }
            },
        };
        Ok(WitnessAdmission {
            turn,
            authorized,
            message_exists,
        })
    }
}

/// A receipt type is host-owned, not an extra vocabulary choice for callers.
fn validate_witness_origin(turn: &WitnessTurn, host_executor: bool) -> MemoryResult<()> {
    if !host_executor
        && turn.messages.iter().any(|message| {
            message.message_type == crate::code_run::blocked::BLOCKED_REPORT_MESSAGE_TYPE
        })
    {
        return Err(MemoryError::bad_request(
            "report-blocked receipts require the executor door",
        ));
    }
    Ok(())
}

/// The overlay receipt carries SESSION-LOCAL short ids: in-room aliases are
/// temporary presentation handles, and canonical ids are allocated at promote
/// (ONE-1730). `aliases` runs turn, messages, then the summary.
fn overlay_receipt(
    plan: &WitnessPlan<'_>,
    aliases: Vec<(String, u8)>,
) -> MemoryResult<WitnessReceipt> {
    let mut aliases = aliases.into_iter();
    let turn_short_id = session_short_ref_string(&aliases.next().ok_or(
        Error::InvariantViolation("session witness allocated no turn alias"),
    )?);
    let message_short_ids = aliases
        .by_ref()
        .take(plan.messages.len())
        .map(|alias| session_short_ref_string(&alias))
        .collect();
    Ok(WitnessReceipt {
        turn_short_id,
        message_short_ids,
        receipt_ref: format!("witness:{}", plan.turn_id.to_hex()),
    })
}
