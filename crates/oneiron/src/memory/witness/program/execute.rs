//! The witness program's run: request shape, target, plan, then one write transaction per landing.
//! `Memory::run_witness` and `Memory::run_witness_as` are its call surface.
//! `memory::witness::program` defines the target, door, landing and plan types it runs on.

use super::*;

mod answer;
mod guards;
mod in_txn;
mod request;
mod staging;

use self::in_txn::WitnessWrite;
use self::request::{ResolvedLanding, resolve_witness_landing};

impl Memory<'_> {
    /// The witness program. Every witness verb is this function with a target
    /// and a door; the target's session is the only thing that decides where
    /// the rows land.
    ///
    /// Order, for both landings: request shape, target resolution, the plan
    /// (containers, speaker, message ids and bodies), the landing's pre-write
    /// state, `before_txn`, then ONE write transaction that runs a session
    /// door's [`Admit`], the actor checks, the landing's guards, the
    /// erased-PERSON refusal, the ceiling door on every envelope, the
    /// create-or-verify checks, the landing's staging and receipt, `effect`,
    /// and the route revalidation.
    ///
    /// `before_txn` runs in the window between the ADVISORY container
    /// create-or-get and the transaction, which is the race the in-transaction
    /// TURN re-read closes; production callers pass a no-op. `prepare` runs in
    /// a base landing's transaction before the conversation is re-read (project
    /// birth assembles its room there). `effect` shares the transaction (stream
    /// sidecars, EntityDoc birth): its error rolls back every row, index and
    /// receipt.
    pub(in crate::memory::witness) fn run_witness(
        &self,
        turn: &WitnessTurn,
        target: WitnessTarget<'_, '_>,
        door: WitnessDoor,
        before_txn: impl FnOnce(),
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.run_witness_as(
            crate::store::Callback::Audited,
            turn,
            target,
            door,
            before_txn,
            |txn| prepare(txn).map(|()| None),
            |txn, _| effect(txn),
        )
    }

    /// [`Self::run_witness`] through the write door `callback` names: an
    /// `effect` that runs host code is [`crate::store::Callback::Opaque`].
    /// Its `prepare` may prove a Retry's room regeneration permit, which the
    /// room guard admits the witness under (FIX 3149). A base landing hands
    /// `effect` the receipt it just read in the transaction, with the TURN
    /// and MESSAGE ids the turn actually stored (FIX 8533); an overlay
    /// landing's receipt exists only after its segment commits, so it hands
    /// none.
    #[expect(
        clippy::too_many_arguments,
        reason = "the write door joins the witness program's inputs"
    )]
    pub(in crate::memory::witness) fn run_witness_as(
        &self,
        callback: crate::store::Callback,
        turn: &WitnessTurn,
        target: WitnessTarget<'_, '_>,
        door: WitnessDoor,
        before_txn: impl FnOnce(),
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, Option<&WitnessReceipt>) -> MemoryResult<()>,
    ) -> MemoryResult<WitnessReceipt> {
        self.admit_witness_request(turn, door)?;
        let mut session_route = None;
        let ResolvedLanding {
            landing,
            on_record_session,
            saver,
            admit,
            room_speech,
        } = resolve_witness_landing(turn, target, &mut session_route)?;

        // A quote rides a message of a room turn that lands at base and is
        // no import (OF-460, FIX 2027, FIX 2028); the room guard proves each
        // there, cited by its message.
        let quoting = turn.messages.iter().any(|m| m.quote.is_some());
        if quoting && !matches!(landing, Landing::Base { imported: None, .. }) {
            return Err(MemoryError::bad_request(
                "a quote lands only on a non-imported room turn at base",
            ));
        }
        let unlinked_prose = self.witness_unlinked_prose(turn, &landing);
        // OF-063 (FIX 1225/1670): the records a reply asserts it cited or
        // created are read through the writer's own lane, opened here since
        // it takes its own snapshot and so never runs inside the writer. A
        // turn that asserts nothing opens none. `refused` carries the first
        // pointer the lane cannot read out of the aborted writer.
        let silent = turn.assertions.cited.is_empty() && turn.assertions.created.is_empty();
        let assertion_lane = if silent {
            None
        } else {
            Some(self.read_lane(ClaimReadStatus::Recorded)?)
        };
        let refused = Cell::new(None);
        let unproven = Cell::new(Vec::new());
        let plan = self.plan_witness(turn, &landing, door, admit)?;
        let held = match &landing {
            Landing::Base { held, .. } => *held,
            Landing::Overlay { .. } => None,
        };
        let sink = match landing {
            Landing::Base { route, .. } => WitnessSink::Base(self.base_sink(&plan, route)?),
            Landing::Overlay {
                session,
                route,
                summary,
            } => WitnessSink::Overlay(self.overlay_sink(session, route, summary)?),
        };
        // FIX 2027: a quote's selection is read under the speaker's own key,
        // taken here, before the writer opens: no read snapshot nests in it.
        let quote_key = quoting.then(|| self.read_key()).transpose()?;
        // FIX 3284: which of the turn's messages this write lands new, carried
        // out of its transaction. A message an exact retry finds stored lands
        // nothing and owes no second prose receipt.
        let mut lands_new: Vec<bool> = Vec::new();
        let write = WitnessWrite {
            plan: &plan,
            sink: &sink,
            held,
            door,
            room_speech,
            quote_key: quote_key.as_ref(),
            assertion_lane: assertion_lane.as_ref(),
            refused: &refused,
            unproven: &unproven,
            silent,
            saver: saver.as_ref(),
        };
        before_txn();

        let landed = self.with_witness_write_txn_as(callback, admit, room_speech, |wtxn| {
            self.land_witness_in_txn(wtxn, &write, prepare, effect, &mut lands_new)
        });
        // A refused assertion is receipted only now, on its own write, once
        // the turn's writer has aborted.
        if let Some(pointer) = refused.take() {
            return Err(self.settle_refused_assertion(&pointer));
        }
        let landed = landed?;

        let answer = self.answer_landed_witness(landed, &plan, sink, on_record_session);
        if answer.is_ok() {
            let landed_prose =
                crate::gate::record_references::landed_witness_prose(unlinked_prose, &lands_new);
            crate::gate::record_references::receipt_landed_prose(self, &landed_prose);
            crate::receipt::receipt_creations_not_proven(
                self,
                crate::gate::record_references::WITNESS_PROSE_ROW,
                &unproven.take(),
            );
        }
        answer
    }

    /// Receipts a refused assertion on its own write, as a refused typed ref
    /// is (`admit_row_references`), and returns the refusal; if the receipt
    /// cannot be written, the store's error instead. Inside an anonymous
    /// off-record session the refusal stands with no receipt. A model
    /// stream's continuation terminal settles its own through it too (FIX
    /// 3416).
    pub(in crate::memory::witness) fn settle_refused_assertion(
        &self,
        pointer: &str,
    ) -> MemoryError {
        let facts = crate::receipt::ReferenceRefusalFacts {
            actor: self.actor,
            actor_class: self.actor_class,
            row: crate::gate::record_references::WITNESS_PROSE_ROW,
            field: pointer.to_owned(),
            outcome: crate::receipt::ReferenceOutcome::Refused,
        };
        match crate::receipt::receipt_reference_refusals(self, &[facts]) {
            Ok(recorded) => crate::gate::record_references::invented_reference(pointer, recorded),
            Err(error) => error.into(),
        }
    }
}