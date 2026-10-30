//! The witness write's guards and admission: a base landing's guards, or an overlay
//! landing's guards read against its composed view, then the admission of every envelope.

use super::in_txn::WitnessWrite;
use super::*;

/// A landing's guards: a hard-deleted id refuses it, or the admission it
/// lands under and what the base guards found.
pub(super) enum LandingGuards<'p> {
    HardDeleted(EntityId),
    Admitted {
        admission: WitnessAdmission<'p>,
        mint_conversation: bool,
        leader_project: Option<EntityId>,
        quoted: Option<crate::conversation_dag::QuotedReply>,
    },
}

impl Memory<'_> {
    pub(super) fn admit_landing_in_txn<'w>(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &WitnessWrite<'w, '_, '_, '_, '_>,
        prepare: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<Option<RoomRegenerationPermit>>,
    ) -> MemoryResult<LandingGuards<'w>> {
        let WitnessWrite {
            plan,
            sink,
            quote_key,
            assertion_lane,
            refused,
            unproven,
            ..
        } = *write;
        let mut mint_conversation = false;
        let mut leader_project = None;
        let mut quoted: Option<crate::conversation_dag::QuotedReply> = None;
        let admission = match sink {
            WitnessSink::Base(_) => {
                let (person_author, thread) =
                    match self.base_guards_in_txn(plan, wtxn, prepare, quote_key)? {
                        BaseGuards::HardDeleted(id) => return Ok(LandingGuards::HardDeleted(id)),
                        BaseGuards::Clear {
                            mint_conversation: absent,
                            person_author,
                            leader_project: project,
                            quoted: proven,
                            thread,
                        } => {
                            mint_conversation = absent;
                            leader_project = project;
                            quoted = proven;
                            // The importer is not the author of the source's words.
                            (person_author.filter(|_| plan.imported.is_none()), thread)
                        }
                    };
                let assertions = assertion_lane.map(|lane| AssertionRead {
                    lane,
                    refused,
                    unproven,
                });
                self.admit_witness_in_txn(
                    plan,
                    &self.vault.store,
                    wtxn,
                    assertions,
                    person_author,
                    quoted.as_ref(),
                    thread.as_ref(),
                )?
            }
            // Host-derived ids are create-or-verify in the COMPOSED
            // overlay/base snapshot. The view is dropped before the
            // overlay segment installs, and a divergent body or parent
            // leaves no journal or index delta.
            WitnessSink::Overlay(overlay) => self.admit_overlay_in_txn(wtxn, write, overlay)?,
        };
        Ok(LandingGuards::Admitted {
            admission,
            mint_conversation,
            leader_project,
            quoted,
        })
    }

    fn admit_overlay_in_txn<'w>(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &WitnessWrite<'w, '_, '_, '_, '_>,
        overlay: &OverlaySink<'_, '_>,
    ) -> MemoryResult<WitnessAdmission<'w>> {
        let WitnessWrite {
            plan,
            room_speech,
            assertion_lane,
            refused,
            unproven,
            ..
        } = *write;
        let rostered = room_speech.is_some();
        let person_author =
            self.overlay_guards_in_txn(plan, overlay, rostered, wtxn)?;
        // The writer's own key reads the composed room view, as
        // recall's session lane does; both drop here.
        let view = overlay.read_view()?;
        // A thread turn staged here is born bound as on base, to
        // the stretch's room and read against its base members
        // (FIX 3122); a stored one keeps its thread and takes
        // words from its audience alone.
        let thread = crate::workspace_roster::overlay_thread_binding_in(
            self.vault,
            &view.read(),
            wtxn,
            overlay.room()?,
            plan.conversation_id,
            plan.turn_id,
            self.actor,
            plan.turn,
        )?;
        let session_lane = assertion_lane.map(|lane| {
            self.vault
                .scoped_read_in_session(lane.actor_key().clone(), &view)
                .with_claim_status(ClaimReadStatus::Recorded)
        });
        let assertions = session_lane.as_ref().map(|lane| AssertionRead {
            lane,
            refused,
            unproven,
        });
        self.admit_witness_in_txn(
            plan,
            &view,
            wtxn,
            assertions,
            person_author,
            None,
            thread.as_ref(),
        )?
    }
}
