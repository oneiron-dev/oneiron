//! The served-form receipts a read in an off-record room keeps (WILL L11-01
//! S01-2b, OF-329): what it served of each image, recorded in the room's own
//! store under the holder it read as, before it answers. Each is the record
//! [`ScopedRead::commit_served_forms`] writes for a canonical read, from the
//! same carrier ([`crate::receipt::served_form_carrier`]), with the holder
//! rechecked on base the same way; only where it lands differs. It stages
//! through the room's own apply on the run's captured route, so the room's
//! close drops it, and it rides no turn, so no promote or save replays it.
//! Its bytes are content the room keeps, spent from the room's budget as any
//! row it stages is. It takes nothing from the vault's id or clock floors.

use crate::EntityId;
use crate::batch::BatchOp;
use crate::claim::ScopedRead;
use crate::error::{Error, Result};
use crate::off_record::{OffRecordSession, SessionWriteRoute};
use crate::ports::EntityStoreRead;
use crate::receipt::ServedForm;
use crate::registry::ENTITY_TYPE_RECEIPT_RECORD;
use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};
use crate::temporal::TimeRange;

/// The domain a room's served-form record id derives under (CALLS-8): one
/// host call's identity and the form's place among its sorted forms.
const ROOM_SERVED_FORM_ID: &[u8] = b"oneiron/room-served-form/v1";

impl ScopedRead<'_> {
    /// Keeps `served`, what this lane's read in `session` served, as one
    /// served-form receipt per asset and form in the room, each naming this
    /// lane's holder and, when the lane knows one, its class. All of them
    /// stage in one segment on `route`, the run's captured route, and the
    /// read answers only once it commits: a failed stage fails the read with
    /// its own error. The segment first rechecks the holder in its base
    /// transaction (`holder_live_in`), as the canonical record does. Answers
    /// the receipts' refs. Nothing served stages, allocates and checks
    /// nothing.
    ///
    /// # Errors
    ///
    /// The route's own refusal once the room flipped, closed or keeps no
    /// record; the holder's; the room's
    /// [`OffRecordOverlayFull`](crate::error::OffRecordError::OffRecordOverlayFull)
    /// once its budget cannot take the receipts; storage errors.
    pub(crate) fn commit_served_forms_in_room(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        served: &[ServedForm],
    ) -> Result<Vec<String>> {
        let mut served = served.to_vec();
        served.sort_unstable();
        served.dedup();
        if served.is_empty() {
            return Ok(Vec::new());
        }
        let call = uuid::Uuid::now_v7();
        let ids = (0..served.len())
            .map(|ordinal| room_served_form_id(call.as_bytes(), ordinal))
            .collect::<Result<Vec<_>>>()?;
        let conversation = session.overlay_conversation_shell()?;
        session.overlay_write_routed(route, |wtxn, apply| {
            self.holder_live_in(wtxn)?;
            let at = crate::ports::job_recorded_at_in_txn(&session.read_view()?, wtxn)?;
            let mut refs = Vec::with_capacity(ids.len());
            for (id, served) in ids.into_iter().zip(&served) {
                let occupied = session.read_view()?.port_entity_record(wtxn, &id)?;
                if occupied.is_some() {
                    return Err(Error::CorruptedIndex("served form record id occupied"));
                }
                let (body, receipt_ref) =
                    crate::receipt::served_form_carrier(&id, served, &self.actor_key, at)?;
                let carrier = session_served_form_carrier(conversation, id, body, at);
                apply(wtxn, carrier)?;
                refs.push(receipt_ref);
            }
            Ok(refs)
        })
    }
}

/// The id of a room's served-form record (CALLS-8): derived from `call`, the
/// host call's own identity, and `ordinal`, the form's place among that
/// call's sorted forms. Never one the vault's clock allocates; a later
/// serving of the same form is a call of its own, with an id of its own.
fn room_served_form_id(call: &[u8], ordinal: usize) -> Result<EntityId> {
    let ordinal = u64::try_from(ordinal).map_err(|_| Error::IndexOverflow("room served form"))?;
    EntityId::derive(ROOM_SERVED_FORM_ID, &[call, &ordinal.to_le_bytes()])
}

/// A room's served-form carrier (CALLS-8, CALLS-4): the record `body` at
/// `id`, stamped `at`, as the one RECEIPT_RECORD put the room's apply admits
/// (the maintenance flag the canonical carrier sets). Its scope's turn is
/// the record itself, so no turn of the room holds it and no promote or save
/// plans it, and it is an ordinary row of the room, spent from its budget.
fn session_served_form_carrier(
    conversation: EntityId,
    id: EntityId,
    body: Vec<u8>,
    at: u64,
) -> JournalEntry {
    let occurred = TimeRange { start: at, end: at };
    JournalEntry {
        scope: JournalScope::new(conversation, id),
        role: JournalRole::TurnOwnedArtifact,
        learned_at: at,
        occurred,
        op: BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_RECEIPT_RECORD,
            occurred,
            learned_at: at,
            data: body,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
        source_run: None,
    }
}
