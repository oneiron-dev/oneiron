//! The result a MESSAGE carries, read by the bound actor (FIX 365): its card,
//! or a `slice`, `search`, `query` or `chunks` page of the body it holds.
//!
//! The MESSAGE is admitted through the actor's read lane, as its transcript
//! admits it, and only the body its own hold backs resolves: nothing a caller
//! sends names another run, body or occurrence. Each read is checked again,
//! as the run's own reads are, against the rows the run's answers were served
//! from and the taint the hold has now; so is the preview a transcript shows.
//! A MESSAGE no canonical read finds is looked up in the off-record room
//! session the surface binds (FIX 3620): for someone in the room, by the
//! sight its talk copy shows the result by, its body read through the
//! room's own storage and never copied to this vault.

use serde_json::Value;

use super::structural::kind_string_for_type;
use super::*;

use crate::claim::{CallerLocality, ClaimReadStatus, ScopedReadResult};
use crate::code_run::{
    CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunRawOutput, ExecutorStorage, ResultFacet, ResultRead,
    result_refusal, unknown_handle,
};
use crate::engine_executor::{JsResultRef, JsResultTarget};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::off_record::OffRecordSession;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::vault::ReadMode;

/// The facet input key that narrows a read to a range of the body: a range
/// ref of it, as a `chunks` page names one (`<handle>#<start>-<end>`).
const RANGE_REF_KEY: &str = "ref";

impl MessageResultAttachment {
    /// The attachment as a reader is shown it: its preview withheld when
    /// `withhold` says the body is not clean for them, or when the write
    /// door's rules find a secret in it now (OF-067).
    #[must_use]
    pub(crate) fn as_shown(self, withhold: bool) -> Self {
        if !withhold
            && crate::batch::secret_scan::write_payload_hit(self.preview.as_bytes()).is_none()
        {
            return self;
        }
        Self {
            preview: CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned(),
            preview_truncated: true,
            ..self
        }
    }
}

impl Memory<'_> {
    /// Reads the result MESSAGE `message` carries, as the bound actor: its
    /// card when `facet` is `None`, else that facet of its body, from `input`
    /// (a null input is an empty one). `input.ref`, a range ref of this
    /// result, narrows the read to that range; a ref to anything else names
    /// no result of it. The reply is the run's own: `{"output": ...}` or a
    /// `denied` refusal, `result_withheld` while the rows the run's answers
    /// were served from stay where the actor is not.
    ///
    /// A MESSAGE that is no canonical one the actor may read is read as an
    /// overlay MESSAGE of the off-record room session this surface binds,
    /// when there is one ([`Self::in_off_record_session`], FIX 3620):
    /// through the room's storage, as its participant, on the route the read
    /// captures.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` when the actor may not read the MESSAGE, it is no visible
    /// MESSAGE, or it carries no result a hold of its own backs; in the
    /// room, when they are not on its roster, their membership did not show
    /// the MESSAGE when it was said, or no run of the room holds its body.
    pub fn read_message_result(
        &self,
        message: &EntityId,
        facet: Option<ResultFacet>,
        input: Value,
    ) -> MemoryResult<Value> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ScopedReadResult {
            value: views,
            receipt,
        } = self.read_views(&lane, &[Some((*message, ReadMode::Live))])?;
        let message_kind = kind_string_for_type(ENTITY_TYPE_MESSAGE);
        let Some(body) = views
            .into_iter()
            .flatten()
            .find(|view| view.kind == message_kind)
            .and_then(|view| view.body)
            .filter(|body| body.get("is_visible").and_then(Value::as_bool) == Some(true))
        else {
            if let Some(reply) = self.read_room_message_result(*message, facet, input)? {
                return Ok(reply);
            }
            return Err(MemoryError::not_found("message not found").with_read_receipt(receipt));
        };
        let held = match MessageResultAttachment::from_metadata(body.get("metadata")) {
            Ok(Some(attachment)) => self.held_result(*message, &attachment)?,
            Ok(None) | Err(_) => None,
        };
        let Some((output, withheld)) = held else {
            return Err(
                MemoryError::not_found("the message carries no result").with_read_receipt(receipt)
            );
        };
        if withheld {
            return Ok(result_refusal("result_withheld"));
        }
        let (range, input) = match narrowed(&output, input) {
            Ok(narrowed) => narrowed,
            Err(refused) => return Ok(refused),
        };
        let storage = ExecutorStorage::Canonical(self.vault);
        Ok(ResultRead::outside_run(
            &storage, *message, output, None, range, facet, input,
        )?)
    }

    /// [`Self::read_message_result`] of `message` as an overlay MESSAGE of
    /// the off-record room session this surface binds (FIX 3620), for the
    /// principal it binds the session for. They must be on the room's roster
    /// and their membership must have shown the MESSAGE when it was said, as
    /// their copy of the talk shows its result. Its body is read through the
    /// room's storage on the route the read captures, checked against the
    /// participant on every read, as a run in the room reads it: only a body
    /// the room's producer run holds at the path the MESSAGE names resolves,
    /// withheld as the canonical read withholds one, by the rows that run's
    /// answers were served from and by the marks the room keeps on the
    /// producer's occurrence and the MESSAGE's own. A read only: nothing of
    /// the room is written to this vault. `None` for every refusal, so a
    /// caller who is not in the room hears today's not-found and learns
    /// nothing more.
    fn read_room_message_result(
        &self,
        message: EntityId,
        facet: Option<ResultFacet>,
        input: Value,
    ) -> MemoryResult<Option<Value>> {
        let Some((session_ref, Some(reader))) = self.off_record_binding() else {
            return Ok(None);
        };
        let held = self
            .vault
            .off_record_session_vault()
            .bind_for(session_ref, reader)
            .and_then(|session| room_held_result(&session, message, reader));
        let held = match held {
            Ok(Some(held)) => held,
            Ok(None) | Err(Error::OffRecord(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let rows = held.served_rows.as_deref();
        self.produced_from(rows.into_iter().flatten().copied());
        let withheld = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.withholds_served_in(&txn, rows)?
        };
        if withheld {
            return Ok(Some(result_refusal("result_withheld")));
        }
        let (range, input) = match narrowed(&held.output, input) {
            Ok(narrowed) => narrowed,
            Err(refused) => return Ok(Some(refused)),
        };
        match ResultRead::outside_run(
            &held.storage,
            held.owner,
            held.output,
            None,
            range,
            facet,
            input,
        ) {
            Ok(reply) => Ok(Some(reply)),
            // Removed from the room while the body was read.
            Err(Error::OffRecord(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// `attachment` as MESSAGE `message`'s transcript shows it to this
    /// reader now: `None` when no hold of the MESSAGE's own backs it, its
    /// preview withheld while the rows the run's answers were served from
    /// stay where the reader is not or the held body is not clean. A preview
    /// stored when the MESSAGE was said never outlives a later withholding.
    /// Called with no snapshot open: the taint read opens its own.
    pub(super) fn shown_result(
        &self,
        message: EntityId,
        attachment: MessageResultAttachment,
    ) -> MemoryResult<Option<MessageResultAttachment>> {
        let Some((output, withheld)) = self.held_result(message, &attachment)? else {
            return Ok(None);
        };
        let (state, _) =
            ExecutorStorage::Canonical(self.vault).code_run_result_taint(Some(message), &output)?;
        Ok(Some(attachment.as_shown(withheld || state.is_tainted())))
    }

    /// The body `attachment` names as MESSAGE `message` holds it: its
    /// manifest, and whether the rows the run's answers were served from stay
    /// where this reader is not. `None` when no hold of the MESSAGE's own
    /// backs what the attachment says, so a result it does not hold is none.
    /// The rows are listed as the read's producers.
    fn held_result(
        &self,
        message: EntityId,
        attachment: &MessageResultAttachment,
    ) -> MemoryResult<Option<(CodeRunRawOutput, bool)>> {
        let output = attachment.output()?;
        let occurrence = attachment.message_occurrence(message)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let hold = crate::provenance::body::owned_body_in_txn(
            &self.vault.store,
            &txn,
            &message,
            &occurrence,
        )?;
        let source = &attachment.source;
        let Some(provenance) = hold
            .filter(|hold| {
                hold.state.held().is_some_and(|body| {
                    body.blake3 == output.raw_blake3 && body.bytes == output.raw_len
                })
            })
            .and_then(|hold| hold.result)
            .filter(|held| {
                held.run_id == source.run_id
                    && held.occurrence == source.occurrence
                    && held.path == source.path
            })
        else {
            return Ok(None);
        };
        let rows = provenance.served_rows.as_deref();
        self.produced_from(rows.into_iter().flatten().copied());
        let withheld = self.withholds_served_in(&txn, rows)?;
        Ok(Some((output, withheld)))
    }

    /// Whether the rows a run's answers were served from (`None` when it kept
    /// no set, which is unknown) stay where this reader is not: a reader off
    /// this device reads nothing a world withheld from the machine its rows
    /// go to keeps (DEC-0005, mesh PR2b). Unknown producers stay withheld,
    /// a proved destination too: that is integrity, not the owner's choice.
    fn withholds_served_in(
        &self,
        txn: &heed::RoTxn<'_>,
        rows: Option<&[EntityId]>,
    ) -> MemoryResult<bool> {
        if self.locality() == CallerLocality::OnDevice {
            return Ok(false);
        }
        let Some(rows) = rows else {
            return Ok(true);
        };
        let kept = crate::settings::device_local_worlds_for(self.vault, txn, self.destination())?;
        for row in rows {
            if crate::settings::device_local_keeps_among(&self.vault.store, txn, &kept, row)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The body a room's MESSAGE carries, as one in the room reads it
/// ([`Memory::read_room_message_result`]).
struct RoomHeldResult<'v> {
    /// The room's storage, bound for the reader on the route captured now.
    storage: ExecutorStorage<'v>,
    output: CodeRunRawOutput,
    /// The run whose occurrence of the body answers for its taint: the
    /// MESSAGE's own once the room marks it, else its producer's, so the
    /// read is withheld while either is marked, as the talk copy's preview
    /// is.
    owner: EntityId,
    /// The rows the producer run's answers were served from; `None` when
    /// its record keeps no set, which is unknown.
    served_rows: Option<Vec<EntityId>>,
}

/// The body MESSAGE `message` of `session`'s room carries, for `reader`, who
/// is in the room ([`OffRecordSession::room_message_result`]); `None` when
/// the room said no such MESSAGE, it carries no result, or the room's
/// producer run holds no such body at the path it names.
fn room_held_result<'v>(
    session: &OffRecordSession<'v>,
    message: EntityId,
    reader: EntityId,
) -> crate::Result<Option<RoomHeldResult<'v>>> {
    let Some(attachment) = session.room_message_result(message, reader)? else {
        return Ok(None);
    };
    let output = attachment.output()?;
    let storage = ExecutorStorage::for_session(session, reader)?;
    let producer = attachment.source.run_id;
    let Some(record) = storage.get_code_run_replay_record(&producer)? else {
        return Ok(None);
    };
    let produced = record.outputs.iter().any(|held| {
        held.path == output.path
            && held.handle == output.handle
            && held.raw_blake3 == output.raw_blake3
            && held.raw_len == output.raw_len
    });
    if !produced {
        return Ok(None);
    }
    let (own, _) = storage.code_run_result_taint(Some(message), &output)?;
    let owner = if own.is_tainted() { message } else { producer };
    Ok(Some(RoomHeldResult {
        storage,
        output,
        owner,
        served_rows: record.agent_verb_rows(),
    }))
}

/// `input` less its range ref, and the range of `output`'s body that ref
/// names (`None` for the whole body). A ref to anything but this body is
/// refused as one to no result of it; a null input is an empty one.
fn narrowed(
    output: &CodeRunRawOutput,
    input: Value,
) -> std::result::Result<(Option<(u64, u64)>, Value), Value> {
    let mut input = match input {
        Value::Null => Value::Object(serde_json::Map::new()),
        input => input,
    };
    let Some(reference) = input
        .as_object_mut()
        .and_then(|fields| fields.remove(RANGE_REF_KEY))
    else {
        return Ok((None, input));
    };
    match reference.as_str().map(JsResultTarget::parse) {
        Some(JsResultTarget {
            reference: JsResultRef::Handle(handle),
            range,
        }) if handle == output.handle => Ok((range, input)),
        _ => Err(unknown_handle(&[])),
    }
}
