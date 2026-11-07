//! The source-audience obligation's authority (fix list row 16256): the
//! proof a source landing holds to stamp the obligation on the rows it
//! lands, and the reading of a row's own stamp.
//!
//! The obligation is one engine-owned key in a bound row's own body
//! ([`crate::store::source_audience_obligation`]). A row a source landed
//! carries it from its first byte, so the judge knows it as a source's row
//! whatever its kind and whatever has arrived beside it. Only a writer that
//! holds a [`SourceAudienceBirth`] stamps it; every other door refuses it.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN,
};
use crate::store::ManifestDbs;
use crate::store::source_audience_obligation::{
    SourceAudienceObligation, decode_source_audience_obligation,
};
use crate::{EntityId, Vault};

use super::{BIRTHS, POLICIES, SourceAudienceKind, SourceAudiencePolicy};

/// The refusal of a write that carries the key no source landing stamped.
const UNBORN_STAMP: &str = "source_audience_required is stamped by a source landing alone, on the \
     CONVERSATION, TURN and MESSAGE rows it binds; no other write carries it";

/// The refusal of a write that drops or changes a stored row's key.
const KEPT_STAMP: &str = "a row stamped source_audience_required keeps it: a write neither drops \
     nor changes it";

/// The proof that a source landing writes under a live source policy: the
/// one capability that stamps the source-audience obligation on a row. It
/// names the source policy and nothing a read decides by: no reader, no
/// share, no revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceAudienceBirth {
    source: EntityId,
}

impl SourceAudienceBirth {
    /// The proof for a landing under the source policy `source`, read in
    /// `txn`: the policy exists there and is a source's, not a thread's.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for a policy `txn` does not hold, and
    /// [`Error::InvalidConfig`] for a thread policy.
    pub(crate) fn mint_in(vault: &Vault, txn: &heed::RoTxn<'_>, source: &EntityId) -> Result<Self> {
        match POLICIES.get(&vault.store, txn, source)? {
            Some(SourceAudiencePolicy {
                kind: SourceAudienceKind::Source { .. },
                ..
            }) => Ok(Self { source: *source }),
            Some(_) => Err(Error::InvalidConfig(
                "a source landing writes under a source policy".into(),
            )),
            None => Err(Error::EntityNotFound),
        }
    }
}

/// The obligation the entity row `raw` states in its own body, whatever its
/// kind. A row with no readable header states none.
pub(crate) fn row_obligation(raw: &[u8]) -> SourceAudienceObligation {
    if EntityMetadataHeader::parse(raw).is_none() {
        return SourceAudienceObligation::Absent;
    }
    decode_source_audience_obligation(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default())
}

/// Whether `entity_type` is a kind a source landing stamps and binds.
const fn bound_kind(entity_type: u8) -> bool {
    matches!(
        entity_type,
        ENTITY_TYPE_CONVERSATION | ENTITY_TYPE_TURN | ENTITY_TYPE_MESSAGE
    )
}

/// The refusal of a write of `entity_type`, in the kind its door's other
/// body refusals take.
fn write_refusal(entity_type: u8, reason: &'static str) -> Error {
    match entity_type {
        ENTITY_TYPE_MESSAGE => RecordError::InvalidWitnessMessageBody(reason).into(),
        ENTITY_TYPE_CONVERSATION | ENTITY_TYPE_TURN => {
            RecordError::InvalidConversationBody(reason).into()
        }
        ENTITY_TYPE_CLAIM => Error::InvalidClaimBody(reason),
        _ => Error::InvalidConfig(reason.to_owned()),
    }
}

/// Marks the row `id` born in `txn` under a source landing's proof, before
/// the landing stages it stamped: the one mark under which the write door
/// admits the stamp ([`admit_obligation_in_txn`]). Binding the row takes it
/// away again ([`super::bind_record_in_txn`]).
///
/// # Errors
///
/// Storage failures.
pub(crate) fn mark_birth_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    _birth: &SourceAudienceBirth,
    id: &EntityId,
) -> Result<()> {
    BIRTHS.put(&vault.store, txn, id, &())
}

/// Takes away the birth mark of the row `id`, bound now.
pub(super) fn clear_birth_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    BIRTHS.delete(&vault.store, txn, id).map(drop)
}

/// Refuses a source landing whose rows `ids` are still marked born in
/// `txn`: each row it stamped is bound in the same write, or the write
/// commits none of them.
///
/// # Errors
///
/// [`Error::InvariantViolation`] for a row still marked; storage failures.
pub(crate) fn refuse_unbound_births_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<()> {
    for id in ids {
        if BIRTHS.contains(&vault.store, txn, id)? {
            return Err(Error::InvariantViolation(
                "a source landing binds every row it stamps source_audience_required before it \
                 commits",
            ));
        }
    }
    Ok(())
}

/// The one write-door guard of the source-audience obligation (fix list row
/// 16256), for the row `id` of `entity_type` put with `incoming_body` in
/// `txn`:
///
/// - a body that names the key in any shape is refused, unless it is a
///   valid stamp on a CONVERSATION, TURN or MESSAGE that a source landing
///   marked born in this write, or a replicated put of the owner's own
///   import tier (`ImportTier::OwnDevice`, chosen by the authenticated
///   import context: a federated tier's put meets
///   [`refuse_written_obligation`] in its own admission before it reaches
///   here, so every replicated put that does reach here is the owner's own,
///   a forward replay and a pending retry included);
/// - a stored row whose own bytes name the key refuses a put whose body
///   drops it or states it otherwise, except a bodiless erase shell.
///
/// Nothing changes for a row whose stored and incoming bytes do not name
/// it. The guard reads `txn` alone; it opens no transaction.
///
/// # Errors
///
/// The refusal, in the kind of the door's other body refusals; storage
/// failures.
pub(crate) fn admit_obligation_in_txn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    incoming_body: &[u8],
    replicated: bool,
) -> Result<()> {
    let incoming = decode_source_audience_obligation(incoming_body);
    if incoming.is_present()
        && !(incoming == SourceAudienceObligation::Required
            && bound_kind(entity_type)
            && (replicated || BIRTHS.contains(dbs, txn, id)?))
    {
        return Err(write_refusal(entity_type, UNBORN_STAMP));
    }
    keep_stored_obligation(dbs, txn, id, entity_type, incoming_body, incoming)
}

/// [`admit_obligation_in_txn`] for a row an off-record session stages in
/// its overlay: an overlay never births a stamp, so a body that names the
/// key in any shape is refused, and a stored stamp is kept as on base.
///
/// # Errors
///
/// As [`admit_obligation_in_txn`].
pub(crate) fn admit_session_obligation_in_txn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    incoming_body: &[u8],
) -> Result<()> {
    let incoming = decode_source_audience_obligation(incoming_body);
    if incoming.is_present() {
        return Err(write_refusal(entity_type, UNBORN_STAMP));
    }
    keep_stored_obligation(dbs, txn, id, entity_type, incoming_body, incoming)
}

/// Refuses a put of `incoming_body`, which states `incoming`, over a stored
/// row of `id` whose own bytes name the key otherwise. A bodiless erase
/// shell keeps no words, and passes.
fn keep_stored_obligation(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    incoming_body: &[u8],
    incoming: SourceAudienceObligation,
) -> Result<()> {
    if incoming_body.is_empty() {
        return Ok(());
    }
    let Some(stored) = dbs.port_entity_raw_wiped(txn, id)? else {
        return Ok(());
    };
    let held = row_obligation(&stored);
    if held.is_present() && held != incoming {
        return Err(write_refusal(entity_type, KEPT_STAMP));
    }
    Ok(())
}

/// Refuses a raw put of `body`, of `entity_type`, that names the key in any
/// shape: the early check of every raw door but the two a source landing
/// writes its stamped rows through.
///
/// # Errors
///
/// The refusal, in the kind of the door's other body refusals.
pub(crate) fn refuse_written_obligation(entity_type: u8, body: &[u8]) -> Result<()> {
    if body_names_obligation(body) {
        return Err(write_refusal(entity_type, UNBORN_STAMP));
    }
    Ok(())
}

/// Whether the MessagePack body `body` names the key in any shape.
pub(crate) fn body_names_obligation(body: &[u8]) -> bool {
    decode_source_audience_obligation(body).is_present()
}

/// Whether `pointer`, the document-pointer body that replaces the stored
/// row `stored`'s body, states the obligation exactly as `stored` does.
pub(crate) fn keeps_row_obligation(stored: &[u8], pointer: &[u8]) -> bool {
    row_obligation(stored) == decode_source_audience_obligation(pointer)
}

/// Whether the row `id`, as `txn` holds it, names the key in its own bytes
/// and has no binding: a row that must not stand here unbound.
///
/// # Errors
///
/// Storage and codec failures.
#[cfg(feature = "sync")]
pub(crate) fn unbound_obligation_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let stamped = vault
        .store
        .port_entity_raw_wiped(txn, id)?
        .is_some_and(|raw| row_obligation(&raw).is_present());
    Ok(stamped && super::RECORDS.get(&vault.store, txn, id)?.is_none())
}

/// Whether a restored entity row `raw` states the obligation validly: not
/// at all, or as a valid stamp on a CONVERSATION, TURN or MESSAGE. Its
/// bytes are restored exactly as they are.
pub(crate) fn restorable_obligation(raw: &[u8]) -> bool {
    match row_obligation(raw) {
        SourceAudienceObligation::Absent => true,
        SourceAudienceObligation::Required => {
            EntityMetadataHeader::parse(raw).is_some_and(|header| bound_kind(header.entity_type))
        }
        SourceAudienceObligation::Malformed => false,
    }
}

/// Whether a carried binding stands on `carried`, the entity row it binds
/// as the same artifact carries it: a valid stamp on a CONVERSATION, TURN
/// or MESSAGE, or a bodiless erase shell. A row the artifact does not
/// carry is judged where it lands.
pub(crate) fn binding_stands_on(carried: Option<&[u8]>) -> bool {
    carried.is_none_or(|raw| {
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .is_none_or(<[u8]>::is_empty)
            || (row_obligation(raw) == SourceAudienceObligation::Required
                && restorable_obligation(raw))
    })
}
