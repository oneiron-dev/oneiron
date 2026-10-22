//! A room write's birth (FIX 4281; Engine 10-22): the `made_by` envelope a
//! NOTE or claim staged in an off-record room carries, stamped beside its row
//! in the room's overlay, in the segment that stages the row, and dropped
//! with the room at close. It is bookkeeping: it spends none of the room's
//! byte budget (`session_overlay::keyspace::unbudgeted_row`).
//!
//! A room keeps today's acceptance: an evidence ref the room does not read as
//! a TURN, and a concluded write with no evidence at all, still stage. The
//! birth keeps every supplied ref as supplied ([`RoomEvidence`]); only the
//! refs the caller read as a TURN are its inputs, hashed as read. Nothing
//! here is a base stamp: a base stamper treats the room's evidence as absent.

use heed::RwTxn;
use sha2::{Digest, Sha256};

use super::{ROW_BIRTH, RoomEvidence, RoomEvidenceRef, RowBirth};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use crate::vault::live_entity_row_in_txn;
use crate::write_envelope::WriteActor;

/// One evidence ref a room write's caller supplied: as spelled, and the
/// TURN the caller read it as in the room with the bytes it read, when it
/// read one.
pub(crate) struct SuppliedEvidence {
    pub(crate) supplied: String,
    pub(crate) turn: Option<(EntityId, Vec<u8>)>,
}

impl RowBirth {
    /// The birth of a row `actor` staged in a room through `door` at `at`, of
    /// `class`, made from `inputs` (rows it derives from, with their bytes as
    /// read) and naming `evidence` as its caller supplied it. Each evidence
    /// ref the caller read as a TURN is an input too, hashed as read; each
    /// other ref is kept as supplied. A concluded birth that names no input
    /// is kept: the room never refuses a write for its evidence.
    pub(crate) fn in_room(
        actor: WriteActor,
        class: MadeByClass,
        door: &str,
        inputs: &[(EntityId, Vec<u8>)],
        evidence: &[SuppliedEvidence],
        at: u64,
    ) -> Self {
        let mut seen = std::collections::BTreeSet::new();
        let mut named = Vec::new();
        let mut read: Vec<&[u8]> = Vec::new();
        let supported = evidence
            .iter()
            .filter_map(|supplied| supplied.turn.as_ref());
        for (row, bytes) in inputs.iter().chain(supported) {
            if seen.insert(*row) {
                named.push(MadeByInput {
                    row: *row,
                    role: MadeByInputRole::Input,
                });
                read.push(bytes);
            }
        }
        let refs = evidence
            .iter()
            .map(|supplied| RoomEvidenceRef {
                supplied: supplied.supplied.clone(),
                turn: supplied.turn.as_ref().map(|(turn, _)| turn.to_hex()),
            })
            .collect();
        Self {
            made_by: MadeBy {
                inputs: named,
                process: MadeByProcess {
                    actor: actor.entity_ref(),
                    class,
                    identity: door.to_owned(),
                    version: "1".into(),
                    // A write door takes no render parameters.
                    params_hash: format!("{:x}", Sha256::digest([])),
                },
                at,
                trigger: None,
            },
            content_hash: if read.is_empty() {
                String::new()
            } else {
                Self::content_hash_of(&read)
            },
            withheld: Vec::new(),
            room_evidence: Some(RoomEvidence { refs }),
        }
    }
}

/// Stamps `birth`, a room's ([`RowBirth::in_room`]), for `row` in `view`'s
/// room, on the segment's transaction `txn` that staged the row. A birth is
/// immutable: a row the room already stamped keeps its first birth, and a
/// write staged again over it changes nothing here. The room never refuses
/// a write for its birth (Engine 10-22): a row the room does not hold as
/// live gets none.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for an engine-built birth that is not a room's
/// or is malformed (never a caller's input); storage errors as they occur.
pub(crate) fn stamp_room_birth_in_txn(
    view: &crate::store::SessionStoreView<'_>,
    txn: &mut RwTxn<'_>,
    row: &EntityId,
    birth: &RowBirth,
) -> Result<()> {
    if birth.room_evidence.is_none() || !birth.withheld.is_empty() {
        return Err(Error::InvalidConfig(
            "a room birth carries its room evidence and withholds no ref".into(),
        ));
    }
    birth.check_shape()?;
    if !live_entity_row_in_txn(view, txn, row)?.is_live() || ROW_BIRTH.contains(view, txn, row)? {
        return Ok(());
    }
    ROW_BIRTH.put(view, txn, row, birth)
}
