//! The authored carriers whose writers already mask a new write: an
//! owner-policy ruling or proposal, an eval case, and a stream's seed. An old
//! row gets what a new write of it gets today (Engine ruling D = (a)): its
//! writer's own door admits it again at its own key, each secret a rule
//! places goes to custody and leaves its handle, and the row keeps its ids,
//! links and times. Nothing is applied again, appended or notified. A hit the
//! door does not place, and a row no door reads, files a proposal.

use heed::RwTxn;

use super::super::write_payload_hit;
use super::{Done, LiftCause};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self as t, SideTableDecl};

/// The writer door that admits a carrier's rows again.
#[derive(Clone, Copy)]
enum Door {
    /// `Vault::lift_policy_change_row_in_txn`, by whole key.
    PolicyRow,
    /// `Vault::lift_eval_case_in_txn`, by case id.
    EvalCase,
    /// `Vault::lift_stream_seed_in_txn`, by message id.
    StreamSeed,
}

fn door_of(decl: &SideTableDecl) -> Option<Door> {
    [
        (&t::OWNER_POLICY_CHANGE_PROPOSAL, Door::PolicyRow),
        (&t::OWNER_POLICY_CHANGE_RECEIPT, Door::PolicyRow),
        (&t::SKILL_OPTIMIZE_EVAL_CASE, Door::EvalCase),
        (&t::MESSAGE_STREAM_ACTIVE, Door::StreamSeed),
    ]
    .into_iter()
    .find_map(|(held, door)| (held.name == decl.name).then_some(door))
}

/// What row `row_key` of carrier `decl`, read again as `row`, comes to
/// through its own door; `None` when no door here writes `decl`.
pub(super) fn lift(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    decl: &SideTableDecl,
    row_key: &[u8],
    row: Option<&[u8]>,
) -> Result<Option<Done>> {
    let Some(door) = door_of(decl) else {
        return Ok(None);
    };
    // A row a writer has cleaned since the census read it is done.
    let Some(reason) = row.and_then(write_payload_hit) else {
        return Ok(Some(Done::Clean));
    };
    let id = row_key
        .get(decl.prefix.len()..)
        .and_then(|suffix| <[u8; 16]>::try_from(suffix).ok())
        .and_then(|bytes| EntityId::from_bytes(bytes).ok());
    let placed = match (door, id) {
        (Door::PolicyRow, _) => vault.lift_policy_change_row_in_txn(txn, row_key)?,
        (Door::EvalCase, Some(case)) => vault.lift_eval_case_in_txn(txn, &case)?,
        (Door::StreamSeed, Some(message)) => vault.lift_stream_seed_in_txn(txn, &message)?,
        (Door::EvalCase | Door::StreamSeed, None) => None,
    };
    Ok(Some(match placed {
        None => Done::Propose(LiftCause::NoDoor, reason),
        Some(false) => Done::Propose(LiftCause::Unplaceable, reason),
        // A hit the door's reading of the row does not reach is still the
        // owner's; the handles the door placed commit with its proposal.
        Some(true) => match vault
            .store
            .vault_meta
            .get(txn, row_key)?
            .and_then(|stored| write_payload_hit(&stored))
        {
            Some(left) => Done::Propose(LiftCause::Unplaceable, left),
            None => Done::Masked {
                history: false,
                reason,
            },
        },
    }))
}
