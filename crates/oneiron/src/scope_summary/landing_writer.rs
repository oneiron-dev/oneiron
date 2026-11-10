//! The engine writer a scope summary lands under (Engine ruling
//! SUMMARY-AS-RECORD-PERMIT-SHAPE = A): the merge header and the trunk reply
//! hold words the Dreamer composed, so they are written by this one engine
//! MACHINE, not by the summary's requester (ARCH-0040: the label follows who
//! composed the words). The default manifest binds its Generated permit and
//! its ceiling to this writer alone, so no other Generated write is trusted.
//! The requester stays the reply's read lane and holds its receipts.
//!
//! No other caller writes as it. Its header claim carries the engine's
//! MACHINE signature, which only the host-provisioned signer gives. Its DAG
//! append is refused unless it is the reply the landing on this thread
//! admitted, with that landing's summary, turn and conversation
//! ([`check_landing_append`]). Shared TURN admission also requires the exact
//! summary text and door-owned reply fields, in the summary's conversation,
//! backed by a stored merge header signed by this MACHINE. Every RepliesTo
//! edge must name that header's subject, including raw and replicated writes;
//! a missing landing refuses rather than deferring the writer's authority.
//!
//! When slice 6.7 lands, the summary commits through `vault.derive.commit` by
//! the generating agent under its Steward derive grant, and this writer and
//! its two manifest rows are removed.

use std::cell::Cell;

use super::codec::invalid;
use crate::conversation_dag::AppendRecord;
use crate::entity_id::derived_domains::SCOPE_SUMMARY_LANDING_ACTOR;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::store::Store;
use crate::{EdgeActorClass, EntityId, Result, TimeRange, Vault, WriteActor};

/// The reply a landing admits: its vault, summary, turn and conversation.
type Landing = (usize, [u8; 16], [u8; 16], [u8; 16]);
thread_local! {
    static LANDING: Cell<Option<Landing>> = const { Cell::new(None) };
}

/// Admits one landing's reply while it lives; dropping it restores the
/// thread's previous admission.
pub(super) struct LandingPermit(Option<Landing>);
impl Drop for LandingPermit {
    fn drop(&mut self) {
        LANDING.with(|slot| slot.set(self.0));
    }
}

fn landing(store: &Store, summary: EntityId, turn: EntityId, conversation: EntityId) -> Landing {
    (
        store as *const Store as usize,
        *summary.as_bytes(),
        *turn.as_bytes(),
        *conversation.as_bytes(),
    )
}

/// Admits the trunk reply that lands `summary` on `turn` in `conversation`,
/// in this vault, while its synchronous append runs.
pub(super) fn admit_reply(
    store: &Store,
    summary: EntityId,
    turn: EntityId,
    conversation: EntityId,
) -> LandingPermit {
    let admitted = landing(store, summary, turn, conversation);
    LandingPermit(LANDING.with(|slot| slot.replace(Some(admitted))))
}

/// Refuses a DAG append under the landing writer that is not the reply the
/// landing on this thread admitted: its summary, the turn it replies to and
/// its conversation must be that landing's. Every other writer passes.
pub(crate) fn check_landing_append(
    store: &Store,
    input: &AppendRecord,
    summary: Option<EntityId>,
) -> Result<()> {
    if input.actor.entity_ref() != landing_writer_id()? {
        return Ok(());
    }
    let admitted = match (summary, input.reply_to) {
        (Some(summary), Some(turn)) => {
            LANDING.with(|slot| slot.get())
                == Some(landing(store, summary, turn, input.conversation))
        }
        _ => false,
    };
    if admitted {
        Ok(())
    } else {
        Err(invalid(
            "only a scope summary landing writes as its landing writer",
        ))
    }
}

/// The landing writer's id: derived, so every device names the same one.
pub(crate) fn landing_writer_id() -> Result<EntityId> {
    EntityId::derive(SCOPE_SUMMARY_LANDING_ACTOR, &[])
}

/// The landing writer, its MACHINE row put on first use. A row of another
/// type under its id refuses.
pub(crate) fn landing_writer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<WriteActor> {
    let id = landing_writer_id()?;
    match vault.get_entity_type_in_txn(txn, &id)? {
        None => vault
            .batch_in()
            .put_internal(
                &id,
                ENTITY_TYPE_MACHINE,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"scope summary landing writer",
            )
            .apply(txn)?,
        Some(ENTITY_TYPE_MACHINE) => {}
        Some(_) => return Err(invalid("the scope summary landing writer is unavailable")),
    }
    Ok(WriteActor::new(id, EdgeActorClass::System))
}
