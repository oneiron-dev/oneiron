//! Every generic entity-document commit carries its made_by receipt (FIX
//! 7790, ARCH-0035): the engine stamp, then `|made_by=` and the commit's
//! [`MadeBy`] envelope as JSON, in the commit message the operation log
//! keeps, replicates and checkpoints with the change itself. The change is
//! the receipt's operation span, and the document's birth names its entity
//! (a SWITCH moves its storage slot, never its birth). No side table holds a
//! receipt.
//!
//! The envelope says what the engine knows: the writing actor and its class,
//! the engine operation that wrote the change ([`engine_process`]), the rows
//! a writer named as read for it, and the commit time. It names no model,
//! prompt or trigger the engine did not see. The stamp and the envelope name
//! the actor by its opaque stamp token (FIX 10930), which its claim resolves
//! here; a reader hands back the envelope naming the resolved actor. A
//! message alone authenticates nothing: a receipt is read only where the
//! writing peer's binding vouches for its actor, as the attribution reader
//! asks. A commit with none (an unstamped, erased, malformed or unvouched
//! one, or one whose token resolves to no one) reads as unknown provenance,
//! never as refused text.
//!
//! Canonical recovery replays a document into fresh operations, whose
//! writers are gone. Each replayed commit restates the row's birth instead
//! ([`ROW_BIRTH_RESTATED`], FIX 10929): it names no one itself, and reads as
//! the row's surviving `RowBirth.made_by`, the vault's own record. Once an
//! erase drops that birth, the restated commits read as unknown again. A
//! door whose row already holds its birth gives the document's birth commit
//! that same envelope ([`receipted_as`]). A receipt naming a trigger is
//! vouched only when the trigger is a known kind with its own record here: a
//! live task, ask or skill row, or a run's stored replay record.

use loro::ChangeMeta;
use sha2::{Digest, Sha256};

use crate::entity_doc::document::Stamped;
use crate::entity_doc::document::cut_stamp;
use crate::entity_doc::document::parse_stamp;
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::ActorStamp;
use crate::write_envelope::provenance::made_by::MadeBy;
use crate::write_envelope::provenance::made_by::MadeByClass;
use crate::write_envelope::provenance::made_by::MadeByInput;
use crate::write_envelope::provenance::made_by::MadeByInputRole;
use crate::write_envelope::provenance::made_by::MadeByProcess;
use crate::write_envelope::provenance::made_by::MadeByTrigger;
use crate::write_envelope::provenance::text_commit::RowProvenance;
use crate::write_envelope::provenance::text_commit::TextCommitReceipt;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// What joins a commit's engine stamp to its receipt.
pub const RECEIPT_PREFIX: &str = "|made_by=";

/// The whole message of a commit canonical recovery replayed: it restates
/// the row's birth, whose surviving `RowBirth.made_by` is its receipt (FIX
/// 10929). It names no actor, so no erase has anything to take from it.
pub const ROW_BIRTH_RESTATED: &str = "oneiron.entity_doc.v1 row_birth";

/// The process a generic commit's receipt names (C-ENTITY-PROCESS): the
/// engine operation `oneiron.entity_doc.<verb>` at version 1, which takes no
/// render parameters, so its parameter hash is the empty input's. It is the
/// operation that wrote the change, not a model. Its actor is the writer's
/// stamp token (FIX 10930).
pub fn engine_process(stamp: ActorStamp, verb: &str) -> MadeByProcess {
    MadeByProcess {
        actor: stamp.token,
        class: MadeByClass::of_writer(stamp.class),
        identity: format!("oneiron.entity_doc.{verb}"),
        version: "1".to_owned(),
        params_hash: format!("{:x}", Sha256::digest([])),
    }
}

/// `stamped` with `made_by` as its receipt: the generic receipt, or a row's
/// own birth envelope that names the stamp's actor at the commit's time (FIX
/// 10929), written naming the stamp's token (FIX 10930).
pub fn receipted_as(stamped: &str, made_by: &MadeBy) -> Result<String> {
    let receipt = serde_json::to_string(made_by)
        .map_err(|_| Error::InvariantViolation("document receipt encoding"))?;
    Ok(format!("{stamped} {RECEIPT_PREFIX}{receipt}"))
}

/// The engine stamp and the receipt `message` carries, when it carries both
/// as [`receipted`] spells them.
fn decode(message: &str) -> Option<(&str, MadeBy)> {
    let (stamped, receipt) = message.split_once(RECEIPT_PREFIX)?;
    let stamped = stamped.strip_suffix(' ')?;
    cut_stamp(stamped)?;
    Some((stamped, serde_json::from_str(receipt).ok()?))
}

/// The four store reads a receipt's validation needs. The public reader keeps
/// its existing per-read transactions; the probe reader uses its caller's.
pub trait ReceiptReads {
    fn trigger_recorded(&self, trigger: Option<&MadeByTrigger>) -> Result<bool>;
    fn prompt_input_present(&self, row: &EntityId) -> Result<bool>;
    fn resolve_actor(&self, token: &EntityId) -> Result<Option<WriteActor>>;
    fn peer_honors(&self, peer: u64, at: u64, actor: &WriteActor) -> Result<bool>;
}

pub fn receipt_of_with<R: ReceiptReads>(
    reads: &R,
    document: EntityId,
    birth: Option<&MadeBy>,
    meta: &ChangeMeta,
) -> Result<Option<TextCommitReceipt>> {
    let len = i32::try_from(meta.len).ok().filter(|&len| len > 0);
    let Some(end) = len.and_then(|len| meta.id.counter.checked_add(len)) else {
        return Ok(None);
    };
    let receipt = |made_by: MadeBy| TextCommitReceipt {
        document,
        peer: meta.id.peer,
        start: meta.id.counter,
        end,
        made_by,
    };
    if meta.message.as_deref() == Some(ROW_BIRTH_RESTATED) {
        return Ok(birth.cloned().map(receipt));
    }
    let Some((stamped, mut made_by)) = meta.message.as_deref().and_then(decode) else {
        return Ok(None);
    };
    let Stamped::Live(stamp) = parse_stamp(Some(stamped)) else {
        return Ok(None);
    };
    let states = made_by.process.class == MadeByClass::Stated;
    if made_by.process.actor != stamp.token
        || (states && stamp.class != EdgeActorClass::Human)
        || !made_by.process.is_valid()
        || u64::try_from(meta.timestamp).ok() != Some(made_by.at)
        || !reads.trigger_recorded(made_by.trigger.as_ref())?
    {
        return Ok(None);
    }
    for input in &made_by.inputs {
        if input.role == MadeByInputRole::Prompt && !reads.prompt_input_present(&input.row)? {
            return Ok(None);
        }
    }
    // An unresolved token names no one: no receipt (FIX 10930).
    let Some(actor) = reads
        .resolve_actor(&stamp.token)?
        .filter(|actor| actor.actor_class() == stamp.class)
    else {
        return Ok(None);
    };
    let vouched = reads.peer_honors(meta.id.peer, made_by.at, &actor)?;
    made_by.process.actor = actor.entity_ref();
    Ok(vouched.then(|| receipt(made_by)))
}
