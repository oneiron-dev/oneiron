//! Bound rooms on the doc plane (WORK-TALK-DOC-EDIT = A, lead 21 Nov 2026).
//!
//! A work talk (one-vault mode) and a leader chat each bind exactly two
//! writers. A TURN or MESSAGE there changes through the doc plane only by one
//! of them: a text edit, an update that lands, a settled proposal, metadata, a
//! pin, a migration or a sync edit. Anyone else, the company Owner included,
//! is not covered: a direct edit is refused, and an update or a proposal is
//! kept for review, which only a bound writer can settle (ARCH-0002: editing
//! someone else's message is a proposal). Read, retention, legal hold and
//! erase do not pass here and stay with the Owner.
//!
//! A work-talk writer passes the shared vault's Content check on its binding
//! instead of a vault-wide Content grant, as on the witness path (L7-05), and
//! only for a TURN or MESSAGE of its own talk: the companion holds no Content
//! grant, and the member's grant names her PERSON, not her roster actor.

use crate::error::Result;
#[cfg(feature = "sync")]
use crate::error::{ArtifactError, Error};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use heed::RoTxn;

/// The two writers a room binds, read for one of its records.
struct BoundWriters {
    writers: [EntityId; 2],
    /// A work talk: its writers pass the Content check on the binding.
    work_talk: bool,
}

/// The writers bound to the room that holds `entity`, when `entity` is a
/// TURN or MESSAGE of a work talk or a leader chat; `None` for every other
/// record and room. A binding that does not read fails closed.
fn bound_writers_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<BoundWriters>> {
    let kind = vault.get_entity_type_in_txn(txn, entity)?;
    if kind != Some(ENTITY_TYPE_TURN) && kind != Some(ENTITY_TYPE_MESSAGE) {
        return Ok(None);
    }
    let Some(room) = crate::conversation::room_for_record_in(vault, txn, *entity)? else {
        return Ok(None);
    };
    if let Some(binding) = crate::workspace_roster::work_talk_binding_in_txn(vault, txn, room)? {
        return Ok(Some(BoundWriters {
            writers: [binding.member_actor, binding.companion_actor],
            work_talk: true,
        }));
    }
    Ok(
        crate::workspace_roster::leader_chat_writers_in(vault, txn, room)?.map(|writers| {
            BoundWriters {
                writers,
                work_talk: false,
            }
        }),
    )
}

/// Whether `actor` may change `entity` given the room that holds it: `true`
/// unless `entity` is a TURN or MESSAGE of a bound room whose binding does
/// not name `actor` as one of its two writers.
pub(super) fn bound_writer_admits_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    actor: WriteActor,
) -> Result<bool> {
    Ok(bound_writers_in_txn(vault, txn, entity)?
        .is_none_or(|bound| bound.writers.contains(&actor.entity_ref())))
}

/// The shared vault's role and record scope for a doc-plane write of
/// `entity` by `actor` (FIX 9846). A work-talk writer writing a TURN or
/// MESSAGE of its own talk passes on its binding, with its write actor still
/// checked against store truth, as the witness path checks it. Every other
/// write, the Owner's included, takes the full check.
pub(super) fn authorize_content_write_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: EntityId,
    actor: &WriteActor,
) -> Result<()> {
    let on_binding = bound_writers_in_txn(vault, txn, &entity)?
        .is_some_and(|bound| bound.work_talk && bound.writers.contains(&actor.entity_ref()));
    if !on_binding {
        return vault.authorize_shared_content_write_in_txn(txn, entity, actor);
    }
    if vault.shared_vault_creation_in_txn(txn)?.is_some() {
        vault.verify_write_actor_in_txn(txn, actor)?;
    }
    Ok(())
}

/// [`bound_writer_admits_in_txn`] as a refusal, for a doc-plane write that
/// has no review path to fall back on: the sync document plane's edit.
#[cfg(feature = "sync")]
pub(super) fn require_bound_writer_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    actor: WriteActor,
) -> Result<()> {
    if bound_writer_admits_in_txn(vault, txn, entity, actor)? {
        Ok(())
    } else {
        Err(Error::Artifact(ArtifactError::SettleNotAuthorized(
            "only the room's two bound writers change its messages",
        )))
    }
}
