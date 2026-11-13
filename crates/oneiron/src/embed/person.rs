//! The PERSON half of embedding (ruling PERSON-VECTOR-CHOICES, 13 Nov): a
//! PERSON embeds its public `about` line, which the Dreamer writes for band 0
//! from only the public facts about the person (ARCH-0067). The entity
//! linker's vector rung ranks a mention's candidate persons by that vector.
//!
//! The text is one point read of the person's `about` row
//! ([`crate::dreamer_consolidation::public_about_line_in_txn`]), never a walk
//! of its claims (FIX 8660). It moves only where the row's lines move: a
//! landing and the owner's revert of one, each of which marks the person
//! here in its own write. A CLAIM write about the person only hides the line
//! until the Dreamer writes it again; the vector of the line it hides stays
//! until then ("staleness OK", research-0910). Idle publication never embeds
//! a PERSON's body fields ([`super::indexed_payload`]): it drops the vector
//! a body edit stands beside and marks the person again, so one producer
//! writes each person's vector.
//!
//! The vector stays while a plain CLAIM write hides the line, and goes only
//! where the facts its line was written from go (ruling D4): an erase of one
//! of them, a door that drops one (an archive, a use limit, a cooperative
//! restriction), and the wake pass that clears the lines of a person with no
//! facts left. A wake pass that shows a line again with no new landing marks
//! a person that holds no vector of it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Marks `person` for embedding at its public `about` line, committed with
/// the write that moved the line: a landing, or the owner's revert of one.
///
/// The marker commits to the line and the embedding epoch, as a TURN's does
/// to its text, so a fill for an older line no longer matches it and is
/// dropped as stale. A person left with no public line drops its vector,
/// which would otherwise keep ranking it by words its line no longer has. A
/// vault with no embedder marks nothing: attaching one queues every person
/// with a line.
pub(crate) fn mark_person_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    person: EntityId,
) -> Result<()> {
    if vault.config.embedding_model.is_none() {
        return Ok(());
    }
    if !mark_public_line_in_txn(vault, wtxn, person)? {
        crate::vault::entity_revision::drop_vector_state(vault, wtxn, &person)?;
    }
    Ok(())
}

/// The publication half: a write that published a PERSON's body (an idle
/// revision, an entity document) left its line as it was, so it marks the
/// person again only when the line shows. Idle publication dropped the
/// vector beside the body edit; this fills it again from the line. It never
/// drops one: a hidden line keeps its vector until the next landing.
pub(super) fn mark_person_on_publication_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    person: EntityId,
) -> Result<()> {
    mark_public_line_in_txn(vault, wtxn, person)?;
    Ok(())
}

/// Drops `person`'s vector, its marker and its job, in the transaction of a
/// door that took facts its `about` lines were written from: an erase of one
/// (the lines go), a door that drops one (the lines hide), or the wake pass
/// that clears the lines of a person with no facts left. The vector would
/// otherwise keep ranking the person by words those facts said until the
/// next landing (ruling PERSON-VECTOR-CHOICES, D4). It holds the store
/// only, as those doors do, so it drops whether or not an embedder is set.
pub(crate) fn drop_person_vector_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    person: &EntityId,
) -> Result<()> {
    crate::vault::entity_revision::drop_vector_state_in_store(store, wtxn, person)
}

/// The wake pass's half: a line the pass shows again with no new landing
/// (the facts are back where it was written from) marks `person` when it
/// holds neither a vector nor a current marker. That is a person whose
/// vector an idle body edit dropped while the line was hidden, or one an
/// erase or drop left with none: no landing would mark it again (FIX
/// PERSON-VECTOR-IDLE-EDIT-WHILE-HIDDEN). A person that still holds its
/// vector keeps it, so a pass never embeds an unchanged line twice.
pub(crate) fn mark_unembedded_person_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    person: EntityId,
) -> Result<()> {
    if vault.config.embedding_model.is_none()
        || vault.store.vectors.get(wtxn, person.as_bytes())?.is_some()
        || vault
            .store
            .has_current_pending_embedding_in_txn(wtxn, &person)?
    {
        return Ok(());
    }
    mark_public_line_in_txn(vault, wtxn, person)?;
    Ok(())
}

/// Marks `person` at its public line and queues its job; `false` when it
/// shows no public line, and nothing is marked.
fn mark_public_line_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    person: EntityId,
) -> Result<bool> {
    let Some(line) = crate::dreamer_consolidation::public_about_line_in_txn(vault, wtxn, &person)?
    else {
        return Ok(false);
    };
    vault
        .store
        .mark_pending_embedding(wtxn, &person, line.as_bytes())?;
    #[cfg(feature = "sync")]
    crate::sync::queue::push_embed_job_in_txn(
        &vault.store,
        wtxn,
        &person,
        super::EMBED_PRIORITY_DEVICE,
    )?;
    Ok(true)
}
