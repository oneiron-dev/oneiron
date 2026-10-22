//! Idle publication and refill of a record whose text is a repo blob's
//! (FIX 7608 slice 3): what the embedder, the text index and the phonetic
//! index receive is the record's copy, built before any provider call.
//!
//! A staged text field is kept and read as its copy; a staged vector or
//! phonetic code made from the stored bytes is dropped, and the copy's own
//! is derived instead. The writer that publishes compares the copy it
//! publishes with the one its own transaction makes, so an answer made from
//! an older copy is superseded and the record is taken again, never refused.
//! A mask change publishes the record's text and codes again as their copy
//! and queues its vector for refill. Canonical revisions, history and read
//! modes are unchanged.

use heed::{RoTxn, RwTxn};

use super::pending_index::{self, Inputs};
use super::storage::{read_entity_revision_in_txn, revision_text_fields, state};
use super::vector_refill::REFILL;
use super::{IndexedRevisionInput, ReadMode, RevisionRef};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, apply_ops};
use crate::origin::secret_projection::index::RepoIndexMarks;
use crate::ports::RetrievalIndexInventory;
use crate::{EntityId, Result, Vault};

/// The repo marks one idle pass reads its records under, in their own
/// snapshot.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(super) fn pass_marks(vault: &Vault) -> Result<RepoIndexMarks> {
    let txn = vault.store.env.read_txn()?;
    RepoIndexMarks::read_in_txn(vault, &txn)
}

/// `input` as idle publication and refill derive from it: its body and
/// fields as their copies.
///
/// # Errors
/// A store failure reading a mask row.
pub(super) fn project_revision_input_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    input: IndexedRevisionInput,
) -> Result<IndexedRevisionInput> {
    if !marks.touches(&input.entity, &input.body, &input.fields) {
        return Ok(input);
    }
    let IndexedRevisionInput {
        entity,
        entity_type,
        source_revision_ref,
        body,
        fields,
    } = input;
    Ok(IndexedRevisionInput {
        body: marks.body_in_txn(vault, txn, &entity, body)?,
        fields: marks.fields_in_txn(vault, txn, &entity, fields)?,
        entity,
        entity_type,
        source_revision_ref,
    })
}

/// The marks `txn` reads now, when `input`, read in `mode` before the
/// provider call under `pass`, is still the copy this transaction makes;
/// `None` when it is not, and the work is superseded.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(super) fn revision_copy_current_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    pass: &RepoIndexMarks,
    input: &IndexedRevisionInput,
    mode: ReadMode,
) -> Result<Option<RepoIndexMarks>> {
    let marks = RepoIndexMarks::read_in_txn(vault, txn)?;
    if pass.is_empty() && marks.is_empty() {
        return Ok(Some(marks));
    }
    let Some(raw) = read_entity_revision_in_txn(vault, txn, &input.entity, mode)? else {
        return Ok(None);
    };
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let fields = revision_text_fields(
        &vault.store,
        txn,
        &input.entity,
        input.source_revision_ref,
        &body,
    )?;
    let now = project_revision_input_in_txn(
        vault,
        txn,
        &marks,
        IndexedRevisionInput {
            entity: input.entity,
            entity_type: raw[0],
            source_revision_ref: input.source_revision_ref,
            body,
            fields,
        },
    )?;
    Ok((now.body == input.body && now.fields == input.fields).then_some(marks))
}

/// The staged inputs of `entity` at `revision`, as publication may use
/// them: every staged field kept as its copy, and a staged vector dropped
/// when the record is a marked blob's or a staged field had to be copied.
///
/// # Errors
/// A store failure reading a mask row.
pub(super) fn staged_inputs_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoIndexMarks,
    entity: &EntityId,
    revision: RevisionRef,
) -> Result<Inputs> {
    let mut staged = pending_index::load(&vault.store, txn, entity, revision)?;
    if marks.is_empty() {
        return Ok(staged);
    }
    let mut copied = marks.source_of(entity).is_some();
    if let Some(fields) = staged.fields.take() {
        let projected = marks.fields_in_txn(vault, txn, entity, fields.clone())?;
        copied |= projected != fields;
        staged.fields = Some(projected);
    }
    if copied {
        staged.vector = None;
        staged.provenance = None;
    }
    Ok(staged)
}

/// [`super::phonetic::take_phonetic`] for `input`, a marked blob's record
/// first dropping the codes staged from its stored bytes.
///
/// # Errors
/// A store failure.
pub(super) fn take_phonetic_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    marks: &RepoIndexMarks,
    input: &IndexedRevisionInput,
) -> Result<Vec<String>> {
    if marks.source_of(&input.entity).is_some() {
        super::phonetic::clear_phonetic(&vault.store, txn, &input.entity)?;
    }
    super::phonetic::take_phonetic(
        &vault.store,
        txn,
        &input.entity,
        input.source_revision_ref,
        input.entity_type,
        &input.body,
    )
}

/// A mask change on the blob record `entity` stands for: its staged codes
/// are dropped, its published text and codes are published again as their
/// copy through the batch door, and a vector it holds is queued for
/// refill. `false` for a record with no revision state, whose index the
/// caller refreshes by its own door.
///
/// # Errors
/// A store failure, or the batch door's.
pub(crate) fn refresh_repo_revision_projection_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    marks: &RepoIndexMarks,
    entity: &EntityId,
) -> Result<bool> {
    if state(&vault.store, txn, entity)?.is_none() {
        return Ok(false);
    }
    super::phonetic::clear_phonetic(&vault.store, txn, entity)?;
    let (Some(revision), Some(raw)) = (
        vault.indexed_revision_in_txn(txn, entity)?,
        read_entity_revision_in_txn(vault, txn, entity, ReadMode::Indexed)?,
    ) else {
        return Ok(true);
    };
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let fields = revision_text_fields(&vault.store, txn, entity, revision, &body)?;
    let input = project_revision_input_in_txn(
        vault,
        txn,
        marks,
        IndexedRevisionInput {
            entity: *entity,
            entity_type: raw[0],
            source_revision_ref: revision,
            body,
            fields,
        },
    )?;
    crate::batch::delete_from_phonetic_postings(&vault.store, txn, entity)?;
    let codes =
        crate::batch::phonetic_codes::codes_for_body(input.entity_type, &input.body);
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![
            BatchOp::Phonetic {
                id: *entity,
                codes,
            },
            BatchOp::Text {
                id: *entity,
                fields: input.fields,
            },
        ],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        false,
    )?;
    if vault
        .store
        .port_vector_with_raw(txn, entity, |_| Ok(()))?
        .is_some()
    {
        REFILL.put(&vault.store, txn, entity, &())?;
    }
    Ok(true)
}
