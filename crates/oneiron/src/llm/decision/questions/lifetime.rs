//! FIX 9918: an erased answer takes its copies with it. A bound
//! `judgment.answer` claim's receipt is copied into its question's answer
//! row, its outcome labels and its closed window; a `tasks.ask` answer's
//! selection is also its single version's one Choice option. Deleting or
//! erasing the claim removes every one of those rows in the erase's own
//! transaction, at both delete doors ([`crate::deletion`]), so no question
//! read serves an erased selection. A generic question's version, used by
//! surviving answers, stays.

use super::arrival::unwatch;
use super::records::AnswerRecord;
use super::store::{
    AnswerKey, HeadKey, LabelKey, QUESTION_ANSWER, QUESTION_HEAD, QUESTION_LABEL,
    QUESTION_VERSION, VersionKey, family_prefix,
};
use super::windows::{QUESTION_WINDOW, WindowKey};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::store::Store;
use crate::{EntityId, Error, Result};

/// The adapter whose one version carries its answer's selection.
const TASK_ASK_ADAPTER: &str = "tasks.ask";

/// Removes every typed-question row that copies the answer `id` is, when
/// `id` is a bound `judgment.answer` claim; a no-op for any other record.
pub(crate) fn erase_question_source_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(answer) = bound_answer_in_txn(store, &*wtxn, id)? else {
        return Ok(());
    };
    let question = answer.decision.receipt.question;
    let claim = answer.claim;
    if !QUESTION_ANSWER.delete(store, wtxn, &AnswerKey { question, claim })? {
        return Ok(());
    }
    let mut labels = family_prefix(question, b"label");
    labels.extend_from_slice(claim.as_bytes());
    let labels: Vec<LabelKey> = QUESTION_LABEL
        .scan_from(store, &*wtxn, &labels)?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    for key in labels {
        QUESTION_LABEL.delete(store, wtxn, &key)?;
    }
    QUESTION_WINDOW.delete(store, wtxn, &WindowKey { question, claim })?;
    let version = VersionKey {
        id: question,
        version: answer.decision.receipt.question_version,
    };
    let Some(record) = QUESTION_VERSION.get(store, &*wtxn, &version)? else {
        return Ok(());
    };
    if record.definition.adapter != TASK_ASK_ADAPTER {
        return Ok(());
    }
    // A tasks.ask question is its one answer: its version holds the copied
    // selection as its only option, so the version, its head and its watch
    // go with the answer.
    QUESTION_VERSION.delete(store, wtxn, &version)?;
    if QUESTION_HEAD
        .get(store, &*wtxn, &HeadKey(question))?
        .is_some_and(|head| head.version == version.version)
    {
        QUESTION_HEAD.delete(store, wtxn, &HeadKey(question))?;
    }
    unwatch(store, wtxn, &record)
}

/// The answer receipt `id` carries when it is a live `judgment.answer`
/// claim whose body is one.
fn bound_answer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<AnswerRecord>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Ok(None);
    }
    let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(None);
    };
    if body.predicate != "judgment.answer" {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body.value)
        .map_err(|_| Error::InvariantViolation("judgment answer encoding"))?;
    Ok(rmp_serde::from_slice::<AnswerRecord>(&bytes)
        .ok()
        .filter(|answer| answer.claim == *id))
}
