//! Durable, once-per-person soft-confirm notice for a companion commitment.
use super::{TaskAskAnswer, TaskAskWord};
use crate::{EntityId, Result, Vault};

pub(super) const SOFT_CONFIRM: &str = "tasks.ask_soft_confirm";

pub(super) fn notice(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
    person: EntityId,
) -> Result<Option<super::TaskAskSoftConfirmNotice>> {
    let id = crate::EntityId::derive(crate::entity_id::derived_domains::TASK_ASK_SOFT_CONFIRM, &[group.as_bytes(), person.as_bytes()])?;
    let Some(notice): Option<super::TaskAskSoftConfirmNotice> =
        super::ask_record::read(vault, txn, id, SOFT_CONFIRM)?
    else {
        return Ok(None);
    };
    let ask =
        super::ask_record::read_group(vault, txn, group)?.ok_or_else(super::ask_record::invalid)?;
    // A person's authenticated reply or an already-settled revision closes
    // confirmation; do not deliver a stale companion prompt afterwards.
    if super::ask_settlement::read_result(vault, txn, group)?.is_some()
        || super::ask_record::evidence_in(vault, txn, group, &ask)?
            .iter()
            .any(|entry| entry.source == super::TaskAskSource::Human && entry.person_ref == person)
    {
        return Ok(None);
    }
    if !ask.effective.what.commitment
        || notice.group_ref != group
        || notice.person_ref != person
        || notice.revision != ask.effective.what.revision
        || Some(notice.deadline) != ask.effective.until
        || !super::ask_record::evidence_in(vault, txn, group, &ask)?
            .iter()
            .any(|entry| {
                entry.source == super::TaskAskSource::Companion
                    && entry.person_ref == person
                    && entry.answer.word_ref == notice.companion_answer_ref
                    && entry.answer.task_ref == notice.task_ref
                    && entry.word.option == notice.option
            })
    {
        return Err(super::ask_record::invalid());
    }
    Ok(Some(notice))
}

pub(super) fn put_notice(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    subject: (EntityId, EntityId),
    answer: &TaskAskAnswer,
    word: &TaskAskWord,
    effective: &super::TaskAskSpec,
    now: u64,
) -> Result<()> {
    let (group, person) = subject;
    let id = crate::EntityId::derive(crate::entity_id::derived_domains::TASK_ASK_SOFT_CONFIRM, &[group.as_bytes(), person.as_bytes()])?;
    if super::ask_record::read::<super::TaskAskSoftConfirmNotice>(vault, txn, id, SOFT_CONFIRM)?
        .is_some()
    {
        return Ok(());
    }
    super::ask_record::put(
        vault,
        txn,
        id,
        SOFT_CONFIRM,
        &super::TaskAskSoftConfirmNotice {
            group_ref: group,
            revision: effective.what.revision,
            person_ref: person,
            companion_answer_ref: answer.word_ref,
            option: word.option.clone(),
            task_ref: answer.task_ref,
            deadline: effective.until.ok_or_else(super::ask_record::invalid)?,
        },
        now,
    )?;
    super::ask_soft_confirm_delivery::register(vault, txn, group, person)
}

/// Validate a human's typed response against the immutable effective notice.
/// The original ask option remains the chosen slot, not an invented `no` id.
pub(super) fn validate_confirmation(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
    ask: &super::ask_record::AskGroup,
    person: EntityId,
    word: &TaskAskWord,
) -> Result<()> {
    let response = word
        .confirmation
        .as_ref()
        .ok_or_else(super::ask_record::invalid)?;
    let id = crate::EntityId::derive(crate::entity_id::derived_domains::TASK_ASK_SOFT_CONFIRM, &[group.as_bytes(), person.as_bytes()])?;
    let notice: super::TaskAskSoftConfirmNotice =
        super::ask_record::read(vault, txn, id, SOFT_CONFIRM)?
            .ok_or_else(super::ask_record::invalid)?;
    if !ask.effective.what.commitment
        || notice.group_ref != group
        || notice.person_ref != person
        || notice.revision != response.revision
        || notice.revision != ask.effective.what.revision
        || notice.companion_answer_ref != response.companion_answer_ref
        || notice.deadline != ask.effective.until.ok_or_else(super::ask_record::invalid)?
        || match response.decision {
            super::TaskAskConfirmationDecision::Approve => word.option != notice.option,
            super::TaskAskConfirmationDecision::Reject => word.option.is_some(),
        }
    {
        return Err(super::ask_record::invalid());
    }
    super::ask_record::validate_notice_companion(vault, txn, group, ask, &notice)
}

/// Check the frozen send against the live ask at admission AND at the last
/// transport boundary. Only the reserved dedupe namespace can address a
/// confirmation; ordinary outbound intents retain their existing semantics.
pub(crate) fn validate_dispatch(
    vault: &Vault,
    request: &crate::outbound::OutboundDispatchRequest,
) -> Result<bool> {
    let Some(idempotency) = request.intent.idempotency_key.as_deref() else {
        return Ok(true);
    };
    let Some(ids) = idempotency.strip_prefix("ask-soft-confirm/") else {
        return Ok(true);
    };
    let mut parts = ids.split('/');
    let (Some(group), Some(person), None) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(false);
    };
    let (Ok(group), Ok(person)) = (EntityId::from_hex(group), EntityId::from_hex(person)) else {
        return Ok(false);
    };
    let expected = crate::EntityId::derive(crate::entity_id::derived_domains::TASK_ASK_SOFT_CONFIRM, &[group.as_bytes(), person.as_bytes()])?;
    if request.intent.content_ref.as_deref() != Some(expected.to_hex().as_str()) {
        return Ok(false);
    }
    let txn = vault.store.env.read_txn()?;
    let Some(notice) = notice(vault, &txn, group, person)? else {
        return Ok(false);
    };
    let ask = super::ask_record::read_group(vault, &txn, group)?
        .ok_or_else(super::ask_record::invalid)?;
    let super::TaskAskTarget::Guests(guests) =
        ask.effective.who.ok_or_else(super::ask_record::invalid)?
    else {
        return Ok(false);
    };
    let companion = guests
        .get(&person)
        .ok_or_else(super::ask_record::invalid)?
        .companion_ref;
    Ok(request.intent.trigger_ref == notice.task_ref.to_hex()
        && request.intent.actor == companion.to_hex()
        && request.actor.actor_entity_ref == Some(companion))
}
