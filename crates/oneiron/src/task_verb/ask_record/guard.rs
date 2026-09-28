//! Shared raw-put and replay validation for immutable ask facts.
use super::*;

fn fact_kind(bytes: &[u8]) -> Option<&'static str> {
    let value = rmpv::decode::read_value(&mut &bytes[..]).ok()?;
    value.as_map()?.iter().find_map(|(key, value)| {
        if key.as_str() != Some("subkind") {
            return None;
        }
        match value.as_str()? {
            GROUP => Some(GROUP),
            ANSWER => Some(ANSWER),
            "tasks.ask_settlement" => Some("tasks.ask_settlement"),
            crate::task_verb::ask_soft_confirm::SOFT_CONFIRM => {
                Some(crate::task_verb::ask_soft_confirm::SOFT_CONFIRM)
            }
            _ => None,
        }
    })
}

/// An ask word or receipt is checked against its group row, so a replicated
/// batch applies it after the batch's other rows.
#[cfg(feature = "sync")]
pub(crate) fn waits_for_ask_group(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob).is_some_and(|header| header.entity_type == ENTITY_TYPE_TASK)
        && blob
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(fact_kind)
            .is_some_and(|kind| kind != GROUP)
}

/// A replicated fact can arrive before its group. Absence stays retryable;
/// a present row that is not an ask group is a bad fact.
fn stored_group(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
) -> Result<AskGroup> {
    let raw = store
        .entities
        .get(txn, group.as_bytes())?
        .ok_or(Error::Record(RecordError::AskDependencyPending))?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != ENTITY_TYPE_TASK {
        return Err(invalid());
    }
    decode(
        raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?,
        GROUP,
    )?
    .ok_or_else(invalid)
}

pub(crate) fn guard_ask_fact_put(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    occurred: crate::TimeRange,
    learned_at: u64,
    data: &[u8],
) -> Result<()> {
    let kind = fact_kind(data);
    if let Some(raw) = store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(raw.as_ref()).ok_or_else(invalid)?;
        let old = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
        if kind.is_some() || fact_kind(old).is_some() {
            // Identity pins BOTH body and header, including an identical-body
            // metadata rewrite through sync replay or internal batch.
            if old != data
                || header.occurred_start != occurred.start
                || header.occurred_end != occurred.end
                || header.learned_at != learned_at
            {
                return Err(invalid());
            }
        }
    }
    match kind {
        Some(GROUP) => {
            let group: AskGroup = decode(data, GROUP)?.ok_or_else(invalid)?;
            let who = group
                .members
                .iter()
                .map(|member| entity(&member.actor))
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            if group.base_policy_version != 1
                || group.members.len() != who.len()
                || group
                    .requested
                    .effective(&who, group.created_at, group.context_class.clone())
                    .map_err(|_| invalid())?
                    != group.effective
                || blake3::hash(&rmp_serde::to_vec_named(&group.requested).map_err(|_| invalid())?)
                    .to_hex()
                    .as_str()
                    != group.request_digest
            {
                return Err(invalid());
            }
            if let Some(crate::task_verb::TaskAskTarget::Guests(guests)) = &group.effective.who {
                if group.guest_grants.len() != guests.len()
                    || group.guest_grants.iter().any(|(person, grant)| {
                        !guests.contains_key(person)
                            || derived_id(b"oneiron.tasks.ask.guest.v1", id, person.as_bytes()).ok()
                                != Some(*grant)
                    })
                {
                    return Err(invalid());
                }
            } else if !group.guest_grants.is_empty() {
                return Err(invalid());
            }
            for member in &group.members {
                if entity(&member.task)? != member_id(id, entity(&member.actor)?)? {
                    return Err(invalid());
                }
            }
            entity(&group.owner)?;
        }
        Some(ANSWER) => {
            let fact: AskAnswerFact = decode(data, ANSWER)?.ok_or_else(invalid)?;
            if fact.order == 0
                || fact.at == 0
                || occurred.start != fact.at
                || occurred.end != fact.at
                || learned_at != fact.at
                || (fact.source == TaskAskSource::Inform) != fact.word.inform_for.is_some()
                || (fact.source == TaskAskSource::Companion) != fact.word.companion_for.is_some()
                || (fact.source != TaskAskSource::Companion && fact.delegation_grant_ref.is_some())
                || answer_id(fact.group, fact.task, fact.actor, fact.source, &fact.word)? != id
            {
                return Err(invalid());
            }
            if fact.source == TaskAskSource::ForeignStated {
                let group = stored_group(store, txn, fact.group)?;
                super::link_proof::validate_source(store, txn, id, &group, &fact)?;
            } else if fact.link_proof.is_some() {
                return Err(invalid());
            }
        }
        Some(crate::task_verb::ask_soft_confirm::SOFT_CONFIRM) => {
            let notice: crate::task_verb::TaskAskSoftConfirmNotice =
                decode(data, crate::task_verb::ask_soft_confirm::SOFT_CONFIRM)?
                    .ok_or_else(invalid)?;
            if notice.revision == 0
                || derived_id(
                    b"oneiron.tasks.ask.soft_confirm.v1",
                    notice.group_ref,
                    notice.person_ref.as_bytes(),
                )? != id
            {
                return Err(invalid());
            }
        }
        Some("tasks.ask_settlement") => {
            let result = decode::<crate::task_verb::TaskAskResult>(data, "tasks.ask_settlement")?
                .ok_or_else(invalid)?;
            crate::task_verb::ask_settlement::validate_result(id, &result)?;
            // A consistent reducer transcript is not proof of link intake:
            // only the group's issuer can sign a receipt with such words.
            if result
                .evidence
                .iter()
                .any(|entry| entry.source == TaskAskSource::ForeignStated)
                || result.settlement.link_result_proof.is_some()
            {
                let group = stored_group(store, txn, result.settlement.group_ref)?;
                verify_link_settlement(&group, &result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(in crate::task_verb) fn validate_notice_companion(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group_ref: EntityId,
    group: &AskGroup,
    notice: &crate::task_verb::TaskAskSoftConfirmNotice,
) -> Result<()> {
    let fact = read_answer(vault, txn, notice.companion_answer_ref)?.ok_or_else(invalid)?;
    let crate::task_verb::TaskAskTarget::Guests(guests) =
        group.effective.who.as_ref().ok_or_else(invalid)?
    else {
        return Err(invalid());
    };
    let guest = guests.get(&notice.person_ref).ok_or_else(invalid)?;
    let member = group
        .members
        .iter()
        .find(|m| m.actor == notice.person_ref.to_hex())
        .ok_or_else(invalid)?;
    if fact.group != group_ref
        || fact.source != TaskAskSource::Companion
        || fact.actor != guest.companion_ref
        || fact.task != entity(&member.task)?
        || fact.word.companion_for != Some(notice.person_ref)
        || fact.word.option != notice.option
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn validate_word(group: &AskGroup, word: &TaskAskWord) -> Result<()> {
    if word.provenance_refs.len() > 64
        || (word.companion_for.is_some() && word.inform_for.is_some())
    {
        return Err(invalid());
    }
    if word.confirmation.is_some() && (word.inform_for.is_some() || word.companion_for.is_some()) {
        return Err(invalid());
    }
    if match &word.option {
        Some(option) => !group.effective.what.options.contains_key(option),
        None => {
            !group.effective.what.options.is_empty()
                && !word.confirmation.as_ref().is_some_and(|response| {
                    response.decision == crate::task_verb::TaskAskConfirmationDecision::Reject
                })
        }
    } {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.ask.option",
        )));
    }
    Ok(())
}
