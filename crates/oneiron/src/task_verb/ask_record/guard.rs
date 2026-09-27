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
        }
        _ => {}
    }
    Ok(())
}
