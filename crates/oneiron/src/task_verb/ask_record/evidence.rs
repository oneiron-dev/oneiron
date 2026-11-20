//! An ask group's admitted words read as evidence: every word in order, and
//! each member's projected word.
//! Entry: `evidence_in`, `person_evidence_in`.

use super::*;

pub(in crate::task_verb) fn evidence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Vec<TaskAskEvidence>> {
    // Every word is read, however many (rule 5); `txn` is the caller's and
    // may be a write, so a crossing is deferred.
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::AskWordRows,
        id.as_bytes(),
    )?;
    let mut evidence = Vec::new();
    for row in vault.store.port_edges(
        txn,
        &id,
        crate::ports::EdgeDirection::In,
        Some(crate::EdgeKind::About),
        None,
    )? {
        count.row();
        let word_ref = row?.target;
        let Some(fact) = read_answer(vault, txn, word_ref)? else {
            continue;
        };
        if fact.group != id {
            continue;
        }
        let person = fact
            .word
            .inform_for
            .or(fact.word.companion_for)
            .unwrap_or(fact.actor);
        if !group
            .members
            .iter()
            .any(|member| member.task == fact.task.to_hex() && member.actor == person.to_hex())
            || fact.order == 0
            || fact.at == 0
            || (fact.source == TaskAskSource::Inform) != fact.word.inform_for.is_some()
            || (fact.source == TaskAskSource::Inform && fact.actor.to_hex() != group.owner)
            || (fact.source == TaskAskSource::ForeignStated
                && (fact.word.inform_for.is_some()
                    || vault.get_entity_type_in_txn(txn, &fact.actor)?
                        != Some(crate::registry::ENTITY_TYPE_PERSON)))
            || (fact.source == TaskAskSource::Companion) != fact.word.companion_for.is_some()
            || (fact.source != TaskAskSource::Companion && fact.delegation_grant_ref.is_some())
            || fact.delegation_grant_ref.as_ref().is_some_and(|reference| {
                !super::super::ask_guest::check_delegation_record(
                    vault,
                    txn,
                    person,
                    fact.actor,
                    group.effective.what.class_key.as_deref(),
                    reference,
                )
                .unwrap_or(false)
            })
            || answer_id(id, fact.task, fact.actor, fact.source, &fact.word)? != word_ref
        {
            return Err(invalid());
        }
        validate_word(group, &fact.word).map_err(|_| Error::CorruptedIndex("tasks.ask.word"))?;
        link_proof::validate_source(&vault.store, txn, word_ref, group, &fact)?;
        if fact.word.confirmation.is_some() {
            if fact.source != TaskAskSource::Human {
                return Err(invalid());
            }
            super::super::ask_soft_confirm::validate_confirmation(
                vault, txn, id, group, fact.actor, &fact.word,
            )?;
        }
        if fact.source == TaskAskSource::Companion {
            super::super::ask_guest::validate_companion_fact(
                vault, txn, id, group, fact.actor, &fact.word,
            )?;
        }
        evidence.push(TaskAskEvidence {
            answer: TaskAskAnswer::new(
                fact.task,
                fact.actor,
                fact.word.result_ref,
                word_ref,
                fact.actor_kind,
                fact.result_kind,
            ),
            word: fact.word,
            source: fact.source,
            person_ref: person,
            order: fact.order,
            reason: TaskAskEvidenceReason::OutsideElectorate,
            ladder_changed: None,
            soft_confirm: fact.source == TaskAskSource::Companion
                && group.effective.what.commitment,
            delegation_grant_ref: fact.delegation_grant_ref,
        });
    }
    evidence.sort_by_key(|entry| (entry.order, entry.answer.word_ref));
    count.defer(&vault.store);
    Ok(evidence)
}

/// Projects all admitted words without erasing their speakers. A person
/// without a word becomes unknown only when the cutoff has passed or settled.
pub(in crate::task_verb) fn person_evidence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    now: u64,
) -> Result<Vec<TaskAskPersonEvidence>> {
    let settled = super::super::ask_settlement::read_result(vault, txn, id)?;
    let cutoff = settled
        .as_ref()
        .map(|result| result.settlement.at)
        .or_else(|| group.effective.until.filter(|until| *until <= now));
    let words = super::super::ask_settlement::evidence(vault, txn, id, group)?;
    let mut answers = Vec::with_capacity(group.members.len());
    for member in &group.members {
        let who = entity(&member.actor)?;
        let selected = words
            .iter()
            .filter(|entry| entry.person_ref == who)
            .max_by_key(|entry| {
                (
                    u8::from(matches!(
                        entry.source,
                        TaskAskSource::Human | TaskAskSource::ForeignStated
                    )),
                    entry.order,
                )
            });
        if let Some(entry) = selected {
            let fact = read_answer(vault, txn, entry.answer.word_ref)?.ok_or_else(invalid)?;
            answers.push(TaskAskPersonEvidence {
                who,
                answer: Some(entry.word.clone()),
                kind: if matches!(
                    entry.source,
                    TaskAskSource::Human | TaskAskSource::ForeignStated
                ) {
                    TaskAskPersonKind::Word
                } else {
                    TaskAskPersonKind::Companion
                },
                at: fact.at,
                source: Some(entry.answer.actor_ref),
            });
        } else if let Some(at) = cutoff {
            answers.push(TaskAskPersonEvidence {
                who,
                answer: None,
                kind: TaskAskPersonKind::Unknown,
                at,
                source: None,
            });
        }
    }
    Ok(answers)
}
