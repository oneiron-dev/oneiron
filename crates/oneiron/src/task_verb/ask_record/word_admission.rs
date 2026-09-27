//! Single answer admission path for authenticated actors and bearer-bound friends.

use super::*;

pub(in crate::task_verb) fn admit_word(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    writer: crate::WriteActor,
    word: &TaskAskWord,
    now: u64,
) -> Result<TaskAskAnswer> {
    admit_word_with_source(
        vault,
        txn,
        id,
        group,
        WordWriter::Authenticated(writer),
        word,
        now,
    )
}

/// A bearer proves access to this one recipient link, not an authenticated actor session.
pub(in crate::task_verb) fn admit_link_word(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    link: (EntityId, [u8; 32]),
    word: &TaskAskWord,
    now: u64,
) -> Result<TaskAskAnswer> {
    admit_word_with_source(vault, txn, id, group, WordWriter::Link(link), word, now)
}

enum WordWriter {
    Authenticated(crate::WriteActor),
    Link((EntityId, [u8; 32])),
}

fn admit_word_with_source(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: WordWriter,
    word: &TaskAskWord,
    now: u64,
) -> Result<TaskAskAnswer> {
    let (writer, token_digest) = match source {
        WordWriter::Authenticated(writer) => (writer, None),
        WordWriter::Link((friend, digest)) => (
            crate::WriteActor::new(friend, crate::EdgeActorClass::Human),
            Some(digest),
        ),
    };
    validate_word(group, word)?;
    if token_digest.is_some() && word.inform_for.is_some() {
        return Err(invalid());
    }
    for reference in &word.provenance_refs {
        if vault.get_entity_type_in_txn(txn, &reference.entity_ref())?
            != Some(reference.entity_type())
        {
            return Err(invalid());
        }
    }
    let actor = writer.entity_ref();
    let person = word.inform_for.unwrap_or(actor);
    let source = if word.inform_for.is_some() {
        if actor.to_hex() != group.owner || writer.actor_class() != crate::EdgeActorClass::Agent {
            return Err(invalid());
        }
        TaskAskSource::Inform
    } else if token_digest.is_some() {
        TaskAskSource::ForeignStated
    } else if writer.actor_class() == crate::EdgeActorClass::Human {
        TaskAskSource::Human
    } else {
        TaskAskSource::Executor
    };
    let member = group
        .members
        .iter()
        .find(|member| member.actor == person.to_hex())
        .ok_or_else(invalid)?;
    let task = entity(&member.task)?;
    let body = super::super::create_validation::task_body_in_txn(vault, txn, task)
        .map_err(|_| invalid())?;
    let authority = vault
        .task_authority_state_in(txn, task)?
        .ok_or_else(invalid)?;
    if body.owner_ref != group.owner
        || authority.owner_ref.to_hex() != group.owner
        || body.consult.as_ref().is_none_or(|payload| {
            payload.correlation_ref != id || payload.question_ref != group.effective.what.reference
        })
        || (authority.cancelled
            && super::super::ask_settlement::read_result(vault, txn, id)?.is_none())
    {
        return Err(invalid());
    }
    let word_ref = answer_id(id, task, actor, source, word)?;
    let answer = TaskAskAnswer {
        task_ref: task,
        actor_ref: actor,
        result_ref: word.result_ref,
        word_ref,
    };
    if let Some(existing) = read_answer(vault, txn, word_ref)? {
        if existing.group == id
            && existing.task == task
            && existing.actor == actor
            && existing.source == source
            && existing.word == *word
        {
            return Ok(answer);
        }
        return Err(invalid());
    }
    for reference in
        std::iter::once(word.result_ref).chain(word.provenance_refs.iter().map(|r| r.entity_ref()))
    {
        crate::llm::decision::questions::validate_task_answer_unit(
            vault,
            txn,
            entity(&group.owner)?,
            actor,
            reference,
        )?;
    }
    let evidence = evidence_in(vault, txn, id, group)?;
    if evidence.len() >= 4096 {
        return Err(Error::IndexOverflow("ask words"));
    }
    let order = evidence
        .iter()
        .map(|entry| entry.order)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(invalid)?;
    let mut fact = AskAnswerFact {
        group: id,
        task,
        actor,
        source,
        word: word.clone(),
        link_proof: None,
        order,
        at: now,
    };
    if let Some(digest) = token_digest {
        fact.link_proof = Some(super::link_proof::sign_link_word(
            vault, txn, id, group, word_ref, &fact, digest,
        )?);
    }
    put(vault, txn, word_ref, ANSWER, &fact, now)?;
    vault
        .batch_in()
        .edge(&word_ref, crate::EdgeKind::About, &id, 1.0)
        .apply(txn)?;
    Ok(answer)
}
