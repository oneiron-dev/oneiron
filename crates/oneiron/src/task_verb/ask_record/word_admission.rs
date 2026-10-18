//! Single answer admission path for authenticated actors and bearer-bound friends.

use super::*;

/// `owner` is the live owner proof the writer's surface carries, if any; an
/// attendee ask admits a word only under it (`attendee_answer::guard_word`).
#[expect(
    clippy::too_many_arguments,
    reason = "one admission over the word, its writer and the owner proof"
)]
pub(in crate::task_verb) fn admit_word(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    writer: crate::WriteActor,
    word: &TaskAskWord,
    owner: Option<&crate::consent::AuthenticatedOwner>,
    now: u64,
) -> Result<TaskAskAnswer> {
    admit_word_with_source(
        vault,
        txn,
        id,
        group,
        WordWriter::Authenticated(writer),
        word,
        owner,
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
    admit_word_with_source(
        vault,
        txn,
        id,
        group,
        WordWriter::Link(link),
        word,
        None,
        now,
    )
}

enum WordWriter {
    Authenticated(crate::WriteActor),
    Link((EntityId, [u8; 32])),
}

#[expect(
    clippy::too_many_arguments,
    reason = "one admission over the word, its writer and the owner proof"
)]
fn admit_word_with_source(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: WordWriter,
    word: &TaskAskWord,
    owner: Option<&crate::consent::AuthenticatedOwner>,
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
    let person = word.inform_for.or(word.companion_for).unwrap_or(actor);
    let source = if word.companion_for.is_some() {
        if writer.actor_class() != crate::EdgeActorClass::Agent {
            return Err(invalid());
        }
        super::super::ask_guest::check_companion_answer(vault, txn, id, group, actor, word, now)?;
        TaskAskSource::Companion
    } else if word.inform_for.is_some() {
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
    // An attendee ask's word is the authenticated owner's own, or nothing:
    // refused here, before anything is recorded.
    super::super::attendee_answer::guard_word(vault, txn, id, group, source, actor, word, owner)?;
    super::super::training_offer_ask::guard_word(
        vault, txn, id, group, source, actor, word, owner,
    )?;
    if word.confirmation.is_some() {
        if source != TaskAskSource::Human {
            return Err(invalid());
        }
        super::super::ask_soft_confirm::validate_confirmation(vault, txn, id, group, actor, word)?;
    }
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
    let delegation_grant_ref = if source == TaskAskSource::Companion {
        super::super::ask_guest::delegated_class(
            vault,
            txn,
            person,
            actor,
            group.effective.what.class_key.as_deref(),
        )?
    } else {
        None
    };
    let word_ref = answer_id(id, task, actor, source, word)?;
    if source == TaskAskSource::Companion
        && group.effective.what.commitment
        && let Some(notice) = read::<super::super::TaskAskSoftConfirmNotice>(
            vault,
            txn,
            crate::EntityId::derive(
                crate::entity_id::derived_domains::TASK_ASK_SOFT_CONFIRM,
                &[id.as_bytes(), person.as_bytes()],
            )?,
            super::super::ask_soft_confirm::SOFT_CONFIRM,
        )?
        && notice.companion_answer_ref != word_ref
    {
        return Err(invalid()); // A changed commitment needs a new ask revision.
    }
    if let Some(existing) = read_answer(vault, txn, word_ref)? {
        if existing.group == id
            && existing.task == task
            && existing.actor == actor
            && existing.source == source
            && existing.word == *word
        {
            // The kinds the fact stored, not a re-read of a result that may
            // since be erased.
            return Ok(TaskAskAnswer::new(
                task,
                actor,
                word.result_ref,
                word_ref,
                existing.actor_kind,
                existing.result_kind,
            ));
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
    let actor_kind = vault
        .get_entity_type_in_txn(txn, &actor)?
        .ok_or(Error::EntityNotFound)?;
    let result_kind = vault
        .get_entity_type_in_txn(txn, &word.result_ref)?
        .ok_or(Error::EntityNotFound)?;
    let evidence = evidence_in(vault, txn, id, group)?;
    // A bearer of one recipient link is a stranger to this vault: its words
    // stay bounded. An authenticated actor's never are (rule 5).
    if token_digest.is_some() && evidence.len() >= super::LINK_WORDS_PER_ASK {
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
        actor_kind,
        source,
        word: word.clone(),
        result_kind,
        link_proof: None,
        order,
        delegation_grant_ref,
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
    let answer = TaskAskAnswer::new(
        task,
        actor,
        word.result_ref,
        word_ref,
        actor_kind,
        result_kind,
    );
    if source == TaskAskSource::Companion && group.effective.what.commitment {
        super::super::ask_soft_confirm::put_notice(
            vault,
            txn,
            (id, person),
            &answer,
            word,
            &group.effective,
            now,
        )?;
    }
    Ok(answer)
}
