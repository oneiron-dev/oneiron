//! Settles an ask: applies a choice, keeps the names separate, or escalates.
//! Entry: `settle_ask_in_txn`, `keep_separate_in_txn` and `escalate_in_txn`.
//! The ask types are in the parent; their undo is in `settle_undo`.

use std::collections::BTreeSet;

use super::super::applied::MaintenanceInverse;
use super::{
    ASK_ANSWER_CONTEXT, ASKS, Answer, IDENTITY_NOTIFICATION_PRODUCER, IDENTITY_RECHECK_FACET,
    IS_PREFIX, IdentityAsk, MAX_CANDIDATES, ProvisionalInverse, SOMEONE_NEW, SOMEONE_NEW_RATIONALE,
    erase, evidence, key_hex, put_hint_in_txn,
};
use crate::claim::ClaimSource;
use crate::identity_topology::{
    AssertDistinctOp, EngineCause, IdentityOpWrite, IdentityTopologyOp, TopologySeal,
};
use crate::{EntityId, Result, Vault};

/// Whether `id` is a stored entity of `kind`.
pub(super) fn entity_of_kind_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> Result<bool> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .is_some_and(|raw| raw.first() == Some(&kind)),
    )
}

/// The person an option names, when it is one of the ask's.
pub(super) fn parse_choice(ask: &IdentityAsk, choice: &str) -> Option<Answer> {
    if choice == SOMEONE_NEW {
        return Some(Answer::SomeoneNew);
    }
    let hex = choice.strip_prefix(IS_PREFIX)?;
    ask.candidates
        .iter()
        .find(|id| id.to_hex() == hex)
        .map(|id| Answer::Is(*id))
}

/// The candidates a decision lists as options, in stored order: the first
/// [`MAX_CANDIDATES`], the mention's own provisional entity always among
/// them.
pub(super) fn listed_candidates(ask: &IdentityAsk) -> Vec<EntityId> {
    let mut listed: Vec<EntityId> = ask
        .candidates
        .iter()
        .take(MAX_CANDIDATES)
        .copied()
        .collect();
    if let Some(own) = ask.provisional
        && ask.candidates.contains(&own)
        && !listed.contains(&own)
    {
        listed.pop();
        listed.push(own);
    }
    listed
}

/// The id an owner's answer to ask `key` binds its topology decision to.
pub(super) fn ask_answer_id(key: &[u8; 32]) -> Result<EntityId> {
    EntityId::derive(ASK_ANSWER_CONTEXT, &[key])
}

/// The Dreamer's own topology decision: no owner answer, no Grant line.
pub(super) fn dreamer_seal() -> TopologySeal {
    TopologySeal::engine(EngineCause::DreamerInference)
}

/// Asserts the new person `fresh` distinct from each real person the ask
/// offered, as each resolves now (ARCH-0055 §6: "different things" mints
/// `assert_distinct`), with `source` as the claim's and `seal` as who
/// decided. Nothing when `fresh` is no stored entity: no readable text named
/// it any more.
fn assert_distinct_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    fresh: EntityId,
    (source, seal): (ClaimSource, &TopologySeal),
    now: u64,
) -> Result<()> {
    if !entity_of_kind_in_txn(vault, txn, &fresh, ask.kind)? {
        return Ok(());
    }
    let mut real = BTreeSet::new();
    for candidate in &ask.candidates {
        for head in vault.resolve_entity_in_txn(txn, candidate)? {
            if head != fresh
                && entity_of_kind_in_txn(vault, txn, &head, ask.kind)?
                && crate::deletion::topology_delete_reservation_in_txn(&vault.store, txn, &head)?
                    .is_none()
            {
                real.insert(head);
            }
        }
    }
    let write = IdentityOpWrite::auto(source);
    for head in real {
        vault.apply_identity_topology_op_as_in_txn(
            txn,
            &IdentityTopologyOp::AssertDistinct(AssertDistinctOp {
                a: fresh,
                b: head,
                reason: SOMEONE_NEW_RATIONALE.to_owned(),
            }),
            &write,
            seal,
            now,
        )?;
    }
    Ok(())
}

/// Settles the ask's mention as `answer` and saves the hint: a chosen
/// candidate takes the span (and absorbs the mention's own provisional
/// entity, everywhere it is named); someone new keeps that provisional
/// entity, or mints one for the span, confirms it as a real person and
/// asserts it distinct from the real candidates, said by `source` and
/// decided by `seal`.
pub(super) fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ask: &IdentityAsk,
    answer: Answer,
    (source, seal): (ClaimSource, &TopologySeal),
    now: u64,
) -> Result<EntityId> {
    let original = evidence::snapshot_in_txn(vault, txn, ask)?;
    let span = (&ask.message, ask.start, ask.end);
    let entity = match answer {
        Answer::Is(chosen) => {
            let absorbed = match ask.provisional {
                Some(own) if own != chosen => {
                    crate::tagging::resolve_provisional_in_txn(vault, txn, &own, &chosen)?
                }
                _ => false,
            };
            if !absorbed {
                crate::tagging::settle_mention_in_txn(vault, txn, &ask.turn, span, chosen)?;
            }
            chosen
        }
        Answer::SomeoneNew => {
            let fresh = match ask.provisional {
                Some(own) => own,
                None => crate::tagging::mint_for_span_in_txn(
                    vault, txn, ask.kind, &ask.name, ask.turn, now,
                )?,
            };
            crate::tagging::settle_mention_in_txn(vault, txn, &ask.turn, span, fresh)?;
            crate::tagging::confirm_provisional_in_txn(vault, txn, &fresh)?;
            assert_distinct_in_txn(vault, txn, ask, fresh, (source, seal), now)?;
            fresh
        }
    };
    put_hint_in_txn(vault, txn, ask, entity, now)?;
    evidence::record_in_txn(vault, txn, ask, entity, source, now, original)?;
    Ok(entity)
}

/// Settles an open ask and closes it.
pub(super) fn settle_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    ask: &IdentityAsk,
    answer: Answer,
    said: (ClaimSource, &TopologySeal),
    now: u64,
) -> Result<EntityId> {
    let entity = apply_in_txn(vault, txn, ask, answer, said, now)?;
    ASKS.delete(&vault.store, txn, key)?;
    Ok(entity)
}

/// One inbox Ask per owner, in the conversation of `turn`: a new row per
/// ask and turn, so a later mention surfaces it again.
pub(super) fn notify_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    turn: &EntityId,
    now: u64,
) -> Result<()> {
    let conversation = crate::conversation_dag::conversation_of(&vault.store, txn, turn).ok();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let ask = key_hex(key);
    for owner in owners {
        vault.record_notification_in_txn(
            txn,
            &crate::inbox::NotificationEvent {
                kind: crate::inbox::NotificationKind::Ask,
                source: crate::inbox::NotificationSource {
                    producer: IDENTITY_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{ask}:{}:{}", turn.to_hex(), owner.to_hex()),
                    result: Some(ask.clone()),
                    ..crate::inbox::NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(owner),
                created_at: now,
                origin_conversation: conversation,
            },
        )?;
    }
    Ok(())
}

/// Keeps the names separate for now (OF-023): a nightly decision that
/// abstained merges, confirms and asks nothing. The candidates and the
/// mention's provisional entity stay as they are; the ask stays open and
/// answerable, out of the due list until its candidates change. The
/// Dreamer's receipt and the prior ask let the owner revert it.
pub(super) fn keep_separate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    ask: IdentityAsk,
    now: u64,
) -> Result<()> {
    let kept = IdentityAsk {
        kept_separate_at: Some(now),
        ..ask.clone()
    };
    ASKS.put(&vault.store, txn, key, &kept)?;
    let source = erase::ask_anchor_in_txn(vault, txn, &ask)?;
    let actor = vault.dreamer_authority_in_txn(txn, now)?;
    super::super::applied::record_disposition_in_txn(
        vault,
        txn,
        *key,
        IDENTITY_RECHECK_FACET,
        actor,
        MaintenanceInverse::IdentityProvisional(Box::new(ProvisionalInverse {
            prior: Some(ask),
            source,
            kept_at: now,
        })),
        &kept,
        None,
        now,
    )
}

/// Sends an ask to the person: it waits on their answer from now on.
pub(super) fn escalate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    mut ask: IdentityAsk,
    now: u64,
) -> Result<()> {
    ask.escalated_at = Some(now);
    ask.surfaced_turn = Some(ask.turn);
    ASKS.put(&vault.store, txn, key, &ask)?;
    notify_in_txn(vault, txn, key, &ask.turn, now)
}
