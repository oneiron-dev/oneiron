//! A finalized continuation brings its consumed TURN back to consolidation
//! even where moving the TURN row cannot: behind a scope cursor that a later
//! TURN already advanced, and in a conversation that adopted the DAG, whose
//! TURN rows are append-only. A TURN changed again in the second it was
//! learned is planned by a session end in that same second, and settling it
//! strands no TURN learned after it. A consumed continuation hides no later
//! re-put of its TURN, comes back on an operator's full rescan, and settles
//! through the public complete-second door, which consumes only the carriers
//! its round was selected at: a re-put past the settled second, and a newer
//! continuation finalized in that same second, stay dirty.
#![cfg(feature = "sync")]

use super::*;

/// The Micro dirty round from the live cursor, in scan order.
fn round(vault: &Vault) -> Result<Vec<WorkingSetTurn>> {
    let scope = DreamerConsolidationScope::Micro;
    scan_dirty_turns(vault, scope, &read_watermark(vault, scope)?, 10)
}

/// [`round`] as TURN ids.
fn dirty(vault: &Vault) -> Result<Vec<EntityId>> {
    Ok(round(vault)?.into_iter().map(|turn| turn.turn_id).collect())
}

/// Queues the dirty round, then settles the Micro cursor on its last TURN, as
/// a consumed round leaves it: the round's attempt.
fn consume(vault: &Vault) -> Result<AttemptId> {
    let scope = DreamerConsolidationScope::Micro;
    let attempt = queue_micro(vault)?;
    let round = round(vault)?;
    advance_watermark_to_turn(vault, scope, round.last().expect("a round to consume"))?;
    assert!(dirty(vault)?.is_empty(), "the round consumed every turn");
    Ok(attempt)
}

/// The Meso dirty scan from the live cursor: the scope session ends settle.
fn meso_dirty(vault: &Vault) -> Result<Vec<EntityId>> {
    let scope = DreamerConsolidationScope::Meso;
    let turns = scan_dirty_turns(vault, scope, &read_watermark(vault, scope)?, 10)?;
    Ok(turns.into_iter().map(|turn| turn.turn_id).collect())
}

/// How many queued Meso partition rounds name `turn`.
fn meso_rounds_of(vault: &Vault, turn: EntityId) -> Result<usize> {
    let mut rounds = 0;
    for attempt in crate::attempt_queue::AttemptQueue::new(vault).list()? {
        if attempt.kind != crate::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND {
            continue;
        }
        let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&attempt.payload)?;
        if payload.attempt_type != DreamerConsolidationScope::Meso.as_str() {
            continue;
        }
        let (_, turns, _) = decode_partition_payload(&payload.input)?;
        rounds += usize::from(turns.contains(&turn));
    }
    Ok(rounds)
}

fn open_session(vault: &Vault, now: u64) -> Result<EntityId> {
    match vault.mint_session(now)? {
        crate::SessionMintOutcome::Minted(session) => Ok(session),
        other => panic!("{other:?}"),
    }
}

/// Ends `session` at `now` through the production session-end wake (plan,
/// then the fenced enqueue and Meso settlement), then opens the next one.
fn close_session(vault: &Vault, session: EntityId, now: u64) -> Result<EntityId> {
    let wake = vault.plan_session_end_wake()?;
    let explicit = crate::SessionClosePredicate::Explicit;
    let ended = vault.end_session_with_wake(&session, explicit, now, &wake)?;
    assert!(ended.is_some(), "the open session ends");
    open_session(vault, now)
}

/// What a branch of `attempt` reads of `turn`.
fn transcript(
    vault: &Vault,
    conversation: EntityId,
    turn: EntityId,
    attempt: AttemptId,
) -> Result<String> {
    let branch = BranchResources::open(
        vault,
        vault.dreamer_authority()?,
        partition_of(conversation),
        &[turn],
        attempt,
        None,
    )?;
    branch.transcript(branch.scope(), &[turn])
}

/// A continuation that reuses its turn's original input (occurrence 10) after
/// a later turn (occurrence 20) moved the cursor past it: the next scan
/// selects the turn again, its round is a new attempt, and the branch reads
/// the appended words.
#[test]
fn a_continuation_behind_a_later_consumed_turn_is_selected_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, conversation, _, input) = stream_turn(&vault, 0x91, "call me", "finalize")?;
    let writer = EntityId::from_bytes([0x91; 16])?;
    let later = EntityId::now();
    vault
        .memory(writer, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(later.to_hex()),
            messages: vec![message(0, WitnessAuthor::User, "the weather is fine", true)],
            occurred_at: 20,
        })
        .expect("a later turn");
    assert_eq!(dirty(&vault)?, vec![turn, later], "both turns are dirty");
    let consumed = consume(&vault)?;
    end_stream(&vault, writer, &input, " Oleksii", "finalize");
    assert_eq!(dirty(&vault)?, vec![turn], "the continued turn comes back");
    let again = queue_micro(&vault)?;
    assert_ne!(again, consumed, "the new words get a new attempt");
    assert_eq!(
        transcript(&vault, conversation, turn, again)?,
        format!("[{} user] call me Oleksii\n", turn.to_hex())
    );
    Ok(())
}

/// A consumed turn whose conversation a normal read adopted into the DAG: a
/// finalized continuation leaves the append-only TURN row byte-identical, and
/// the next scan still selects the turn, as a new attempt over the new words.
#[test]
fn a_continuation_in_an_adopted_dag_conversation_is_selected_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, conversation, _, input) = stream_turn(&vault, 0x93, "call me", "finalize")?;
    let consumed = consume(&vault)?;
    let head = vault.head(&conversation)?;
    assert_eq!(head, Some(turn), "a read adopts the DAG");
    let row = vault.get_raw(&turn)?;
    end_stream(
        &vault,
        EntityId::from_bytes([0x93; 16])?,
        &input,
        " Oleksii",
        "finalize",
    );
    assert_eq!(vault.get_raw(&turn)?, row, "the TURN row is append-only");
    assert_eq!(dirty(&vault)?, vec![turn], "the continued turn comes back");
    let again = queue_micro(&vault)?;
    assert_ne!(again, consumed, "the new words get a new attempt");
    assert_eq!(
        transcript(&vault, conversation, turn, again)?,
        format!("[{} user] call me Oleksii\n", turn.to_hex())
    );
    Ok(())
}

/// A turn changed twice more in the very second it was learned, with the clock
/// never moving: each session end in that second plans the turn again as a new
/// Meso round, and a turn witnessed afterwards in that same second, under a
/// default id, is still selected after the last of them.
#[test]
fn a_same_second_continuation_is_planned_by_its_close_and_strands_no_new_turn() -> Result<()> {
    let (_dir, vault, _clock) = open_clocked_vault();
    let now = 50;
    let mut session = open_session(&vault, now)?;
    let writer = EntityId::from_bytes([0x95; 16])?;
    vault.put_entity(
        &writer,
        ENTITY_TYPE_PERSON,
        occurred(1),
        1,
        b"stream writer",
    )?;
    crate::test_util::bind_test_owner(&vault, writer);
    let conversation = EntityId::from_bytes([0x96; 16])?;
    let turn = EntityId::now();
    let input = WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: Some(turn.to_hex()),
        messages: vec![message(0, WitnessAuthor::User, "", true)],
        occurred_at: now,
    };
    end_stream(&vault, writer, &input, "call me", "finalize");
    for (round, words) in [(1, " Oleksii"), (2, " please"), (3, "")] {
        session = close_session(&vault, session, now)?;
        assert_eq!(
            meso_rounds_of(&vault, turn)?,
            round,
            "the close at the same second planned the turn as a new round"
        );
        assert!(meso_dirty(&vault)?.is_empty(), "the close consumed it");
        if !words.is_empty() {
            end_stream(&vault, writer, &input, words, "finalize");
        }
    }
    let later = EntityId::now();
    vault
        .memory(writer, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(later.to_hex()),
            messages: vec![message(0, WitnessAuthor::User, "the weather is fine", true)],
            occurred_at: now,
        })
        .expect("a new turn in the same second");
    assert_eq!(
        meso_dirty(&vault)?,
        vec![later],
        "the new turn is not stranded"
    );
    Ok(())
}

/// A consumed continuation hides no later work on its TURN: a generic re-put
/// of the row at a later occurrence, ahead of the cursor but before the
/// continuation's second, is selected again on its own key.
#[test]
fn a_re_put_after_a_consumed_continuation_is_selected_again() -> Result<()> {
    let (_dir, vault, _clock) = open_clocked_vault();
    let (turn, _, _, input) = stream_turn(&vault, 0x97, "call me", "finalize")?;
    let writer = EntityId::from_bytes([0x97; 16])?;
    consume(&vault)?;
    end_stream(&vault, writer, &input, " Oleksii", "finalize");
    assert_eq!(dirty(&vault)?, vec![turn], "the continued turn comes back");
    consume(&vault)?;
    let row = vault.get_raw(&turn)?.expect("the turn row");
    vault.put_entity(
        &turn,
        crate::registry::ENTITY_TYPE_TURN,
        occurred(20),
        20,
        &row[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    assert_eq!(dirty(&vault)?, vec![turn], "the re-put is new work");
    Ok(())
}

/// An operator's full rescan reopens a TURN whose continuation a round
/// already consumed, and the public complete-second settlement through the
/// continuation's second consumes it again.
#[test]
fn a_consumed_continuation_comes_back_on_a_full_rescan_and_settles_by_second() -> Result<()> {
    let (_dir, vault, _clock) = open_clocked_vault();
    let (turn, _, _, input) = stream_turn(&vault, 0x99, "call me", "finalize")?;
    let writer = EntityId::from_bytes([0x99; 16])?;
    consume(&vault)?;
    end_stream(&vault, writer, &input, " Oleksii", "finalize");
    consume(&vault)?;
    let scope = DreamerConsolidationScope::Micro;
    crate::dreamer_prefilter::reopen_prefilter_rescan(&vault, scope, 0)?;
    let reopened = round(&vault)?;
    assert_eq!(
        reopened.iter().map(|turn| turn.turn_id).collect::<Vec<_>>(),
        vec![turn],
        "a full rescan reopens every turn"
    );
    crate::dreamer_consolidation::advance_watermark(&vault, scope, 50, &reopened)?;
    assert!(
        dirty(&vault)?.is_empty(),
        "settling through its second consumes it"
    );
    Ok(())
}

/// A host settles a carried round through the public complete-second door
/// after a later re-put of its TURN: the settlement completes the carrier's
/// second, not the re-put above it, which the next scan selects.
#[test]
fn a_public_settlement_leaves_a_later_re_put_dirty() -> Result<()> {
    let (_dir, vault, clock) = open_clocked_vault();
    let (turn, _, _, input) = stream_turn(&vault, 0x9B, "call me", "finalize")?;
    let writer = EntityId::from_bytes([0x9B; 16])?;
    consume(&vault)?;
    end_stream(&vault, writer, &input, " Oleksii", "finalize");
    let queued = round(&vault)?;
    queue_micro(&vault)?;
    clock.set(60);
    let row = vault.get_raw(&turn)?.expect("the turn row");
    vault.put_entity(
        &turn,
        crate::registry::ENTITY_TYPE_TURN,
        occurred(60),
        60,
        &row[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    let scope = DreamerConsolidationScope::Micro;
    crate::dreamer_consolidation::advance_watermark(&vault, scope, 50, &queued)?;
    assert_eq!(
        dirty(&vault)?,
        vec![turn],
        "the re-put past the settled second is new work"
    );
    Ok(())
}

/// A host queues a carried round at second 50, another continuation of the
/// same TURN finalizes in that same second, and the host then settles its
/// round through 50 at the public complete-second door: the settlement
/// consumes the carrier the round was selected at, never its replacement,
/// which the next scan selects with the newer words.
#[test]
fn a_public_settlement_leaves_a_same_second_replacement_pending() -> Result<()> {
    let (_dir, vault, _clock) = open_clocked_vault();
    let (turn, _, _, input) = stream_turn(&vault, 0x9D, "call me", "finalize")?;
    let writer = EntityId::from_bytes([0x9D; 16])?;
    consume(&vault)?;
    end_stream(&vault, writer, &input, " Oleksii", "finalize");
    let queued = round(&vault)?;
    let attempt = queue_micro(&vault)?;
    end_stream(&vault, writer, &input, " please", "finalize");
    let scope = DreamerConsolidationScope::Micro;
    crate::dreamer_consolidation::advance_watermark(&vault, scope, 50, &queued)?;
    assert_eq!(
        dirty(&vault)?,
        vec![turn],
        "the replacement continuation is still pending"
    );
    assert_ne!(
        queue_micro(&vault)?,
        attempt,
        "the newer words get a new attempt"
    );
    Ok(())
}
