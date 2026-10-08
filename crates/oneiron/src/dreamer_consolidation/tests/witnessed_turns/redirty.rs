//! A finalized continuation brings its consumed TURN back to consolidation
//! even where moving the TURN row cannot: behind a scope cursor that a later
//! TURN already advanced, and in a conversation that adopted the DAG, whose
//! TURN rows are append-only.
#![cfg(feature = "sync")]

use super::*;

/// The Micro dirty scan from the live cursor, as TURN ids in scan order.
fn dirty(vault: &Vault) -> Result<Vec<EntityId>> {
    let scope = DreamerConsolidationScope::Micro;
    let turns = scan_dirty_turns(vault, scope, &read_watermark(vault, scope)?, 10)?;
    Ok(turns.into_iter().map(|turn| turn.turn_id).collect())
}

/// Queues the dirty round, then settles the Micro cursor on its last TURN, as
/// a consumed round leaves it: the round's attempt.
fn consume(vault: &Vault) -> Result<AttemptId> {
    let scope = DreamerConsolidationScope::Micro;
    let attempt = queue_micro(vault)?;
    let round = scan_dirty_turns(vault, scope, &read_watermark(vault, scope)?, 10)?;
    advance_watermark_to_turn(vault, scope, round.last().expect("a round to consume"))?;
    assert!(dirty(vault)?.is_empty(), "the round consumed every turn");
    Ok(attempt)
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
