//! A new message's terminal: its witness, with a Retry proven again in the same write.

use super::*;

/// The new MESSAGE's write: the witness program lands its turn, a Retry's
/// proof prepares it, and its receipt is finished in the same transaction.
#[expect(
    clippy::too_many_arguments,
    reason = "the new message's write joins its turn, its retry proof and its gates"
)]
pub(super) fn write_new_message_terminal(
    vault: &Vault,
    seed: &Seed,
    memory: &Memory<'_>,
    turn: &crate::memory::WitnessTurn,
    gate: TerminalGate<'_>,
    callback: Callback,
    refused: &std::cell::Cell<bool>,
    receipt: &mut MessageStreamReceipt,
) -> MessageStreamResult<()> {
    // A Retry's reads take their own snapshots, so they open before the
    // writer does.
    match seed
        .action
        .as_ref()
        .map(|action| memory.retry_lanes(action))
        .transpose()
    {
        Err(error) => {
            refused.set(true);
            Err(error.into())
        }
        Ok(lanes) => {
            let claimed = std::cell::Cell::new(None);
            let landed = memory.witness_with_route_prepare_and_txn_effect(
                turn,
                None,
                callback,
                || {},
                |txn| {
                    prepare_retry_in_txn(
                        vault,
                        memory,
                        seed,
                        lanes.as_ref(),
                        gate,
                        refused,
                        &claimed,
                        txn,
                    )
                },
                |txn| -> MemoryResult<()> {
                    // The new MESSAGE keeps its words inline: its document
                    // is born at its first later edit (FIX 4840).
                    if let Some(source) = seed.regenerates {
                        // The kind's creation is this stream's alone (FIX
                        // 5972), its pair proven above in this transaction:
                        // the internal write lands it at the public put's
                        // weight, neutral VAD, no flags and clock.
                        let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
                        vault
                            .batch_in()
                            .edge_with_value_fields(
                                &seed.message_id,
                                crate::edge::EdgeKind::Regenerates,
                                &source,
                                crate::batch::EdgeValueFields {
                                    weight: 1.0,
                                    created_at,
                                    vad: oneiron_contracts::affect::Vad::NEUTRAL,
                                    provenance: None,
                                },
                            )
                            .apply(txn)?;
                    }
                    // The turn's set, seed and terminal, was admitted in
                    // this write: its receipt keeps it (FIX 10260).
                    receipt.reply_assertions =
                        admitted_in_txn(&vault.store, txn, &[&turn.assertions])?;
                    storage::finish(vault, txn, seed, receipt)?;
                    Ok(())
                },
            );
            // FIX 1794: the claim a Retry took on its parent, and the facts
            // it recorded, reach the live windows that carry them
            // (HOMERETRY-AUTHORITY = C).
            #[cfg(feature = "sync")]
            if landed.is_ok()
                && let Some(parent) = claimed.get()
            {
                vault.refresh_room_turn_facts_in_live_windows(parent);
            }
            landed.map(|_| ()).map_err(MessageStreamError::from)
        }
    }
}

/// A Retry's reply names the reply it answers again, and the Retry is proven
/// again, in the transaction that writes it: its TURN lands here, or its room
/// regeneration permit admits its room row. `claimed` takes the parent whose
/// claim the Retry took in this write.
#[expect(
    clippy::too_many_arguments,
    reason = "the Retry's proof joins its seed, its reads, its gate and what its write took"
)]
fn prepare_retry_in_txn(
    vault: &Vault,
    memory: &Memory<'_>,
    seed: &Seed,
    lanes: Option<&(crate::claim::ScopedRead<'_>, crate::claim::ScopedRead<'_>)>,
    gate: TerminalGate<'_>,
    refused: &std::cell::Cell<bool>,
    claimed: &std::cell::Cell<Option<crate::EntityId>>,
    txn: &mut heed::RwTxn<'_>,
) -> MemoryResult<Option<crate::workspace_roster::RoomRegenerationPermit>> {
    admit_terminal(gate, txn)?;
    let retry = match admission::validate_regeneration(vault, txn, seed) {
        Err(error) => Err(crate::memory::MemoryError::bad_request(error.to_string())),
        Ok(()) => match (&seed.action, lanes) {
            (Some(action), Some((writer, requester))) => memory.prepare_action_retry_in_txn(
                txn,
                action,
                seed.turn,
                seed.occurred_at,
                writer,
                requester,
            ),
            _ => Ok(None),
        },
    };
    if retry.is_err() && seed.action.is_some() {
        refused.set(true);
    }
    if let Ok(Some(permit)) = &retry {
        claimed.set(permit.took_claim());
    }
    retry
}
