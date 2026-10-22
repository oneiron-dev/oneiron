//! Witness provenance checks and the overlay landing's receipt.
//! `validate_witness_origin` and `validate_container_provenance` are its call surface.
//! `memory::witness::program` defines the plan types; `witness::validation` has the turn checks.

use super::*;

/// Imported and witnessed speech never share a container. An imported turn
/// lands only in a conversation and a turn of its own source: their ids derive
/// from public source ids, so a plain writer could claim one first, and
/// imported rows appended there would read as live words. A witnessed turn
/// never lands in an imported conversation or turn, where the Dreamer would
/// read live words as imported evidence. `source` is the landing's import
/// source, `None` for a witnessed turn.
pub(super) fn validate_container_provenance(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    source: Option<&str>,
    conversation_id: &EntityId,
    existing_turn: Option<&EntityRecord>,
) -> MemoryResult<()> {
    let expected = source.map_or(ImportStamp::Live, |source| {
        ImportStamp::Imported(source.to_owned())
    });
    let matches = |body: &[u8]| import_stamp(body) == expected;
    let refusal = |container: &str| {
        MemoryError::bad_request(match source {
            Some(_) => {
                format!("an imported turn joins only a {container} imported from the same source")
            }
            None => format!("a witnessed turn does not join an imported {container}"),
        })
    };
    if let Some(conversation) = dbs.port_entity_record(txn, conversation_id)?
        && !matches(&conversation.body)
    {
        return Err(refusal("conversation"));
    }
    if existing_turn.is_some_and(|turn| !matches(&turn.body)) {
        return Err(refusal("turn"));
    }
    Ok(())
}

/// A receipt type is host-owned, not an extra vocabulary choice for callers.
pub(super) fn validate_witness_origin(turn: &WitnessTurn, host_executor: bool) -> MemoryResult<()> {
    if !host_executor
        && turn.messages.iter().any(|message| {
            message.message_type == crate::code_run::blocked::BLOCKED_REPORT_MESSAGE_TYPE
        })
    {
        return Err(MemoryError::bad_request(
            "report-blocked receipts require the executor door",
        ));
    }
    // A result attachment names a body its MESSAGE holds (FIX 365): only the
    // executor writes one, and only one that decodes whole.
    for message in &turn.messages {
        let reserved = message
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.get(MESSAGE_RESULT_METADATA_KEY).is_some());
        if !reserved {
            continue;
        }
        if !host_executor {
            return Err(MemoryError::bad_request(
                "a result attachment requires the executor door",
            ));
        }
        MessageResultAttachment::from_metadata(message.metadata.as_ref())
            .map_err(MemoryError::bad_request)?;
    }
    Ok(())
}

/// The overlay receipt carries SESSION-LOCAL short ids: in-room aliases are
/// temporary presentation handles, and canonical ids are allocated at promote
/// (ONE-1730). `aliases` runs turn, messages, then the summary.
pub(super) fn overlay_receipt(
    plan: &WitnessPlan<'_>,
    aliases: Vec<(String, u8)>,
) -> MemoryResult<WitnessReceipt> {
    let mut aliases = aliases.into_iter();
    let turn_short_id = session_short_ref_string(&aliases.next().ok_or(
        Error::InvariantViolation("session witness allocated no turn alias"),
    )?);
    let message_short_ids = aliases
        .by_ref()
        .take(plan.messages.len())
        .map(|alias| session_short_ref_string(&alias))
        .collect();
    Ok(WitnessReceipt {
        turn_short_id,
        message_short_ids,
        receipt_ref: format!("witness:{}", plan.turn_id.to_hex()),
        // Off-record rows are no vault records until promoted: no ref names
        // them.
        turn: None,
        messages: Vec::new(),
    })
}
