//! The summary reply's parse and the sources' version-pin readers, shared by
//! the compose arm and the serve-time checks.

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SummaryOutput {
    pub(super) text: String,
    pub(super) keep: String,
}

/// The reply's summary, or the static reason it is none: its text parts
/// parse as [`SummaryOutput`] and the summary text is not blank. The step's
/// check and the landing both read the reply through this one parse.
pub(super) fn summary_output(
    response: &LlmResponse,
) -> std::result::Result<SummaryOutput, &'static str> {
    let body = output::reply_text(response);
    let output: SummaryOutput = serde_json::from_str(body.trim())
        .map_err(|_| "the model wrote an invalid summary/keep result")?;
    if output.text.trim().is_empty() {
        return Err("the model wrote an empty summary");
    }
    Ok(output)
}

/// The summary step's reply check: a reply [`summary_output`] refuses is
/// refused inside the step, paid and never memoized.
pub(super) fn check_summary_reply(response: &LlmResponse) -> std::result::Result<(), String> {
    summary_output(response).map(drop).map_err(str::to_owned)
}

/// The version pins of `sources` as the Dreamer reads them in `txn` (FIX
/// 10092); `None` once one of them is gone or the Dreamer does not read it.
pub(crate) fn editor_source_pins_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> Result<Option<Vec<SummarySourceVersion>>> {
    let rows = dreamer_read(vault)?.get_entities_parts_in_txn(txn, sources)?;
    let mut pins = Vec::with_capacity(sources.len());
    for (source, row) in sources.iter().zip(rows) {
        let Some(row) = row else {
            return Ok(None);
        };
        pins.push(source_pin(vault, txn, *source, Some(&row))?);
    }
    Ok(Some(pins))
}

/// A NOTE as a summary reads it (FIX 907, 6321): the Dreamer's one NOTE
/// projection of `body`, and the pin of it a summary's body holds, its
/// stored revision and the projection's fingerprint. `None` when the
/// Dreamer does not read it as a source.
pub(super) fn note_read_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<(SummarySourceNote, NoteText)>> {
    Ok(
        super::super::note_text::note_text_in(vault, txn, id, body)?.map(|note| {
            let pin = SummarySourceNote {
                id: *id,
                revision: super::super::swarm_evidence_content_hash(body),
                projected_text: note.fingerprint,
            };
            (pin, note)
        }),
    )
}

/// Each of `notes` as a summary's evidence would pin it now, through the
/// Dreamer's own read and NOTE projection (FIX 6321): `None` for one the
/// Dreamer does not read as a source. A NOTE set's summary is checked
/// against these at every serve.
pub(crate) fn note_source_pins_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    notes: &[EntityId],
) -> Result<Vec<Option<SummarySourceNote>>> {
    let read = dreamer_read(vault)?;
    let rows = read.get_entities_parts_in_txn(txn, notes)?;
    let mut pins = Vec::with_capacity(notes.len());
    for (note, row) in notes.iter().zip(rows) {
        pins.push(match row {
            Some((ENTITY_TYPE_NOTE, _, body)) => {
                note_read_in(vault, txn, note, &body)?.map(|(pin, _)| pin)
            }
            _ => None,
        });
    }
    Ok(pins)
}

/// Reads through the Dreamer's own scoped read, including every child of a
/// witnessed turn. It is also the landing fence, under the landing writer.
/// Every record shows under a call-local label (FIX 7574), each TURN a `T`
/// and each NOTE an `N`, in source order: a sitting's lines cite those.
/// A sitting's TURNs (`keep_turns`, FIX 7509) are kept as read for paging.
pub(crate) fn scope_summary_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
    keep_turns: bool,
) -> Result<ScopeSummaryEvidence> {
    evidence_in_txn(vault, txn, sources, keep_turns, false)
}
