//! The model-only view of a stored program; execution always reads its original bytes.

use super::{clean_for_context, decode_text_output};
use crate::code_run::{CODE_RUN_OUTPUT_PREVIEW_WITHHELD, CodeRunReplayRecord, ExecutorStorage};
use crate::store::known_value_index::handle_text;
use crate::{Error, Result};

/// Masks known custody values after the existing taint check. A bounded view
/// reads only its raw prefix and holds back an unfinished match at that edge.
pub(in crate::engine_executor) fn load_script_context(
    storage: &ExecutorStorage<'_>,
    record: &CodeRunReplayRecord,
    path: &str,
    cap: Option<usize>,
) -> Result<String> {
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex("executor replay output path"))?;
    if !clean_for_context(storage, Some(record.run_id), output)? {
        return Ok(CODE_RUN_OUTPUT_PREVIEW_WITHHELD.to_owned());
    }
    let prefix = cap.filter(|cap| output.raw_len > *cap as u64);
    let raw = match prefix {
        Some(cap) => storage.read_code_run_raw_output_range(output, 0, cap)?,
        None => storage.get_code_run_raw_output(output)?,
    }
    .ok_or(Error::CorruptedIndex("executor replay output bytes"))?;
    // Complete reads still reject corrupt original UTF-8, even if a mask
    // would hide it. The already-truncated window keeps its lossy rendering.
    let raw = if prefix.is_none() {
        decode_text_output(raw)?.into_bytes()
    } else {
        raw
    };
    let (text, consumed) = masked_prefix(storage, &raw, prefix.is_none(), cap)?;
    if prefix.is_none() && consumed == raw.len() {
        return Ok(text);
    }
    // Count original bytes consumed, not the expanded handle text's length.
    Ok(format!(
        "{}\n[the first {} of {} bytes; the whole result is stored as output:blake3:{}:{}]",
        text,
        consumed,
        output.raw_len,
        crate::entity_id::bytes_to_hex_lower(&output.raw_blake3),
        output.raw_len,
    ))
}

/// `text` with every known custody value replaced by its handle, as a model
/// view of a stored program shows it.
pub(in crate::engine_executor) fn mask_known_text(
    storage: &ExecutorStorage<'_>,
    text: &str,
) -> Result<String> {
    masked_prefix(storage, text.as_bytes(), true, None).map(|(text, _)| text)
}

fn masked_prefix(
    storage: &ExecutorStorage<'_>,
    raw: &[u8],
    complete: bool,
    cap: Option<usize>,
) -> Result<(String, usize)> {
    let source = match storage {
        ExecutorStorage::Canonical(vault) => vault.known_source()?,
        ExecutorStorage::Session(binding) => binding.answered(|| binding.session.known_source())?,
    };
    let original = || (String::from_utf8_lossy(raw).into_owned(), raw.len());
    let Some(source) = source else {
        return Ok(original());
    };
    source.pass(|known| {
        let Some(known) = known else {
            return original();
        };
        // KnownSweep's stable-prefix rule: a match starting before the limit
        // is replaced whole; the tail that might finish beyond it stays out.
        let limit = if complete {
            raw.len()
        } else {
            raw.len().saturating_sub(known.reach().saturating_sub(1))
        };
        let mut masked = Vec::with_capacity(raw.len());
        let remaining = |len: usize| cap.map_or(usize::MAX, |cap| cap.saturating_sub(len));
        let rendered =
            |bytes: Vec<u8>, consumed| (String::from_utf8_lossy(&bytes).into_owned(), consumed);
        let mut from = 0;
        for hit in known.spans(raw) {
            if hit.span.start >= limit {
                break;
            }
            let keep = (hit.span.start - from).min(remaining(masked.len()));
            masked.extend_from_slice(&raw[from..from + keep]);
            from += keep;
            let handle = handle_text(hit.handle);
            // Reuse the window cap after replacement expansion too. Stop
            // before a value whose complete handle would not fit.
            if from < hit.span.start || handle.len() > remaining(masked.len()) {
                return rendered(masked, from);
            }
            masked.extend_from_slice(handle.as_bytes());
            from = hit.span.end;
        }
        let end = from.max(limit);
        let consumed = from + (end - from).min(remaining(masked.len()));
        masked.extend_from_slice(&raw[from..consumed]);
        // A custody value may be arbitrary bytes within a UTF-8 code point.
        // Render the masked bytes, never fail a valid original program for it.
        rendered(masked, consumed)
    })
}
