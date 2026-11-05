//! Whole annotation transcripts and capped dispatch briefings.
//!
//! Returned holds keep their pre-allocation booking with the caller through
//! assignment and dispatch.

use super::super::model::{AnnotationComment, AnnotationThread};
use crate::context_projection::CONTEXT_SPEC_MAX_TEXT_BYTES;
use crate::error::{Error, Result};
use crate::office_body::machine_memory_refused;
use oneiron_docedit::resource::{Hold, Resources};

/// Joins the whole transcript, admitting its exact UTF-8 bytes first.
/// The caller grows the same hold for later owned copies.
pub(super) fn thread_transcript(
    comments: &[AnnotationComment],
    resources: &Resources,
) -> Result<(Hold, String)> {
    let mut total: u128 = 0;
    for comment in comments {
        total += comment.text.len() as u128;
    }
    total += comments.len().saturating_sub(1) as u128;
    let hold = resources
        .reserve(u64::try_from(total).unwrap_or(u64::MAX))
        .map_err(machine_memory_refused)?;
    let capacity = usize::try_from(total).map_err(|_| {
        Error::from(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "thread transcript capacity overflow",
        ))
    })?;
    let mut out = String::new();
    out.try_reserve_exact(capacity).map_err(|_| {
        Error::from(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "thread transcript allocation failed",
        ))
    })?;
    for (index, comment) in comments.iter().enumerate() {
        if index != 0 {
            out.push('\n');
        }
        out.push_str(comment.text.as_str());
    }
    Ok((hold, out))
}

/// Builds the same capped UTF-8 prefix without materializing the discarded tail.
/// The small header allocation stays outside the returned booking.
pub(super) fn agent_briefing(
    thread: &AnnotationThread,
    brief_ref: &str,
    thread_text: &str,
    resources: &Resources,
) -> Result<(Hold, String)> {
    let mut header = format!(
        "Annotation thread {} on artifact {}@{} was assigned to you as {brief_ref}. The thread:\n",
        thread.thread_id.to_hex(),
        thread.anchor.artifact_id.to_hex(),
        thread.anchor.version,
    );
    if header.len() > CONTEXT_SPEC_MAX_TEXT_BYTES {
        header.truncate(header.floor_char_boundary(CONTEXT_SPEC_MAX_TEXT_BYTES));
        let hold = resources.reserve(0).map_err(machine_memory_refused)?;
        return Ok((hold, header));
    }
    let available = CONTEXT_SPEC_MAX_TEXT_BYTES.saturating_sub(header.len());
    let prefix = &thread_text[..thread_text.floor_char_boundary(available)];
    let hold = resources
        .reserve(u64::try_from(prefix.len()).unwrap_or(u64::MAX))
        .map_err(machine_memory_refused)?;
    header.try_reserve_exact(prefix.len()).map_err(|_| {
        Error::from(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "briefing allocation failed",
        ))
    })?;
    header.push_str(prefix);
    Ok((hold, header))
}
