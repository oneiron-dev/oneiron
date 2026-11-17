//! Whole-row paging and request-bound pins for extraction observations.

use serde::Serialize;

use super::types::{
    ExtractionObservationsPage, ExtractionObservationsPageRequest, ObservationFacts,
};
use crate::memory::{MemoryError, MemoryResult};

/// One ordered section of the complete observations read.
#[derive(Clone, Copy)]
enum ObservationSection {
    /// The candidate operand facts.
    Candidates,
    /// The admitted prior facts.
    Priors,
    /// The separate unlisted provisional cohorts.
    Replay,
    /// The stored-vector pair scores.
    Scores,
}

impl ObservationSection {
    /// Returns the section's stable cursor spelling.
    fn as_str(self) -> &'static str {
        match self {
            Self::Candidates => "candidates",
            Self::Priors => "priors",
            Self::Replay => "replay",
            Self::Scores => "scores",
        }
    }

    /// Returns the following section, or none after the scores.
    fn following(self) -> Option<Self> {
        match self {
            Self::Candidates => Some(Self::Priors),
            Self::Priors => Some(Self::Replay),
            Self::Replay => Some(Self::Scores),
            Self::Scores => None,
        }
    }

    /// Returns the number of complete rows in this section.
    fn len(self, facts: &ObservationFacts) -> usize {
        match self {
            Self::Candidates => facts.candidates.len(),
            Self::Priors => facts.priors.len(),
            Self::Replay => facts.replay.len(),
            Self::Scores => facts.scores.len(),
        }
    }
}

/// Pins the attempt, host clock, unchanged operands, policy and complete fact set.
pub(super) fn observation_facts_pin(
    input: &ExtractionObservationsPageRequest,
    policy_pin: &str,
    facts: &ObservationFacts,
) -> MemoryResult<String> {
    let encoded = serde_json::to_vec(&(
        &input.attempt,
        input.now_ms,
        &input.candidates,
        policy_pin,
        facts,
    ))
    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:extraction:observations-facts:v1");
    hash.update(&[0]);
    hash.update(&encoded);
    Ok(hash.finalize().to_hex().to_string())
}

/// Cuts a whole-row page across ordered sections under the effective bounds.
pub(super) fn page_observation_facts(
    input: &ExtractionObservationsPageRequest,
    policy_pin: String,
    facts_pin: String,
    facts: ObservationFacts,
    row_bound: u32,
    byte_bound: u64,
) -> MemoryResult<ExtractionObservationsPage> {
    let (mut section, mut offset) = match input.cursor.as_deref() {
        Some(cursor) => {
            let (section, offset, pin) = observation_cursor(cursor)?;
            if pin != facts_pin {
                return Err(MemoryError::bad_request(
                    "stale extraction observations cursor",
                ));
            }
            if offset >= section.len(&facts) {
                return Err(MemoryError::bad_request(
                    "invalid extraction observations offset",
                ));
            }
            (section, offset)
        }
        None => (ObservationSection::Candidates, 0),
    };
    let limit = input.limit.unwrap_or(row_bound).min(row_bound).max(1);
    let mut page = ExtractionObservationsPage {
        attempt: input.attempt.clone(),
        now_ms: input.now_ms,
        policy_pin,
        facts_pin,
        candidates: Vec::new(),
        priors: Vec::new(),
        replay: Vec::new(),
        scores: Vec::new(),
        next: None,
    };
    let mut rows = 0u32;
    let mut bytes = 0u64;
    loop {
        if offset == section.len(&facts) {
            match section.following() {
                Some(following) => {
                    section = following;
                    offset = 0;
                    continue;
                }
                None => break,
            }
        }
        let size = match section {
            ObservationSection::Candidates => encoded_row_size(&facts.candidates[offset])?,
            ObservationSection::Priors => encoded_row_size(&facts.priors[offset])?,
            ObservationSection::Replay => encoded_row_size(&facts.replay[offset])?,
            ObservationSection::Scores => encoded_row_size(&facts.scores[offset])?,
        };
        if rows == 0 && size > byte_bound {
            return Err(MemoryError::bad_request(
                "the snapshot page byte bound cannot hold the extraction observation row",
            ));
        }
        if rows >= limit || bytes.saturating_add(size) > byte_bound {
            page.next = Some(format!(
                "extraction-observations:v1:{}:{offset}:{}",
                section.as_str(),
                page.facts_pin,
            ));
            break;
        }
        match section {
            ObservationSection::Candidates => {
                page.candidates.push(facts.candidates[offset].clone())
            }
            ObservationSection::Priors => page.priors.push(facts.priors[offset].clone()),
            ObservationSection::Replay => page.replay.push(facts.replay[offset].clone()),
            ObservationSection::Scores => page.scores.push(facts.scores[offset].clone()),
        }
        rows += 1;
        bytes = bytes.saturating_add(size);
        offset += 1;
    }
    Ok(page)
}

/// Measures only the encoded row, as the existing extraction inputs page does.
fn encoded_row_size(row: &impl Serialize) -> MemoryResult<u64> {
    serde_json::to_vec(row)
        .map(|encoded| encoded.len() as u64)
        .map_err(|error| MemoryError::bad_request(error.to_string()))
}

/// Decodes a section, canonical offset and fact pin without admitting another spelling.
fn observation_cursor(cursor: &str) -> MemoryResult<(ObservationSection, usize, &str)> {
    let invalid = || MemoryError::bad_request("invalid extraction observations cursor");
    let suffix = cursor
        .strip_prefix("extraction-observations:v1:")
        .ok_or_else(invalid)?;
    let mut parts = suffix.split(':');
    let section = match parts.next() {
        Some("candidates") => ObservationSection::Candidates,
        Some("priors") => ObservationSection::Priors,
        Some("replay") => ObservationSection::Replay,
        Some("scores") => ObservationSection::Scores,
        _ => return Err(invalid()),
    };
    let text = parts.next().ok_or_else(invalid)?;
    let offset = text.parse::<usize>().map_err(|_| invalid())?;
    let pin = parts.next().ok_or_else(invalid)?;
    if text != offset.to_string()
        || pin.len() != 64
        || !pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || parts.next().is_some()
    {
        return Err(invalid());
    }
    Ok((section, offset, pin))
}
