//! The resident-dreaming candidate inlet (OF-490): a resident's own dreaming
//! proposes craft notes about itself — "diary entries, plus actor.lesson and
//! actor.failure_mode candidates, admitted like any other write"
//! (agent-mind design, ARCH-0053 §9).
//!
//! A candidate lands **Proposed**, so it is a proposal and not learned truth:
//! every reader that serves or scores an `actor.*` row (`claim_surfaceable`,
//! the writer's head reads, the resident pack loader) admits only Auto or
//! Approved rows. The writer builds the body, as [`super::write_actor_claim`]
//! does: `src` is Observed (the dreaming observed its own trace), the lineage
//! meet is Generated (the note is model-written prose), and the evidence
//! names the dreaming attempt the note came from. That evidence shape is what
//! [`is_resident_craft_candidate`] recognizes, so validation admits a
//! Proposed row of exactly this shape and no other.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;

use super::evidence::KEY_AT;
use super::rows::{ACTOR_NOTE_MAX_BYTES, PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON};
use super::validate::actor_claim_lineage;
use super::write::{require_actor_entity, scope_with_lineage};

const KEY_LANE: &str = "lane";
const KEY_ATTEMPT: &str = "attempt";
const LANE_RESIDENT_DREAM: &str = "resident_dream";

/// One craft note a resident's dreaming proposes about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResidentCraftCandidate {
    /// A distilled craft note: what to do.
    Lesson(String),
    /// A recurring lapse pattern: what keeps going wrong.
    FailureMode(String),
}

impl ResidentCraftCandidate {
    fn predicate(&self) -> &'static str {
        match self {
            Self::Lesson(_) => PREDICATE_ACTOR_LESSON,
            Self::FailureMode(_) => PREDICATE_ACTOR_FAILURE_MODE,
        }
    }

    fn text(&self) -> &str {
        match self {
            Self::Lesson(text) | Self::FailureMode(text) => text,
        }
    }
}

/// Lands `candidates` that `resident`'s dreaming `attempt` proposed, as
/// Proposed `actor.*` rows on the resident, in the caller's write. A note is
/// whitespace-folded; one longer than a note row holds is split at word
/// boundaries into consecutive rows, never cut short. A note the resident
/// already holds as a standing fact or a standing candidate adds no row.
/// Returns the rows written.
///
/// # Errors
///
/// A resident that is no actor entity, and storage or validation errors.
pub(crate) fn write_resident_craft_candidates_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    resident: EntityId,
    attempt: AttemptId,
    candidates: &[ResidentCraftCandidate],
    at: u64,
) -> Result<Vec<EntityId>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    require_actor_entity(vault, &resident)?;
    let mut standing = std::collections::BTreeSet::new();
    for id in vault.claims_for_subject_in_txn(wtxn, &resident)? {
        let Some(body) = vault.get_claim_in_txn(wtxn, &id)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Observed)
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
            )
        {
            continue;
        }
        if let Some(text) = body.value.as_str() {
            standing.insert((body.predicate.clone(), text.to_owned()));
        }
    }
    let evidence = candidate_evidence(attempt, at);
    let scope = scope_with_lineage(None, ClaimSource::Generated);
    let mut written = Vec::new();
    for candidate in candidates {
        let predicate = candidate.predicate();
        for part in note_parts(candidate.text()) {
            if !standing.insert((predicate.to_owned(), part.clone())) {
                continue;
            }
            let id = vault.store.clock.entity_id()?;
            let mut body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(resident),
                Value::from(part),
                1.0,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            )?;
            body.evidence = Some(evidence.clone());
            body.scope = Some(scope.clone());
            body.valid_from = Some(at);
            body.source = Some(ClaimSource::Observed);
            vault.put_reserved_claim_in_txn(
                wtxn,
                &id,
                &body,
                TimeRange { start: at, end: at },
                at,
            )?;
            written.push(id);
        }
    }
    Ok(written)
}

/// Whether `body` is a resident-dreaming candidate as
/// [`write_resident_craft_candidates_in_txn`] writes it: a Proposed, Observed
/// lesson or failure mode of Generated lineage whose evidence is exactly the
/// dreaming attempt and its time.
pub(super) fn is_resident_craft_candidate(body: &ClaimBody) -> bool {
    if !matches!(
        body.predicate.as_str(),
        PREDICATE_ACTOR_LESSON | PREDICATE_ACTOR_FAILURE_MODE
    ) || body.approval != ClaimApprovalStatus::Proposed
        || body.source != Some(ClaimSource::Observed)
        || actor_claim_lineage(body) != Some(ClaimSource::Generated)
    {
        return false;
    }
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return false;
    };
    let mut lane = 0_usize;
    let mut attempt = 0_usize;
    let mut at = 0_usize;
    for (key, value) in entries {
        match key.as_str() {
            Some(KEY_LANE) if value.as_str() == Some(LANE_RESIDENT_DREAM) => lane += 1,
            Some(KEY_ATTEMPT)
                if value.as_str().is_some_and(|hex| {
                    hex.len() == 2 * std::mem::size_of::<AttemptId>()
                        && hex.bytes().all(|b| b.is_ascii_hexdigit())
                }) =>
            {
                attempt += 1;
            }
            Some(KEY_AT) if value.as_u64().is_some() => at += 1,
            _ => return false,
        }
    }
    (lane, attempt, at) == (1, 1, 1)
}

/// The evidence a candidate rests on: the dreaming attempt that proposed it
/// (its durable model step and landed diary entry are that attempt's) and
/// when.
fn candidate_evidence(attempt: AttemptId, at: u64) -> Value {
    let hex: String = attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Value::Map(vec![
        (Value::from(KEY_AT), Value::from(at)),
        (Value::from(KEY_LANE), Value::from(LANE_RESIDENT_DREAM)),
        (Value::from(KEY_ATTEMPT), Value::from(hex)),
    ])
}

/// `text` whitespace-folded, in consecutive parts a note row holds, split at
/// word boundaries (a single word longer than a row splits at a character
/// boundary). Nothing is dropped; a blank note has no parts.
fn note_parts(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    for word in text.split_whitespace() {
        if !part.is_empty() && part.len() + 1 + word.len() > ACTOR_NOTE_MAX_BYTES {
            parts.push(std::mem::take(&mut part));
        }
        let mut word = word;
        while word.len() > ACTOR_NOTE_MAX_BYTES {
            let mut cut = ACTOR_NOTE_MAX_BYTES;
            while !word.is_char_boundary(cut) {
                cut -= 1;
            }
            parts.push(word[..cut].to_owned());
            word = &word[cut..];
        }
        if !part.is_empty() {
            part.push(' ');
        }
        part.push_str(word);
    }
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}
