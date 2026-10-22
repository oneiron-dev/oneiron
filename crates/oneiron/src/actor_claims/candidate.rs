//! The resident-dreaming candidate inlet (OF-490): a resident's own dreaming
//! proposes craft notes about itself — "diary entries, plus actor.lesson and
//! actor.failure_mode candidates, admitted like any other write"
//! (agent-mind design, ARCH-0053 §9).
//!
//! A candidate lands **Proposed**, so it is a proposal and not learned truth:
//! every reader that serves or scores an `actor.*` row (`claim_surfaceable`,
//! the writer's head reads, the resident pack loader) admits only Auto or
//! Approved rows. The writer builds the body, as [`super::write_actor_claim`]
//! does: `src` and the lineage meet are both Generated (the note is
//! model-written prose, FIX 8641), and the evidence names the dreaming
//! attempt the note came from. That evidence shape is what
//! [`is_resident_craft_candidate`] recognizes, so validation admits a
//! Proposed row of exactly this shape and no other.
//!
//! **The owner's review.** Each candidate waits on its card ("Waiting on
//! you", `/v1/owner/craft-candidates`, `vault.craft_candidates`), which pins
//! its content hash. [`answer_craft_candidate_as_owner`] writes the verdict
//! through this same inlet, in one write: an Approved or Rejected row of the
//! one shape [`is_resident_craft_verdict`] recognizes, which supersedes the
//! candidate, and one decision receipt. An Approved verdict is the
//! resident's learned craft; a Rejected one settles that candidate only.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_inbox_lens::{
    AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
};
use crate::attempt_queue::AttemptId;
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ClaimError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord,
};
use crate::temporal::TimeRange;

use super::evidence::KEY_AT;
use super::invalid;
use super::rows::{ACTOR_NOTE_MAX_BYTES, PREDICATE_ACTOR_FAILURE_MODE, PREDICATE_ACTOR_LESSON};
use super::validate::{actor_claim_lineage, native_actor_source};
use super::write::{require_actor_entity, scope_with_lineage};

const KEY_LANE: &str = "lane";
const KEY_ATTEMPT: &str = "attempt";
const LANE_RESIDENT_DREAM: &str = "resident_dream";
const KEY_CANDIDATE: &str = "candidate";
const KEY_CANDIDATE_HASH: &str = "candidate_hash";
const KEY_VERDICT: &str = "verdict";
const KEY_OWNER: &str = "owner";
const KEY_RECEIPT: &str = "receipt";
/// A decision receipt's ref: the Gate family's prefix, then 32 hex.
const RECEIPT_PREFIX: &str = "gate:";
/// What a candidate's content hash starts from, so it hashes nothing else.
const CANDIDATE_HASH_DOMAIN: &[u8] = b"oneiron.actor.craft_candidate.v1";
/// The verdict receipt's content kind and the channel of its details.
const CRAFT_REVIEW_CONTENT_KIND: &str = "actor_craft_review";
/// The verdict receipt's reason code; the verdict follows it.
const CRAFT_REVIEW_REASON: &str = "gate.actor.craft_review";
/// Where a waiting candidate sorts in the owner's INBOX: a review that holds
/// no work, with the other rows that wait on a read.
const CRAFT_INBOX_IMPACT: u16 = 100;

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

/// The owner's verdict on one craft candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CraftVerdict {
    /// The note becomes the resident's learned craft.
    Approved,
    /// The note is set aside; a later dreaming may propose it again.
    Rejected,
}

impl CraftVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    const fn approval(self) -> ClaimApprovalStatus {
        match self {
            Self::Approved => ClaimApprovalStatus::Approved,
            Self::Rejected => ClaimApprovalStatus::Rejected,
        }
    }
}

/// `vault.craft_candidates`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CraftCandidatesRequest {
    /// Only this resident's candidates (32 hex); every resident's when absent.
    #[serde(default)]
    pub resident: Option<String>,
}

/// `vault.craft_candidates.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CraftCandidateAnswer {
    /// The candidate's claim id (32 hex), as its card names it.
    pub candidate_id: String,
    /// The content hash its card showed (64 hex); another refuses.
    pub content_hash: String,
    pub verdict: CraftVerdict,
}

/// One candidate as its card shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CraftCandidateView {
    pub candidate_id: String,
    /// What an answer pins (64 hex): the candidate's id, kind and words and
    /// the dreaming they came from.
    pub content_hash: String,
    /// The resident the note is about (32 hex).
    pub resident: String,
    /// `actor.lesson` or `actor.failure_mode`.
    pub predicate: String,
    pub text: String,
    /// The dreaming attempt that proposed it (32 hex).
    pub attempt: String,
    /// When it was proposed, on the vault clock.
    pub proposed_at: u64,
}

/// `vault.craft_candidates`'s answer, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CraftCandidatesView {
    pub candidates: Vec<CraftCandidateView>,
}

/// The owner's verdict as it landed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CraftVerdictView {
    pub candidate_id: String,
    pub verdict: CraftVerdict,
    /// The verdict row (32 hex), which superseded the candidate.
    pub verdict_id: String,
    /// The decision's receipt (`gate:<hex>`).
    pub receipt_ref: String,
    /// When the owner decided, on the vault clock.
    pub decided_at: u64,
}

/// Lands `candidates` that `resident`'s dreaming `attempt` proposed, as
/// Proposed `actor.*` rows on the resident, in the caller's write. A note is
/// whitespace-folded; one longer than a note row holds is split at word
/// boundaries into consecutive rows, never cut short. A note the resident
/// already holds as a standing fact (learned, or approved by its owner) or a
/// standing candidate adds no row. Returns the rows written.
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
            || !native_actor_source(body.source)
            || !(matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
            ) || is_approved_craft_verdict(&body))
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
            body.source = Some(ClaimSource::Generated);
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
/// [`write_resident_craft_candidates_in_txn`] writes it: a Proposed lesson or
/// failure mode of a native source (Generated as written, FIX 8641) and
/// Generated lineage whose evidence is exactly the dreaming attempt and its
/// time.
pub(super) fn is_resident_craft_candidate(body: &ClaimBody) -> bool {
    if !matches!(
        body.predicate.as_str(),
        PREDICATE_ACTOR_LESSON | PREDICATE_ACTOR_FAILURE_MODE
    ) || body.approval != ClaimApprovalStatus::Proposed
        || !native_actor_source(body.source)
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

/// Whether `body` is the owner's verdict on a candidate as
/// [`answer_craft_candidate_as_owner`] writes it, in any lifecycle: a later
/// head may close it.
pub(super) fn is_resident_craft_verdict(body: &ClaimBody) -> bool {
    verdict_stamp(body).is_some()
}

/// Whether `body` is the owner's Approved verdict on a candidate: the one
/// reviewed shape the writer's head read and the candidate dedupe take
/// beside Auto.
pub(super) fn is_approved_craft_verdict(body: &ClaimBody) -> bool {
    body.approval == ClaimApprovalStatus::Approved && is_resident_craft_verdict(body)
}

/// The craft candidates waiting on the owner's verdict, newest first: every
/// resident's, or the one `request` names.
///
/// # Errors
///
/// A proof that is not this vault's live owner, a resident that is no id,
/// and storage errors.
pub fn craft_candidates_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &CraftCandidatesRequest,
) -> Result<CraftCandidatesView> {
    owner.revalidate(vault)?;
    let residents = match &request.resident {
        Some(hex) => {
            vec![EntityId::from_hex(hex).map_err(|_| invalid("a resident is a 32-hex entity id"))?]
        }
        None => vault.entities_by_type(ENTITY_TYPE_AGENT_DEF)?,
    };
    let rtxn = vault.store.env.read_txn()?;
    let candidates = pending_in_txn(vault, &rtxn, &residents)?
        .into_iter()
        .map(|(_, card)| card)
        .collect();
    Ok(CraftCandidatesView { candidates })
}

/// The owner approves or rejects one candidate, as its card showed it. In one
/// write: the verdict row, Approved or Rejected, with the candidate's own
/// dreaming evidence plus the candidate, its hash, the verdict, the owner and
/// the decision receipt; the candidate superseded by it; and one decision
/// receipt. An approval also folds the resident's standing heads of the same
/// note into the verdict; a rejection closes nothing but the candidate.
///
/// The same verdict again answers as it landed and writes nothing; the other
/// verdict is refused.
///
/// # Errors
///
/// A proof that is not this vault's live owner, an id that names no
/// candidate, a hash that is not the card's, a candidate already decided the
/// other way or closed by another write, and storage errors.
pub fn answer_craft_candidate_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    answer: &CraftCandidateAnswer,
) -> Result<CraftVerdictView> {
    let candidate = EntityId::from_hex(&answer.candidate_id)
        .map_err(|_| invalid("a craft candidate id is a 32-hex claim id"))?;
    vault.with_write_txn_grouped(|wtxn| answer_in_txn(vault, wtxn, owner, candidate, answer))
}

fn answer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    candidate: EntityId,
    answer: &CraftCandidateAnswer,
) -> Result<CraftVerdictView> {
    let actor = owner.revalidate_in_txn(vault, wtxn)?;
    let body = vault
        .get_claim_in_txn(wtxn, &candidate)?
        .ok_or(Error::EntityNotFound)?;
    let (resident, hash, card) = candidate_card(&candidate, &body).ok_or(Error::EntityNotFound)?;
    if !answer.content_hash.eq_ignore_ascii_case(&card.content_hash) {
        return Err(invalid(
            "the answer does not bind the craft candidate that was shown",
        ));
    }
    let verdict = answer.verdict;
    let mut prior = None;
    let mut heads = Vec::new();
    for id in vault.claims_for_subject_in_txn(wtxn, &resident)? {
        let Some(row) = vault.get_claim_in_txn(wtxn, &id)? else {
            continue;
        };
        if let Some(stamp) = verdict_stamp(&row)
            && EntityId::from_hex(&stamp.candidate).ok() == Some(candidate)
        {
            if prior.replace((id, row.valid_from, stamp)).is_some() {
                return Err(invalid("the craft candidate holds more than one verdict"));
            }
            continue;
        }
        if row.lifecycle == ClaimLifecycleStatus::Active
            && native_actor_source(row.source)
            && row.predicate == body.predicate
            && row.value == body.value
            && (row.approval == ClaimApprovalStatus::Auto || is_approved_craft_verdict(&row))
        {
            heads.push(id);
        }
    }
    if let Some((verdict_id, decided_at, stamp)) = prior {
        if stamp.verdict != verdict || stamp.candidate_hash != card.content_hash {
            return Err(invalid("the craft candidate is already decided otherwise"));
        }
        return Ok(CraftVerdictView {
            candidate_id: card.candidate_id,
            verdict,
            verdict_id: verdict_id.to_hex(),
            receipt_ref: stamp.receipt,
            decided_at: decided_at.unwrap_or_default(),
        });
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(Error::Claim(ClaimError::ClaimAlreadyClosed {
            status: body.lifecycle,
        }));
    }

    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let verdict_id = vault.store.clock.entity_id()?;
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
        created_at: at,
        outcome: verdict.as_str().to_owned(),
        reason_codes: vec![format!("{CRAFT_REVIEW_REASON}.{}", verdict.as_str())],
        receipt_reasons: Vec::new(),
        system_notices: GateSystemNoticeRecord::receipt_details(
            CRAFT_REVIEW_CONTENT_KIND,
            vec![
                format!("{KEY_CANDIDATE}:{}", card.candidate_id),
                format!("{KEY_CANDIDATE_HASH}:{}", card.content_hash),
                format!("verdict_claim:{}", verdict_id.to_hex()),
                format!("resident:{}", card.resident),
            ],
        ),
        actor_class: "human".to_owned(),
        actor_ref: Some(actor.to_hex()),
        content_kind: CRAFT_REVIEW_CONTENT_KIND.to_owned(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: Some(*candidate.as_bytes()),
        grant_ref: None,
        diff_handle: hash.as_bytes().to_vec(),
        read_frontier_hash: [0; 32],
        redacted_at: None,
    };
    let receipt_ref = crate::receipt::gate_decision_receipt(&record).receipt_id;
    let Some(Value::Map(mut evidence)) = body.evidence.clone() else {
        return Err(Error::EntityNotFound);
    };
    evidence.extend([
        (
            Value::from(KEY_CANDIDATE),
            Value::from(card.candidate_id.as_str()),
        ),
        (
            Value::from(KEY_CANDIDATE_HASH),
            Value::from(card.content_hash.as_str()),
        ),
        (Value::from(KEY_VERDICT), Value::from(verdict.as_str())),
        (Value::from(KEY_OWNER), Value::from(actor.to_hex())),
        (Value::from(KEY_RECEIPT), Value::from(receipt_ref.as_str())),
    ]);
    let mut verdict_body = ClaimBody::new(
        body.predicate.as_str(),
        ClaimSubject::Entity(resident),
        body.value.clone(),
        1.0,
        verdict.approval(),
        ClaimLifecycleStatus::Active,
    )?;
    verdict_body.evidence = Some(Value::Map(evidence));
    verdict_body.scope = Some(scope_with_lineage(None, ClaimSource::Generated));
    verdict_body.valid_from = Some(at);
    verdict_body.source = Some(ClaimSource::Generated);
    vault.put_reserved_claim_in_txn(
        wtxn,
        &verdict_id,
        &verdict_body,
        TimeRange { start: at, end: at },
        at,
    )?;
    let closed = match verdict {
        CraftVerdict::Approved => heads,
        CraftVerdict::Rejected => Vec::new(),
    };
    for old in std::iter::once(candidate).chain(closed) {
        // The close re-puts the old row over `{its start, now}`, so `now` is
        // never earlier than its start.
        let start = occurred_start_in_txn(vault, wtxn, &old)?;
        vault.supersede_reserved_claim_in_txn(wtxn, &verdict_id, &old, at.max(start))?;
    }
    vault.store.append_gate_decision_in_txn(wtxn, &record)?;
    Ok(CraftVerdictView {
        candidate_id: card.candidate_id,
        verdict,
        verdict_id: verdict_id.to_hex(),
        receipt_ref,
        decided_at: at,
    })
}

/// Each candidate waiting on a verdict as an INBOX row for the vault's live
/// owners (kind ApprovalRequired, so "Waiting on you"), on the resident that
/// proposed it and carrying the candidate id its card answers with. A vault
/// with no live owner has no one to ask and makes no row. Never folded into
/// a thread.
pub(crate) fn craft_candidate_inbox_items(vault: &Vault) -> Result<Vec<AgentInboxLensItem>> {
    let residents = vault.entities_by_type(ENTITY_TYPE_AGENT_DEF)?;
    let rtxn = vault.store.env.read_txn()?;
    let pending = pending_in_txn(vault, &rtxn, &residents)?;
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let participants: Vec<_> = crate::policy_model::owners_in_txn(vault, &rtxn)?
        .into_iter()
        .map(|owner| AgentInboxParticipant {
            identity_ref: Some(owner),
            actor_ref: owner,
        })
        .collect();
    if participants.is_empty() {
        return Ok(Vec::new());
    }
    Ok(pending
        .into_iter()
        .map(|(resident, card)| AgentInboxLensItem {
            item_id: format!("craft:{}", card.candidate_id),
            kind: AgentInboxItemKind::ApprovalRequired,
            thread_ref: None,
            identity_ref: Some(resident),
            actor_ref: resident,
            facet_ref: None,
            participants: participants.clone(),
            impact: InboxImpact(CRAFT_INBOX_IMPACT),
            occurred_at: card.proposed_at,
            receipt_ref: None,
            payload_ref: Some(card.candidate_id),
            concern: None,
            diary_review: None,
            sender: None,
            widening: None,
        })
        .collect())
}

/// Every still-open candidate on `residents`, newest first, beside its
/// resident.
fn pending_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    residents: &[EntityId],
) -> Result<Vec<(EntityId, CraftCandidateView)>> {
    let mut cards = Vec::new();
    for resident in residents {
        for id in vault.claims_for_subject_in_txn(rtxn, resident)? {
            let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
                continue;
            };
            if body.lifecycle == ClaimLifecycleStatus::Active
                && let Some((_, _, card)) = candidate_card(&id, &body)
            {
                cards.push((*resident, card));
            }
        }
    }
    cards.sort_by(|(_, a), (_, b)| {
        b.proposed_at
            .cmp(&a.proposed_at)
            .then_with(|| a.candidate_id.cmp(&b.candidate_id))
    });
    Ok(cards)
}

/// The card candidate `id` shows, with its resident and content hash, or
/// `None` for a row that is no candidate. Its lifecycle is no part of it, so
/// a settled candidate still hashes as its verdict names it.
fn candidate_card(
    id: &EntityId,
    body: &ClaimBody,
) -> Option<(EntityId, blake3::Hash, CraftCandidateView)> {
    if !is_resident_craft_candidate(body) {
        return None;
    }
    let ClaimSubject::Entity(resident) = body.subject else {
        return None;
    };
    let text = body.value.as_str()?;
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return None;
    };
    let field = |name: &str| {
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
    };
    let attempt = field(KEY_ATTEMPT)?.as_str()?;
    let at = field(KEY_AT)?.as_u64()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CANDIDATE_HASH_DOMAIN);
    hasher.update(id.as_bytes());
    for part in [body.predicate.as_str(), text, attempt] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(&at.to_be_bytes());
    let hash = hasher.finalize();
    Some((
        resident,
        hash,
        CraftCandidateView {
            candidate_id: id.to_hex(),
            content_hash: hash.to_hex().to_string(),
            resident: resident.to_hex(),
            predicate: body.predicate.clone(),
            text: text.to_owned(),
            attempt: attempt.to_owned(),
            proposed_at: at,
        },
    ))
}

/// What an owner's verdict row says, read back from its evidence.
struct VerdictStamp {
    candidate: String,
    candidate_hash: String,
    verdict: CraftVerdict,
    receipt: String,
}

/// The verdict `body` is, or `None` for any other row: an Approved or
/// Rejected lesson or failure mode of a native source and Generated lineage
/// whose evidence is exactly the candidate's dreaming evidence plus the
/// candidate, its hash, the verdict its approval says, the owner and the
/// receipt, each once.
fn verdict_stamp(body: &ClaimBody) -> Option<VerdictStamp> {
    if !matches!(
        body.predicate.as_str(),
        PREDICATE_ACTOR_LESSON | PREDICATE_ACTOR_FAILURE_MODE
    ) || !native_actor_source(body.source)
        || actor_claim_lineage(body) != Some(ClaimSource::Generated)
    {
        return None;
    }
    let verdict = match body.approval {
        ClaimApprovalStatus::Approved => CraftVerdict::Approved,
        ClaimApprovalStatus::Rejected => CraftVerdict::Rejected,
        _ => return None,
    };
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return None;
    };
    let id_hex = |text: Option<&str>| text.is_some_and(|hex| is_hex(hex, 2 * ENTITY_ID_LEN));
    let (mut candidate, mut candidate_hash, mut receipt) = (None, None, None);
    let mut seen = 0_u8;
    for (key, value) in entries {
        let text = value.as_str();
        let bit = match key.as_str()? {
            KEY_AT if value.as_u64().is_some() => 1,
            KEY_LANE if text == Some(LANE_RESIDENT_DREAM) => 2,
            KEY_ATTEMPT
                if text.is_some_and(|hex| is_hex(hex, 2 * std::mem::size_of::<AttemptId>())) =>
            {
                4
            }
            KEY_CANDIDATE if id_hex(text) => {
                candidate = text;
                8
            }
            KEY_CANDIDATE_HASH if text.is_some_and(|hex| is_hex(hex, 64)) => {
                candidate_hash = text;
                16
            }
            KEY_VERDICT if text == Some(verdict.as_str()) => 32,
            KEY_OWNER if id_hex(text) => 64,
            KEY_RECEIPT
                if text
                    .and_then(|text| text.strip_prefix(RECEIPT_PREFIX))
                    .is_some_and(|hex| is_hex(hex, 32)) =>
            {
                receipt = text;
                128
            }
            _ => return None,
        };
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
    }
    if seen != u8::MAX {
        return None;
    }
    Some(VerdictStamp {
        candidate: candidate?.to_owned(),
        candidate_hash: candidate_hash?.to_owned(),
        verdict,
        receipt: receipt?.to_owned(),
    })
}

/// Whether `text` is exactly `len` hex digits.
fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Where `id`'s envelope starts.
fn occurred_start_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> Result<u64> {
    let raw = vault
        .store
        .port_entity_record(rtxn, id)?
        .map(|row| row.encode())
        .ok_or(Error::CorruptedIndex("actor claim entity"))?;
    Ok(EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("entity header"))?
        .occurred_start)
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
