use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use super::support::{
    DREAMER_GAP_DECAY_MS, DREAMER_GAP_HASH_DOMAIN, DREAMER_PRIVATE_GAP_PREFIX, GAP_SCHEMA_VERSION,
    KEY_DECAYED, KEY_ESCALATIONS, KEY_EVIDENCE_TURN_REFS, KEY_FIRST_SEEN, KEY_KIND, KEY_LAST_SEEN,
    KEY_SCHEMA_VERSION, KEY_SUBJECT, decode_value, encode_value, expect_key, expect_map,
    invalid_consolidation,
};
use super::watermark::{WorkingSetTurn, entity_ref_from_value, read_turn_facts};
use crate::Vault;
use crate::dreamer_runner::DreamerTurnRole;
use crate::entity_id::EntityId;
use crate::error::Result;

// ---------------------------------------------------------------------------
// Phase 4 — reflection gap scan
// ---------------------------------------------------------------------------

/// The pinned gap taxonomy — exactly these four kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReflectionGapKind {
    MissingFollowUp,
    UnresolvedThread,
    StatedIntentWithoutAction,
    ContradictionLeftStanding,
}

impl ReflectionGapKind {
    /// Stable kind string for gap rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingFollowUp => "missing_follow_up",
            Self::UnresolvedThread => "unresolved_thread",
            Self::StatedIntentWithoutAction => "stated_intent_without_action",
            Self::ContradictionLeftStanding => "contradiction_left_standing",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "missing_follow_up" => Some(Self::MissingFollowUp),
            "unresolved_thread" => Some(Self::UnresolvedThread),
            "stated_intent_without_action" => Some(Self::StatedIntentWithoutAction),
            "contradiction_left_standing" => Some(Self::ContradictionLeftStanding),
            _ => None,
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::MissingFollowUp => 0,
            Self::UnresolvedThread => 1,
            Self::StatedIntentWithoutAction => 2,
            Self::ContradictionLeftStanding => 3,
        }
    }
}

/// One observed reflection gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectionGap {
    pub kind: ReflectionGapKind,
    pub subject: EntityId,
    pub evidence_turn_refs: Vec<EntityId>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub escalations: u32,
    pub decayed: bool,
}

/// Gap identity hash: BLAKE3 over domain + kind byte + subject bytes +
/// normalized description.
#[must_use]
pub fn gap_hash(kind: ReflectionGapKind, subject: &EntityId, description: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DREAMER_GAP_HASH_DOMAIN);
    hasher.update(&[kind.byte()]);
    hasher.update(subject.as_bytes());
    hasher.update(description.trim().to_ascii_lowercase().as_bytes());
    *hasher.finalize().as_bytes()
}

/// Outcome of one gap-queue upsert pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GapQueueDelta {
    pub created: u32,
    pub refreshed: u32,
    pub decayed: u32,
    /// Gaps due their ONE escalation per lifetime (the caller routes these
    /// through the promotion writer as Proposed inbox claims — ONE-1290).
    pub escalations: Vec<ReflectionGap>,
}

/// v1 deterministic gap detectors over the working set (taxonomy + queue
/// mechanics are the deliverable; detector quality iterates post-ship):
/// a user turn ending the conversation unanswered → `UnresolvedThread`;
/// a user turn asking a question with no later assistant turn in the set →
/// `MissingFollowUp`; a user turn declaring intent ("i will"/"i'll") →
/// `StatedIntentWithoutAction`. `ContradictionLeftStanding` gaps are fed by
/// the reducer's escalate outcomes, not this scan.
pub fn scan_reflection_gaps(
    vault: &Vault,
    working_set: &[WorkingSetTurn],
    now: u64,
) -> Result<Vec<ReflectionGap>> {
    let mut by_conversation: BTreeMap<EntityId, Vec<&WorkingSetTurn>> = BTreeMap::new();
    for turn in working_set {
        if let Some(conversation) = turn.conversation {
            by_conversation.entry(conversation).or_default().push(turn);
        }
    }

    let mut gaps = Vec::new();
    for (conversation, mut turns) in by_conversation {
        turns.sort_by_key(|turn| turn.learned_at);
        let Some(last) = turns.last() else {
            continue;
        };
        if last.role == DreamerTurnRole::User {
            gaps.push(ReflectionGap {
                kind: ReflectionGapKind::UnresolvedThread,
                subject: conversation,
                evidence_turn_refs: vec![last.turn_id],
                first_seen: now,
                last_seen: now,
                escalations: 0,
                decayed: false,
            });
        }
        for (position, turn) in turns.iter().enumerate() {
            if turn.role != DreamerTurnRole::User {
                continue;
            }
            let text = read_turn_facts(vault, &turn.turn_id)?
                .text
                .unwrap_or_default()
                .to_ascii_lowercase();
            let answered = turns[position + 1..]
                .iter()
                .any(|later| later.role == DreamerTurnRole::Assistant);
            if text.contains('?') && !answered {
                gaps.push(ReflectionGap {
                    kind: ReflectionGapKind::MissingFollowUp,
                    subject: conversation,
                    evidence_turn_refs: vec![turn.turn_id],
                    first_seen: now,
                    last_seen: now,
                    escalations: 0,
                    decayed: false,
                });
            }
            if text.contains("i will ") || text.contains("i'll ") {
                gaps.push(ReflectionGap {
                    kind: ReflectionGapKind::StatedIntentWithoutAction,
                    subject: conversation,
                    evidence_turn_refs: vec![turn.turn_id],
                    first_seen: now,
                    last_seen: now,
                    escalations: 0,
                    decayed: false,
                });
            }
        }
    }
    Ok(gaps)
}

fn gap_row_key(prefix: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(hash);
    key
}

/// Upserts observed gaps into the private gap queue: re-observation
/// refreshes `last_seen`; a stored gap not re-observed within
/// [`DREAMER_GAP_DECAY_MS`] decays and is never re-surfaced; the FIRST
/// insertion of a gap earns its single per-lifetime escalation.
pub fn upsert_gap_queue(
    vault: &Vault,
    gaps: Vec<ReflectionGap>,
    now: u64,
) -> Result<GapQueueDelta> {
    upsert_gap_projection(vault, gaps, now, DREAMER_PRIVATE_GAP_PREFIX)
}

/// A real private projection namespace. Partition identity includes the world
/// and facet, so a branch can neither refresh nor decay a different branch.
pub(super) fn branch_gap_projection(
    partition: &super::partition::ConsolidationPartitionKey,
    scope: &crate::llm::Scope,
) -> crate::llm::ScopeResource {
    crate::llm::ScopeResource::Projection {
        key: format!(
            "dreamer:gap-branch:v1:{}:{}:{}:",
            crate::entity_id::bytes_to_hex_lower(&partition.partition_hash()),
            scope
                .relationship
                .map_or_else(|| "none".to_owned(), |id| id.to_hex()),
            scope
                .project
                .map_or_else(|| "none".to_owned(), |id| id.to_hex())
        ),
    }
}

pub(super) fn upsert_branch_gap_queue(
    vault: &Vault,
    scope: &crate::llm::Scope,
    partition: &super::partition::ConsolidationPartitionKey,
    gaps: Vec<ReflectionGap>,
    now: u64,
) -> Result<GapQueueDelta> {
    let resource = branch_gap_projection(partition, scope);
    if !scope.allows_write(&resource)
        || scope.world != partition.world_ref
        || scope.facet != partition.facet_ref
    {
        return Err(invalid_consolidation("branch gap projection write refused"));
    }
    let crate::llm::ScopeResource::Projection { key } = resource else {
        unreachable!("branch gap identity is a projection");
    };
    upsert_gap_projection(vault, gaps, now, key.as_bytes())
}

fn upsert_gap_projection(
    vault: &Vault,
    gaps: Vec<ReflectionGap>,
    now: u64,
    prefix: &[u8],
) -> Result<GapQueueDelta> {
    let mut delta = GapQueueDelta::default();
    let mut observed: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut wtxn = vault.store.env.write_txn()?;

    for gap in gaps {
        let hash = gap_hash(gap.kind, &gap.subject, "");
        let key = gap_row_key(prefix, &hash);
        observed.insert(key.clone());
        match vault.store.vault_meta.get(&wtxn, &key)? {
            Some(raw) => {
                let mut stored = decode_gap_row(&raw)?;
                if stored.decayed {
                    // Decayed gaps are let go — never re-surfaced.
                    continue;
                }
                stored.last_seen = now;
                stored.evidence_turn_refs = gap.evidence_turn_refs;
                let encoded = encode_gap_row(&stored)?;
                vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
                delta.refreshed += 1;
            }
            None => {
                let stored = ReflectionGap {
                    first_seen: now,
                    last_seen: now,
                    escalations: 1,
                    decayed: false,
                    ..gap
                };
                let encoded = encode_gap_row(&stored)?;
                vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
                delta.created += 1;
                delta.escalations.push(stored);
            }
        }
    }

    // Decay pass over stored gaps that were NOT re-observed this round.
    let stale: Vec<(Vec<u8>, ReflectionGap)> = {
        let mut stale = Vec::new();
        for row in vault.store.vault_meta.prefix_iter(&wtxn, prefix)? {
            let (key, raw) = row?;
            if observed.contains(key.as_ref()) {
                continue;
            }
            let stored = decode_gap_row(&raw)?;
            if !stored.decayed && now.saturating_sub(stored.last_seen) >= DREAMER_GAP_DECAY_MS {
                stale.push((key.to_vec(), stored));
            }
        }
        stale
    };
    for (key, mut stored) in stale {
        stored.decayed = true;
        let encoded = encode_gap_row(&stored)?;
        vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        delta.decayed += 1;
    }

    wtxn.commit()?;
    Ok(delta)
}

fn encode_gap_row(gap: &ReflectionGap) -> Result<Vec<u8>> {
    encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(GAP_SCHEMA_VERSION),
        ),
        (Value::from(KEY_KIND), Value::from(gap.kind.as_str())),
        (
            Value::from(KEY_SUBJECT),
            Value::Binary(gap.subject.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_EVIDENCE_TURN_REFS),
            Value::Array(
                gap.evidence_turn_refs
                    .iter()
                    .map(|id| Value::Binary(id.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (Value::from(KEY_FIRST_SEEN), Value::from(gap.first_seen)),
        (Value::from(KEY_LAST_SEEN), Value::from(gap.last_seen)),
        (Value::from(KEY_ESCALATIONS), Value::from(gap.escalations)),
        (Value::from(KEY_DECAYED), Value::from(gap.decayed)),
    ]))
}

fn decode_gap_row(raw: &[u8]) -> Result<ReflectionGap> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value, "dreamer gap row must be a MessagePack map")?;
    let mut kind = None;
    let mut subject = None;
    let mut evidence = Vec::new();
    let mut first_seen = None;
    let mut last_seen = None;
    let mut escalations = None;
    let mut decayed = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => {}
            KEY_KIND => {
                kind = value.as_str().and_then(ReflectionGapKind::parse);
            }
            KEY_SUBJECT => subject = entity_ref_from_value(value),
            KEY_EVIDENCE_TURN_REFS => {
                if let Value::Array(items) = value {
                    for item in items {
                        if let Some(id) = entity_ref_from_value(item) {
                            evidence.push(id);
                        }
                    }
                }
            }
            KEY_FIRST_SEEN => first_seen = value.as_u64(),
            KEY_LAST_SEEN => last_seen = value.as_u64(),
            KEY_ESCALATIONS => escalations = value.as_u64(),
            KEY_DECAYED => decayed = value.as_bool(),
            _ => return Err(invalid_consolidation("dreamer gap row key is not pinned")),
        }
    }
    Ok(ReflectionGap {
        kind: kind.ok_or(invalid_consolidation("missing dreamer gap kind"))?,
        subject: subject.ok_or(invalid_consolidation("missing dreamer gap subject"))?,
        evidence_turn_refs: evidence,
        first_seen: first_seen.ok_or(invalid_consolidation("missing dreamer gap first_seen"))?,
        last_seen: last_seen.ok_or(invalid_consolidation("missing dreamer gap last_seen"))?,
        escalations: u32::try_from(escalations.unwrap_or(0))
            .map_err(|_| invalid_consolidation("dreamer gap escalations out of range"))?,
        decayed: decayed.unwrap_or(false),
    })
}
