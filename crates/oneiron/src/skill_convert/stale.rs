//! The stale fold: the reverse source index, the staleness note, and the deletion-time
//! sweep that stales every skill citing an erased source.

use crate::ports::EntityStoreRead;
use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::side_table::{self, Raw, RawValue, SideTable};
use crate::skill::{SkillLifecycle, SkillRecord, encode_skill_record, validate_skill_update};
use crate::store::Store;
use crate::temporal::TimeRange;

use super::provenance::source_message_refs;
use crate::error::ArtifactError;

// ─── the stale fold (ONE-1447) ──────────────────────────────────────────
//
// A converted skill CITES conversation. When the cited words leave the active
// store the skill is no longer grounded in anything a reader can check, so it
// stops loading as canon — visibly, reversibly, and without losing the record.
// Terminal delete never happens here (ARCH-0053 §6): a silent orphan and a
// deleted skill are the two failures this fold exists to avoid.

/// The reverse source index: skills citing a source. Key: id16(source) + id16(skill), empty
/// value.
///
/// Asking "which skills cite this id" by scanning every skill's provenance is
/// O(library) on EVERY entity delete; this makes it one prefix seek. The index
/// is a CACHE with an authority — the records themselves — and
/// [`rebuild_skill_source_index`] reconstructs it from them, so a missing or
/// drifted row costs a rebuild, never truth.
pub(super) const SOURCE_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::SKILL_SOURCE_INDEX);

/// The staleness note of a skill, carrying a MessagePack map of
/// [`STALE_NOTE_REASON_KEY`] and [`STALE_NOTE_DELETED_REFS_KEY`]. Key: id16(skill).
pub(super) const STALE_NOTE: SideTable<EntityId, SkillStaleNote, Raw> =
    SideTable::new(&side_table::SKILL_STALE_NOTE);

impl RawValue for SkillStaleNote {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(encode_stale_note(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        Ok(decode_stale_note(bytes)?)
    }
}

/// Staleness-note key naming WHY a record went stale.
pub const STALE_NOTE_REASON_KEY: &str = "stale_reason";

/// Staleness-note key carrying the source ids whose deletion caused it, as
/// 32-char entity-id hex strings.
pub const STALE_NOTE_DELETED_REFS_KEY: &str = "deleted_refs";

/// The [`STALE_NOTE_REASON_KEY`] value this fold writes.
pub const STALE_REASON_SOURCE_MESSAGE_DELETED: &str = "source_message_deleted";

/// Why a skill is currently stale, and which deletions caused it.
///
/// Read through [`skill_stale_note`], which answers `None` for a record that is
/// not stale: the note describes the CURRENT episode, and an owner who has
/// already flipped the skill back to `active` ended it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillStaleNote {
    /// [`STALE_REASON_SOURCE_MESSAGE_DELETED`] for this fold.
    pub reason: String,
    /// The deleted source ids, in the order their deletions landed.
    pub deleted_refs: Vec<EntityId>,
}

/// The skills citing `source` as provenance, per the reverse index.
pub fn skills_dependent_on_message(vault: &Vault, source: &EntityId) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    dependent_skills_in_txn(&vault.store, &rtxn, source)
}

/// The staleness note of a currently-stale skill, or `None`.
pub fn skill_stale_note(vault: &Vault, skill: &EntityId) -> Result<Option<SkillStaleNote>> {
    if vault.get_skill_record(skill)?.map(|r| r.lifecycle_status) != Some(SkillLifecycle::Stale) {
        return Ok(None);
    }
    let rtxn = vault.store.env.read_txn()?;
    STALE_NOTE.get(&vault.store, &rtxn, skill)
}

/// Rebuilds the reverse source index from the SKILL records (the CID-7 door).
///
/// Drops every existing row first, so a rebuild is an identity rather than a
/// merge: a row for a citation no record makes any more would otherwise
/// outlive its evidence, which is precisely the failure this index guards.
pub fn rebuild_skill_source_index(vault: &Vault) -> Result<()> {
    let store = &vault.store;
    let mut wtxn = store.env.write_txn()?;

    // Collect, then write: the cursors are dropped before the first mutation
    // (the `backfill_content_hash_index_if_needed` pattern).
    let dead: Vec<(EntityId, EntityId)> = SOURCE_INDEX
        .scan(store, &wtxn)?
        .into_iter()
        .map(|(key, ())| key)
        .collect();
    let mut live: Vec<(EntityId, EntityId)> = Vec::new();
    for entry in store.port_entity_ids_by_type(&wtxn, ENTITY_TYPE_SKILL, None)? {
        let skill = entry?;
        let Some(record) = read_live_skill_record_in_txn(store, &wtxn, &skill)? else {
            continue;
        };
        // Lenient on the way IN to a rebuild: one corrupt linkage must not deny
        // the whole reconstruction. The write door below is where a malformed
        // linkage is refused.
        for source in source_message_refs(&record.0).unwrap_or_default() {
            live.push((source, skill));
        }
    }

    for key in &dead {
        SOURCE_INDEX.delete(store, &mut wtxn, key)?;
    }
    for (source, skill) in &live {
        SOURCE_INDEX.put(store, &mut wtxn, &(*source, *skill), &())?;
    }
    wtxn.commit()?;
    Ok(())
}

/// Maintains the reverse index as a SKILL body lands, at the batch put
/// chokepoint every road funnels through — the typed doors, hub import, and
/// sync rematerialization alike. `previous` is the record this put replaces.
///
/// STRICT on the incoming linkage and lenient on the outgoing one: a malformed
/// `source_messages` in the new body is refused here, where the corruption
/// would enter, so the deletion sweep can never read a broken linkage as "this
/// skill cites nothing"; an unreadable PRIOR body is already on disk and only
/// costs unindexed rows, which the rebuild door clears.
pub(crate) fn maintain_skill_source_index_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    previous: Option<&SkillRecord>,
    record: &SkillRecord,
) -> Result<()> {
    let next = source_message_refs(record)?;
    let dropped = previous
        .and_then(|previous| source_message_refs(previous).ok())
        .unwrap_or_default();
    for source in dropped.iter().filter(|source| !next.contains(source)) {
        SOURCE_INDEX.delete(store, wtxn, &(*source, *skill))?;
    }
    for source in &next {
        SOURCE_INDEX.put(store, wtxn, &(*source, *skill), &())?;
    }
    Ok(())
}

impl Vault {
    /// Marks every skill citing `deleted` as stale, inside the transaction that
    /// is erasing it — so no reader ever observes a live skill grounded in
    /// evidence this vault has already dropped.
    ///
    /// The LIFECYCLE MACHINE decides who moves, not this fold: only a record
    /// whose state may transition to `stale` flips (ARCH-0053 §6 — `active`,
    /// plus the `stale` self-loop that records a second lost source). A
    /// `candidate` has not been admitted, and `quarantined`/`superseded`
    /// already never load as canon; none of them has a legal move here, and
    /// inventing one would put this hook above the table every other door
    /// obeys.
    ///
    /// Returns the skills it staled.
    pub(crate) fn mark_dependent_skills_stale_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mutation_recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        let dependents = dependent_skills_in_txn(&self.store, &*wtxn, deleted)?;
        let mut staled = Vec::with_capacity(dependents.len());
        for skill in dependents {
            let Some((record, occurred)) =
                read_live_skill_record_in_txn(&self.store, wtxn, &skill)?
            else {
                // The cited skill left the active store while its row lingered.
                // Prune as we read: the index is a cache, and a row nothing can
                // answer for is the one kind that never becomes true again.
                SOURCE_INDEX.delete(&self.store, wtxn, &(*deleted, skill))?;
                continue;
            };
            if !record
                .lifecycle_status
                .can_transition(SkillLifecycle::Stale)
            {
                continue;
            }
            let note = match record.lifecycle_status {
                // Already stale: this is another source lost in the SAME
                // episode, so the note grows and the record is left alone —
                // re-encoding an unchanged body would mint an entity revision
                // that says nothing new.
                SkillLifecycle::Stale => {
                    let mut note = self.read_stale_note_in_txn(wtxn, &skill)?;
                    if !note.deleted_refs.contains(deleted) {
                        note.deleted_refs.push(*deleted);
                    }
                    note
                }
                // A fresh episode REPLACES the note: the refs of an episode the
                // owner already reversed are history, not causes of this one.
                _ => {
                    let mut staled_record = record.clone();
                    staled_record.lifecycle_status = SkillLifecycle::Stale;
                    validate_skill_update(&record, &staled_record)?;
                    let data = encode_skill_record(&staled_record)?;
                    // `occurred` is preserved and only `learned_at` moves: the
                    // skill did not happen again, this vault merely learned its
                    // evidence is gone.
                    self.apply_skill_record_body(
                        wtxn,
                        &skill,
                        occurred,
                        mutation_recorded_at,
                        data,
                        false,
                    )?;
                    SkillStaleNote {
                        reason: STALE_REASON_SOURCE_MESSAGE_DELETED.to_owned(),
                        deleted_refs: vec![*deleted],
                    }
                }
            };
            STALE_NOTE.put(&self.store, wtxn, &skill, &note)?;
            staled.push(skill);
        }
        Ok(staled)
    }

    fn read_stale_note_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        skill: &EntityId,
    ) -> Result<SkillStaleNote> {
        Ok(match STALE_NOTE.get(&self.store, wtxn, skill)? {
            Some(note) => note,
            None => SkillStaleNote {
                reason: STALE_REASON_SOURCE_MESSAGE_DELETED.to_owned(),
                deleted_refs: Vec::new(),
            },
        })
    }
}

fn dependent_skills_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    source: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(SOURCE_INDEX
        .scan_keys(store, rtxn, source.as_bytes())?
        .into_iter()
        .map(|(_, skill)| skill)
        .collect())
}

/// The SKILL record behind `id` plus its `occurred` range, or `None` when the
/// entity is gone or holds a body this fold cannot read (a soft-erased 25-byte
/// shell, a non-SKILL id, a legacy-opaque body).
fn read_live_skill_record_in_txn(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<(SkillRecord, TimeRange)>> {
    let Some(raw) = store.port_entity_record(txn, id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    let Ok(record) = crate::skill::decode_skill_record(&raw.body) else {
        return Ok(None);
    };
    Ok(Some((
        record,
        TimeRange {
            start: raw.occurred.start,
            end: raw.occurred.end,
        },
    )))
}

fn encode_stale_note(note: &SkillStaleNote) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(STALE_NOTE_REASON_KEY),
            Value::from(note.reason.as_str()),
        ),
        (
            Value::from(STALE_NOTE_DELETED_REFS_KEY),
            Value::Array(
                note.deleted_refs
                    .iter()
                    .map(|reference| Value::from(reference.to_hex()))
                    .collect(),
            ),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidSkillBody(
            "stale note MessagePack encode failed",
        ))
    })?;
    Ok(bytes)
}

fn decode_stale_note(bytes: &[u8]) -> Result<SkillStaleNote> {
    const CONTEXT: &str = "skill stale note";
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) else {
        return Err(Error::CorruptedIndex(CONTEXT));
    };
    let entry = |wanted: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(wanted))
            .map(|(_, value)| value)
    };
    let reason = entry(STALE_NOTE_REASON_KEY)
        .and_then(Value::as_str)
        .ok_or(Error::CorruptedIndex(CONTEXT))?
        .to_owned();
    let Some(Value::Array(refs)) = entry(STALE_NOTE_DELETED_REFS_KEY) else {
        return Err(Error::CorruptedIndex(CONTEXT));
    };
    let deleted_refs = refs
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(CONTEXT))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SkillStaleNote {
        reason,
        deleted_refs,
    })
}
