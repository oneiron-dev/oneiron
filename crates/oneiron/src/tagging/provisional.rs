//! Provisional entities: what a save mints when the identity key names
//! nothing (ARCH-0055 §10), for the Dreamer to resolve.
//!
//! A provisional entity is local like the tags (owner ruling 2026-10-08,
//! card 3 = A). It is a row of `vault_meta`, never an entity row, so sync
//! never carries it and another device of the vault never sees it. Its name
//! is indexed beside it the way the engine's identity index keys a name, so
//! the next lookup of the same key finds it instead of minting a twin. The
//! Dreamer's or an actor's confirmation makes the real, synced entity, under
//! the same id, or names an existing entity in its place.

#[cfg(feature = "sync")]
use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::tags;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, TimeRange, Vault};

/// A provisional entity. Key: its id.
const PROVISIONAL: SideTable<EntityId, ProvisionalEntity, Named> =
    SideTable::new(&side_table::TAGGING_PROVISIONAL);
/// Its name, keyed as the identity index keys a hint. Key: kind byte,
/// `blake3(hint)`, id.
const PROVISIONAL_HINT: SideTable<([u8; 1], [u8; 32], EntityId), (), Raw> =
    SideTable::new(&side_table::TAGGING_PROVISIONAL_HINT);

/// A cold entity a save minted, waiting for the Dreamer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionalEntity {
    pub kind: u8,
    /// The text of a span that keys to it, in [`Self::origin`].
    pub name: String,
    /// The turn that span is in. When that turn no longer names the entity,
    /// another turn that does takes its place; when none does, the entity
    /// is retired.
    pub origin: EntityId,
    /// The facet of the turn it was minted from: a derivation is born under
    /// its source's facet (ARCH-0022).
    pub facet: Option<EntityId>,
    /// Store-clock seconds of the mint.
    pub minted_at: u64,
}

impl Vault {
    /// Holds `id` as a provisional entity named `name`, from the turn
    /// `origin`, as a save mints one. For fixtures outside this module.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn hold_provisional_id_for_test(
        &self,
        id: &EntityId,
        name: &str,
        origin: &EntityId,
    ) -> Result<()> {
        let entity = ProvisionalEntity {
            kind: crate::registry::ENTITY_TYPE_PERSON,
            name: name.to_owned(),
            origin: *origin,
            facet: None,
            minted_at: 1,
        };
        self.with_write_txn(|txn| mint_in_txn(&self.store, txn, id, &entity))
    }

    /// A provisional entity, while it is one and the text its name came from
    /// reads.
    pub fn provisional_entity(&self, id: &EntityId) -> Result<Option<ProvisionalEntity>> {
        let txn = self.store.env.read_txn()?;
        let Some(entity) = PROVISIONAL.get(&self.store, &txn, id)? else {
            return Ok(None);
        };
        Ok(tags::origin_reads_in_txn(&self.store, &txn, &entity.origin, id)?.then_some(entity))
    }

    /// Up to `limit` provisional entities in id order, after `after`, each
    /// while the text its name came from reads: the Dreamer's worklist.
    pub fn provisional_entities(
        &self,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<(EntityId, ProvisionalEntity)>> {
        let txn = self.store.env.read_txn()?;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut found = Vec::new();
        for row in PROVISIONAL.iter_range(&self.store, &txn, start, Bound::Unbounded)? {
            if found.len() == limit {
                break;
            }
            let (id, entity) = row?;
            if tags::origin_reads_in_txn(&self.store, &txn, &entity.origin, &id)? {
                found.push((id, entity));
            }
        }
        Ok(found)
    }
}

impl Memory<'_> {
    /// Confirms a provisional entity: the real entity is born under its id,
    /// named by the text a turn still holds for it, and syncs as any entity
    /// does. Every tag set that named the provisional entity now names the
    /// real one. A provisional entity no readable text names any more is not
    /// found: no copy of a deleted name becomes synced truth.
    pub fn confirm_provisional_entity(&self, id: &EntityId) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            if !confirm_in_txn(self.vault(), txn, id)? {
                return Err(MemoryError::not_found("no provisional entity"));
            }
            Ok(())
        })
    }

    /// Confirms that a provisional entity is the existing entity `into`:
    /// every tag set that named it names `into` instead, and it is retired.
    pub fn resolve_provisional_entity(&self, id: &EntityId, into: &EntityId) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            let Some(entity) = PROVISIONAL.get(&self.vault().store, txn, id)? else {
                return Err(MemoryError::not_found("no provisional entity"));
            };
            if !super::save::linkable_in_txn(&self.vault().store, txn, into, entity.kind)? {
                return Err(MemoryError::bad_request(
                    "a provisional entity resolves into a live or archived entity of its kind",
                ));
            }
            tags::redirect_in_txn(&self.vault().store, txn, id, *into)?;
            retire_in_txn(&self.vault().store, txn, id)?;
            Ok(())
        })
    }
}

pub(super) fn get_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ProvisionalEntity>> {
    PROVISIONAL.get(store, txn, id)
}

pub(super) fn exists_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    PROVISIONAL.contains(store, txn, id)
}

/// The provisional entities of `kind` whose name keys as `mention` does.
pub(super) fn lookup_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    kind: u8,
    mention: &str,
) -> Result<Vec<EntityId>> {
    let digest = crate::ingest::identity_hint_digest(mention);
    let mut prefix = vec![kind];
    prefix.extend_from_slice(&digest);
    let mut found = Vec::new();
    for (_, _, id) in PROVISIONAL_HINT.scan_keys(store, txn, &prefix)? {
        // The index is checked against the row it points at, as the
        // identity index is checked against the record.
        if PROVISIONAL.get(store, txn, &id)?.is_some_and(|entity| {
            entity.kind == kind && crate::ingest::identity_hint_digest(&entity.name) == digest
        }) {
            found.push(id);
        }
    }
    Ok(found)
}

pub(super) fn mint_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity: &ProvisionalEntity,
) -> Result<()> {
    PROVISIONAL.put(store, txn, id, entity)?;
    PROVISIONAL_HINT.put(store, txn, &hint_key(entity, id), &())?;
    Ok(())
}

/// Removes a provisional entity and its name from the index. The tag sets
/// that name it are the caller's.
pub(super) fn retire_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(entity) = PROVISIONAL.get(store, txn, id)? else {
        return Ok(false);
    };
    PROVISIONAL_HINT.delete(store, txn, &hint_key(&entity, id))?;
    PROVISIONAL.delete(store, txn, id)?;
    Ok(true)
}

/// Settles a provisional entity after a tag set that named it changed. One
/// whose origin turn still names it is left as it is: one index read. One
/// whose origin turn no longer does moves to the first turn that names it by
/// a span keyed to its name, and takes that span's text; when no such span
/// is left, it is taken out of every tag set and retired, so no copy of a
/// name outlives the text it came from. One no tag set names is retired.
pub(super) fn settle_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let store = &vault.store;
    let Some(entity) = PROVISIONAL.get(store, txn, id)? else {
        return Ok(());
    };
    if tags::names_in_txn(store, txn, id, &entity.origin)? {
        return Ok(());
    }
    rehome_in_txn(vault, txn, id, entity)?;
    Ok(())
}

/// A provisional entity with the name a turn's readable text holds for it,
/// read in the caller's transaction: its origin's text, or else the first
/// turn's whose text names it by a span keyed to its name, which becomes its
/// origin. `None` when no readable text names it: it is then taken out of
/// every tag set and retired.
fn sourced_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<ProvisionalEntity>> {
    let Some(mut entity) = PROVISIONAL.get(&vault.store, txn, id)? else {
        return Ok(None);
    };
    let digest = crate::ingest::identity_hint_digest(&entity.name);
    if let Some(name) = tags::keyed_text_in_txn(vault, txn, &entity.origin, id, &digest)? {
        entity.name = name;
        return Ok(Some(entity));
    }
    rehome_in_txn(vault, txn, id, entity)
}

/// Moves `entity` to the first turn, in id order, whose text names it by a
/// span keyed to its name, and takes that span's text; with none left, takes
/// it out of every tag set and retires it, so no copy of a name outlives the
/// text it came from.
fn rehome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    mut entity: ProvisionalEntity,
) -> Result<Option<ProvisionalEntity>> {
    let store = &vault.store;
    let digest = crate::ingest::identity_hint_digest(&entity.name);
    let mut after = None;
    while let Some(turn) = tags::next_ref_in_txn(store, txn, id, after.as_ref())? {
        if let Some(name) = tags::keyed_text_in_txn(vault, txn, &turn, id, &digest)? {
            entity.origin = turn;
            entity.name = name;
            PROVISIONAL.put(store, txn, id, &entity)?;
            return Ok(Some(entity));
        }
        after = Some(turn);
    }
    tags::strip_in_txn(store, txn, id)?;
    retire_in_txn(store, txn, id)?;
    Ok(None)
}

/// A provisional id is held until it is confirmed, resolved or retired, so
/// an entity write never lands under one, except a replicated one. A
/// replicated row came from another device, which never saw this one's
/// provisional entities: the synced row stands, and the local entity leaves
/// every tag set and is retired. The put runs this past every check that can
/// reject the row remotely, since a rejected replicated put is quarantined
/// and its transaction commits: a row that never lands takes nothing.
pub(crate) fn release_held_id_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if PROVISIONAL.contains(store, txn, id)? {
        tags::strip_in_txn(store, txn, id)?;
        retire_in_txn(store, txn, id)?;
    }
    Ok(())
}

/// Refuses a local write under a provisional id, reading only: a session
/// overlay stages through this, so a row promote would replay into base is
/// refused before it is staged.
pub(crate) fn refuse_held_id_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if PROVISIONAL.contains(dbs, txn, id)? {
        return Err(Error::InvariantViolation(
            "an entity write names a provisional entity's id",
        ));
    }
    Ok(())
}

fn hint_key(entity: &ProvisionalEntity, id: &EntityId) -> ([u8; 1], [u8; 32], EntityId) {
    (
        [entity.kind],
        crate::ingest::identity_hint_digest(&entity.name),
        *id,
    )
}

/// Resolves the provisional entity `id` into the live or archived entity
/// `into` of its kind, in the caller's transaction: every tag set that named
/// it names `into`, and it is retired. The identity re-check's settle
/// (OF-123); `false` when `id` is no provisional entity or `into` is none it
/// may resolve into.
pub(crate) fn resolve_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    into: &EntityId,
) -> Result<bool> {
    let Some(entity) = PROVISIONAL.get(&vault.store, txn, id)? else {
        return Ok(false);
    };
    if !super::save::linkable_in_txn(&vault.store, txn, into, entity.kind)? {
        return Ok(false);
    }
    tags::redirect_in_txn(&vault.store, txn, id, *into)?;
    retire_in_txn(&vault.store, txn, id)?;
    Ok(true)
}

/// Confirms the provisional entity `id` in the caller's transaction, as
/// [`Memory::confirm_provisional_entity`] does: the real entity is born
/// under its id, named by the text a turn still holds for it. The identity
/// re-check's "someone new" (OF-123); `false` when `id` is no provisional
/// entity or no readable text names it any more.
pub(crate) fn confirm_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if !PROVISIONAL.contains(&vault.store, txn, id)? {
        return Ok(false);
    }
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, id)? {
        return Err(Error::InvariantViolation(
            "a provisional id names an entity row",
        ));
    }
    let Some(entity) = sourced_in_txn(vault, txn, id)? else {
        return Ok(false);
    };
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![("name".into(), entity.name.as_str().into())]),
    )
    .map_err(|_| Error::InvariantViolation("provisional entity encoding"))?;
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let at = TimeRange {
        start: entity.minted_at,
        end: entity.minted_at,
    };
    retire_in_txn(&vault.store, txn, id)?;
    vault
        .batch_in()
        .put(id, entity.kind, at, now, &body)
        .apply(txn)?;
    Ok(true)
}

/// Mints a provisional entity named `name` from the turn `origin`, for a
/// span the identity re-check found to be someone new (OF-123): local and
/// unsynced, under the turn's facet, as a save mints one.
pub(crate) fn mint_for_span_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    kind: u8,
    name: &str,
    origin: EntityId,
    now: u64,
) -> Result<EntityId> {
    let id = vault.new_entity_id()?;
    crate::ports::persist_id_floor_in_txn(&vault.store, txn)?;
    let facet = crate::federation::record_scope::birth_facet(&vault.store, txn, origin)?;
    mint_in_txn(
        &vault.store,
        txn,
        &id,
        &ProvisionalEntity {
            kind,
            name: name.to_owned(),
            origin,
            facet,
            minted_at: now,
        },
    )?;
    Ok(id)
}

/// The provisional entity `id`, while it is one.
pub(crate) fn provisional_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ProvisionalEntity>> {
    PROVISIONAL.get(store, txn, id)
}

/// How a window demotion settles a provisional entity whose origin TURN it
/// removes (OF-534).
#[cfg(feature = "sync")]
enum Demoted {
    /// No kept tag set names it and no legal hold stands on it: it goes.
    Retire,
    /// A kept turn whose tag set still reads names it by a span keyed to its
    /// name: that turn becomes its origin, and that span's text its name.
    Rehome(EntityId, String),
    /// A kept tag set or a hold needs it, and no kept turn's text can take
    /// it over: it stays, and so does its origin turn.
    KeepOrigin,
}

/// The removed TURNs a window demotion keeps whole (OF-534): each is the
/// origin of a provisional entity a kept tag set or a legal hold still
/// needs, which no kept turn's text can take over. `gone` is every member
/// the demotion removes; `partial` the kept turns that lose a MESSAGE to
/// it, whose words read partly here until promotion. Reads only.
#[cfg(feature = "sync")]
pub(crate) fn demotion_kept_origins_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    gone: &BTreeSet<EntityId>,
    partial: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut kept = BTreeSet::new();
    for turn in gone {
        let Some(set) = tags::tag_set_in_txn(store, txn, turn)? else {
            continue;
        };
        for id in set.entities() {
            let Some(entity) = PROVISIONAL.get(store, txn, &id)? else {
                continue;
            };
            if entity.origin == *turn
                && matches!(
                    demoted_in_txn(store, txn, &id, &entity, gone, partial)?,
                    Demoted::KeepOrigin
                )
            {
                kept.insert(*turn);
                break;
            }
        }
    }
    Ok(kept)
}

/// The tagging half of a window demotion (OF-534), in the remover's
/// transaction before any row or edge of `gone` goes: each removed TURN
/// loses its tag set and its own mention index rows, and each provisional
/// entity whose origin it was is settled against the kept turns alone. One
/// no kept set names and no hold protects is retired; one a kept turn's
/// readable text names by a span keyed to its name moves there. A kept
/// turn is never retagged and keeps its stored set: while a MESSAGE it was
/// read from is away, the set reads as absent. Run it after
/// [`demotion_kept_origins_in_txn`], with those origins left out of `gone`.
#[cfg(feature = "sync")]
pub(crate) fn demote_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    gone: &BTreeSet<EntityId>,
    partial: &BTreeSet<EntityId>,
) -> Result<()> {
    let mut named = BTreeSet::new();
    for turn in gone {
        named.extend(tags::drop_demoted_set_in_txn(store, txn, turn)?);
    }
    for id in named {
        let Some(mut entity) = PROVISIONAL.get(store, txn, &id)? else {
            continue;
        };
        if !gone.contains(&entity.origin) {
            continue;
        }
        match demoted_in_txn(store, txn, &id, &entity, gone, partial)? {
            Demoted::Retire => {
                retire_in_txn(store, txn, &id)?;
            }
            // The name keys as before, so its index row stands.
            Demoted::Rehome(origin, name) => {
                entity.origin = origin;
                entity.name = name;
                PROVISIONAL.put(store, txn, &id, &entity)?;
            }
            Demoted::KeepOrigin => {}
        }
    }
    Ok(())
}

/// How a demotion that removes `gone` settles the provisional entity `id`.
/// A kept turn that names it needs it; one whose words the demotion leaves
/// partial is no new origin, nor is one whose tag set will not read.
#[cfg(feature = "sync")]
fn demoted_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity: &ProvisionalEntity,
    gone: &BTreeSet<EntityId>,
    partial: &BTreeSet<EntityId>,
) -> Result<Demoted> {
    let digest = crate::ingest::identity_hint_digest(&entity.name);
    let mut needed = crate::store::legal_hold::held_in_txn(store, txn, id.as_bytes())?;
    let mut after = None;
    while let Some(turn) = tags::next_ref_in_txn(store, txn, id, after.as_ref())? {
        after = Some(turn);
        if gone.contains(&turn) {
            continue;
        }
        needed = true;
        if partial.contains(&turn) {
            continue;
        }
        if let Some(name) = keyed_text_in_store(store, txn, &turn, id, &digest, gone)? {
            return Ok(Demoted::Rehome(turn, name));
        }
    }
    Ok(if needed {
        Demoted::KeepOrigin
    } else {
        Demoted::Retire
    })
}

/// The text of a span in `turn` linked to `entity` whose own text keys to
/// `digest`, read through the store alone (the remover holds no vault):
/// the check [`rehome_in_txn`] makes, for a live TURN whose tag set reads
/// and keeps reading once the members in `gone` are removed. Each message
/// is read as the tagger reads it: live, its words not withdrawn, its
/// document's text in its body, shown.
#[cfg(feature = "sync")]
fn keyed_text_in_store(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    entity: &EntityId,
    digest: &[u8; 32],
    gone: &BTreeSet<EntityId>,
) -> Result<Option<String>> {
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
    use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
    let Some(set) = tags::readable_in_txn(store, txn, turn)? else {
        return Ok(None);
    };
    let live_turn = matches!(
        live_entity_row_in_txn(store, txn, turn)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TURN
    );
    if !live_turn || set.messages.iter().any(|message| gone.contains(message)) {
        return Ok(None);
    }
    for mention in &set.mentions {
        if !mention.link.entities().contains(entity) || !set.messages.contains(&mention.message) {
            continue;
        }
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(store, txn, &mention.message)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_MESSAGE
            || !crate::ports::body_readable_in_txn(
                store,
                txn,
                &mention.message,
                &body,
                crate::ports::BodyStale::Withdrawn,
            )?
        {
            continue;
        }
        let body = crate::entity_doc::resolve_record_body(store, txn, &mention.message, &body)?;
        let Some(text) = super::input::shown_message_text(&body) else {
            continue;
        };
        let Some(span) = text.get(mention.start..mention.end).map(str::trim) else {
            continue;
        };
        if !span.is_empty() && crate::ingest::identity_hint_digest(span) == *digest {
            return Ok(Some(span.to_owned()));
        }
    }
    Ok(None)
}
