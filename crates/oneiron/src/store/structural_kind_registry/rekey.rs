//! One-shot byte-space v3 type-byte migration over entities, type_index, counters, and registry rows.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{StructuralKindRegistration, zone_of};
use crate::store::{RawDatabases, short_id_counter_key};

use super::registry::{
    build_structural_kind_registry, decode_structural_kind_registration_for_rekey,
    encode_structural_kind_registration, structural_kind_registry_key,
};

/// One kind's move in the byte-space v3 persisted re-key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypeByteRekey {
    pub kind: &'static str,
    pub old: u8,
    pub new: u8,
}

/// The ONE atomic byte-space v3 map.
///
/// `old` is the LANDING-BASE constant audited on this branch, NOT canon's
/// `byteMigrationV3.oldByte` — canon records the docs lineage, and two rows
/// diverge from what the engine actually persisted: ACCESS_GRANT's lineage is
/// null while the engine shipped 128, and CONNECTOR_KEY's lineage is 128 while
/// the engine shipped 135. `new` is canon and binds absolutely.
///
/// Sources and destinations OVERLAP on 64 and 80–84: COMPANION_REGISTER
/// vacates 64 into REDACTION_AUDIT's destination, and TASK_LIST/TASK/MACHINE/
/// CODE_ARTIFACT/CODE_SYMBOL vacate 80–84 into COUNTERPARTY_CONTACT/
/// OUTBOUND_GRANT/PERSONA_SNAPSHOT_EXPORT/COMM_RECORD/SKILL_CONTENT_ANCHOR.
/// That overlap is exactly why the pass stages every source row in memory,
/// deletes all source keys, and only then writes destinations — a per-kind
/// migration would clobber live rows halfway through.
///
/// IDENTITY_TOPOLOGY_EVENT (76) and SECRET_CUSTODY (77) are absent on purpose:
/// they already sat at their canon bytes, so there is nothing to move.
pub(crate) const TYPE_BYTE_REKEY_V3: &[TypeByteRekey] = &[
    TypeByteRekey {
        kind: "REDACTION_AUDIT",
        old: 120,
        new: 64,
    },
    TypeByteRekey {
        kind: "MODEL",
        old: 121,
        new: 65,
    },
    TypeByteRekey {
        kind: "AUTHORITY_LOG",
        old: 122,
        new: 66,
    },
    TypeByteRekey {
        kind: "POLICY_MANIFEST",
        old: 123,
        new: 67,
    },
    TypeByteRekey {
        kind: "FEDERATION_GRANT",
        old: 124,
        new: 68,
    },
    TypeByteRekey {
        kind: "CONNECTOR_KEY",
        old: 135,
        new: 70,
    },
    TypeByteRekey {
        kind: "PSYCH_PROFILE",
        old: 129,
        new: 71,
    },
    TypeByteRekey {
        kind: "ACCESS_GRANT",
        old: 128,
        new: 73,
    },
    TypeByteRekey {
        kind: "COMPANION_REGISTER",
        old: 64,
        new: 78,
    },
    TypeByteRekey {
        kind: "CHANNEL_IDENTITY",
        old: 131,
        new: 79,
    },
    TypeByteRekey {
        kind: "COUNTERPARTY_CONTACT",
        old: 132,
        new: 80,
    },
    TypeByteRekey {
        kind: "OUTBOUND_GRANT",
        old: 133,
        new: 81,
    },
    TypeByteRekey {
        kind: "PERSONA_SNAPSHOT_EXPORT",
        old: 134,
        new: 82,
    },
    TypeByteRekey {
        kind: "COMM_RECORD",
        old: 136,
        new: 83,
    },
    TypeByteRekey {
        kind: "SKILL_CONTENT_ANCHOR",
        old: 138,
        new: 84,
    },
    TypeByteRekey {
        kind: "TASK_LIST",
        old: 80,
        new: 100,
    },
    TypeByteRekey {
        kind: "TASK",
        old: 81,
        new: 101,
    },
    TypeByteRekey {
        kind: "MACHINE",
        old: 82,
        new: 102,
    },
    TypeByteRekey {
        kind: "CODE_ARTIFACT",
        old: 83,
        new: 103,
    },
    TypeByteRekey {
        kind: "CODE_SYMBOL",
        old: 84,
        new: 104,
    },
    TypeByteRekey {
        kind: "BLOB_ARTIFACT",
        old: 85,
        new: 105,
    },
    TypeByteRekey {
        kind: "NOTE",
        old: 86,
        new: 106,
    },
];

/// What the byte-space v3 pass actually moved. Returned so the caller can log
/// it and so tests can assert on real work rather than a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RekeyCounts {
    pub entities: usize,
    pub type_index: usize,
    pub short_id_counters: usize,
    pub kind_registrations: usize,
    /// Registry rows the map does not move, rewritten in place at the current
    /// record version. Counted apart from `kind_registrations` because nothing
    /// relocates: only the record format advances.
    pub kind_registrations_rezoned: usize,
}

/// Everything one kind contributes to the re-key, staged before any write.
#[derive(Default)]
struct StagedKind {
    entities: Vec<(EntityId, Vec<u8>)>,
    type_index_ids: BTreeSet<EntityId>,
    short_id_counter: Option<Vec<u8>>,
    kind_registration: Option<StructuralKindRegistration>,
}

fn rekey_corrupt(context: &'static str) -> Error {
    Error::CorruptedIndex(context)
}

/// Executes the byte-space v3 persisted type-byte re-key inside the caller's
/// write transaction.
///
/// Only PERSISTED TYPE-BYTE FIELDS move: byte 0 of each `entities` envelope,
/// the leading byte of each `type_index` key, the `sid_counter:<byte>` keys,
/// and the structural-kind registry records whose own byte is in the map.
/// Entity ids are the `entities` keys and do not encode a type byte, so those
/// rows are patched in place — ids, timestamps, hashes, MessagePack bodies,
/// vectors and CRDT payloads are never rewritten. Edge keys and values carry
/// entity ids and edge data, never endpoint type bytes, so `edges_out` /
/// `edges_in` are not touched at all; the caller asserts their totals are
/// unchanged.
///
/// FAIL-CLOSED: every anomaly — a destination byte already occupied by rows
/// this map does not vacate, a duplicate source or destination, an envelope
/// too short to carry a type byte, an entity/type-index count or id-set
/// mismatch, or a short-id-counter collision — returns `Err`. The caller runs
/// this inside the open-path transaction and stamps the new ABI only on `Ok`,
/// so any abort rolls the whole transaction back and leaves the old bytes and
/// the old stamp intact: the vault stays openable by the predecessor engine.
pub(crate) fn rekey_type_bytes_v3_in_txn(
    dbs: &RawDatabases,
    txn: &mut RwTxn<'_>,
    map: &[TypeByteRekey],
) -> Result<RekeyCounts> {
    let mut sources = BTreeMap::new();
    let mut destinations = BTreeMap::new();
    for entry in map {
        if sources.insert(entry.old, entry.kind).is_some() {
            return Err(rekey_corrupt("byte-space v3 duplicate migration source"));
        }
        if destinations.insert(entry.new, entry.kind).is_some() {
            return Err(rekey_corrupt(
                "byte-space v3 duplicate migration destination",
            ));
        }
    }

    // ---- stage every source row, touching nothing ----
    let mut staged: BTreeMap<u8, StagedKind> = BTreeMap::new();
    for entry in map {
        staged.entry(entry.old).or_default();
    }

    // A destination that this map does not also vacate must be EMPTY. Byte 64
    // and 80-84 are legitimately occupied right now precisely because they are
    // sources; anything else holding rows means the map disagrees with the
    // vault and the whole pass aborts.
    let mut occupied_destinations: BTreeSet<u8> = BTreeSet::new();

    for row in dbs.entities.iter(txn)? {
        let (key, value) = row?;
        let type_byte = *value
            .first()
            .ok_or_else(|| rekey_corrupt("byte-space v3 malformed entity envelope"))?;
        if value.len() < ENTITY_METADATA_HEADER_LEN {
            return Err(rekey_corrupt("byte-space v3 malformed entity envelope"));
        }
        if !sources.contains_key(&type_byte) {
            if destinations.contains_key(&type_byte) {
                occupied_destinations.insert(type_byte);
            }
            continue;
        }
        let id = EntityId::from_bytes(
            key.try_into()
                .map_err(|_| rekey_corrupt("byte-space v3 entity key"))?,
        )
        .map_err(|_| rekey_corrupt("byte-space v3 entity key"))?;
        staged
            .get_mut(&type_byte)
            .expect("staged entry exists for every source byte")
            .entities
            .push((id, value.to_vec()));
    }

    for row in dbs.type_index.iter(txn)? {
        let (key, _) = row?;
        let type_byte = *key
            .first()
            .ok_or_else(|| rekey_corrupt("byte-space v3 type index key"))?;
        if !sources.contains_key(&type_byte) {
            if destinations.contains_key(&type_byte) {
                occupied_destinations.insert(type_byte);
            }
            continue;
        }
        let id = crate::vault::entity_id_from_type_index_key(key)?;
        if !staged
            .get_mut(&type_byte)
            .expect("staged entry exists for every source byte")
            .type_index_ids
            .insert(id)
        {
            return Err(rekey_corrupt("byte-space v3 duplicate type index row"));
        }
    }

    for entry in map {
        let staged_kind = staged
            .get_mut(&entry.old)
            .expect("staged entry exists for every source byte");
        staged_kind.short_id_counter = dbs
            .vault_meta
            .get(txn, &short_id_counter_key(entry.old))?
            .map(<[u8]>::to_vec);
        staged_kind.kind_registration = dbs
            .vault_meta
            .get(txn, &structural_kind_registry_key(entry.old))?
            .map(|raw| {
                decode_structural_kind_registration_for_rekey(
                    &structural_kind_registry_key(entry.old),
                    raw,
                )
            })
            .transpose()?;

        // Destinations this map does not vacate must be clear in vault_meta too.
        if !sources.contains_key(&entry.new) {
            if dbs
                .vault_meta
                .get(txn, &short_id_counter_key(entry.new))?
                .is_some()
            {
                return Err(rekey_corrupt("byte-space v3 short-id counter collision"));
            }
            if dbs
                .vault_meta
                .get(txn, &structural_kind_registry_key(entry.new))?
                .is_some()
            {
                return Err(rekey_corrupt("byte-space v3 kind registry collision"));
            }
        }
    }

    if let Some(byte) = occupied_destinations.first() {
        tracing::error!(
            type_byte = byte,
            "byte-space v3 destination already holds rows this map does not vacate"
        );
        return Err(rekey_corrupt("byte-space v3 destination collision"));
    }

    // Per-kind pre-counts: an entity envelope without its type-index row (or
    // vice versa) means the source data is already inconsistent, and re-keying
    // it would launder that inconsistency into the new ABI.
    for entry in map {
        let staged_kind = &staged[&entry.old];
        let entity_ids: BTreeSet<EntityId> =
            staged_kind.entities.iter().map(|(id, _)| *id).collect();
        if entity_ids.len() != staged_kind.entities.len() {
            return Err(rekey_corrupt("byte-space v3 duplicate entity id"));
        }
        if entity_ids != staged_kind.type_index_ids {
            tracing::error!(
                kind = entry.kind,
                entities = entity_ids.len(),
                type_index = staged_kind.type_index_ids.len(),
                "byte-space v3 entity/type-index id sets disagree"
            );
            return Err(rekey_corrupt("byte-space v3 entity/type-index mismatch"));
        }
    }

    let expected = RekeyCounts {
        entities: staged.values().map(|kind| kind.entities.len()).sum(),
        type_index: staged.values().map(|kind| kind.type_index_ids.len()).sum(),
        short_id_counters: staged
            .values()
            .filter(|kind| kind.short_id_counter.is_some())
            .count(),
        kind_registrations: staged
            .values()
            .filter(|kind| kind.kind_registration.is_some())
            .count(),
        // Nothing is staged for the in-place rewrite: it visits whatever the
        // map leaves behind, so its count is discovered, not predicted, and it
        // is filled in after this equality holds.
        kind_registrations_rezoned: 0,
    };

    // ---- delete every source key ----
    // `entities` is absent here on purpose: its key is the entity id, which
    // carries no type byte, so those rows are patched in place below rather
    // than deleted and re-inserted under a new key.
    for entry in map {
        let staged_kind = &staged[&entry.old];
        for id in &staged_kind.type_index_ids {
            let mut key = [0u8; 17];
            key[0] = entry.old;
            key[1..].copy_from_slice(id.as_bytes());
            if !dbs.type_index.delete(txn, &key)? {
                return Err(rekey_corrupt("byte-space v3 type index delete"));
            }
        }
        if staged_kind.short_id_counter.is_some() {
            dbs.vault_meta
                .delete(txn, &short_id_counter_key(entry.old))?;
        }
        if staged_kind.kind_registration.is_some() {
            dbs.vault_meta
                .delete(txn, &structural_kind_registry_key(entry.old))?;
        }
    }

    // ---- write every destination ----
    let mut written = RekeyCounts::default();
    for entry in map {
        let staged_kind = &staged[&entry.old];
        for (id, value) in &staged_kind.entities {
            let mut patched = value.clone();
            patched[0] = entry.new;
            dbs.entities.put(txn, id.as_bytes(), &patched)?;
            written.entities += 1;
        }
        for id in &staged_kind.type_index_ids {
            let mut key = [0u8; 17];
            key[0] = entry.new;
            key[1..].copy_from_slice(id.as_bytes());
            dbs.type_index.put(txn, &key, &[])?;
            written.type_index += 1;
        }
        if let Some(counter) = &staged_kind.short_id_counter {
            dbs.vault_meta
                .put(txn, &short_id_counter_key(entry.new), counter)?;
            written.short_id_counters += 1;
        }
        if let Some(registration) = &staged_kind.kind_registration {
            let moved = StructuralKindRegistration {
                type_byte: entry.new,
                short_id_prefix: registration.short_id_prefix.clone(),
                // The zone is a pure function of the byte, so it is re-derived
                // rather than carried: a moved row must not keep a zone code
                // describing where it used to live.
                zone: zone_of(entry.new),
                pack: registration.pack.clone(),
            };
            dbs.vault_meta.put(
                txn,
                &structural_kind_registry_key(entry.new),
                &encode_structural_kind_registration(&moved)?,
            )?;
            written.kind_registrations += 1;
        }
    }

    if written != expected {
        return Err(rekey_corrupt("byte-space v3 write count mismatch"));
    }

    // ---- rewrite every registry row this map does NOT move ----
    // A pre-v3 vault could dynamically register a pack anywhere in the old
    // companion/productivity/CRM bands, so rows outside the map are legitimate
    // and common. Their persisted byte-2 discriminant is a six-band ordinal
    // read off a table v3 replaced, so leaving them alone does not preserve
    // them — it silently redefines them. Every surviving row is written back at
    // the current record version with its zone re-derived from its byte, the
    // same rule the moved rows above follow.
    let mut survivors = Vec::new();
    for byte in u8::MIN..=u8::MAX {
        if destinations.contains_key(&byte) {
            // Written by this pass already, at the current version.
            continue;
        }
        let key = structural_kind_registry_key(byte);
        if let Some(raw) = dbs.vault_meta.get(txn, &key)? {
            survivors.push((
                key,
                decode_structural_kind_registration_for_rekey(&key, raw)?,
            ));
        }
    }
    for (key, registration) in survivors {
        let rezoned = StructuralKindRegistration {
            zone: zone_of(registration.type_byte),
            ..registration
        };
        dbs.vault_meta
            .put(txn, &key, &encode_structural_kind_registration(&rezoned)?)?;
        written.kind_registrations_rezoned += 1;
    }

    // ---- the migrated registry must LOAD ----
    // `load_structural_kind_registry` runs after the open transaction commits,
    // so any row it rejects would otherwise be rejected against a vault already
    // stamped at the new ABI — unopenable by this engine AND by its
    // predecessor. Running the loader's own rules here turns that into an
    // ordinary abort with the old bytes and old stamp intact.
    let mut migrated_rows = Vec::new();
    for byte in u8::MIN..=u8::MAX {
        let key = structural_kind_registry_key(byte);
        if let Some(raw) = dbs.vault_meta.get(txn, &key)? {
            migrated_rows.push((key.to_vec(), raw.to_vec()));
        }
    }
    build_structural_kind_registry(&migrated_rows)?;

    // ---- post-assertions: destinations hold exactly what was staged, and no
    // source row survives ----
    let mut destination_entities: BTreeMap<u8, BTreeSet<EntityId>> = BTreeMap::new();
    for row in dbs.entities.iter(txn)? {
        let (key, value) = row?;
        let type_byte = *value
            .first()
            .ok_or_else(|| rekey_corrupt("byte-space v3 malformed entity envelope"))?;
        if sources.contains_key(&type_byte) && !destinations.contains_key(&type_byte) {
            return Err(rekey_corrupt("byte-space v3 source row survived"));
        }
        if destinations.contains_key(&type_byte) {
            let id = EntityId::from_bytes(
                key.try_into()
                    .map_err(|_| rekey_corrupt("byte-space v3 entity key"))?,
            )
            .map_err(|_| rekey_corrupt("byte-space v3 entity key"))?;
            destination_entities
                .entry(type_byte)
                .or_default()
                .insert(id);
        }
    }
    let mut destination_index: BTreeMap<u8, BTreeSet<EntityId>> = BTreeMap::new();
    for row in dbs.type_index.iter(txn)? {
        let (key, _) = row?;
        let type_byte = *key
            .first()
            .ok_or_else(|| rekey_corrupt("byte-space v3 type index key"))?;
        if sources.contains_key(&type_byte) && !destinations.contains_key(&type_byte) {
            return Err(rekey_corrupt("byte-space v3 source index row survived"));
        }
        if destinations.contains_key(&type_byte) {
            destination_index
                .entry(type_byte)
                .or_default()
                .insert(crate::vault::entity_id_from_type_index_key(key)?);
        }
    }
    for entry in map {
        let staged_ids: BTreeSet<EntityId> = staged[&entry.old]
            .entities
            .iter()
            .map(|(id, _)| *id)
            .collect();
        let landed = destination_entities.remove(&entry.new).unwrap_or_default();
        let landed_index = destination_index.remove(&entry.new).unwrap_or_default();
        if landed != staged_ids || landed_index != staged_ids {
            tracing::error!(
                kind = entry.kind,
                old = entry.old,
                new = entry.new,
                staged = staged_ids.len(),
                landed = landed.len(),
                landed_index = landed_index.len(),
                "byte-space v3 destination id set does not match staged source"
            );
            return Err(rekey_corrupt("byte-space v3 destination count mismatch"));
        }
    }

    Ok(written)
}
