//! Vault-scoped dynamic entity-type/kind registry: registration, load and
//! rebuild, zone validation, and the type-byte re-key migration.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str;

use heed::{Env, RwTxn};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, secret_scan};
use crate::companion::{
    COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::registry::{
    StructuralKindRegistration, TypeByteZone, entity_type_registry_entry, short_id_prefix,
    static_short_id_prefix_collision, validate_entity_type as validate_static_entity_type,
    validate_public_entity_type as validate_static_public_entity_type, zone_of,
};

use super::*;

/// `vault_meta` key prefix for vault-scoped dynamic StructuralKind
/// registrations. The full key is `b"kind_reg:"` followed by the raw type
/// byte; the value is a versioned record carrying `(type_byte,
/// short_id_prefix, zone, pack)`.
pub(crate) const STRUCTURAL_KIND_REGISTRY_KEY_PREFIX: &[u8] = b"kind_reg:";

pub(crate) const STRUCTURAL_KIND_REGISTRY_KEY_LEN: usize = 10;

const _: () =
    assert!(STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len() + 1 == STRUCTURAL_KIND_REGISTRY_KEY_LEN);

/// Current record version. Byte 2 is a [`TypeByteZone`] ordinal.
///
/// Advanced for byte-space v3 (ONE-1754) because the meaning of byte 2 changed
/// underneath a fixed layout: version 1 carried the pre-v3 SIX-BAND ordinal
/// (Companion 2, Productivity 3, CRM 4), and the v3 zone table reads those same
/// codes as System, CompiledProduct and EngineExperimental. Two record formats
/// sharing one version number is how a stale row gets silently reinterpreted
/// instead of loudly rejected, so the version moves with the table.
pub(crate) const STRUCTURAL_KIND_REGISTRY_RECORD_VERSION: u8 = 2;

/// The pre-v3 record version. Readable ONLY by the byte-space v3 re-key, which
/// is the one place a version-1 row legitimately exists, and which never
/// interprets its byte 2 — the zone is a pure function of the type byte.
const STRUCTURAL_KIND_REGISTRY_RECORD_VERSION_PRE_V3: u8 = 1;

const STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN: usize = 6;

pub(crate) fn structural_kind_registry_key(
    type_byte: u8,
) -> [u8; STRUCTURAL_KIND_REGISTRY_KEY_LEN] {
    let mut key = [0u8; STRUCTURAL_KIND_REGISTRY_KEY_LEN];
    key[..STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len()]
        .copy_from_slice(STRUCTURAL_KIND_REGISTRY_KEY_PREFIX);
    key[STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len()] = type_byte;
    key
}

impl Store {
    pub(crate) fn structural_kind_registration(
        &self,
        type_byte: u8,
    ) -> Option<StructuralKindRegistration> {
        let registry = self
            .kind_registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.get(&type_byte).cloned()
    }

    pub(crate) fn structural_kind_registrations(&self) -> Vec<StructuralKindRegistration> {
        let registry = self
            .kind_registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries: Vec<StructuralKindRegistration> = registry.values().cloned().collect();
        entries.sort_by_key(|entry| entry.type_byte);
        entries
    }

    /// Static validation, then vault-scoped dynamic registrations.
    ///
    /// A persisted dynamic row may only widen inside the ONE zone that admits
    /// dynamic registration. This is what makes the done-means true: a STALE
    /// row naming a byte in 128-247 — written before the pack half was closed,
    /// or forged — cannot make this gate (or any public write riding it) pass,
    /// because the zone is consulted before the registry, not after.
    pub(crate) fn validate_entity_type(&self, entity_type: u8) -> Result<()> {
        if validate_static_entity_type(entity_type).is_ok() {
            return Ok(());
        }
        if zone_of(entity_type) == TypeByteZone::CompiledProduct
            && self.structural_kind_registration(entity_type).is_some()
        {
            return Ok(());
        }
        Err(Error::InvalidEntityType(entity_type))
    }

    pub(crate) fn validate_public_entity_type(&self, entity_type: u8) -> Result<()> {
        if entity_type_registry_entry(entity_type).is_some() {
            return validate_static_public_entity_type(entity_type);
        }
        self.validate_entity_type(entity_type)
    }

    pub(crate) fn short_id_prefix(&self, entity_type: u8) -> Result<String> {
        if let Ok(prefix) = short_id_prefix(entity_type) {
            return Ok(prefix.to_owned());
        }
        self.structural_kind_registration(entity_type)
            .map(|entry| entry.short_id_prefix)
            .ok_or(Error::InvalidEntityType(entity_type))
    }

    pub(crate) fn register_structural_kind(
        &self,
        type_byte: u8,
        short_id_prefix: impl Into<String>,
        zone: TypeByteZone,
        pack: impl Into<String>,
    ) -> Result<StructuralKindRegistration> {
        let registration = StructuralKindRegistration {
            type_byte,
            short_id_prefix: short_id_prefix.into(),
            zone,
            pack: pack.into(),
        };
        vet_structural_kind_registration_shape(&registration)?;
        vet_structural_kind_registration_zone(&registration)?;
        secret_scan::scan_metadata_field(&registration.pack)?;
        if entity_type_registry_entry(type_byte).is_some() {
            return Err(Error::StructuralKindTypeByteCollision(type_byte));
        }
        if static_short_id_prefix_collision(&registration.short_id_prefix) {
            return Err(Error::StructuralKindPrefixCollision(
                registration.short_id_prefix,
            ));
        }

        let key = structural_kind_registry_key(type_byte);
        let encoded = encode_structural_kind_registration(&registration)?;
        let mut wtxn = self.env.write_txn()?;
        let mut registry = self
            .kind_registry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if registry.contains_key(&type_byte) || self.vault_meta.get(&wtxn, &key)?.is_some() {
            return Err(Error::StructuralKindTypeByteCollision(type_byte));
        }
        if registry
            .values()
            .any(|entry| entry.short_id_prefix == registration.short_id_prefix)
            || vault_meta_has_structural_kind_prefix(
                &self.vault_meta,
                &wtxn,
                &registration.short_id_prefix,
            )?
        {
            return Err(Error::StructuralKindPrefixCollision(
                registration.short_id_prefix,
            ));
        }

        self.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        registry.insert(type_byte, registration.clone());
        Ok(registration)
    }
}

pub(super) fn load_structural_kind_registry(
    env: &Env,
    vault_meta: &OverlayDb,
) -> Result<HashMap<u8, StructuralKindRegistration>> {
    let rtxn = env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault_meta.prefix_iter(&rtxn, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)? {
        let (key, value) = row?;
        rows.push((key.to_vec(), value.to_vec()));
    }
    drop(rtxn);
    build_structural_kind_registry(&rows)
}

/// Turns persisted registry rows into the runtime registry, applying every
/// load-time rule.
///
/// Split out from [`load_structural_kind_registry`] so the byte-space v3 re-key
/// can run the SAME rules against the rows it is about to commit. The loader
/// runs after the open transaction commits, so without this the re-key could
/// stamp the new ABI over a registry the very next statement rejects — a vault
/// neither engine can open.
fn build_structural_kind_registry(
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<HashMap<u8, StructuralKindRegistration>> {
    let mut registry = HashMap::new();
    let mut prefixes = HashSet::new();
    for (key, value) in rows {
        let registration = decode_structural_kind_registration(key, value)?;
        vet_structural_kind_registration_shape(&registration)
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?;
        vet_structural_kind_registration_zone_consistency(&registration)
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?;
        if entity_type_registry_entry(registration.type_byte).is_some()
            || static_short_id_prefix_collision(&registration.short_id_prefix)
        {
            if is_compatible_legacy_companion_register_row(&registration) {
                continue;
            }
            if is_post_dynamic_static_collision(&registration) {
                // Forward-compat, not corruption (OF-368 ARTL-1 review): the
                // row was written while its byte/prefix was legitimately
                // dynamically registrable and a LATER engine release claimed
                // it statically. The static definition wins for the byte;
                // the persisted row stays in vault_meta untouched, and its
                // prefix stays reserved here so no new dynamic pack can mint
                // short ids colliding with rows already written under it.
                prefixes.insert(registration.short_id_prefix.clone());
                continue;
            }
            return Err(Error::CorruptedIndex("structural kind registry"));
        }
        if !prefixes.insert(registration.short_id_prefix.clone())
            || registry
                .insert(registration.type_byte, registration)
                .is_some()
        {
            return Err(Error::CorruptedIndex("structural kind registry"));
        }
    }
    Ok(registry)
}

/// Static kinds whose type byte (and short-id prefix) were claimed by a
/// release AFTER older releases already accepted arbitrary dynamic
/// registrations of them. A persisted dynamic row colliding with one of
/// these is legacy data from that window — tolerated at load, never
/// corruption. COMPANION_REGISTER is deliberately NOT in this set: its
/// static claim shipped together with dynamic registration itself, so only
/// its own exact legacy shape (handled separately above) can exist
/// legitimately and anything else at byte 64 stays fail-closed.
const POST_DYNAMIC_STATIC_KIND_BYTES: &[u8] = &[crate::registry::ENTITY_TYPE_BLOB_ARTIFACT];

fn is_post_dynamic_static_collision(registration: &StructuralKindRegistration) -> bool {
    POST_DYNAMIC_STATIC_KIND_BYTES.contains(&registration.type_byte)
        || POST_DYNAMIC_STATIC_KIND_BYTES.iter().any(|byte| {
            entity_type_registry_entry(*byte).and_then(|entry| entry.short_id_prefix)
                == Some(registration.short_id_prefix.as_str())
        })
}

fn is_compatible_legacy_companion_register_row(registration: &StructuralKindRegistration) -> bool {
    registration.type_byte == ENTITY_TYPE_COMPANION_REGISTER
        && registration.short_id_prefix == COMPANION_REGISTER_SHORT_ID_PREFIX
        && registration.zone == TypeByteZone::System
        && registration.pack == COMPANION_REGISTER_PACK_ID
}

fn vault_meta_has_structural_kind_prefix(
    vault_meta: &OverlayDb,
    txn: &RwTxn<'_>,
    short_id_prefix: &str,
) -> Result<bool> {
    for row in vault_meta.prefix_iter(txn, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)? {
        let (key, value) = row?;
        let registration = decode_structural_kind_registration(&key, &value)?;
        if registration.short_id_prefix == short_id_prefix {
            return Ok(true);
        }
    }
    Ok(false)
}

fn vet_structural_kind_registration_shape(registration: &StructuralKindRegistration) -> Result<()> {
    let prefix = registration.short_id_prefix.as_bytes();
    if prefix.len() != 2 || !prefix.iter().all(u8::is_ascii_lowercase) {
        return Err(Error::InvalidStructuralKindRegistration(
            "short_id_prefix must be exactly two lowercase ASCII letters",
        ));
    }
    if registration.pack.is_empty() {
        return Err(Error::InvalidStructuralKindRegistration(
            "pack must not be empty",
        ));
    }
    if registration.pack.len() > u16::MAX as usize {
        return Err(Error::InvalidStructuralKindRegistration(
            "pack must fit in u16 bytes",
        ));
    }
    Ok(())
}

/// Vets a dynamic StructuralKind registration against the v3 zone map.
///
/// Byte-space v3 narrows this hard. Pre-v3 a pack could dynamically register
/// anywhere in the companion, productivity, or CRM bands. Under v3 the ONLY
/// production-registrable zone is compiled-product 100–125: the system zone is
/// engine-authored, and the pack half is PackByteMap's, so admitting either
/// here would make `register_structural_kind` an accidental PackByteMap —
/// exactly the hole this ticket closes. The two experimental zones are
/// development-mode only, matching `validate_entity_type_for_mode`.
/// Zone CONSISTENCY only: the declared zone must be the byte's zone.
///
/// This is the load-time rule. Whether a zone is REGISTRABLE is a write-path
/// question (`vet_structural_kind_registration_zone`), and applying it at load
/// would reject rows the loader is about to tolerate or ignore — a persisted
/// row's admissibility was settled when it was written, not on every open.
/// Nothing is widened by loading such a row: `Store::validate_entity_type`
/// only honours dynamic registrations inside the compiled-product zone.
fn vet_structural_kind_registration_zone_consistency(
    registration: &StructuralKindRegistration,
) -> Result<()> {
    let actual_zone = zone_of(registration.type_byte);
    if actual_zone != registration.zone {
        return Err(Error::StructuralKindZoneViolation {
            type_byte: registration.type_byte,
            declared_zone: registration.zone,
            actual_zone,
            reason: "type byte is outside the declared zone",
        });
    }
    Ok(())
}

fn vet_structural_kind_registration_zone(registration: &StructuralKindRegistration) -> Result<()> {
    vet_structural_kind_registration_zone_consistency(registration)?;
    let actual_zone = zone_of(registration.type_byte);
    let violation = |reason: &'static str| Error::StructuralKindZoneViolation {
        type_byte: registration.type_byte,
        declared_zone: registration.zone,
        actual_zone,
        reason,
    };
    match actual_zone {
        TypeByteZone::CompiledProduct => Ok(()),
        // Engine-half experimental is development-only, exactly like
        // `validate_entity_type_for_mode`. The PACK-half experimental zone is
        // deliberately NOT mirrored here: the whole pack half is PackByteMap's,
        // and a dev-mode door into 248–254 would be a static allocation in the
        // half that must never carry one.
        TypeByteZone::EngineExperimental => {
            if cfg!(debug_assertions) {
                Ok(())
            } else {
                Err(violation("the experimental zone is development-mode only"))
            }
        }
        TypeByteZone::Semantic | TypeByteZone::Core => {
            Err(violation("semantic and CORE bytes are reserved"))
        }
        TypeByteZone::System => Err(violation("the system zone is engine-authored")),
        TypeByteZone::PackHandle | TypeByteZone::PackExperimental => Err(violation(
            "the pack half belongs to PackByteMap, not static registration",
        )),
        TypeByteZone::Sentinel => Err(violation("255 is the reserved sentinel")),
    }
}

fn encode_structural_kind_registration(
    registration: &StructuralKindRegistration,
) -> Result<Vec<u8>> {
    let prefix = registration.short_id_prefix.as_bytes();
    let pack = registration.pack.as_bytes();
    let pack_len = u16::try_from(pack.len())
        .map_err(|_| Error::InvalidStructuralKindRegistration("pack must fit in u16 bytes"))?;

    let mut encoded =
        Vec::with_capacity(STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN + prefix.len() + pack.len());
    encoded.push(STRUCTURAL_KIND_REGISTRY_RECORD_VERSION);
    encoded.push(registration.type_byte);
    encoded.push(type_byte_zone_code(registration.zone));
    encoded.push(u8::try_from(prefix.len()).expect("prefix length vetted as two bytes"));
    encoded.extend_from_slice(&pack_len.to_le_bytes());
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(pack);
    Ok(encoded)
}

fn decode_structural_kind_registration(
    key: &[u8],
    raw: &[u8],
) -> Result<StructuralKindRegistration> {
    decode_structural_kind_registration_inner(key, raw, false)
}

/// Reads a record written by EITHER ABI, for the byte-space v3 re-key alone.
///
/// A pre-v3 row's byte 2 is a six-band ordinal off a table that no longer
/// exists, so it is never interpreted: the predecessor engine enforced
/// `band == band_of(type_byte)` on every open, which makes the type byte the
/// authority and the zone a re-derivation. The re-key writes every row back at
/// the current version before the new ABI is stamped.
fn decode_structural_kind_registration_for_rekey(
    key: &[u8],
    raw: &[u8],
) -> Result<StructuralKindRegistration> {
    decode_structural_kind_registration_inner(key, raw, true)
}

fn decode_structural_kind_registration_inner(
    key: &[u8],
    raw: &[u8],
    accept_pre_v3: bool,
) -> Result<StructuralKindRegistration> {
    let version_accepted = raw.first().is_some_and(|version| {
        *version == STRUCTURAL_KIND_REGISTRY_RECORD_VERSION
            || (accept_pre_v3 && *version == STRUCTURAL_KIND_REGISTRY_RECORD_VERSION_PRE_V3)
    });
    if key.len() != STRUCTURAL_KIND_REGISTRY_KEY_LEN
        || !key.starts_with(STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)
        || raw.len() < STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN
        || !version_accepted
    {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }

    let type_byte = raw[1];
    if key[STRUCTURAL_KIND_REGISTRY_KEY_PREFIX.len()] != type_byte {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }
    let zone = if raw[0] == STRUCTURAL_KIND_REGISTRY_RECORD_VERSION {
        type_byte_zone_from_code(raw[2]).ok_or(Error::CorruptedIndex("structural kind registry"))?
    } else {
        zone_of(type_byte)
    };
    let prefix_len = raw[3] as usize;
    let pack_len = u16::from_le_bytes(
        raw[4..6]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?,
    ) as usize;
    let expected_len = STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN + prefix_len + pack_len;
    if raw.len() != expected_len {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }
    let prefix_start = STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN;
    let pack_start = prefix_start + prefix_len;
    let short_id_prefix = str::from_utf8(&raw[prefix_start..pack_start])
        .map_err(|_| Error::CorruptedIndex("structural kind registry"))?
        .to_owned();
    let pack = str::from_utf8(&raw[pack_start..])
        .map_err(|_| Error::CorruptedIndex("structural kind registry"))?
        .to_owned();

    Ok(StructuralKindRegistration {
        type_byte,
        short_id_prefix,
        zone,
        pack,
    })
}

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

/// Persisted zone discriminant for a structural-kind registry record.
///
/// These are the v3 zone ordinals. The pre-v3 six-band codes are gone with the
/// ABI bump, and the ONE-1754 re-key rewrites every surviving row.
fn type_byte_zone_code(zone: TypeByteZone) -> u8 {
    match zone {
        TypeByteZone::Semantic => 0,
        TypeByteZone::Core => 1,
        TypeByteZone::System => 2,
        TypeByteZone::CompiledProduct => 3,
        TypeByteZone::EngineExperimental => 4,
        TypeByteZone::PackHandle => 5,
        TypeByteZone::PackExperimental => 6,
        TypeByteZone::Sentinel => 7,
    }
}

fn type_byte_zone_from_code(code: u8) -> Option<TypeByteZone> {
    match code {
        0 => Some(TypeByteZone::Semantic),
        1 => Some(TypeByteZone::Core),
        2 => Some(TypeByteZone::System),
        3 => Some(TypeByteZone::CompiledProduct),
        4 => Some(TypeByteZone::EngineExperimental),
        5 => Some(TypeByteZone::PackHandle),
        6 => Some(TypeByteZone::PackExperimental),
        7 => Some(TypeByteZone::Sentinel),
        _ => None,
    }
}
