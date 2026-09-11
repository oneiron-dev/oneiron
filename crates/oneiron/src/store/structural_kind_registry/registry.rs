//! Vault-scoped structural-kind registry core: keys, record codec, load and rebuild, and registration vet rules.

use std::collections::{HashMap, HashSet};
use std::str;

use heed::{Env, RwTxn};

use crate::batch::secret_scan;
use crate::companion::{
    COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX, ENTITY_TYPE_COMPANION_REGISTER,
};
use crate::error::RegistryError;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::registry::{
    StructuralKindRegistration, TypeByteZone, entity_type_registry_entry, short_id_prefix,
    static_short_id_prefix_collision, validate_entity_type as validate_static_entity_type,
    validate_public_entity_type as validate_static_public_entity_type, zone_of,
};
use crate::store::Store;

/// `vault_meta` key prefix for vault-scoped dynamic StructuralKind
/// registrations. The full key is `b"kind_reg:"` followed by the raw type
/// byte; the value is a versioned record carrying `(type_byte,
/// short_id_prefix, zone, pack)`.
pub(crate) const STRUCTURAL_KIND_REGISTRY_KEY_PREFIX: &[u8] = b"kind_reg:";

const STRUCTURAL_KIND_REGISTRY_KEY_LEN: usize = 10;

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
pub(in crate::store) const STRUCTURAL_KIND_REGISTRY_RECORD_VERSION_PRE_V3: u8 = 1;

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
            return Err(Error::Registry(
                RegistryError::StructuralKindTypeByteCollision(type_byte),
            ));
        }
        if static_short_id_prefix_collision(&registration.short_id_prefix) {
            return Err(Error::Registry(
                RegistryError::StructuralKindPrefixCollision(registration.short_id_prefix),
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
            return Err(Error::Registry(
                RegistryError::StructuralKindTypeByteCollision(type_byte),
            ));
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
            return Err(Error::Registry(
                RegistryError::StructuralKindPrefixCollision(registration.short_id_prefix),
            ));
        }

        self.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        registry.insert(type_byte, registration.clone());
        Ok(registration)
    }
}

pub(in crate::store) fn load_structural_kind_registry(
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
pub(super) fn build_structural_kind_registry(
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
        return Err(Error::Registry(
            RegistryError::InvalidStructuralKindRegistration(
                "short_id_prefix must be exactly two lowercase ASCII letters",
            ),
        ));
    }
    if registration.pack.is_empty() {
        return Err(Error::Registry(
            RegistryError::InvalidStructuralKindRegistration("pack must not be empty"),
        ));
    }
    if registration.pack.len() > u16::MAX as usize {
        return Err(Error::Registry(
            RegistryError::InvalidStructuralKindRegistration("pack must fit in u16 bytes"),
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
        return Err(Error::Registry(
            RegistryError::StructuralKindZoneViolation {
                type_byte: registration.type_byte,
                declared_zone: registration.zone,
                actual_zone,
                reason: "type byte is outside the declared zone",
            },
        ));
    }
    Ok(())
}

fn vet_structural_kind_registration_zone(registration: &StructuralKindRegistration) -> Result<()> {
    vet_structural_kind_registration_zone_consistency(registration)?;
    let actual_zone = zone_of(registration.type_byte);
    let violation = |reason: &'static str| {
        Error::Registry(RegistryError::StructuralKindZoneViolation {
            type_byte: registration.type_byte,
            declared_zone: registration.zone,
            actual_zone,
            reason,
        })
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

pub(super) fn encode_structural_kind_registration(
    registration: &StructuralKindRegistration,
) -> Result<Vec<u8>> {
    let prefix = registration.short_id_prefix.as_bytes();
    let pack = registration.pack.as_bytes();
    let pack_len = u16::try_from(pack.len()).map_err(|_| {
        Error::Registry(RegistryError::InvalidStructuralKindRegistration(
            "pack must fit in u16 bytes",
        ))
    })?;

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

pub(in crate::store) fn decode_structural_kind_registration(
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
pub(super) fn decode_structural_kind_registration_for_rekey(
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
