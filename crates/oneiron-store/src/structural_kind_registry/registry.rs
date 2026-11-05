//! Vault-scoped structural-kind registry core: keys, record codec, load and rebuild, and registration vet rules.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::str;

use heed::{Env, RoTxn, RwTxn};

use crate::overlay_db::OverlayDb;
use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::RegistryError;
use oneiron_base::error::Result;
use oneiron_base::registry::StructuralKindRegistration;
use oneiron_base::registry::TypeByteFamily;
use oneiron_base::registry::TypeByteZone;
use oneiron_base::registry::allocate_type_byte;
use oneiron_base::registry::entity_type_registry_entry;
use oneiron_base::registry::short_id_prefix;
use oneiron_base::registry::static_short_id_prefix_collision;
use oneiron_base::registry::validate_entity_type as validate_static_entity_type;
use oneiron_base::registry::validate_public_entity_type as validate_static_public_entity_type;
use oneiron_base::registry::zone_of;
use oneiron_contracts::record_layout::EntityMetadataHeader;

/// Current record version: v3 appends an explicit optional family code to
/// the v2 `(type_byte, zone, prefix, pack)` record. A spilled kind retains its
/// declared family; it is never rediscovered from its byte. The ABI17-to-18
/// migration upgrades v2 rows. Older v1 records fail closed.
pub const STRUCTURAL_KIND_REGISTRY_RECORD_VERSION: u8 = 3;

const STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN: usize = 6;

impl RawValue for StructuralKindRegistration {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_structural_kind_registration(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_structural_kind_registration_value(bytes)?)
    }
}

pub fn encode_structural_kind_registration(
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
    encoded.push(registration.family.map_or(0, TypeByteFamily::code));
    Ok(encoded)
}

/// The value-only half of [`decode_structural_kind_registration`]: every
/// check that reads `raw` alone, with no key to cross-check against. This is
/// the [`RawValue`] decode for [`REGISTRY`]: the typed door decodes a key and
/// a value independently, so the key/type-byte cross-check that used to live
/// in one function now runs at each call site that has both in hand.
pub fn decode_structural_kind_registration_value(raw: &[u8]) -> Result<StructuralKindRegistration> {
    if raw.len() < STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN
        || raw.first() != Some(&STRUCTURAL_KIND_REGISTRY_RECORD_VERSION)
    {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }

    let type_byte = raw[1];
    let zone = type_byte_zone_from_code(raw[2])
        .ok_or(Error::CorruptedIndex("structural kind registry"))?;
    let prefix_len = raw[3] as usize;
    let pack_len = u16::from_le_bytes(
        raw[4..6]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("structural kind registry"))?,
    ) as usize;
    let expected_len = STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN + prefix_len + pack_len + 1;
    if raw.len() != expected_len {
        return Err(Error::CorruptedIndex("structural kind registry"));
    }
    let prefix_start = STRUCTURAL_KIND_REGISTRY_RECORD_HEADER_LEN;
    let pack_start = prefix_start + prefix_len;
    let short_id_prefix = str::from_utf8(&raw[prefix_start..pack_start])
        .map_err(|_| Error::CorruptedIndex("structural kind registry"))?
        .to_owned();
    let pack = str::from_utf8(&raw[pack_start..pack_start + pack_len])
        .map_err(|_| Error::CorruptedIndex("structural kind registry"))?
        .to_owned();

    Ok(StructuralKindRegistration {
        type_byte,
        short_id_prefix,
        zone,
        pack,
        family: match raw[expected_len - 1] {
            0 => None,
            code => Some(
                TypeByteFamily::from_code(code)
                    .ok_or(Error::CorruptedIndex("structural kind family"))?,
            ),
        },
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
