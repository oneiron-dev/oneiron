//! Admission projection (SECRET-02, SOL-1920-04): the borrowing reader of
//! a stored custody body the lease doors admit through, never a value copy.

use rmpv::ValueRef;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::store::Store;

use super::super::codec::{SECRET_CUSTODY_SEALED_VALUE_KEY, invalid_body};
use super::super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_STORED_SCHEMA_VERSION,
    SecretBinding, SecretCustodyStatus,
};

/// The admission projection of a custody record: every field SECRET-02's
/// lease doors need to ADMIT and to drive T2, and nothing else. Has no
/// value field by construction — admission never heap-copies plaintext;
/// the ONE value decode is the bound door [`crate::Vault::get_secret_value_in_txn`]
/// itself (its caller wraps the bytes in `Zeroizing`). Raw-record access is
/// not broadened: the full decode stays behind
/// [`super::read_secret_custody_in_txn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretCustodyAdmission {
    /// The secret name.
    pub(crate) name: String,
    /// The custody class.
    pub(crate) class: CustodyClass,
    /// Lifecycle status.
    pub(crate) status: SecretCustodyStatus,
    /// Rotation generation counter (the S6 staleness signal leases stamp).
    pub(crate) rotation_generation: u32,
    /// Effector bindings.
    pub(crate) bindings: Vec<SecretBinding>,
    /// Manifest-declared local paths (the T2 target set).
    pub(crate) declared_paths: Vec<String>,
}

impl SecretCustodyAdmission {
    /// Looks up the binding covering `effector` — mirrors
    /// [`super::super::SecretCustodyRecord::binding_for`], drives tier admission.
    #[must_use]
    pub(crate) fn binding_for(&self, effector: &str) -> Option<&SecretBinding> {
        self.bindings.iter().find(|b| b.effector == effector)
    }
}

/// The borrowing half of [`required_value`]: a MISSING or DUPLICATED key
/// both yield `None`, over [`ValueRef`] entries.
fn required_value_ref<'a, 'b>(
    entries: &'b [(ValueRef<'a>, ValueRef<'a>)],
    key: &str,
) -> Option<&'b ValueRef<'a>> {
    let mut found = None;
    for (k, v) in entries {
        if let ValueRef::String(s) = k
            && s.as_str() == Some(key)
        {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

/// A string field out of a borrowing value, tied to the body buffer.
fn str_ref<'a>(value: &ValueRef<'a>, reason: &'static str) -> Result<&'a str> {
    match value {
        ValueRef::String(s) => s.into_str().ok_or(invalid_body(reason)),
        _ => Err(invalid_body(reason)),
    }
}

/// An integer field out of a borrowing value (the owned codec's `as_u64`
/// discipline: u64 direct, else a non-negative i64).
fn u64_ref(value: &ValueRef<'_>, reason: &'static str) -> Result<u64> {
    match value {
        ValueRef::Integer(n) => n
            .as_u64()
            .or_else(|| n.as_i64().and_then(|v| u64::try_from(v).ok()))
            .ok_or(invalid_body(reason)),
        _ => Err(invalid_body(reason)),
    }
}

/// The borrowing half of [`binding_from_value`].
fn binding_from_value_ref(value: &ValueRef<'_>) -> Result<SecretBinding> {
    let ValueRef::Map(entries) = value else {
        return Err(invalid_body("binding must be a map"));
    };
    let effector = str_ref(
        required_value_ref(entries, "effector").ok_or(invalid_body("binding effector"))?,
        "binding effector",
    )?
    .to_owned();
    let tier_raw = u64_ref(
        required_value_ref(entries, "tier_ceiling").ok_or(invalid_body("binding tier_ceiling"))?,
        "binding tier_ceiling",
    )?;
    let tier_ceiling = CustodyTier::from_u8(
        u8::try_from(tier_raw).map_err(|_| invalid_body("binding tier_ceiling"))?,
    )
    .ok_or(invalid_body("binding tier_ceiling"))?;
    let scopes = match required_value_ref(entries, "scopes") {
        Some(ValueRef::Array(items)) => {
            let mut scopes = Vec::with_capacity(items.len());
            for item in items {
                scopes.push(str_ref(item, "binding scope")?.to_owned());
            }
            scopes
        }
        Some(_) => return Err(invalid_body("binding scopes must be an array")),
        None => Vec::new(),
    };
    Ok(SecretBinding {
        effector,
        tier_ceiling,
        scopes,
    })
}

/// Decodes the admission projection from a stored custody body WITHOUT
/// materializing the value: the borrowing MessagePack reader leaves
/// `sealed_value` a slice of the LMDB-resident page, so the admission path
/// holds no heap copy of the value at all (SOL-1920-04). The keys the doors
/// consume validate with the same missing-or-duplicated reject discipline
/// as [`decode_secret_custody_body`], and the value slot as the strict
/// stored decoder reads it (KS-6, FIX-LIST 9246 item 2): the stored schema,
/// exactly one binary `sealed_value`, and no `value_bytes` slot; keys the
/// doors never read stay the full codec's affair (registration already ran
/// it).
pub(crate) fn decode_secret_custody_admission_body(bytes: &[u8]) -> Result<SecretCustodyAdmission> {
    use std::io::Cursor;

    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value_ref(&mut cursor)
        .map_err(|_| invalid_body("decode secret custody body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_body("trailing bytes after secret custody body"));
    }
    let ValueRef::Map(entries) = value else {
        return Err(invalid_body("secret custody body must be a map"));
    };
    // A value rests sealed under the stored stamp, or not at all: a body
    // with a plaintext slot, even one a duplicate hides, is no stored body
    // (KS-6, no old-format reader). The sealed bytes stay a borrow of the
    // store page.
    let schema = u64_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[0])
            .ok_or(invalid_body("schema_version"))?,
        "schema_version",
    )?;
    if schema != u64::from(SECRET_CUSTODY_STORED_SCHEMA_VERSION) {
        return Err(invalid_body("unsupported secret custody schema version"));
    }
    let plaintext_slot = entries.iter().any(|(key, _)| {
        matches!(key, ValueRef::String(s) if s.as_str() == Some(SECRET_CUSTODY_BODY_KEYS[4]))
    });
    if plaintext_slot
        || !matches!(
            required_value_ref(&entries, SECRET_CUSTODY_SEALED_VALUE_KEY),
            Some(ValueRef::Binary(_))
        )
    {
        return Err(invalid_body("value_bytes"));
    }
    let name = str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[1]).ok_or(invalid_body("name"))?,
        "name",
    )?
    .to_owned();
    let class = CustodyClass::parse(str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[2]).ok_or(invalid_body("class"))?,
        "class",
    )?)
    .ok_or(invalid_body("class"))?;
    let status = SecretCustodyStatus::parse(str_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[5]).ok_or(invalid_body("status"))?,
        "status",
    )?)
    .ok_or(invalid_body("status"))?;
    let rotation_generation = u32::try_from(u64_ref(
        required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[8])
            .ok_or(invalid_body("rotation_generation"))?,
        "rotation_generation",
    )?)
    .map_err(|_| invalid_body("rotation_generation"))?;
    let bindings = match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[9]) {
        Some(ValueRef::Array(items)) => {
            let mut bindings = Vec::with_capacity(items.len());
            for item in items {
                bindings.push(binding_from_value_ref(item)?);
            }
            bindings
        }
        Some(_) => return Err(invalid_body("bindings must be an array")),
        None => return Err(invalid_body("bindings")),
    };
    let declared_paths = match required_value_ref(&entries, SECRET_CUSTODY_BODY_KEYS[11]) {
        Some(ValueRef::Array(items)) => {
            let mut paths = Vec::with_capacity(items.len());
            for item in items {
                paths.push(str_ref(item, "declared_path")?.to_owned());
            }
            paths
        }
        Some(_) => return Err(invalid_body("declared_paths must be an array")),
        None => return Err(invalid_body("declared_paths")),
    };
    Ok(SecretCustodyAdmission {
        name,
        class,
        status,
        rotation_generation,
        bindings,
        declared_paths,
    })
}

/// Reads the admission projection under either txn kind — the doors of
/// SECRET-02 resolve this instead of the full record (SOL-1920-04). It
/// decodes the record where the transaction holds it, so the value bytes are
/// never copied out.
pub(crate) fn read_secret_custody_admission_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyAdmission>> {
    store.port_entity_with_raw(txn, id, |raw| {
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            return Err(Error::CorruptedIndex("secret custody entity header"));
        };
        if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
            return Err(Error::CorruptedIndex("secret custody entity type"));
        }
        decode_secret_custody_admission_body(&raw[ENTITY_METADATA_HEADER_LEN..])
    })
}
