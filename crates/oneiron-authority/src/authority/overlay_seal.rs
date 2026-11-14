//! The erasable overlay of an AUTHORITY_LOG entry (census L5-22; DEC-0005,
//! "verifies without naming"; RULING L5-22-OVERLAY-SCOPE = A).
//!
//! An op leaf that holds a value a person typed or chose
//! ([`super::overlay_classes`]) never rides the log in plaintext. The entry is
//! signed, hashed and stored in its scaffold form: each present such leaf is
//! replaced by a commitment node, a MessagePack ext value of type
//! [`AUTHORITY_OVERLAY_EXT_TYPE`] holding a keyed BLAKE3 hash of the leaf. The
//! leaf values and the seed that keys their commitments are the entry's
//! [`AuthorityOverlayRecord`], kept apart from the log row. Without the record
//! the row's hash and signatures still verify
//! ([`verify_authority_log_entry_scaffold`]), and its commitments name
//! nothing: their key went with the seed.

use std::io::Cursor;

use rmpv::Value;

use crate::error::{Error, RecordError, Result};

use super::*;

/// The MessagePack ext type of a commitment node.
pub const AUTHORITY_OVERLAY_EXT_TYPE: i8 = 0x4f;

/// What [`decode_authority_log_entry_body`] answers for a sealed row whose
/// overlay record it was not given (see [`is_authority_overlay_unavailable`]).
pub const AUTHORITY_OVERLAY_UNAVAILABLE: &str = "authority entry overlay unavailable";

const OVERLAY_LEAF_KEY_CONTEXT: &str = "oneiron authority overlay leaf v1";
const RECORD_KEY_SEED: &str = "seed";
const RECORD_KEY_LEAVES: &str = "leaves";

/// One overlay leaf taken out of an op: its wire path and its value.
#[derive(Clone, PartialEq)]
pub struct OverlayLeaf {
    /// Map keys from the op map's root.
    pub path: Vec<String>,
    /// The plaintext the scaffold commits to.
    pub value: Value,
}

/// An entry's overlay: the seed that keys its commitments and the leaves they
/// commit to. Its Debug shows only the leaf paths.
#[derive(Clone, PartialEq)]
pub struct AuthorityOverlayRecord {
    pub seed: [u8; 32],
    pub leaves: Vec<OverlayLeaf>,
}

impl std::fmt::Debug for OverlayLeaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlayLeaf")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AuthorityOverlayRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityOverlayRecord")
            .field("leaves", &self.leaves)
            .finish_non_exhaustive()
    }
}

/// The error a sealed row gives when its overlay record is absent.
pub fn authority_overlay_unavailable() -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(
        AUTHORITY_OVERLAY_UNAVAILABLE,
    ))
}

/// Whether `error` says a sealed row was read without its overlay record:
/// the row is well formed, and a caller that needs only its scaffold may
/// skip it or read it with [`verify_authority_log_entry_scaffold`].
pub fn is_authority_overlay_unavailable(error: &Error) -> bool {
    matches!(
        error,
        Error::Record(RecordError::InvalidAuthorityLogBody(message))
            if *message == AUTHORITY_OVERLAY_UNAVAILABLE
    )
}

/// A fresh overlay seed for an entry carrying `op`: `Some` exactly when the
/// op has a present overlay leaf, as [`AuthorityLogEntry::validate_shape`]
/// requires. Every door that signs an entry sets it before the transcript.
pub fn authority_overlay_seed_for(op: &AuthorityOp) -> Result<Option<[u8; 32]>> {
    if !op_value_has_overlay_leaf(&op_value(op)) {
        return Ok(None);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|_| Error::InvariantViolation("authority overlay seed: no system randomness"))?;
    Ok(Some(seed))
}

/// Whether the op map `op` has a present overlay leaf.
pub fn op_value_has_overlay_leaf(op: &Value) -> bool {
    let Some(kind) = map_str(op, OP_KEY_KIND) else {
        return false;
    };
    overlay_leaf_classes(kind).any(|class| {
        let (parent, last) = split_class_path(class);
        map_at(op, parent).is_some_and(|parent| {
            !scaffold_by_sibling(parent, class)
                && map_get(parent, last).is_some_and(leaf_is_present)
        })
    })
}

/// Seals the op map `op` under `seed`: every present overlay leaf of the
/// op's kind becomes a commitment node. Returns the scaffold op and the
/// leaves taken out, in table order. An op with no such leaf comes back as
/// it went in.
pub fn seal_op_value(op: &Value, seed: &[u8; 32]) -> (Value, Vec<OverlayLeaf>) {
    let mut sealed = op.clone();
    let mut leaves = Vec::new();
    let Some(kind) = map_str(op, OP_KEY_KIND) else {
        return (sealed, leaves);
    };
    for class in overlay_leaf_classes(kind) {
        let (parent, last) = split_class_path(class);
        let Some(parent) = map_at_mut(&mut sealed, parent) else {
            continue;
        };
        if scaffold_by_sibling(parent, class) {
            continue;
        }
        let Some(slot) = map_get_mut(parent, last) else {
            continue;
        };
        if !leaf_is_present(slot) {
            continue;
        }
        let path: Vec<String> = class.path.iter().map(|key| (*key).to_owned()).collect();
        let commitment = leaf_commitment(seed, &path, slot);
        let value = std::mem::replace(
            slot,
            Value::Ext(AUTHORITY_OVERLAY_EXT_TYPE, commitment.to_vec()),
        );
        leaves.push(OverlayLeaf { path, value });
    }
    (sealed, leaves)
}

/// Opens the scaffold op map `sealed` with `record`: each commitment node
/// takes back the record's leaf at its path once its commitment checks. A
/// node with no leaf, a leaf with no node, or a commitment that does not
/// match fails the whole open.
pub fn open_op_value(sealed: &Value, record: &AuthorityOverlayRecord) -> Result<Value> {
    let mut opened = sealed.clone();
    let mut used = vec![false; record.leaves.len()];
    open_nodes(&mut opened, &mut Vec::new(), record, &mut used)?;
    if used.into_iter().all(|used| used) {
        Ok(opened)
    } else {
        Err(invalid_authority())
    }
}

/// Whether `value` holds a commitment node anywhere.
pub fn contains_overlay_node(value: &Value) -> bool {
    match value {
        Value::Ext(kind, _) => *kind == AUTHORITY_OVERLAY_EXT_TYPE,
        Value::Array(items) => items.iter().any(contains_overlay_node),
        Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| contains_overlay_node(key) || contains_overlay_node(value)),
        _ => false,
    }
}

/// The overlay record of a signed or unsigned entry: `None` when the entry
/// has no seed (so no overlay leaf). This is what the append funnel stores
/// beside the row.
pub fn authority_entry_overlay(
    entry: &AuthorityLogEntry,
) -> Result<Option<AuthorityOverlayRecord>> {
    let Some(seed) = entry.overlay_seed else {
        return Ok(None);
    };
    let (_, leaves) = seal_op_value(&op_value(&entry.op), &seed);
    Ok(Some(AuthorityOverlayRecord { seed, leaves }))
}

/// Canonical bytes of an overlay record.
pub fn encode_authority_overlay_record(record: &AuthorityOverlayRecord) -> Result<Vec<u8>> {
    encode_value(&Value::Map(vec![
        (
            Value::from(RECORD_KEY_SEED),
            Value::Binary(record.seed.to_vec()),
        ),
        (
            Value::from(RECORD_KEY_LEAVES),
            Value::Array(
                record
                    .leaves
                    .iter()
                    .map(|leaf| Value::Array(vec![path_value(&leaf.path), leaf.value.clone()]))
                    .collect(),
            ),
        ),
    ]))
}

/// Decodes canonical overlay record bytes.
pub fn decode_authority_overlay_record(bytes: &[u8]) -> Result<AuthorityOverlayRecord> {
    let value = read_one_value(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &[RECORD_KEY_SEED, RECORD_KEY_LEAVES])?;
    let seed = match required(entries, RECORD_KEY_SEED)? {
        Value::Binary(bytes) => {
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid_authority())?
        }
        _ => return Err(invalid_authority()),
    };
    let Value::Array(items) = required(entries, RECORD_KEY_LEAVES)? else {
        return Err(invalid_authority());
    };
    let mut leaves = Vec::with_capacity(items.len());
    for item in items {
        let Value::Array(pair) = item else {
            return Err(invalid_authority());
        };
        let [Value::Array(path), value] = pair.as_slice() else {
            return Err(invalid_authority());
        };
        let path = path
            .iter()
            .map(|key| {
                key.as_str()
                    .map(str::to_owned)
                    .ok_or_else(invalid_authority)
            })
            .collect::<Result<Vec<_>>>()?;
        if path.is_empty() || !leaf_is_present(value) || contains_overlay_node(value) {
            return Err(invalid_authority());
        }
        leaves.push(OverlayLeaf {
            path,
            value: value.clone(),
        });
    }
    let record = AuthorityOverlayRecord { seed, leaves };
    if encode_authority_overlay_record(&record)? != bytes {
        return Err(invalid_authority());
    }
    Ok(record)
}

/// Whether the stored entry body `bytes` holds a commitment node in its op:
/// a sealed row, which opens only with its overlay record. Nothing is
/// verified here.
///
/// # Errors
/// Bytes that are not one MessagePack value.
pub fn authority_body_is_sealed(bytes: &[u8]) -> Result<bool> {
    let value = read_one_value(bytes)?;
    Ok(map_get(&value, KEY_OP).is_some_and(contains_overlay_node))
}

/// The signed fields of a stored entry, read without its overlay record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityEntryScaffold {
    pub vault_id: Option<AuthorityVaultId>,
    pub seq: u64,
    pub parent_hashes: Vec<AuthorityEntryHash>,
    /// The op map's `kind`.
    pub op_kind: String,
    pub signer: AuthoritySignature,
    pub cosigns: Vec<AuthoritySignature>,
    pub ts: u64,
    /// Whether the row holds a commitment node (so it has an overlay).
    pub sealed: bool,
    /// [`authority_entry_hash`] of the entry: BLAKE3 of the stored bytes.
    pub hash: AuthorityEntryHash,
}

/// Verifies a stored entry body over its scaffold, with no overlay record:
/// the canonical envelope, the signer and cosign rules, and every signature
/// over the transcript of the stored map itself. Neither the op's fields
/// nor its fold rules are checked; a reader that needs them opens the row
/// with its record ([`open_authority_log_entry_body`]).
pub fn verify_authority_log_entry_scaffold(bytes: &[u8]) -> Result<AuthorityEntryScaffold> {
    let value = read_one_value(bytes)?;
    let entries = map_entries(&value)?;
    let Some(keys) = entries
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<Option<Vec<&str>>>()
    else {
        return Err(invalid_authority());
    };
    if keys != AUTHORITY_ENTRY_KEYS {
        return Err(invalid_authority());
    }
    if required(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(AUTHORITY_LOG_SCHEMA_VERSION) {
        return Err(invalid_authority());
    }
    let vault_id = decode_optional_hash(required(entries, KEY_VAULT_ID)?)?;
    let seq = required(entries, KEY_SEQ)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    let parent_hashes = decode_hash_array(required(entries, KEY_PARENT_HASHES)?)?;
    if !parent_hashes.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid_authority());
    }
    let op = required(entries, KEY_OP)?;
    let op_kind = map_str(op, OP_KEY_KIND)
        .ok_or_else(invalid_authority)?
        .to_owned();
    let signer = super::wire_decode::decode_signature(required(entries, KEY_SIGNER)?)?;
    let cosigns = decode_signature_array(required(entries, KEY_COSIGNS)?)?;
    let ts = required(entries, KEY_TS)?
        .as_u64()
        .ok_or_else(invalid_authority)?;
    // The envelope rules of `AuthorityLogEntry::validate_shape`.
    let genesis = op_kind == OP_KIND_GENESIS;
    if (op_kind != OP_KIND_FRONTIER_JOIN && parent_hashes.len() > MAX_PARENTS)
        || cosigns.len() > MAX_COSIGNS
        || genesis != vault_id.is_none()
        || (genesis && (!parent_hashes.is_empty() || !cosigns.is_empty()))
    {
        return Err(invalid_authority());
    }
    signer.validate()?;
    let mut previous: Option<&AuthorityKey> = None;
    for cosign in &cosigns {
        cosign.validate()?;
        if cosign.public_key == signer.public_key
            || previous.is_some_and(|previous| previous >= &cosign.public_key)
        {
            return Err(invalid_authority());
        }
        previous = Some(&cosign.public_key);
    }
    // The transcript of `authority_transcript`, built from the stored map:
    // the body without its signatures, then the signer and cosign keys.
    let unsigned = Value::Map(
        entries
            .iter()
            .filter(|(key, _)| {
                key.as_str()
                    .is_some_and(|key| key != KEY_SIGNER && key != KEY_COSIGNS)
            })
            .cloned()
            .collect(),
    );
    let transcript_map = Value::Map(vec![
        (Value::from("entry"), unsigned),
        (Value::from(KEY_SIGNER), key_value(&signer.public_key)),
        (
            Value::from("cosign_keys"),
            Value::Array(
                cosigns
                    .iter()
                    .map(|cosign| key_value(&cosign.public_key))
                    .collect(),
            ),
        ),
    ]);
    let mut transcript = AUTHORITY_TRANSCRIPT_DOMAIN.to_vec();
    transcript.extend_from_slice(&encode_value(&transcript_map)?);
    if !verify_authority_signature(&signer, &transcript)
        || !cosigns
            .iter()
            .all(|cosign| verify_authority_signature(cosign, &transcript))
        || encode_value(&value)? != bytes
    {
        return Err(invalid_authority());
    }
    Ok(AuthorityEntryScaffold {
        vault_id,
        seq,
        parent_hashes,
        op_kind,
        signer,
        cosigns,
        ts,
        sealed: contains_overlay_node(op),
        hash: *blake3::hash(bytes).as_bytes(),
    })
}

/// A stored entry body as a reader with no overlay record sees it.
// Both arms are short-lived read results; boxing either adds an allocation
// per row on the fold paths for no saving.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityEntryRead {
    /// A row with nothing sealed: decoded, re-encoded and verified as
    /// [`open_authority_log_entry_body`] does.
    Open(AuthorityLogEntry),
    /// A sealed row: its scaffold verified, its op left sealed.
    Sealed(AuthorityEntryScaffold),
}

/// Reads a stored entry body with no store at hand: an unsealed row opens
/// whole; a sealed row answers its verified scaffold, for a reader that
/// needs only the envelope or the op kind (a kind filter, a hash or parent
/// walk). A reader that needs a sealed op's fields opens the row with its
/// overlay record instead.
///
/// # Errors
/// A body that is not a well-formed, validly signed entry.
pub fn read_authority_log_entry_body(bytes: &[u8]) -> Result<AuthorityEntryRead> {
    if authority_body_is_sealed(bytes)? {
        return verify_authority_log_entry_scaffold(bytes).map(AuthorityEntryRead::Sealed);
    }
    open_authority_log_entry_body(bytes, None).map(AuthorityEntryRead::Open)
}

/// Decodes a stored entry body with its overlay record when the row is
/// sealed: opens the op, decodes and validates the entry, checks that it
/// re-encodes to exactly `bytes`, and verifies its signatures. A sealed row
/// with no record answers [`AUTHORITY_OVERLAY_UNAVAILABLE`]; a record given
/// for a row with nothing sealed is refused.
pub fn open_authority_log_entry_body(
    bytes: &[u8],
    record: Option<&AuthorityOverlayRecord>,
) -> Result<AuthorityLogEntry> {
    let mut value = read_one_value(bytes)?;
    let sealed = map_get(&value, KEY_OP).is_some_and(contains_overlay_node);
    let seed = match (sealed, record) {
        (false, None) => None,
        (false, Some(_)) => return Err(invalid_authority()),
        (true, None) => {
            // Only a row whose scaffold verifies is merely unavailable.
            verify_authority_log_entry_scaffold(bytes)?;
            return Err(authority_overlay_unavailable());
        }
        (true, Some(record)) => {
            let op = map_get_mut(&mut value, KEY_OP).ok_or_else(invalid_authority)?;
            *op = open_op_value(op, record)?;
            Some(record.seed)
        }
    };
    let mut entry = decode_entry_value(&value)?;
    entry.overlay_seed = seed;
    entry.validate_shape()?;
    let canonical = encode_authority_log_entry_body(&entry)?;
    if canonical == bytes && verify_entry_signatures(&entry).is_ok() {
        return Ok(entry);
    }
    Err(invalid_authority())
}

fn open_nodes(
    value: &mut Value,
    path: &mut Vec<String>,
    record: &AuthorityOverlayRecord,
    used: &mut [bool],
) -> Result<()> {
    match value {
        Value::Ext(kind, commitment) if *kind == AUTHORITY_OVERLAY_EXT_TYPE => {
            let index = record
                .leaves
                .iter()
                .position(|leaf| leaf.path == *path)
                .ok_or_else(invalid_authority)?;
            let leaf = &record.leaves[index];
            if used[index] || leaf_commitment(&record.seed, path, &leaf.value)[..] != commitment[..]
            {
                return Err(invalid_authority());
            }
            used[index] = true;
            *value = leaf.value.clone();
        }
        Value::Map(entries) => {
            for (key, child) in entries {
                // Only a map key path names a leaf; a node anywhere else
                // was never sealed by `seal_op_value`.
                let Some(key) = key.as_str() else {
                    if contains_overlay_node(child) {
                        return Err(invalid_authority());
                    }
                    continue;
                };
                path.push(key.to_owned());
                open_nodes(child, path, record, used)?;
                path.pop();
            }
        }
        Value::Array(items) => {
            if items.iter().any(contains_overlay_node) {
                return Err(invalid_authority());
            }
        }
        _ => {}
    }
    Ok(())
}

/// The commitment to `value` at `path` under `seed`: a BLAKE3 keyed hash
/// whose key is derived from the seed and the path, so equal values at two
/// paths, or in two entries, commit differently.
fn leaf_commitment(seed: &[u8; 32], path: &[String], value: &Value) -> [u8; 32] {
    let mut material = seed.to_vec();
    material.extend_from_slice(&value_bytes(&path_value(path)));
    let key = blake3::derive_key(OVERLAY_LEAF_KEY_CONTEXT, &material);
    *blake3::keyed_hash(&key, &value_bytes(value)).as_bytes()
}

/// MessagePack bytes of `value`. Writing into a `Vec` has no I/O to fail, so
/// sealing stays infallible and `entry_value` keeps its signature.
fn value_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .expect("MessagePack into a Vec never fails: the writer has no I/O");
    out
}

fn path_value(path: &[String]) -> Value {
    Value::Array(path.iter().map(|key| Value::from(key.as_str())).collect())
}

/// A leaf worth sealing: anything but nil or an empty string, binary, array
/// or map (an absent value names nothing).
fn leaf_is_present(value: &Value) -> bool {
    match value {
        Value::Nil => false,
        Value::String(text) => !text.as_bytes().is_empty(),
        Value::Binary(bytes) => !bytes.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
        _ => true,
    }
}

fn split_class_path(class: &OverlayLeafClass) -> (&'static [&'static str], &'static str) {
    match class.path.split_last() {
        Some((last, parent)) => (parent, last),
        None => (&[], ""),
    }
}

fn scaffold_by_sibling(parent: &Value, class: &OverlayLeafClass) -> bool {
    class
        .scaffold_when_sibling
        .is_some_and(|(key, kinds)| map_str(parent, key).is_some_and(|kind| kinds.contains(&kind)))
}

fn map_get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = map else {
        return None;
    };
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
}

fn map_get_mut<'a>(map: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    let Value::Map(entries) = map else {
        return None;
    };
    entries
        .iter_mut()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
}

fn map_str<'a>(map: &'a Value, key: &str) -> Option<&'a str> {
    map_get(map, key).and_then(Value::as_str)
}

fn map_at<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for key in path {
        value = map_get(value, key)?;
    }
    matches!(value, Value::Map(_)).then_some(value)
}

fn map_at_mut<'a>(mut value: &'a mut Value, path: &[&str]) -> Option<&'a mut Value> {
    for key in path {
        value = map_get_mut(value, key)?;
    }
    matches!(value, Value::Map(_)).then_some(value)
}

fn read_one_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_authority())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_authority());
    }
    Ok(value)
}
