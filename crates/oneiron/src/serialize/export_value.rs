//! Credential-safe, type-preserving MessagePack values for whole-vault JSON.
//!
//! No raw/base64 body is shipped inside this tree. Unknown binary and extension
//! payloads are nulled: an opaque byte string is not proof that it is public data.
//! A stored file is no tree: the whole-vault archive carries its bytes beside the
//! document as they are stored (OF-222), and the tree names them ([`ExportBodyFile`]).
//! A value is kept at any depth, and its archive form is flat (FIX 10097, [`tree`]).
use std::borrow::Cow;
use std::io::{Cursor, Read};

use rmpv::Value as Mp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::credential_nulling::{credential_key, null_credentials, reference_carries_credential};
use crate::batch::export::ArchiveFiles;
use crate::batch::secret_scan::{
    decode_members, nested_past_decoder, release_reads_whole, scan_file_content,
    scan_undecoded_body,
};
use crate::error::{Error, Result};

mod file_stream;
pub(crate) use file_stream::attaches_as_file_read;
mod tree;

/// How deep text decoded inside text is read before its original bytes are
/// kept, as deep as the document pass reads. A value's own structure spends
/// none of it (FIX 10097).
const TEXT_DEPTH: usize = 128;

/// A MessagePack value with explicit numeric widths and binary-reference types.
/// Map entries stay ordered, including duplicate keys; they are not JSON objects.
/// It serializes as its nodes in postorder ([`tree`]): no depth of value
/// nests its archive form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportValue {
    Boolean(bool),
    Integer(String),
    F32(u32),
    F64(u64),
    String(String),
    /// Only validated, fixed-width CLAIM references and a PERSON substrate
    /// mask's PERSON id use this representation.
    EntityReference(Vec<u8>),
    /// Inspectable UTF-8 binary; the decoder restores MessagePack Binary.
    BinaryText(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    Nil,
}

/// Body format is explicit; arbitrary blobs are never hidden behind an encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "codec",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExportBody {
    MessagePack(ExportValue),
    Utf8(String),
    Pack(Box<super::ExportPackInstance>),
    HubSource(Box<super::ExportHubSource>),
    /// OF-222: an ASSET's stored file, by digest and length; its bytes are the
    /// archive's `files/<blake3>`. Only a whole-vault archive writes one.
    File(ExportBodyFile),
    Nulled,
}

/// OF-222: the stored file an ASSET body is, by its BLAKE3 (lowercase hex) and
/// length. Its bytes go out as they are stored: no decode, credential scan,
/// mask or sealed check reads them, and a sealed or encrypted container goes
/// as it is (C2). A source tree's member that is no UTF-8 text is named the
/// same way (FIX 10101); the source credential scan reads those bytes first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportBodyFile {
    blake3: String,
    bytes: u64,
}

impl ExportBodyFile {
    pub(crate) fn of(body: &[u8]) -> Self {
        Self {
            blake3: crate::batch::export::blake3_hex(body),
            bytes: body.len() as u64,
        }
    }

    /// The descriptor of a file whose BLAKE3 (lowercase hex) and length the
    /// caller checked as it spooled the file (FIX 3677).
    pub(crate) const fn checked(blake3: String, bytes: u64) -> Self {
        Self { blake3, bytes }
    }

    pub(crate) fn blake3(&self) -> &str {
        &self.blake3
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The archive file this names, at this length, read from the archive
    /// when it is needed (FIX 2766), checked against its name as it is read.
    pub(crate) fn read(&self, files: &dyn ArchiveFiles) -> Result<Vec<u8>> {
        match files.file_len(&self.blake3) {
            Some(bytes) if bytes == self.bytes => files.read_file(&self.blake3),
            Some(_) => Err(invalid("file body length disagrees with its archive file")),
            None => Err(invalid("file body names no archive file")),
        }
    }

    /// [`Self::read`] as a stream (FIX 3677): `read` runs once over the
    /// archive file as it is read, and the file is checked to its end
    /// whether or not `read` reaches it ([`ArchiveFiles::with_file_reader`]).
    pub(crate) fn with_reader(
        &self,
        files: &dyn ArchiveFiles,
        read: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        match files.file_len(&self.blake3) {
            Some(bytes) if bytes == self.bytes => files.with_file_reader(&self.blake3, read),
            Some(_) => Err(invalid("file body length disagrees with its archive file")),
            None => Err(invalid("file body names no archive file")),
        }
    }
}

/// OF-222 (CALLS "OF-222 binary bodies"): whether a whole-vault archive carries
/// this stored body as a file. An ASSET body that is no UTF-8 text and that no
/// owning adapter reads goes as it is stored; this is asked before any
/// MessagePack reading, so an image, PDF or ZIP that happens to decode as
/// MessagePack is still a file. The hub source carrier and package envelope,
/// the pack source and the archived receipt source keep their own adapters; a
/// birth source is JSON, so the text test keeps it. Text keeps the inline path.
/// [`attaches_as_file_read`] judges a body alike as it streams (FIX 3677).
pub(crate) fn attaches_as_file(entity_type: u8, body: &[u8]) -> bool {
    entity_type == crate::registry::ENTITY_TYPE_ASSET
        && std::str::from_utf8(body).is_err()
        && matches!(crate::skill_hub::decode_source_carrier(body), Ok(None))
        && matches!(
            crate::skill_hub::pack_catalog::decode_source_body(body),
            Ok(None)
        )
        && !crate::receipt::is_receipt_archive_source(body)
}

impl ExportBody {
    pub(crate) fn from_bytes(bytes: &[u8], entity_type: u8) -> Self {
        if crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle {
            return match crate::registry::pack_byte_map::PackInstanceEnvelope::from_bytes(bytes) {
                Ok(value) => Self::Pack(Box::new(super::ExportPackInstance::from_envelope(value))),
                Err(_) => Self::Nulled,
            };
        }
        if entity_type == crate::registry::ENTITY_TYPE_ASSET {
            match crate::skill_hub::decode_source_carrier(bytes) {
                Ok(Some((holder, package))) => {
                    return super::ExportHubSource::from_package(&holder, &package)
                        .map_or(Self::Nulled, |source| Self::HubSource(Box::new(source)));
                }
                Err(_) => return Self::Nulled,
                Ok(None) => {}
            }
        }
        let mut cursor = Cursor::new(bytes);
        if let Ok(value) = rmpv::decode::read_value(&mut cursor)
            && cursor.position() == bytes.len() as u64
        {
            let mut exported = tree::export_value_tree(&value, entity_type, 0);
            if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                export_provenance_references(bytes, &mut exported);
                if let Ok(body) = crate::claim::decode_claim_body(bytes, true) {
                    export_scope_references(&body, &mut exported);
                    super::export_actor_references::export_actor_references(&body, &mut exported);
                }
            }
            if entity_type == crate::registry::ENTITY_TYPE_FACET {
                export_substrate_reference(&value, &mut exported);
            }
            // The NOTE codec has one validated binary revision reference.
            // Treating it as arbitrary opaque bytes would null it and make a live
            // edited NOTE's JSON archive impossible to decode on import.
            if entity_type == crate::registry::ENTITY_TYPE_NOTE
                && let Ok(note) =
                    crate::note::decode_note_body_using(bytes, crate::note::NoteKind::wire)
            {
                export_note_references(&note, &mut exported);
            }
            // An id slot is required where it sits (a CLAIM's subject), so a
            // body with one nulled is no body its codec reads: none goes out.
            if null_credential_references(&mut exported) {
                return Self::Nulled;
            }
            // Read whole once every reference is restored: the tree an
            // importer rebuilds carries no secret spread over its parts.
            return match exported.to_msgpack() {
                Ok(tree) if !release_reads_whole(&tree) => Self::MessagePack(exported),
                _ => Self::Nulled,
            };
        }
        match std::str::from_utf8(bytes) {
            Ok(text) if safe_text(text, 0) => Self::Utf8(text.to_owned()),
            _ => Self::Nulled,
        }
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::MessagePack(value) => {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, &value.to_msgpack()?)
                    .map_err(|_| invalid("MessagePack encode failed"))?;
                Ok(bytes)
            }
            Self::Utf8(text) => Ok(text.as_bytes().to_vec()),
            Self::Pack(value) => value.envelope()?.to_bytes(),
            Self::HubSource(value) => value.to_bytes(),
            Self::File(_) => Err(invalid("a file body is read from its archive file")),
            Self::Nulled => Err(invalid(
                "nulled opaque body needs its owning import adapter",
            )),
        }
    }

    /// The stored bytes, a file body's read from the archive's files, and a
    /// hub source's with its file members read from them (FIX 10101).
    pub(crate) fn to_bytes_in(&self, files: &dyn ArchiveFiles) -> Result<Vec<u8>> {
        match self {
            Self::File(file) => file.read(files),
            Self::HubSource(value) => value.to_bytes_in(files),
            body => body.to_bytes(),
        }
    }

    /// Verify imported typed trees through the same serializer transform. No
    /// forged binary tag or proof boolean may smuggle a credential on reimport.
    pub(crate) fn validate(&self, entity_type: u8) -> Result<()> {
        if matches!(self, Self::Nulled) {
            return Ok(());
        }
        if let Self::HubSource(value) = self {
            if entity_type != crate::registry::ENTITY_TYPE_ASSET {
                return Err(invalid("hub source attached to non-asset kind"));
            }
            return value.validate();
        }
        if let Self::Pack(value) = self {
            if crate::registry::zone_of(entity_type) != crate::registry::TypeByteZone::PackHandle {
                return Err(invalid("pack envelope attached to non-pack kind"));
            }
            return value.validate();
        }
        let bytes = self.to_bytes()?;
        if Self::from_bytes(&bytes, entity_type) != *self {
            return Err(invalid(
                "body is not canonical credential-nulled export data",
            ));
        }
        Ok(())
    }

    /// [`Self::validate`] with the archive's verified files (OF-222): a file
    /// body is an ASSET's, names one of them at its length, and holds bytes
    /// the serializer attaches ([`attaches_as_file`]), so no owning adapter's
    /// body or text passes as a file. The file is judged as it streams from
    /// the archive, checked to its end, never held whole (FIX 3677). A hub
    /// source's file members are read from them too (FIX 10101).
    pub(crate) fn validate_in(&self, entity_type: u8, files: &dyn ArchiveFiles) -> Result<()> {
        if let Self::HubSource(value) = self {
            if entity_type != crate::registry::ENTITY_TYPE_ASSET {
                return Err(invalid("hub source attached to non-asset kind"));
            }
            return value.validate_in(files);
        }
        let Self::File(file) = self else {
            return self.validate(entity_type);
        };
        if entity_type != crate::registry::ENTITY_TYPE_ASSET {
            return Err(invalid("file body attached to non-asset kind"));
        }
        let mut attaches = false;
        file.with_reader(files, &mut |body| {
            attaches = attaches_as_file_read(entity_type, body)?;
            Ok(())
        })?;
        if !attaches {
            return Err(invalid("file body is not one the serializer attaches"));
        }
        Ok(())
    }
}

/// An id slot is kept as its bytes, so every one is read for credentials here,
/// before any writer derives rows from the tree: the whole-vault document, an
/// agent's portable knowledge (which spells ids as hex, past any later byte
/// reading) and a bundle all start from the same nulled row.
fn null_credential_references(value: &mut ExportValue) -> bool {
    match value {
        ExportValue::EntityReference(bytes) if reference_carries_credential(bytes, 0) => {
            *value = ExportValue::Nil;
            true
        }
        ExportValue::Array(values) => values.iter_mut().fold(false, |nulled, value| {
            null_credential_references(value) | nulled
        }),
        ExportValue::Map(entries) => entries.iter_mut().fold(false, |nulled, (key, value)| {
            null_credential_references(key) | null_credential_references(value) | nulled
        }),
        _ => false,
    }
}

// The record-position scope stamp is required on every CLAIM; the decoded body
// proves these top-level positions hold ids, not opaque bytes.
fn export_scope_references(body: &crate::claim::ClaimBody, exported: &mut ExportValue) {
    let ExportValue::Map(entries) = exported else {
        return;
    };
    for (key, value) in entries.iter_mut() {
        let ExportValue::String(key) = key else {
            continue;
        };
        let id = match key.as_str() {
            "worldId" => body.world.unwrap_or_else(crate::claim::base_world_id),
            "scopeFacetId" => body.scope_facet,
            "scopeProjectId" => body.scope_project,
            "scopeRelationshipId" => {
                if let Some(relationships) = &body.rel {
                    *value = ExportValue::Array(
                        relationships
                            .iter()
                            .map(|rel| ExportValue::EntityReference(rel.as_bytes().to_vec()))
                            .collect(),
                    );
                }
                continue;
            }
            _ => continue,
        };
        *value = ExportValue::EntityReference(id.as_bytes().to_vec());
    }
}

// The NOTE codec proves this one top-level binary revision is a reference,
// not arbitrary payload. The author ref is a hex STRING and stays one.
fn export_note_references(body: &crate::note::NoteBody, exported: &mut ExportValue) {
    if scan_file_content("", &body.source_revision_ref).is_some() {
        return;
    }
    let ExportValue::Map(entries) = exported else {
        return;
    };
    if let Some(value) = entries.iter_mut().find_map(|(key, value)| {
        matches!(key, ExportValue::String(key) if key == "source_revision_ref").then_some(value)
    }) {
        *value = ExportValue::EntityReference(body.source_revision_ref.to_vec());
    }
}

// A PERSON substrate mask names its PERSON by id; the FACET put door re-proves
// that the mask id binds that PERSON before an imported row lands.
fn export_substrate_reference(value: &Mp, exported: &mut ExportValue) {
    let (Mp::Map(entries), ExportValue::Map(exported)) = (value, exported) else {
        return;
    };
    if entries.len() != 3
        || !entries
            .iter()
            .any(|(key, value)| key.as_str() == Some("kind") && value.as_str() == Some("substrate"))
    {
        return;
    }
    for ((key, value), (_, out)) in entries.iter().zip(exported.iter_mut()) {
        if key.as_str() == Some("person_ref")
            && let Mp::Binary(bytes) = value
            && <[u8; 16]>::try_from(bytes.as_slice())
                .is_ok_and(|id| crate::entity_id::EntityId::from_bytes(id).is_ok())
            && scan_file_content("", bytes).is_none()
        {
            *out = ExportValue::EntityReference(bytes.clone());
        }
    }
}

// Only the owning, validated edge.provenance value map gets these four
// binary reference fields. An equally named field in arbitrary evidence is
// still subject to ordinary opaque-byte nulling.
fn export_provenance_references(bytes: &[u8], exported: &mut ExportValue) {
    let Ok(claim) = crate::claim::decode_claim_body(bytes, true) else {
        return;
    };
    if claim.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE {
        return;
    }
    let Ok(record) = crate::provenance::decode_edge_provenance_body(&claim.value) else {
        return;
    };
    if crate::provenance::resolve_persisted_actor_class(&record, claim.evidence.as_ref()).is_err() {
        return;
    }
    let ExportValue::Map(entries) = exported else {
        return;
    };
    let Some(ExportValue::Map(values)) = entries.iter_mut().find_map(|(key, value)| {
        matches!(key, ExportValue::String(key) if key == "val").then_some(value)
    }) else {
        return;
    };
    for (name, bytes) in [
        (
            "actor_entity_ref",
            Some(*record.actor_entity_ref.as_bytes()),
        ),
        (
            "substrate_ref",
            record.substrate_ref.map(|id| *id.as_bytes()),
        ),
        ("source_revision_ref", record.source_revision_ref),
        ("body_snapshot_ref", record.body_snapshot_ref),
    ] {
        if let Some(bytes) = bytes {
            if scan_file_content("", &bytes).is_some() {
                continue;
            }
            if let Some(value) = values.iter_mut().find_map(|(key, value)| {
                matches!(key, ExportValue::String(key) if key == name).then_some(value)
            }) {
                *value = ExportValue::EntityReference(bytes.to_vec());
            }
        }
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault export: {reason}"))
}

/// Text keeps its original bytes only when every reading of it is clean: its
/// text, and, when it decodes, every member through the decode the write door
/// runs ([`decode_members`]), a lone JSON string and each repeated key's value
/// included, with nothing this exporter nulls. `depth` is how deep in text
/// decoded inside text this text sits; past [`TEXT_DEPTH`] a decoded member
/// reads as nil.
fn safe_text(text: &str, depth: usize) -> bool {
    let scalar = Value::String(text.to_owned());
    if null_credentials("", &scalar) != scalar {
        return false;
    }
    match decode_members(text.as_bytes()) {
        Some(value) if release_reads_whole(&value) => false,
        Some(value) => {
            // Text holds no codec's id slot: its tree is read as an ASSET body's.
            let read = if depth + 1 < TEXT_DEPTH {
                tree::export_value_tree(&value, crate::registry::ENTITY_TYPE_ASSET, depth + 1)
            } else {
                ExportValue::Nil
            };
            read.to_msgpack().is_ok_and(|read| read == value)
        }
        None => nested_past_decoder(text.as_bytes()).is_none(),
    }
}

fn byte_container_is_opaque_or_tainted(bytes: &[u8], depth: usize) -> bool {
    if scan_undecoded_body(bytes).is_some() {
        return true;
    }
    if std::str::from_utf8(bytes).is_ok_and(|text| !safe_text(text, depth)) {
        return true;
    }
    let mut cursor = Cursor::new(bytes);
    matches!(
        rmpv::decode::read_value(&mut cursor),
        Ok(Mp::Map(_) | Mp::Array(_) | Mp::Binary(_) | Mp::Ext(_, _))
    ) && cursor.position() == bytes.len() as u64
}

fn reference_field(key: &str, bytes: &[u8], entity_type: u8, depth: usize) -> bool {
    if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return false;
    }
    if depth > 1 && key != crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY {
        return false;
    }
    match key {
        "subj" => crate::claim::ClaimSubject::decode(bytes).is_ok(),
        "actor_entity_ref" => <[u8; 16]>::try_from(bytes)
            .ok()
            .is_some_and(|id| crate::entity_id::EntityId::from_bytes(id).is_ok()),
        _ => false,
    }
}

/// An exported item as a second pass reads it joined
/// ([`crate::batch::secret_scan::release_joined_messagepack`] over its
/// MessagePack): a string, binary text or id bytes, and an array of byte
/// values.
fn exported_text(value: &ExportValue) -> Option<Cow<'_, str>> {
    match value {
        ExportValue::String(text) | ExportValue::BinaryText(text) => Some(Cow::Borrowed(text)),
        ExportValue::EntityReference(bytes) => Some(String::from_utf8_lossy(bytes)),
        ExportValue::Array(items) => items
            .iter()
            .map(|item| match item {
                ExportValue::Integer(value) => value.parse::<u8>().ok(),
                _ => None,
            })
            .collect::<Option<Vec<u8>>>()
            .map(|bytes| Cow::Owned(String::from_utf8_lossy(&bytes).into_owned())),
        _ => None,
    }
}

impl ExportValue {
    /// The MessagePack value this restores, at any depth.
    pub(crate) fn to_msgpack(&self) -> Result<Mp> {
        tree::restore_value_tree(self)
    }
}
