//! Vault-resident PACK descriptor records; the shipped kinds are data, not variants.

use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"note_kind:v1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NoteKind(String);

impl NoteKind {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Resolves a shipped kind. Vault-registered kinds use `Vault::note_kind`.
    pub fn parse(raw: &str) -> Option<Self> {
        shipped()
            .into_iter()
            .find(|d| d.kind == raw)
            .map(|d| Self(d.kind))
    }
    pub(crate) fn wire(raw: &str) -> Option<Self> {
        valid_name(raw).then(|| Self(raw.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionDefault {
    Allowed,
    AfterSeal,
    PrivateStrategyOnly,
    Disabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDefault {
    OwnerOnly,
    RelationshipScoped,
    VaultReadable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionDefault {
    Durable,
    SessionSealed,
    ArchiveAfterDays,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteKindDescriptor {
    pub pack: String,
    pub kind: String,
    pub extraction: ExtractionDefault,
    pub context: ContextDefault,
    pub retention: RetentionDefault,
    pub archive_after_days: Option<u32>,
}

fn shipped() -> Vec<NoteKindDescriptor> {
    serde_json::from_str(include_str!("kinds.json")).expect("shipped NOTE descriptors")
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._/-".contains(&c))
}
fn key(kind: &str) -> Vec<u8> {
    [PREFIX, kind.as_bytes()].concat()
}

impl Vault {
    /// Registers immutable PACK-owned kind defaults. A plugin kind is namespaced
    /// as `<pack>/<kind>`; one pack cannot take another pack's discriminator.
    pub fn register_note_kind(&self, descriptor: &NoteKindDescriptor) -> Result<NoteKind> {
        if !valid_name(&descriptor.pack)
            || !valid_name(&descriptor.kind)
            || !(descriptor
                .kind
                .starts_with(&format!("{}/", descriptor.pack))
                || shipped().iter().any(|d| d == descriptor))
            || (descriptor.retention == RetentionDefault::ArchiveAfterDays)
                != descriptor.archive_after_days.is_some_and(|days| days > 0)
        {
            return Err(Error::Record(RecordError::InvalidNoteBody(
                "invalid PACK kind descriptor",
            )));
        }
        let bytes = rmp_serde::to_vec_named(descriptor)
            .map_err(|_| Error::InvariantViolation("NOTE descriptor encoding"))?;
        self.with_write_txn(|txn| {
            if let Some(old) = self.store.vault_meta.get(txn, &key(&descriptor.kind))? {
                if old.as_ref() != bytes.as_slice() {
                    return Err(Error::Record(RecordError::InvalidNoteBody(
                        "kind already registered",
                    )));
                }
            } else {
                self.store
                    .vault_meta
                    .put(txn, &key(&descriptor.kind), &bytes)?;
            }
            Ok(())
        })?;
        Ok(NoteKind(descriptor.kind.clone()))
    }

    pub fn note_kind_descriptors(&self) -> Result<Vec<NoteKindDescriptor>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = shipped();
        for entry in self.store.vault_meta.prefix_iter(&txn, PREFIX)? {
            let (_, value) = entry?;
            let d: NoteKindDescriptor = rmp_serde::from_slice(&value)
                .map_err(|_| Error::CorruptedIndex("NOTE kind descriptor"))?;
            rows.retain(|old| old.kind != d.kind);
            rows.push(d);
        }
        rows.sort_by(|a, b| a.kind.cmp(&b.kind));
        Ok(rows)
    }
    pub fn note_kind(&self, kind: &str) -> Result<NoteKind> {
        self.note_kind_descriptors()?
            .into_iter()
            .find(|d| d.kind == kind)
            .map(|d| NoteKind(d.kind))
            .ok_or(Error::Record(RecordError::InvalidNoteBody(
                "unknown NOTE kind",
            )))
    }
    pub fn read_note(&self, id: &EntityId) -> Result<Option<super::NoteBody>> {
        let descriptors = self.note_kind_descriptors()?;
        let txn = self.store.env.read_txn()?;
        if self.archive_tombstone_in_txn(&txn, id)?.is_some() {
            return Ok(None);
        }
        let Some(raw) = self.get_raw_in(&txn, id)? else {
            return Ok(None);
        };
        if raw.first() != Some(&crate::registry::ENTITY_TYPE_NOTE) {
            return Err(Error::Record(RecordError::InvalidNoteBody(
                "entity is not a NOTE",
            )));
        }
        super::decode_note_body_using(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], |kind| {
            descriptors
                .iter()
                .any(|d| d.kind == kind)
                .then(|| NoteKind(kind.to_owned()))
        })
        .map(Some)
    }
}

/// All local, replay and overlay puts consult the same installed registry.
/// Syntax alone is not evidence that a plugin kind exists in this vault.
pub(crate) fn validate_registered_kind(
    store:&impl crate::store::ManifestDbs, txn:&heed::RoTxn<'_>, bytes:&[u8],
)->Result<()> {
    let body=super::decode_note_body_using(bytes,NoteKind::wire)?;
    let kind=body.kind.as_str();
    if NoteKind::parse(kind).is_some() { return Ok(()); }
    let Some(raw)=store.vault_meta().get(txn,&key(kind))? else {
        return Err(RecordError::InvalidNoteBody("unknown NOTE kind").into());
    };
    let descriptor:NoteKindDescriptor=rmp_serde::from_slice(&raw)
        .map_err(|_|Error::CorruptedIndex("NOTE kind descriptor"))?;
    if descriptor.kind!=kind || !valid_name(&descriptor.pack)
        || !kind.starts_with(&format!("{}/",descriptor.pack)) {
        return Err(Error::CorruptedIndex("NOTE kind binding"));
    }
    Ok(())
}
