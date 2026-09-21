//! Vault-resident PACK descriptor records; the shipped kinds are data, not variants.

use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"note_kind:v1:";

use super::NoteKind;

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
pub(super) fn is_shipped_kind(raw: &str) -> bool {
    shipped().iter().any(|descriptor| descriptor.kind == raw)
}
pub(super) fn valid_name(s: &str) -> bool {
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
        NoteKind::wire(&descriptor.kind).ok_or(Error::Record(RecordError::InvalidNoteBody(
            "invalid NOTE kind",
        )))
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
            .and_then(|d| NoteKind::wire(&d.kind))
            .or_else(|| match NoteKind::parse(kind) {
                Some(kind @ NoteKind::Plugin(_)) => Some(kind),
                _ => None,
            })
            .ok_or(Error::Record(RecordError::InvalidNoteBody(
                "unknown NOTE kind",
            )))
    }
    pub fn read_note(&self, id: &EntityId) -> Result<Option<super::NoteBody>> {
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
        let bytes = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.store, &txn, id, bytes)?;
        #[cfg(feature = "sync")]
        let bytes = resolved.as_slice();
        let bytes = super::live_body_in_txn(
            &self.store,
            &txn,
            id,
            crate::registry::ENTITY_TYPE_NOTE,
            bytes,
        )?;
        super::decode_note_body_in_txn(&self.store, &txn, &bytes).map(Some)
    }
}

/// All local, replay and overlay puts consult the same installed registry.
/// Syntax alone is not evidence that a plugin kind exists in this vault.
pub(crate) fn validate_registered_kind(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<()> {
    let body = super::decode_note_body_using(bytes, NoteKind::wire)?;
    let kind = body.kind.as_str();
    context_in_txn(store, txn, kind.as_ref()).map(|_| ())
}

pub(super) fn context_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    kind: &str,
) -> Result<ContextDefault> {
    if let Some(descriptor) = shipped()
        .into_iter()
        .find(|descriptor| descriptor.kind == kind)
    {
        return Ok(descriptor.context);
    }
    let Some(raw) = store.vault_meta().get(txn, &key(kind))? else {
        return match NoteKind::parse(kind) {
            Some(NoteKind::Plugin(_)) => Ok(ContextDefault::RelationshipScoped),
            _ => Err(RecordError::InvalidNoteBody("unknown NOTE kind").into()),
        };
    };
    let descriptor: NoteKindDescriptor =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("NOTE kind descriptor"))?;
    if descriptor.kind != kind
        || !valid_name(&descriptor.pack)
        || !kind.starts_with(&format!("{}/", descriptor.pack))
    {
        return Err(Error::CorruptedIndex("NOTE kind binding"));
    }
    Ok(descriptor.context)
}
