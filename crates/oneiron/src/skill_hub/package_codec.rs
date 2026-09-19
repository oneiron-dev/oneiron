//! Bounded, typed package persistence. This is storage, not an export door.
use super::package::{MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_FILES, MAX_HUB_PACKAGE_TOTAL_BYTES};
use super::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::skill::{decode_skill_record, encode_skill_record};
use crate::{
    Vault,
    entity_id::EntityId,
    error::{ArtifactError, Error, Result},
};
use std::io::{Cursor, Read};

pub(super) fn invalid(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(message))
}
const MAGIC: &[u8] = b"oneiron.hub-package.v1\0";

/// Envelope pre-check for the immutable carrier guard. A `false` answer means
/// the body is an ordinary asset, never a source candidate, so it must map to
/// `None` at the guard instead of a decode error.
pub(super) fn is_hub_package_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}
const MAX_ENCODED: usize = MAX_HUB_PACKAGE_TOTAL_BYTES + 8 * 1024 * 1024;
const MAX_RECORD: usize = 1024 * 1024;

fn field(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| invalid("package field too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn count(input: &mut Cursor<&[u8]>, max: usize) -> Result<usize> {
    let mut b = [0; 4];
    input
        .read_exact(&mut b)
        .map_err(|_| invalid("truncated package"))?;
    let n = u32::from_be_bytes(b) as usize;
    if n > max {
        return Err(invalid("package field exceeds bound"));
    }
    Ok(n)
}
fn bytes(input: &mut Cursor<&[u8]>, max: usize) -> Result<Vec<u8>> {
    let n = count(input, max)?;
    if n > input
        .get_ref()
        .len()
        .saturating_sub(input.position() as usize)
    {
        return Err(invalid("truncated package field"));
    }
    let mut out = vec![0; n];
    input
        .read_exact(&mut out)
        .map_err(|_| invalid("truncated package"))?;
    Ok(out)
}
fn text(input: &mut Cursor<&[u8]>, max: usize) -> Result<String> {
    String::from_utf8(bytes(input, max)?).map_err(|_| invalid("package text is not UTF-8"))
}

/// Encodes a validated package for bounded local storage or explicit host transport.
/// Does not authorize disclosure: export callers must still run the export gate.
pub fn encode_hub_package(package: &HubPackage) -> Result<Vec<u8>> {
    let hash = package.content_hash()?;
    if package
        .record
        .content_hash
        .is_some_and(|declared| declared != hash)
    {
        return Err(invalid("package hash drift"));
    }
    validate_native_source(package)?;
    let mut out = MAGIC.to_vec();
    out.push(match package.format {
        SkillPackageFormat::Folder => 0,
        SkillPackageFormat::Native => 1,
    });
    let record = encode_skill_record(&package.record)?;
    if record.len() > MAX_RECORD {
        return Err(invalid("package record exceeds bound"));
    }
    field(&mut out, &record)?;
    for set in [
        &package.capabilities.bins,
        &package.capabilities.env,
        &package.capabilities.mcp,
        &package.capabilities.allowed_tools,
    ] {
        out.extend_from_slice(&(set.len() as u32).to_be_bytes());
        for entry in set {
            field(&mut out, entry.as_bytes())?;
        }
    }
    out.extend_from_slice(&(package.files.len() as u32).to_be_bytes());
    let mut files = package.files.iter().collect::<Vec<_>>();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    for file in files {
        field(&mut out, file.path.as_bytes())?;
        field(&mut out, &file.content)?;
    }
    if out.len() > MAX_ENCODED {
        return Err(invalid("encoded package exceeds bound"));
    }
    Ok(out)
}

/// Decodes with bounds checked before allocating each field, and rejects trailing data.
pub fn decode_hub_package(raw: &[u8]) -> Result<HubPackage> {
    if raw.len() > MAX_ENCODED || !raw.starts_with(MAGIC) {
        return Err(invalid("invalid package envelope"));
    }
    let mut input = Cursor::new(&raw[MAGIC.len()..]);
    let mut tag = [0];
    input
        .read_exact(&mut tag)
        .map_err(|_| invalid("truncated package format"))?;
    let format = match tag[0] {
        0 => SkillPackageFormat::Folder,
        1 => SkillPackageFormat::Native,
        _ => return Err(invalid("unknown package format")),
    };
    let record = decode_skill_record(&bytes(&mut input, MAX_RECORD)?)?;
    let mut caps = SkillCapabilitySurface::default();
    for set in [
        &mut caps.bins,
        &mut caps.env,
        &mut caps.mcp,
        &mut caps.allowed_tools,
    ] {
        for _ in 0..count(&mut input, 256)? {
            if !set.insert(text(&mut input, 512)?) {
                return Err(invalid("duplicate capability"));
            }
        }
    }
    let n = count(&mut input, MAX_HUB_PACKAGE_FILES)?;
    let mut files = Vec::with_capacity(n);
    let mut total = 0usize;
    for _ in 0..n {
        let path = text(&mut input, 4096)?;
        let content = bytes(&mut input, MAX_HUB_FILE_BYTES)?;
        total = total
            .checked_add(content.len())
            .ok_or_else(|| invalid("package size overflow"))?;
        if total > MAX_HUB_PACKAGE_TOTAL_BYTES {
            return Err(invalid("package too large"));
        }
        files.push(HubFile::new(path, content));
    }
    if input.position() as usize != raw.len() - MAGIC.len() {
        return Err(invalid("trailing package bytes"));
    }
    let mut package = HubPackage::new(record, files, caps);
    package.format = format;
    let hash = package.content_hash()?;
    if package
        .record
        .content_hash
        .is_some_and(|declared| declared != hash)
    {
        return Err(invalid("package hash drift"));
    }
    validate_native_source(&package)?;
    Ok(package)
}

fn validate_native_source(package: &HubPackage) -> Result<()> {
    if package.format == SkillPackageFormat::Native {
        let source = super::folder::package_from_source(
            &package.record,
            package.files.clone(),
            package.format,
        )?;
        if source.capabilities != package.capabilities {
            return Err(invalid(
                "native package capabilities differ from its source",
            ));
        }
    }
    Ok(())
}

/// A metadata-only write must not strand an existing source package. The typed
/// hub-sync transaction replaces both halves; generic and replay writes do not.
pub(super) fn check_source_binding_update(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &crate::skill::SkillRecord,
    replaces_source: bool,
) -> Result<()> {
    if replaces_source {
        return Ok(());
    }
    if let Some(raw) = store.vault_meta.get(txn, &package_key(id))? {
        let source = decode_hub_package(&raw)?;
        if record.content_hash != Some(source.content_hash()?)
            || record.skill_id != source.record.skill_id
            || record.version != source.record.version
            || record.desc != source.record.desc
        {
            return Err(invalid(
                "source-backed skill revision requires an owning source transaction",
            ));
        }
    }
    Ok(())
}

fn package_key(entity: &EntityId) -> Vec<u8> {
    let mut key = b"skill_hub/package/v1\0".to_vec();
    key.extend_from_slice(entity.as_bytes());
    key
}
impl Vault {
    pub(crate) fn persist_hub_package_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        package: &HubPackage,
    ) -> Result<()> {
        let record = self.read_skill_record_in_txn(txn, entity)?;
        let hash = package.content_hash()?;
        if record.content_hash != Some(hash)
            || record.skill_id != package.record.skill_id
            || record.version != package.record.version
            || record.desc != package.record.desc
        {
            return Err(invalid("stored package differs from its native skill"));
        }
        let encoded = encode_hub_package(package)?;
        // Same-transaction ordinary ASSET carrier: the replicated custody row
        // for this exact tree hash. The stamps are the skill's own header so
        // the carrier reads as contemporaneous evidence, not new activity.
        let raw = self
            .store
            .entities
            .get(txn, entity.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("skill row header"))?;
        let carrier = super::source_carrier::source_carrier_id(&hash)?;
        self.batch_in()
            .put(
                &carrier,
                crate::registry::ENTITY_TYPE_ASSET,
                crate::temporal::TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &encode_hub_package(&super::source_carrier::canonical_source_package(package)?)?,
            )
            .apply(txn)?;
        self.store
            .vault_meta
            .put(txn, &package_key(entity), &encoded)?;
        Ok(())
    }
    /// Recovers the exact package from its replicated carrier when the local
    /// sidecar is absent after sync. Exact tree hash plus skill id, version
    /// and description must match the stored record; anything else fails
    /// closed instead of presenting near or foreign bytes as this skill.
    pub(crate) fn hub_package_from_carrier_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        record: &crate::skill::SkillRecord,
    ) -> Result<Option<HubPackage>> {
        let Some(hash) = record.content_hash else {
            return Ok(None);
        };
        let carrier = super::source_carrier::source_carrier_id(&hash)?;
        let Some(package) =
            super::source_carrier::read_source_carrier_in_txn(&self.store, txn, &carrier)?
        else {
            return Ok(None);
        };
        if package.content_hash()? != hash
            || package.record.skill_id != record.skill_id
            || package.record.version != record.version
            || package.record.desc != record.desc
        {
            return Err(invalid("replicated source differs from its native skill"));
        }
        Ok(Some(package))
    }
    /// Instruction bytes for an admitted runtime load, never a standalone export door.
    pub(crate) fn runtime_skill_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<Option<HubPackage>> {
        let package = match self.store.vault_meta.get(txn, &package_key(entity))? {
            Some(raw) => decode_hub_package(&raw)?,
            None => return self.hub_package_from_carrier_in_txn(txn, record),
        };
        if record.content_hash != Some(package.content_hash()?)
            || record.skill_id != package.record.skill_id
            || record.version != package.record.version
            || record.desc != package.record.desc
        {
            return Err(invalid("runtime package differs from the admitted skill"));
        }
        Ok(Some(package))
    }
    pub(super) fn hub_baseline_instructions(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
    ) -> Result<String> {
        let Some(package) = self.runtime_skill_package_in_txn(txn, entity, record)? else {
            if record.source == crate::claim::ClaimSource::Imported || record.forked_from.is_some()
            {
                return Err(invalid(
                    "imported or forked baseline has no stored instruction package",
                ));
            }
            return Ok(record.desc.clone());
        };
        if record.content_hash != Some(package.content_hash()?) {
            return Err(invalid("baseline package hash drift"));
        }
        let file = package
            .files
            .iter()
            .find(|file| file.path == "SKILL.md")
            .ok_or_else(|| invalid("baseline has no instructions"))?;
        String::from_utf8(file.content.clone())
            .map_err(|_| invalid("baseline instructions are not UTF-8"))
    }
    /// Internal snapshot access only. Callers must apply mandatory export nulling.
    /// The local sidecar answers first; only when it is absent does the
    /// replicated carrier answer, on exact hash plus record-metadata match.
    pub(crate) fn export_hub_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<Option<HubPackage>> {
        if let Some(raw) = self.store.vault_meta.get(txn, &package_key(entity))? {
            return decode_hub_package(&raw).map(Some);
        }
        let Some(raw) = self.store.entities.get(txn, entity.as_bytes())? else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("skill row header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Ok(None);
        }
        let record = decode_skill_record(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        self.hub_package_from_carrier_in_txn(txn, &record)
    }
    pub(super) fn stored_hub_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<HubPackage> {
        self.export_hub_package_in_txn(txn, entity)?
            .ok_or_else(|| invalid("skill has no stored package"))
    }
}

/// Payload erasure; authority origin markers and non-payload receipts deliberately survive.
pub(crate) fn remove_hub_package_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    store.vault_meta.delete(txn, &package_key(id))?;
    Ok(())
}
