//! Reads the whole-vault archive (OF-222) member by member from a seekable
//! source (FIX 2766, rule 5): only the ZIP's central directory and the
//! manifest are read whole. Every member is checked against the manifest
//! (length and BLAKE3) in one streaming pass before a row is read; the record
//! rows are then read one line at a time into the import's disk-backed row
//! index (FIX 3678): each row is checked as it is read and spooled, and only
//! where it is stays indexed. An attached file stays in the archive until a
//! row needs it, checked against its name again each time it is read. The
//! archive holds no member the manifest does not list. No ceiling caps the
//! whole. The rows then pass the same validation and admission doors as
//! before; nothing here grants authority.
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Seek};

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::archive_index::{ArchiveIndex, ArchiveSpool, IndexedArchive, Section};
use super::{
    ArchiveRecordKind, ArchiveSecretCustody, ExportAgentBundle, ExportDerivationEnvelope,
    ExportEdge, ExportEntity, ExportEpochFloor, ExportLedger, ExportPack, ExportResultBody,
    ExportRun, ExportRunResults, ExportSkillBundle, PortableEmbeddingSpace,
    VAULT_ARCHIVE_FILES_DIR, VAULT_ARCHIVE_MANIFEST_PATH, VAULT_ARCHIVE_RECORDS_DIR,
    WholeVaultDocument, WholeVaultDocumentManifest, archive_file_path,
};
use crate::Vault;
use crate::error::{Error, Result};
use crate::serialize::ExportBody;

/// Where an archive's attached files are read from: result bodies stage from
/// them, and an ASSET's file body (OF-222) and a side row's long value (FIX
/// 2768) are read from them, one at a time.
pub(crate) trait ArchiveFiles {
    /// The length the manifest lists for the file named `blake3`, if it does.
    fn file_len(&self, blake3: &str) -> Option<u64>;

    /// Runs `read` once over the file named `blake3` as it streams (FIX
    /// 3677). Whatever `read` leaves is read too, and the file is checked
    /// against its name and listed length to its end whether or not `read`
    /// reaches it: an unread suffix never passes. A failed read or check is
    /// the error before `read`'s own. `read` must not read this archive's
    /// files again while it runs.
    fn with_file_reader(
        &self,
        blake3: &str,
        read: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()>;

    /// The file named `blake3`, checked against its name and listed length.
    fn read_file(&self, blake3: &str) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        self.with_file_reader(blake3, &mut |file| {
            file.read_to_end(&mut body)
                .map_err(|_| invalid("unreadable whole-vault archive member"))?;
            Ok(())
        })?;
        Ok(body)
    }
}

/// The attached files of one archive, read from it on demand.
pub(crate) struct ArchiveFileSource<R: Read + Seek> {
    archive: RefCell<zip::ZipArchive<R>>,
    listed: BTreeMap<String, u64>,
}

impl<R: Read + Seek> ArchiveFiles for ArchiveFileSource<R> {
    fn file_len(&self, blake3: &str) -> Option<u64> {
        self.listed.get(blake3).copied()
    }

    fn with_file_reader(
        &self,
        blake3: &str,
        read: &mut dyn FnMut(&mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let bytes = self
            .file_len(blake3)
            .ok_or_else(|| invalid("archive file listed but absent"))?;
        let mut archive = self.archive.borrow_mut();
        let member = archive
            .by_name(&archive_file_path(blake3))
            .map_err(|_| invalid("archive file listed but absent"))?;
        let mut file = CheckedMember {
            member: member.take(bytes.saturating_add(1)),
            hasher: blake3::Hasher::new(),
            count: 0,
            failed: false,
        };
        let called = read(&mut file);
        if std::io::copy(&mut file, &mut std::io::sink()).is_err() || file.failed {
            return Err(invalid("unreadable whole-vault archive member"));
        }
        let digest = crate::entity_id::bytes_to_hex_lower(file.hasher.finalize().as_bytes());
        if file.count != bytes || digest != blake3 {
            return Err(invalid("archive file does not match its digest"));
        }
        called
    }
}

/// One attached file as it is read from the archive, never past one byte
/// beyond its listed length: counted and hashed as it passes, and marked
/// failed by any read error but an interrupted read's.
struct CheckedMember<M> {
    member: M,
    hasher: blake3::Hasher,
    count: u64,
    failed: bool,
}

impl<M: Read> Read for CheckedMember<M> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self.member.read(out) {
            Ok(read) => {
                self.hasher.update(&out[..read]);
                self.count += read as u64;
                Ok(read)
            }
            Err(error) => {
                self.failed |= error.kind() != std::io::ErrorKind::Interrupted;
                Err(error)
            }
        }
    }
}

/// Reads `source` into the import's row index in `scratch` (FIX 3678): every
/// member is checked against the manifest first, then each record row is
/// checked as it is read and spooled. No row stays in memory.
pub(crate) fn read_vault_archive_indexed<'e, R: Read + Seek>(
    vault: &Vault,
    scratch: &'e crate::store::ScratchEnv,
    source: R,
) -> Result<IndexedArchive<'e, R>> {
    let mut archive =
        zip::ZipArchive::new(source).map_err(|_| invalid("invalid whole-vault archive"))?;
    let mut members = BTreeSet::new();
    for index in 0..archive.len() {
        let name = archive
            .by_index_raw(index)
            .map_err(|_| invalid("invalid whole-vault archive member"))?
            .name()
            .to_owned();
        if !archive_path(&name) {
            return Err(Error::InvalidConfig(format!(
                "whole-vault archive member {name:?} is not an archive path"
            )));
        }
        if !members.insert(name) {
            return Err(invalid("whole-vault archive member appears twice"));
        }
    }
    let manifest_bytes = {
        let member = archive
            .by_name(VAULT_ARCHIVE_MANIFEST_PATH)
            .map_err(|_| invalid("whole-vault archive has no manifest"))?;
        let declared = member.size();
        let mut bytes = Vec::new();
        member
            .take(declared.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("unreadable whole-vault archive member"))?;
        if bytes.len() as u64 != declared {
            return Err(invalid("whole-vault archive member length disagrees"));
        }
        bytes
    };
    members.remove(VAULT_ARCHIVE_MANIFEST_PATH);
    let manifest: WholeVaultDocumentManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| invalid("invalid whole-vault archive manifest"))?;
    drop(manifest_bytes);
    manifest.validate()?;

    // Every listed member is checked whole before any row is read.
    let mut listed = BTreeMap::new();
    for file in &manifest.files {
        let path = archive_file_path(&file.blake3);
        if !members.remove(&path) {
            return Err(invalid("archive file listed but absent"));
        }
        if listed.insert(file.blake3.clone(), file.bytes).is_some() {
            return Err(invalid("archive file listed twice"));
        }
        let (bytes, blake3) = member_digest(&mut archive, &path)?;
        if bytes != file.bytes || blake3 != file.blake3 {
            return Err(invalid("archive file does not match its digest"));
        }
    }
    for records in &manifest.records {
        let expected_path = match records.kind.fixed_path() {
            Some(path) => records.path == path,
            None => {
                records.path.starts_with("records/entity/")
                    && ArchiveRecordKind::Claim.fixed_path() != Some(records.path.as_str())
                    && ArchiveRecordKind::Skill.fixed_path() != Some(records.path.as_str())
            }
        };
        if !expected_path {
            return Err(invalid("archive record file has the wrong path"));
        }
        if !members.remove(&records.path) {
            return Err(invalid("archive record file listed but absent"));
        }
        let (bytes, blake3) = member_digest(&mut archive, &records.path)?;
        if bytes != records.bytes || blake3 != records.blake3 {
            return Err(invalid("archive record file does not match its digest"));
        }
    }
    if let Some(stray) = members.first() {
        return Err(Error::InvalidConfig(format!(
            "whole-vault archive member {stray:?} is not in its manifest"
        )));
    }

    let files = ArchiveFileSource {
        archive: RefCell::new(archive),
        listed,
    };
    let mut spool = ArchiveSpool::new(vault)?;
    let mut cited = BTreeSet::new();
    let mut slots = super::SlotRows::default();
    for records in &manifest.records {
        let mut archive = files.archive.borrow_mut();
        let member = archive
            .by_name(&records.path)
            .map_err(|_| invalid("archive record file listed but absent"))?;
        let mut lines = BufReader::new(member);
        let mut count = 0;
        let mut line = Vec::new();
        spool.begin_member();
        loop {
            line.clear();
            if lines
                .read_until(b'\n', &mut line)
                .map_err(|_| invalid("unreadable whole-vault archive member"))?
                == 0
            {
                break;
            }
            let row = line.strip_suffix(b"\n").unwrap_or(&line);
            if row.is_empty() {
                continue;
            }
            check_row(
                records.kind,
                &records.path,
                row,
                &files,
                &mut cited,
                &mut slots,
            )?;
            spool.push(row)?;
            count += 1;
        }
        spool.end_member(records.kind);
        if count != records.rows {
            return Err(invalid("archive record file row count disagrees"));
        }
    }
    spool.seal()?;
    // A source-tree file's `file` comes back as its text, read from the
    // archive one row at a time.
    for kind in [
        ArchiveRecordKind::Pack,
        ArchiveRecordKind::Skill,
        ArchiveRecordKind::AgentPack,
    ] {
        let mut rows = spool.rows(kind);
        while let Some((_, line)) = rows.next(&spool)? {
            let mut row: Value = self::row(&line)?;
            attach_tree(kind, &mut row, &files, Some(&mut cited))?;
            match kind {
                ArchiveRecordKind::Pack => drop(typed::<ExportPack>(row)?),
                ArchiveRecordKind::Skill => {
                    let bundle: ExportSkillBundle = typed(row)?;
                    cite_entity_file(&bundle.entity, &files, &mut cited)?;
                }
                _ => drop(typed::<ExportAgentBundle>(row)?),
            }
        }
    }
    // OF-370: the kind slots come back from their rows, each kind once; an
    // archive without slot rows carries no embedding setup.
    let slot_bindings = slots.finish()?;
    if cited.len() != files.listed.len() {
        return Err(invalid("archive file no record names"));
    }
    Ok(IndexedArchive {
        manifest,
        files,
        spool,
        index: ArchiveIndex::open(scratch.env()?)?,
        expressions: false,
        slot_bindings,
    })
}

/// The read-time checks of one row of `kind` from the member at `path`: it
/// parses as its kind, an entity row is in its type's file, and each file it
/// names is attached at its length.
fn check_row(
    kind: ArchiveRecordKind,
    path: &str,
    line: &[u8],
    files: &dyn ArchiveFiles,
    cited: &mut BTreeSet<String>,
    slots: &mut super::SlotRows,
) -> Result<()> {
    match kind {
        ArchiveRecordKind::Entity => {
            let row: ExportEntity = row(line)?;
            if ArchiveRecordKind::entity_path(row.entity_type) != path {
                return Err(invalid("archive entity row is in another type's file"));
            }
            cite_entity_file(&row, files, cited)?;
        }
        ArchiveRecordKind::Claim => cite_entity_file(&row(line)?, files, cited)?,
        ArchiveRecordKind::Skill | ArchiveRecordKind::Pack | ArchiveRecordKind::AgentPack => {
            drop(row::<Value>(line)?);
        }
        ArchiveRecordKind::Edge => drop(row::<ExportEdge>(line)?),
        ArchiveRecordKind::DerivationEnvelope => drop(row::<ExportDerivationEnvelope>(line)?),
        ArchiveRecordKind::Run => drop(row::<ExportRun>(line)?),
        ArchiveRecordKind::ResultBody => {
            let body: ExportResultBody = row(line)?;
            if body.content.is_some() {
                return Err(invalid("archive result body carries inline content"));
            }
            if body.withheld.is_none() {
                if files.file_len(&body.blake3).is_none() {
                    return Err(invalid("archive result body file is absent"));
                }
                cited.insert(body.blake3);
            }
        }
        ArchiveRecordKind::SecretCustody => {
            drop(
                serde_json::from_slice::<ArchiveSecretCustody>(line)
                    .map_err(|_| invalid("invalid archive custody record"))?,
            );
        }
        ArchiveRecordKind::EmbeddingSpace => drop(row::<PortableEmbeddingSpace>(line)?),
        ArchiveRecordKind::SlotBinding => slots.push(row(line)?)?,
        ArchiveRecordKind::EpochFloor => drop(row::<ExportEpochFloor>(line)?),
        ArchiveRecordKind::SideTable => {
            // FIX 2768: a side row's long binary value names one attached
            // file too.
            let side: super::ArchiveSideRow = row(line)?;
            for file in side.files() {
                if files.file_len(file.blake3()) != Some(file.bytes()) {
                    return Err(invalid("archive side row file is absent or another length"));
                }
                cited.insert(file.blake3().to_owned());
            }
        }
    }
    Ok(())
}

/// OF-222: an ASSET's file body names one attached file, at its length.
fn cite_entity_file(
    row: &ExportEntity,
    files: &dyn ArchiveFiles,
    cited: &mut BTreeSet<String>,
) -> Result<()> {
    if let ExportBody::File(file) = &row.body {
        if files.file_len(file.blake3()) != Some(file.bytes()) {
            return Err(invalid("archive entity file is absent or another length"));
        }
        cited.insert(file.blake3().to_owned());
    }
    Ok(())
}

impl<R: Read + Seek> IndexedArchive<'_, R> {
    /// The whole document these rows assemble into, for a caller that asked
    /// for it materialized ([`Vault::read_whole_vault_archive_from`]); the
    /// import never builds it.
    pub(crate) fn document(&self) -> Result<WholeVaultDocument> {
        let mut entities = Vec::new();
        let mut after = None;
        // Store order: entity ids ascend, as the snapshot enumerated them.
        while let Some((id, at)) = self.next_entity(after.as_ref())? {
            if at.section == Section::Ledger {
                entities.push(self.entity_row(&at)?);
            }
            after = Some(id);
        }
        Ok(WholeVaultDocument {
            manifest: self.manifest.clone(),
            evidence_ledger: ExportLedger {
                entities,
                edges: self.all(ArchiveRecordKind::Edge)?,
            },
            claims: self.all(ArchiveRecordKind::Claim)?,
            packs: self.all_hydrated(ArchiveRecordKind::Pack)?,
            skills: self.all_hydrated(ArchiveRecordKind::Skill)?,
            agent_packs: self.all_hydrated(ArchiveRecordKind::AgentPack)?,
            derivation_envelopes: self.all(ArchiveRecordKind::DerivationEnvelope)?,
            run_results: ExportRunResults {
                runs: self.all(ArchiveRecordKind::Run)?,
                bodies: self.all(ArchiveRecordKind::ResultBody)?,
            },
            embedding_spaces: self.all(ArchiveRecordKind::EmbeddingSpace)?,
            slot_bindings: self.slot_bindings.clone(),
            epoch_floors: self.all(ArchiveRecordKind::EpochFloor)?,
            side_tables: self.all(ArchiveRecordKind::SideTable)?,
        })
    }

    fn all<T: DeserializeOwned>(&self, kind: ArchiveRecordKind) -> Result<Vec<T>> {
        let mut rows = self.spool.rows(kind);
        let mut all = Vec::new();
        while let Some((_, row)) = rows.next_parsed(&self.spool)? {
            all.push(row);
        }
        Ok(all)
    }

    fn all_hydrated<T: DeserializeOwned>(&self, kind: ArchiveRecordKind) -> Result<Vec<T>> {
        let mut rows = self.spool.rows(kind);
        let mut all = Vec::new();
        while let Some((loc, _)) = rows.next(&self.spool)? {
            all.push(self.hydrated(kind, loc)?);
        }
        Ok(all)
    }
}

fn row<T: DeserializeOwned>(line: &[u8]) -> Result<T> {
    serde_json::from_slice(line).map_err(|_| invalid("invalid whole-vault archive rows"))
}

fn typed<T: DeserializeOwned>(row: Value) -> Result<T> {
    serde_json::from_value(row).map_err(|_| invalid("invalid whole-vault archive rows"))
}

/// Whether `name` is a member path the archive may hold.
fn archive_path(name: &str) -> bool {
    (name == VAULT_ARCHIVE_MANIFEST_PATH
        || (name.starts_with(VAULT_ARCHIVE_RECORDS_DIR) && name.ends_with(".jsonl"))
        || name
            .strip_prefix(VAULT_ARCHIVE_FILES_DIR)
            .is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            }))
        && !name.contains("..")
        && !name.contains('\\')
}

/// One member's length and BLAKE3, read in a stream: never held whole.
fn member_digest<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    path: &str,
) -> Result<(u64, String)> {
    let mut member = archive
        .by_name(path)
        .map_err(|_| invalid("invalid whole-vault archive member"))?;
    let declared = member.size();
    let mut hasher = blake3::Hasher::new();
    let mut read = 0_u64;
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        let count = member
            .read(&mut chunk)
            .map_err(|_| invalid("unreadable whole-vault archive member"))?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
        read += count as u64;
    }
    if read != declared {
        return Err(invalid("whole-vault archive member length disagrees"));
    }
    Ok((
        read,
        crate::entity_id::bytes_to_hex_lower(hasher.finalize().as_bytes()),
    ))
}

/// A source-tree row's files come back as their text, read from the archive
/// one at a time; `cited` notes each file named, when the read is the first.
pub(super) fn attach_tree(
    kind: ArchiveRecordKind,
    row: &mut Value,
    files: &dyn ArchiveFiles,
    mut cited: Option<&mut BTreeSet<String>>,
) -> Result<()> {
    let tree = match kind {
        ArchiveRecordKind::Pack if row.get("kind").and_then(Value::as_str) == Some("source") => {
            row.pointer_mut("/value/source_tree")
        }
        ArchiveRecordKind::Pack => None,
        _ => row.get_mut("source_tree"),
    };
    let Some(tree_files) = tree
        .and_then(|tree| tree.get_mut("files"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };
    for file in tree_files {
        let Some(fields) = file.as_object_mut() else {
            continue;
        };
        let Some(reference) = fields.remove("file") else {
            continue;
        };
        let blake3 = reference
            .as_str()
            .ok_or_else(|| invalid("invalid archive file reference"))?;
        if !fields.get("content").is_none_or(Value::is_null) {
            return Err(invalid("archive tree file carries inline content"));
        }
        if files.file_len(blake3).is_none() {
            return Err(invalid("archive tree file is absent"));
        }
        let text = String::from_utf8(files.read_file(blake3)?)
            .map_err(|_| invalid("archive tree file is not UTF-8 text"))?;
        fields.insert("content".to_owned(), Value::from(text));
        if let Some(cited) = cited.as_mut() {
            cited.insert(blake3.to_owned());
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
