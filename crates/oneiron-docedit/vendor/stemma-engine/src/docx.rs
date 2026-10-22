use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use zip::result::ZipError;
use zip::write::FileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::admission::{Hold, Operation, Refusal, bytes_of, wide};

/// Archive workload limits, supplied by the host policy on native edit and
/// settlement doors. The standalone fork uses `DEFAULT` as its fallback; a
/// vault's trusted row replaces it and a holder can narrow that row, without
/// changing the DOCX reader. The byte ceilings are the caller's; the entry
/// count is an observation, never a reason to refuse (Rule 5; FIX 8570): what
/// each entry costs is reserved through the operation's port instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_part_bytes: u64,
    pub max_total_bytes: u64,
}

impl ArchiveLimits {
    /// Standalone baseline. The Oneiron vault ships these same values in its
    /// default policy manifest, which a trusted vault row replaces.
    pub const DEFAULT: Self = Self {
        max_entries: 1_000,
        max_part_bytes: 200 * 1024 * 1024,
        max_total_bytes: 500 * 1024 * 1024,
    };

    /// A holder may narrow a vault's workload ceiling, never widen it.
    #[must_use]
    pub fn narrow(self, other: Self) -> Self {
        Self {
            max_entries: self.max_entries.min(other.max_entries),
            max_part_bytes: self.max_part_bytes.min(other.max_part_bytes),
            max_total_bytes: self.max_total_bytes.min(other.max_total_bytes),
        }
    }

    /// Deny zero or incoherent settings before ZIP inflation. No dimension
    /// is bounded by [`Self::DEFAULT`]: a host or a vault owner may set any
    /// coherent ceiling (FIX 5355, 8763).
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.max_entries > 0
            && self.max_part_bytes > 0
            && self.max_part_bytes <= self.max_total_bytes
    }
}

/// The ceiling a package passed: one its caller set, or one classic ZIP has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceiling {
    /// [`ArchiveLimits::max_part_bytes`]: one entry's inflated bytes.
    PartBytes,
    /// [`ArchiveLimits::max_total_bytes`]: every entry's inflated bytes.
    TotalBytes,
    /// Classic ZIP's entry count: 65,535 is its ZIP64 sentinel.
    ZipEntries,
    /// Classic ZIP's 4 GiB sizes and offsets.
    ZipBytes,
}

impl Ceiling {
    /// The ceiling's name in a refusal.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::PartBytes => "max_part_bytes",
            Self::TotalBytes => "max_total_bytes",
            Self::ZipEntries => "zip_entries",
            Self::ZipBytes => "zip_bytes",
        }
    }
}

/// The most entries a classic ZIP records: its central directory counts in
/// 16 bits, and 65,535 there is the ZIP64 sentinel, which a classic reader
/// takes as "look for a ZIP64 record".
pub const CLASSIC_ZIP_ENTRIES: u64 = u16::MAX as u64 - 1;

/// The most bytes a classic ZIP records in a size or offset: 32 bits, with
/// 0xFFFFFFFF its ZIP64 sentinel.
pub const CLASSIC_ZIP_BYTES: u64 = u32::MAX as u64 - 1;

#[derive(Debug)]
pub enum DocxError {
    ZipRead(ZipError),
    ZipWrite(ZipError),
    Io(std::io::Error),
    MissingFile(String),
    ZipBomb(String),
    /// Two ZIP items carry equivalent names (OPC §7.3: ZIP item names shall be
    /// unique; equivalence is ASCII case-insensitive per OPC §6.2). Word
    /// reports such packages as corrupt; silently picking one entry would hide
    /// the corruption.
    DuplicatePartName {
        name: String,
        existing: String,
    },
    /// The ZIP writer produced a central directory that could not be safely
    /// normalized for Word compatibility. This is an engine/package invariant,
    /// never an input tolerance.
    InvalidWrittenZip(String),
    /// The package passed a ceiling (FIX 5354): `observed` past `limit`. A
    /// well-formed package, never a corrupt one.
    Capacity {
        ceiling: Ceiling,
        observed: u64,
        limit: u64,
    },
    /// The read's memory was refused at the machine's floor, or its wait or
    /// deadline ran out ([`crate::admission`]): a well-formed package.
    Resource(Refusal),
}

impl DocxError {
    /// Whether the package was well formed and the work stopped at a ceiling
    /// or at the machine's memory or a deadline, rather than at the package.
    #[must_use]
    pub fn is_admission(&self) -> bool {
        matches!(self, Self::Capacity { .. } | Self::Resource(_))
    }
}

impl From<Refusal> for DocxError {
    fn from(refusal: Refusal) -> Self {
        Self::Resource(refusal)
    }
}

#[derive(Clone, Debug)]
pub struct DocxFile {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DocxArchive {
    files: Vec<DocxFile>,
    /// The memory the trees its parts build was reserved under: held while
    /// the archive lives, so until a reader built them from it.
    _trees: Arc<Hold>,
}

impl DocxArchive {
    /// Build an archive directly from a list of files (useful for tests).
    pub fn from_parts(files: Vec<DocxFile>) -> Self {
        Self {
            files,
            _trees: Arc::default(),
        }
    }

    /// Read under the limits of the operation it runs in
    /// ([`Operation::limits`]).
    pub fn read(docx_bytes: &[u8]) -> Result<Self, DocxError> {
        Self::read_with_limits(docx_bytes, Operation::current().limits())
    }

    /// Read under the caller's effective workload policy, reserving what the
    /// read allocates through the operation it runs in. The entry count is an
    /// observation: each entry's record, name and bytes are reserved before
    /// they are allocated, and the read asks the operation at each entry
    /// whether its deadline passed. Declared sizes are checked against the
    /// byte ceilings before inflation, and actual bytes per entry and
    /// cumulatively, so a lying central directory cannot pass them.
    pub fn read_with_limits(docx_bytes: &[u8], limits: ArchiveLimits) -> Result<Self, DocxError> {
        if !limits.is_valid() {
            return Err(DocxError::ZipBomb("invalid archive limits".to_owned()));
        }
        let operation = Operation::current();
        let mut hold = operation.hold();
        let cursor = Cursor::new(docx_bytes);
        let mut zip = ZipArchive::new(cursor).map_err(DocxError::ZipRead)?;

        hold.take(bytes_of::<DocxFile>(zip.len()))?;
        let mut files = Vec::with_capacity(zip.len());
        let mut total_bytes: u64 = 0;
        // OPC §7.3: ZIP item names shall be unique within the package, and
        // logical item names that differ only in ASCII case are equivalent
        // (OPC §6.2). Keyed by the lowercased name, valued by the spelling we
        // first saw, so the error can show both.
        let mut seen_names: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for i in 0..zip.len() {
            operation.checkpoint()?;
            let mut file = zip.by_index(i).map_err(DocxError::ZipRead)?;
            // The name, its lowercased key and the stored spelling.
            hold.take(wide(file.name().len()).saturating_mul(3))?;
            let name = file.name().to_string();

            if !name.ends_with('/')
                && let Some(existing) = seen_names.insert(name.to_ascii_lowercase(), name.clone())
            {
                return Err(DocxError::DuplicatePartName { name, existing });
            }

            // Reject path traversal in filenames (defense in depth).
            if name.contains("..") || name.starts_with('/') {
                return Err(DocxError::ZipBomb(format!(
                    "suspicious filename in archive: {name:?}"
                )));
            }

            // Refuse a declared oversize before inflation; also cap actual
            // bytes with take() because ZIP headers are caller-controlled.
            let remaining = limits.max_total_bytes.saturating_sub(total_bytes);
            let declared = file.size();
            if declared > limits.max_part_bytes {
                return Err(DocxError::Capacity {
                    ceiling: Ceiling::PartBytes,
                    observed: declared,
                    limit: limits.max_part_bytes,
                });
            }
            if declared > remaining {
                return Err(DocxError::Capacity {
                    ceiling: Ceiling::TotalBytes,
                    observed: total_bytes.saturating_add(declared),
                    limit: limits.max_total_bytes,
                });
            }
            // The declared size is the header's word, an estimate: nothing of
            // it is measured until it is inflated.
            hold.take_estimate(declared, 0)?;
            let mut data = Vec::new();
            let cap = limits.max_part_bytes.min(remaining);
            (&mut file)
                .take(cap.saturating_add(1))
                .read_to_end(&mut data)
                .map_err(DocxError::Io)?;
            let actual = wide(data.len());
            if actual > cap {
                return Err(if actual > limits.max_part_bytes {
                    DocxError::Capacity {
                        ceiling: Ceiling::PartBytes,
                        observed: actual,
                        limit: limits.max_part_bytes,
                    }
                } else {
                    DocxError::Capacity {
                        ceiling: Ceiling::TotalBytes,
                        observed: total_bytes.saturating_add(actual),
                        limit: limits.max_total_bytes,
                    }
                });
            }
            // What inflated past the header's word, measured now.
            hold.take(actual.saturating_sub(declared))?;
            total_bytes = total_bytes.saturating_add(actual);

            files.push(DocxFile { name, data });
        }
        // The trees every part builds, reserved before any reader builds one
        // from this archive, and held while the archive lives.
        let trees = crate::parse_budget::admit_parts(
            files.iter().map(|file| file.data.as_slice()),
            &operation,
        )?;
        Ok(Self {
            files,
            _trees: Arc::new(trees),
        })
    }

    pub fn write(&self) -> Result<Vec<u8>, DocxError> {
        // This writer emits classic ZIP only: past its widths the package is
        // refused as that format's limit, before the writer would switch to
        // ZIP64 records Word's normalization below does not read.
        let entries = wide(self.files.len());
        if entries > CLASSIC_ZIP_ENTRIES {
            return Err(DocxError::Capacity {
                ceiling: Ceiling::ZipEntries,
                observed: entries,
                limit: CLASSIC_ZIP_ENTRIES,
            });
        }
        if let Some(file) = self
            .files
            .iter()
            .find(|file| wide(file.data.len()) > CLASSIC_ZIP_BYTES)
        {
            return Err(DocxError::Capacity {
                ceiling: Ceiling::ZipBytes,
                observed: wide(file.data.len()),
                limit: CLASSIC_ZIP_BYTES,
            });
        }
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        // Pin the per-entry modification time to a fixed epoch. With the `time`
        // feature enabled (transitively), `FileOptions::default()` stamps
        // `OffsetDateTime::now_utc()` into every local file header, so two writes
        // of the SAME package seconds apart differ in the DOS date/time fields —
        // a wall-clock leak that breaks byte-level determinism (H1). Word does
        // not read these timestamps; 1980-01-01 (the ZIP epoch,
        // `DateTime::default()`) is the reproducible-build convention.
        let options = FileOptions::default().last_modified_time(zip::DateTime::default());
        for file in &self.files {
            if file.name.ends_with('/') {
                writer
                    .add_directory(file.name.as_str(), options)
                    .map_err(DocxError::ZipWrite)?;
                continue;
            }
            writer
                .start_file(file.name.as_str(), options)
                .map_err(DocxError::ZipWrite)?;
            writer.write_all(&file.data).map_err(DocxError::Io)?;
        }
        let cursor = writer.finish().map_err(DocxError::ZipWrite)?;
        let mut bytes = cursor.into_inner();
        if wide(bytes.len()) > CLASSIC_ZIP_BYTES {
            return Err(DocxError::Capacity {
                ceiling: Ceiling::ZipBytes,
                observed: wide(bytes.len()),
                limit: CLASSIC_ZIP_BYTES,
            });
        }
        normalize_word_compatible_creator_version(&mut bytes)?;
        Ok(bytes)
    }

    /// Look up a part by name. Part-name equivalence is ASCII case-insensitive
    /// (OPC §6.2), so a lookup for `word/document.xml` resolves a part stored
    /// as `word/Document.xml`. An exact match wins; `read` guarantees at most
    /// one case-equivalent entry exists.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.find(name).map(|file| file.data.as_slice())
    }

    fn find(&self, name: &str) -> Option<&DocxFile> {
        self.files
            .iter()
            .find(|file| file.name == name)
            .or_else(|| {
                self.files
                    .iter()
                    .find(|file| file.name.eq_ignore_ascii_case(name))
            })
    }

    fn find_mut(&mut self, name: &str) -> Option<&mut DocxFile> {
        let idx = self
            .files
            .iter()
            .position(|file| file.name == name)
            .or_else(|| {
                self.files
                    .iter()
                    .position(|file| file.name.eq_ignore_ascii_case(name))
            })?;
        Some(&mut self.files[idx])
    }

    /// Replace an existing part's bytes. Resolves the name case-insensitively
    /// (OPC §6.2) and keeps the stored spelling, so relationship targets that
    /// point at the original spelling stay valid.
    pub fn set(&mut self, name: &str, data: Vec<u8>) -> Result<(), DocxError> {
        if let Some(file) = self.find_mut(name) {
            file.data = data;
            return Ok(());
        }
        Err(DocxError::MissingFile(name.to_string()))
    }

    /// Insert or replace a part. Resolves case-insensitively like [`Self::set`]
    /// (keeping the stored spelling on replace) so an upsert can never create a
    /// case-equivalent duplicate of an existing part (OPC §7.3).
    pub fn upsert(&mut self, name: &str, data: Vec<u8>) {
        if let Some(file) = self.find_mut(name) {
            file.data = data;
            return;
        }
        self.files.push(DocxFile {
            name: name.to_string(),
            data,
        });
    }

    pub fn list(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|file| file.name.as_str())
    }
}

/// Normalize the central-directory "version made by" value emitted by zip
/// 0.6.6 from 4.6 to 2.0 while preserving its creator-OS byte.
///
/// The crate hardcodes 4.6 for every entry even when the archive uses only
/// classic ZIP 2.0 features. Real Word can then open the package without a
/// repair prompt yet silently ignore a part (an oracle witness ignored
/// `word/styles.xml`, shifting every framed running head) until Word resaved
/// the archive with creator version 2.0. The field describes the writer, not
/// the compression feature requirement; each local/central "version needed"
/// remains untouched.
///
/// This parser is deliberately bounded to the classic ZIP shape this writer
/// emits: [`DocxArchive::write`] refuses a package past classic ZIP's widths
/// as that format's limit before it gets here. Any mismatch is our own
/// broken-output invariant and fails the write loudly.
fn normalize_word_compatible_creator_version(bytes: &mut [u8]) -> Result<(), DocxError> {
    const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const EOCD_MIN_SIZE: usize = 22;
    const MAX_ZIP_COMMENT: usize = u16::MAX as usize;

    if bytes.len() < EOCD_MIN_SIZE {
        return Err(DocxError::InvalidWrittenZip(
            "ZIP is shorter than the end-of-central-directory record".to_string(),
        ));
    }
    let search_start = bytes.len().saturating_sub(EOCD_MIN_SIZE + MAX_ZIP_COMMENT);
    let eocd = (search_start..=bytes.len() - EOCD_MIN_SIZE)
        .rev()
        .find(|offset| bytes[*offset..].starts_with(&EOCD_SIGNATURE))
        .ok_or_else(|| {
            DocxError::InvalidWrittenZip(
                "ZIP end-of-central-directory signature is missing".to_string(),
            )
        })?;
    let disk = read_zip_u16(bytes, eocd + 4);
    let central_disk = read_zip_u16(bytes, eocd + 6);
    let disk_entries = read_zip_u16(bytes, eocd + 8);
    let total_entries = read_zip_u16(bytes, eocd + 10);
    let central_size = read_zip_u32(bytes, eocd + 12) as usize;
    let central_offset = read_zip_u32(bytes, eocd + 16) as usize;
    let comment_len = read_zip_u16(bytes, eocd + 20) as usize;
    if disk != 0 || central_disk != 0 || disk_entries != total_entries {
        return Err(DocxError::InvalidWrittenZip(format!(
            "expected a single-disk ZIP, got disk={disk} central_disk={central_disk} entries={disk_entries}/{total_entries}"
        )));
    }
    if eocd + EOCD_MIN_SIZE + comment_len != bytes.len() {
        return Err(DocxError::InvalidWrittenZip(format!(
            "ZIP comment length does not reach end of archive: eocd={eocd} comment_len={comment_len} bytes={}",
            bytes.len()
        )));
    }
    let central_end = central_offset.checked_add(central_size).ok_or_else(|| {
        DocxError::InvalidWrittenZip("central-directory size overflowed usize".to_string())
    })?;
    if central_end != eocd {
        return Err(DocxError::InvalidWrittenZip(format!(
            "central directory does not end at EOCD: offset={central_offset} size={central_size} eocd={eocd}"
        )));
    }

    let mut cursor = central_offset;
    for index in 0..usize::from(total_entries) {
        if cursor + 46 > central_end || !bytes[cursor..].starts_with(&CENTRAL_SIGNATURE) {
            return Err(DocxError::InvalidWrittenZip(format!(
                "central-directory entry {index} is truncated or has the wrong signature at offset {cursor}"
            )));
        }
        // Low byte = creator version, high byte = creator operating system.
        let file_name_len = read_zip_u16(bytes, cursor + 28) as usize;
        let extra_len = read_zip_u16(bytes, cursor + 30) as usize;
        let comment_len = read_zip_u16(bytes, cursor + 32) as usize;
        bytes[cursor + 4] = 20;
        cursor = cursor
            .checked_add(46 + file_name_len + extra_len + comment_len)
            .ok_or_else(|| {
                DocxError::InvalidWrittenZip(format!(
                    "central-directory entry {index} length overflowed usize"
                ))
            })?;
    }
    if cursor != central_end {
        return Err(DocxError::InvalidWrittenZip(format!(
            "central-directory entry count did not consume its declared size: cursor={cursor} end={central_end} entries={total_entries}"
        )));
    }
    Ok(())
}

fn read_zip_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_zip_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let opts: FileOptions = FileOptions::default();
            for (name, data) in entries {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(data).unwrap();
            }
            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn read_rejects_exact_duplicate_part_name() {
        let bytes = zip_with_entries(&[
            ("word/document.xml", b"<a/>"),
            ("word/document.xml", b"<b/>"),
        ]);
        let err = DocxArchive::read(&bytes).expect_err("duplicate part names must be rejected");
        assert!(
            matches!(err, DocxError::DuplicatePartName { ref name, ref existing }
                if name == "word/document.xml" && existing == "word/document.xml"),
            "expected DuplicatePartName, got {err:?}"
        );
    }

    #[test]
    fn read_rejects_case_equivalent_duplicate_part_name() {
        // OPC §6.2: names differing only in ASCII case are equivalent.
        let bytes = zip_with_entries(&[
            ("word/document.xml", b"<a/>"),
            ("word/Document.xml", b"<b/>"),
        ]);
        let err = DocxArchive::read(&bytes)
            .expect_err("case-equivalent duplicate part names must be rejected");
        assert!(
            matches!(err, DocxError::DuplicatePartName { ref name, ref existing }
                if name == "word/Document.xml" && existing == "word/document.xml"),
            "expected DuplicatePartName, got {err:?}"
        );
    }

    #[test]
    fn get_resolves_part_name_case_insensitively() {
        let bytes = zip_with_entries(&[("word/Document.xml", b"<doc/>")]);
        let archive = DocxArchive::read(&bytes).unwrap();
        assert_eq!(archive.get("word/document.xml"), Some(b"<doc/>".as_slice()));
        assert_eq!(archive.get("word/Document.xml"), Some(b"<doc/>".as_slice()));
        assert_eq!(archive.get("word/styles.xml"), None);
    }

    #[test]
    fn set_and_upsert_keep_the_stored_spelling() {
        let bytes = zip_with_entries(&[("word/Document.xml", b"<doc/>")]);
        let mut archive = DocxArchive::read(&bytes).unwrap();

        archive
            .set("word/document.xml", b"<set/>".to_vec())
            .expect("set must resolve the case-equivalent stored part");
        archive.upsert("word/document.xml", b"<upserted/>".to_vec());

        // One part, stored spelling preserved (rels Targets point at it).
        let names: Vec<&str> = archive.list().collect();
        assert_eq!(names, vec!["word/Document.xml"]);
        assert_eq!(
            archive.get("word/document.xml"),
            Some(b"<upserted/>".as_slice())
        );
    }

    #[test]
    fn write_uses_word_compatible_creator_version_without_disabling_compression() {
        let archive = DocxArchive::from_parts(vec![
            DocxFile {
                name: "[Content_Types].xml".to_string(),
                data: b"<Types/>".to_vec(),
            },
            DocxFile {
                name: "word/document.xml".to_string(),
                data: b"<w:document/>".to_vec(),
            },
            DocxFile {
                name: "word/_rels/document.xml.rels".to_string(),
                data: b"<Relationships/>".to_vec(),
            },
            DocxFile {
                name: "word/media/image1.bin".to_string(),
                data: vec![0; 1024],
            },
        ]);

        let bytes = archive.write().expect("write package");
        let mut zip = ZipArchive::new(Cursor::new(bytes)).expect("open written package");
        for name in [
            "[Content_Types].xml",
            "word/document.xml",
            "word/_rels/document.xml.rels",
            "word/media/image1.bin",
        ] {
            assert_eq!(
                zip.by_name(name).expect("part").version_made_by(),
                (2, 0),
                "every central-directory creator version must be Word-compatible: {name}"
            );
        }
        assert_eq!(
            zip.by_name("word/media/image1.bin")
                .expect("binary part")
                .compression(),
            zip::CompressionMethod::Deflated,
            "normal package compression remains enabled"
        );
    }
}
