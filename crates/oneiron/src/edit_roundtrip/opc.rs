//! Minimal Open Packaging Conventions (OPC) reader/writer for the ARTL-3
//! edit round-trip pipeline.
//!
//! Office Open XML files (xlsx/docx/pptx) are ZIP containers of XML parts. The
//! pipeline needs to decompose the bytes a code-session produced into their
//! parts so it can enforce the OF-368 D5 fidelity law **independently of the
//! session** — the corruption/passthrough gate must not trust the very tool
//! that wrote the bytes. That is why this lives in the engine (pure Rust,
//! runnable in CI) rather than behind the external-binary seam.
//!
//! Scope is deliberately narrow: read STORED and DEFLATE ZIP entries via the
//! central directory, and write STORED entries. We never re-compress a
//! session's output — the pipeline reads the session bytes to verify and diff
//! them, it does not repackage them. Writing exists only to build the copy
//! handed to a session and to construct test fixtures.
//!
//! Every entry is bounded and verified before it is trusted: the reader
//! rejects a declared uncompressed size over a per-entry or per-package cap
//! before inflating (a zip bomb), inflates against that bound, and checks the
//! resulting length and CRC-32 against the central directory. Duplicate part
//! names, multi-disk archives, ZIP64 sentinels, encrypted entries, and
//! compression methods other than STORED/DEFLATE are rejected as corruption
//! rather than silently mishandled.
//!
//! This is original code written against the published ZIP appnote and the
//! ECMA-376 OPC part-naming conventions (facts, not expression); it copies no
//! source from any packaging library.

use std::collections::BTreeSet;
use std::io::Read;

use crate::error::{Error, Result};

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_DIR_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_FILE_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_MIN_LEN: usize = 22;
const CENTRAL_DIR_MIN_LEN: usize = 46;
const LOCAL_FILE_MIN_LEN: usize = 30;
const ZIP_STORED: u16 = 0;
const ZIP_DEFLATE: u16 = 8;

/// Per-entry ceiling on a central-directory *declared* uncompressed size. An
/// OPC part advertising more than this is rejected before inflation, bounding a
/// single zip-bomb entry (this pipeline reasons over spreadsheet XML, not
/// arbitrary archives).
const MAX_ENTRY_UNCOMPRESSED: u64 = 256 * 1024 * 1024;
/// Whole-package ceiling on the sum of every entry's declared uncompressed
/// size, bounding an archive of many individually-modest entries.
const MAX_PACKAGE_UNCOMPRESSED: u64 = 1024 * 1024 * 1024;

/// The OPC content-type manifest present in every well-formed package.
pub(crate) const CONTENT_TYPES_PART: &str = "[Content_Types].xml";

/// Coarse classification of an OPC part for the fidelity law.
///
/// `Supported` parts are the core editable spreadsheet surface the edit tool
/// is allowed to rewrite. `Unknown` parts — macros, pivots, charts, custom
/// XML, anything unrecognized — must survive an edit byte-for-byte
/// ([passthrough law](super)); a change to one of them is corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartClass {
    Supported,
    Unknown,
}

/// One part of an OPC package: its archive path and decompressed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpcPart {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
}

/// A decomposed OPC package. Part order mirrors the source central directory
/// so a read/write round-trip is stable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OpcPackage {
    parts: Vec<OpcPart>,
}

impl OpcPackage {
    pub(crate) fn from_parts(parts: Vec<OpcPart>) -> Self {
        Self { parts }
    }

    pub(crate) fn parts(&self) -> &[OpcPart] {
        &self.parts
    }

    /// Returns the decompressed bytes for `name`, if present.
    pub(crate) fn part(&self, name: &str) -> Option<&[u8]> {
        self.parts
            .iter()
            .find(|part| part.name == name)
            .map(|part| part.data.as_slice())
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.parts.iter().any(|part| part.name == name)
    }

    /// Iterates part names in package order.
    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().map(|part| part.name.as_str())
    }

    /// Inserts or replaces a part, preserving position for replacements. Used
    /// by the write side (fixture sessions today; a production Rust-side
    /// session that repackages parts will promote it).
    #[cfg(test)]
    pub(crate) fn upsert(&mut self, name: impl Into<String>, data: Vec<u8>) {
        let name = name.into();
        if let Some(existing) = self.parts.iter_mut().find(|part| part.name == name) {
            existing.data = data;
        } else {
            self.parts.push(OpcPart { name, data });
        }
    }
}

/// Reads an OPC package from ZIP bytes via the central directory.
///
/// Returns [`Error::EditRoundtripFailed`] for anything that is not a package
/// this pipeline can safely reason about — a missing/blank EOCD, a truncated
/// entry, or an unsupported compression method. Corruption checks upstream
/// rely on this failing loudly rather than guessing.
pub(crate) fn read(bytes: &[u8]) -> Result<OpcPackage> {
    let eocd = locate_eocd(bytes)?;

    // Multi-disk / spanned archives are out of scope: OPC packages are single
    // files. A non-zero disk number means the central directory this reader
    // walks is only part of the archive, so reject rather than reason over a
    // partial view.
    if read_u16(bytes, eocd + 4)? != 0 || read_u16(bytes, eocd + 6)? != 0 {
        return Err(Error::EditRoundtripFailed(
            "opc archive spans multiple disks (unsupported)",
        ));
    }

    let entry_count = read_u16(bytes, eocd + 10)?;
    let cd_offset = read_u32(bytes, eocd + 16)?;
    // ZIP64 marks an overflowed 16/32-bit EOCD field with all-ones and moves
    // the real value into a ZIP64 record this reader does not parse. Reject the
    // sentinels loudly instead of truncating a 64-bit archive to 32 bits.
    if entry_count == u16::MAX || cd_offset == u32::MAX {
        return Err(Error::EditRoundtripFailed(
            "opc archive uses zip64 sentinels (unsupported)",
        ));
    }
    let entry_count = entry_count as usize;

    let mut parts = Vec::with_capacity(entry_count);
    let mut seen_names = BTreeSet::new();
    let mut total_declared: u64 = 0;
    let mut cursor = cd_offset as usize;
    for _ in 0..entry_count {
        if read_u32(bytes, cursor)? != CENTRAL_DIR_SIGNATURE {
            return Err(Error::EditRoundtripFailed(
                "opc central directory header signature mismatch",
            ));
        }
        let flags = read_u16(bytes, cursor + 8)?;
        // General-purpose bit 0 marks an encrypted entry; we can neither verify
        // nor pass ciphertext through under the fidelity law.
        if flags & 0x0001 != 0 {
            return Err(Error::EditRoundtripFailed(
                "opc entry is encrypted (unsupported)",
            ));
        }
        let method = read_u16(bytes, cursor + 10)?;
        let expected_crc = read_u32(bytes, cursor + 16)?;
        let comp_size = read_u32(bytes, cursor + 20)?;
        let declared_size = read_u32(bytes, cursor + 24)?;
        let name_len = read_u16(bytes, cursor + 28)? as usize;
        let extra_len = read_u16(bytes, cursor + 30)? as usize;
        let comment_len = read_u16(bytes, cursor + 32)? as usize;
        let disk_start = read_u16(bytes, cursor + 34)?;
        let local_offset = read_u32(bytes, cursor + 42)?;

        if disk_start != 0 {
            return Err(Error::EditRoundtripFailed(
                "opc entry lives on another disk (unsupported)",
            ));
        }
        if comp_size == u32::MAX || declared_size == u32::MAX || local_offset == u32::MAX {
            return Err(Error::EditRoundtripFailed(
                "opc entry uses zip64 sentinels (unsupported)",
            ));
        }

        // Zip-bomb bound: reject before inflating any entry whose declared
        // uncompressed size exceeds the per-entry cap, and any package whose
        // declared sizes sum past the whole-package cap.
        let declared_size = u64::from(declared_size);
        if declared_size > MAX_ENTRY_UNCOMPRESSED {
            return Err(Error::EditRoundtripFailed(
                "opc entry declares an uncompressed size over the per-entry cap",
            ));
        }
        total_declared = total_declared.saturating_add(declared_size);
        if total_declared > MAX_PACKAGE_UNCOMPRESSED {
            return Err(Error::EditRoundtripFailed(
                "opc package declares an uncompressed size over the package cap",
            ));
        }

        let name = read_name(bytes, cursor + CENTRAL_DIR_MIN_LEN, name_len)?;
        // OPC part names must be unique; with a duplicate, which of the two
        // same-named parts is authoritative is undefined, so the passthrough
        // law cannot be enforced. Treat it as corruption.
        if !seen_names.insert(name.clone()) {
            return Err(Error::EditRoundtripFailed(
                "opc package has duplicate part names",
            ));
        }

        let data = read_local_entry(
            bytes,
            local_offset as usize,
            method,
            comp_size as usize,
            declared_size,
            expected_crc,
        )?;
        parts.push(OpcPart { name, data });

        cursor = cursor
            .checked_add(CENTRAL_DIR_MIN_LEN + name_len + extra_len + comment_len)
            .ok_or(Error::EditRoundtripFailed("opc central directory overflow"))?;
    }

    Ok(OpcPackage::from_parts(parts))
}

/// Serializes a package to ZIP bytes using STORED (method 0) entries.
///
/// The pipeline only *reads* the bytes a session produced; writing exists to
/// build the copy handed to a session and to construct test fixtures. Until a
/// production Rust-side session (e.g. umya-spreadsheet) or copy-materialization
/// path lands, only the fixture session exercises it.
#[cfg(test)]
pub(crate) fn write(package: &OpcPackage) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;

    for part in package.parts() {
        let name = part.name.as_bytes();
        let crc = crc32(&part.data);
        let size = part.data.len() as u32;
        let local_offset = out.len() as u32;

        out.extend_from_slice(&LOCAL_FILE_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&ZIP_STORED.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(&part.data);

        central.extend_from_slice(&CENTRAL_DIR_SIGNATURE.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&ZIP_STORED.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra len
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name);

        count = count.saturating_add(1);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes()); // entries this disk
    out.extend_from_slice(&count.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// Classifies a part for the fidelity law. Unknown-forcing families (macros,
/// pivots, charts, custom XML) are checked before the generic `xl/` editable
/// surface so a pivot part never counts as supported.
pub(crate) fn classify(name: &str) -> PartClass {
    if is_unknown_forced(name) {
        return PartClass::Unknown;
    }
    if name == CONTENT_TYPES_PART
        || name.starts_with("_rels/")
        || name.contains("/_rels/")
        || name.starts_with("docProps/")
        || is_supported_xl(name)
        || name.starts_with("word/")
        || name.starts_with("ppt/")
    {
        return PartClass::Supported;
    }
    PartClass::Unknown
}

/// True for part families the edit tool never rewrites and must pass through
/// byte-for-byte: VBA macros, pivot caches/tables, charts, and custom XML.
pub(crate) fn is_unknown_forced(name: &str) -> bool {
    name == "xl/vbaProject.bin"
        || name.starts_with("customXml/")
        || name.starts_with("xl/pivotCache/")
        || name.starts_with("xl/pivotTables/")
        || name.starts_with("xl/charts/")
}

fn is_supported_xl(name: &str) -> bool {
    const SUPPORTED_XL_PREFIXES: [&str; 7] = [
        "xl/worksheets/",
        "xl/theme/",
        "xl/tables/",
        "xl/drawings/",
        "xl/metadata",
        "xl/sharedStrings.xml",
        "xl/styles.xml",
    ];
    name == "xl/workbook.xml"
        || name == "xl/calcChain.xml"
        || SUPPORTED_XL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn locate_eocd(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < EOCD_MIN_LEN {
        return Err(Error::EditRoundtripFailed(
            "opc bytes too short for an EOCD record",
        ));
    }
    let max_back = bytes.len() - EOCD_MIN_LEN;
    // The EOCD comment can be up to 0xFFFF bytes; scan that far back at most.
    let scan_floor = max_back.saturating_sub(u16::MAX as usize);
    for candidate in (scan_floor..=max_back).rev() {
        if read_u32(bytes, candidate)? == EOCD_SIGNATURE {
            return Ok(candidate);
        }
    }
    Err(Error::EditRoundtripFailed(
        "opc end-of-central-directory record not found",
    ))
}

fn read_local_entry(
    bytes: &[u8],
    local_offset: usize,
    method: u16,
    comp_size: usize,
    declared_size: u64,
    expected_crc: u32,
) -> Result<Vec<u8>> {
    if read_u32(bytes, local_offset)? != LOCAL_FILE_SIGNATURE {
        return Err(Error::EditRoundtripFailed(
            "opc local file header signature mismatch",
        ));
    }
    let local_name_len = read_u16(bytes, local_offset + 26)? as usize;
    let local_extra_len = read_u16(bytes, local_offset + 28)? as usize;
    let data_start = local_offset
        .checked_add(LOCAL_FILE_MIN_LEN + local_name_len + local_extra_len)
        .ok_or(Error::EditRoundtripFailed("opc local data offset overflow"))?;
    let data_end = data_start
        .checked_add(comp_size)
        .ok_or(Error::EditRoundtripFailed("opc local data length overflow"))?;
    let raw = bytes
        .get(data_start..data_end)
        .ok_or(Error::EditRoundtripFailed("opc entry data truncated"))?;

    let data = match method {
        ZIP_STORED => raw.to_vec(),
        ZIP_DEFLATE => inflate(raw, declared_size)?,
        _ => {
            return Err(Error::EditRoundtripFailed(
                "opc entry uses an unsupported compression method",
            ));
        }
    };

    // Verify the produced bytes against the central-directory declaration. The
    // gate never trusts a length or checksum it did not recompute from the
    // actual bytes: a mismatch is corruption (or a bomb capped by `inflate`).
    if data.len() as u64 != declared_size {
        return Err(Error::EditRoundtripFailed(
            "opc entry size does not match its declared uncompressed size",
        ));
    }
    if crc32(&data) != expected_crc {
        return Err(Error::EditRoundtripFailed(
            "opc entry crc-32 does not match its central-directory checksum",
        ));
    }
    Ok(data)
}

fn inflate(raw: &[u8], declared_size: u64) -> Result<Vec<u8>> {
    // Bound the decompressor at declared+1 bytes: a well-formed entry inflates
    // to exactly `declared_size`, so reading one extra byte is enough for the
    // caller's length check to catch a stream that expands past its declaration
    // (a zip bomb) without ever buffering the full expansion.
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(raw)
        .take(declared_size.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| Error::EditRoundtripFailed("opc deflate entry failed to inflate"))?;
    Ok(out)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or(Error::EditRoundtripFailed("opc read past end of buffer"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(Error::EditRoundtripFailed("opc read past end of buffer"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_name(bytes: &[u8], offset: usize, len: usize) -> Result<String> {
    let raw = bytes
        .get(offset..offset + len)
        .ok_or(Error::EditRoundtripFailed("opc part name truncated"))?;
    String::from_utf8(raw.to_vec())
        .map_err(|_| Error::EditRoundtripFailed("opc part name is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(parts: &[(&str, &[u8])]) -> OpcPackage {
        OpcPackage::from_parts(
            parts
                .iter()
                .map(|(name, data)| OpcPart {
                    name: (*name).to_owned(),
                    data: (*data).to_vec(),
                })
                .collect(),
        )
    }

    #[test]
    fn write_read_round_trips_stored_entries() {
        let pkg = package(&[
            (CONTENT_TYPES_PART, b"<Types/>"),
            ("xl/workbook.xml", b"<workbook/>"),
            (
                "customXml/item1.xml",
                b"<unknown-part>keep me</unknown-part>",
            ),
        ]);
        let bytes = write(&pkg);
        let parsed = read(&bytes).expect("round-trip read");
        assert_eq!(parsed, pkg);
        // Names preserve source order.
        assert_eq!(
            parsed.names().collect::<Vec<_>>(),
            vec![CONTENT_TYPES_PART, "xl/workbook.xml", "customXml/item1.xml"]
        );
    }

    #[test]
    fn read_rejects_non_zip_bytes() {
        let err = read(b"this is definitely not a zip archive at all")
            .expect_err("garbage bytes must not parse as OPC");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_truncated_buffer() {
        let bytes = write(&package(&[("a.xml", b"hello")]));
        let err = read(&bytes[..bytes.len() - 4]).expect_err("truncated EOCD must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn classify_forces_unknown_for_macros_pivots_and_custom_xml() {
        assert_eq!(classify("xl/vbaProject.bin"), PartClass::Unknown);
        assert_eq!(
            classify("xl/pivotTables/pivotTable1.xml"),
            PartClass::Unknown
        );
        assert_eq!(
            classify("xl/pivotCache/pivotCacheDefinition1.xml"),
            PartClass::Unknown
        );
        assert_eq!(classify("xl/charts/chart1.xml"), PartClass::Unknown);
        assert_eq!(classify("customXml/item1.xml"), PartClass::Unknown);
        assert_eq!(classify("some/random/part.bin"), PartClass::Unknown);
    }

    #[test]
    fn classify_marks_core_spreadsheet_surface_supported() {
        assert_eq!(classify(CONTENT_TYPES_PART), PartClass::Supported);
        assert_eq!(classify("xl/workbook.xml"), PartClass::Supported);
        assert_eq!(classify("xl/worksheets/sheet1.xml"), PartClass::Supported);
        assert_eq!(classify("xl/sharedStrings.xml"), PartClass::Supported);
        assert_eq!(classify("xl/_rels/workbook.xml.rels"), PartClass::Supported);
        assert_eq!(classify("docProps/core.xml"), PartClass::Supported);
    }

    #[test]
    fn upsert_replaces_in_place_and_appends_new() {
        let mut pkg = package(&[("a.xml", b"1"), ("b.xml", b"2")]);
        pkg.upsert("a.xml", b"replaced".to_vec());
        pkg.upsert("c.xml", b"new".to_vec());
        assert_eq!(pkg.part("a.xml"), Some(b"replaced".as_slice()));
        assert_eq!(
            pkg.names().collect::<Vec<_>>(),
            vec!["a.xml", "b.xml", "c.xml"]
        );
    }

    /// A raw ZIP entry with every central-directory/local field independently
    /// settable, so a test can force one specific corruption (bad CRC, a lying
    /// size, a ZIP64 sentinel, an encryption flag, ...).
    struct RawEntry {
        name: String,
        flags: u16,
        method: u16,
        crc: u32,
        comp_size: u32,
        uncomp_size: u32,
        disk_start: u16,
        payload: Vec<u8>,
    }

    impl RawEntry {
        /// A STORED entry with self-consistent crc and sizes.
        fn stored(name: &str, data: &[u8]) -> Self {
            Self {
                name: name.to_owned(),
                flags: 0,
                method: ZIP_STORED,
                crc: crc32(data),
                comp_size: data.len() as u32,
                uncomp_size: data.len() as u32,
                disk_start: 0,
                payload: data.to_vec(),
            }
        }

        /// A DEFLATE entry with self-consistent crc and sizes.
        fn deflated(name: &str, data: &[u8]) -> Self {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut encoder, data).unwrap();
            let payload = encoder.finish().unwrap();
            Self {
                name: name.to_owned(),
                flags: 0,
                method: ZIP_DEFLATE,
                crc: crc32(data),
                comp_size: payload.len() as u32,
                uncomp_size: data.len() as u32,
                disk_start: 0,
                payload,
            }
        }
    }

    /// Assembles raw entries into a ZIP. The EOCD disk fields and total entry
    /// count are overridable so tests can exercise the multi-disk / zip64
    /// rejections that the fixture-focused `write` never emits.
    fn build_zip(
        entries: &[RawEntry],
        eocd_disk: u16,
        cd_disk: u16,
        count_override: Option<u16>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for entry in entries {
            let local_offset = out.len() as u32;
            out.extend_from_slice(&LOCAL_FILE_SIGNATURE.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&entry.flags.to_le_bytes());
            out.extend_from_slice(&entry.method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&entry.crc.to_le_bytes());
            out.extend_from_slice(&entry.comp_size.to_le_bytes());
            out.extend_from_slice(&entry.uncomp_size.to_le_bytes());
            out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(entry.name.as_bytes());
            out.extend_from_slice(&entry.payload);

            central.extend_from_slice(&CENTRAL_DIR_SIGNATURE.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&entry.flags.to_le_bytes());
            central.extend_from_slice(&entry.method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central.extend_from_slice(&entry.crc.to_le_bytes());
            central.extend_from_slice(&entry.comp_size.to_le_bytes());
            central.extend_from_slice(&entry.uncomp_size.to_le_bytes());
            central.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra len
            central.extend_from_slice(&0u16.to_le_bytes()); // comment len
            central.extend_from_slice(&entry.disk_start.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(entry.name.as_bytes());
        }

        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        let count = count_override.unwrap_or(entries.len() as u16);
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        out.extend_from_slice(&eocd_disk.to_le_bytes());
        out.extend_from_slice(&cd_disk.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes()); // entries this disk
        out.extend_from_slice(&count.to_le_bytes()); // entries total
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }

    #[test]
    fn read_round_trips_deflate_entries() {
        let body = b"<worksheet>deflate me byte for byte</worksheet>".repeat(64);
        let zip = build_zip(
            &[RawEntry::deflated("xl/worksheets/sheet1.xml", &body)],
            0,
            0,
            None,
        );
        let pkg = read(&zip).expect("deflate entry parses");
        assert_eq!(pkg.part("xl/worksheets/sheet1.xml"), Some(body.as_slice()));
    }

    #[test]
    fn read_rejects_crc_mismatch() {
        let mut entry = RawEntry::stored("a.xml", b"hello");
        entry.crc ^= 0xFFFF_FFFF;
        let err = read(&build_zip(&[entry], 0, 0, None)).expect_err("bad crc must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_declared_size_mismatch() {
        // The stored bytes are 5 long but the entry declares 4.
        let mut entry = RawEntry::stored("a.xml", b"hello");
        entry.uncomp_size = 4;
        let err =
            read(&build_zip(&[entry], 0, 0, None)).expect_err("declared-size mismatch must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_zip_bomb_declared_size() {
        // A tiny stored entry that lies about a ~4 GiB uncompressed size is
        // rejected before any allocation.
        let mut entry = RawEntry::stored("a.xml", b"tiny");
        entry.uncomp_size = u32::MAX - 1;
        let err = read(&build_zip(&[entry], 0, 0, None))
            .expect_err("declared size over the per-entry cap must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_inflation_past_declaration() {
        // A valid deflate stream whose entry under-declares its size: the
        // decompressor is capped and the length check catches the overrun.
        let mut entry = RawEntry::deflated("a.xml", &b"A".repeat(64));
        entry.uncomp_size = 4;
        let err = read(&build_zip(&[entry], 0, 0, None))
            .expect_err("inflation past the declaration must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_zip64_uncompressed_sentinel() {
        let mut entry = RawEntry::stored("a.xml", b"hi");
        entry.uncomp_size = u32::MAX;
        let err =
            read(&build_zip(&[entry], 0, 0, None)).expect_err("zip64 size sentinel must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_duplicate_part_names() {
        let zip = build_zip(
            &[
                RawEntry::stored("dup.xml", b"one"),
                RawEntry::stored("dup.xml", b"two"),
            ],
            0,
            0,
            None,
        );
        let err = read(&zip).expect_err("duplicate part names must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_encrypted_entry() {
        let mut entry = RawEntry::stored("a.xml", b"secret");
        entry.flags |= 0x0001; // encryption bit
        let err = read(&build_zip(&[entry], 0, 0, None)).expect_err("encrypted entry must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_multi_disk_archive() {
        let err = read(&build_zip(&[RawEntry::stored("a.xml", b"x")], 1, 0, None))
            .expect_err("multi-disk archive must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_zip64_entry_count_sentinel() {
        let err = read(&build_zip(
            &[RawEntry::stored("a.xml", b"x")],
            0,
            0,
            Some(u16::MAX),
        ))
        .expect_err("zip64 entry-count sentinel must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_entry_on_another_disk() {
        let mut entry = RawEntry::stored("a.xml", b"x");
        entry.disk_start = 3;
        let err =
            read(&build_zip(&[entry], 0, 0, None)).expect_err("entry on another disk must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }

    #[test]
    fn read_rejects_unsupported_compression_method() {
        let mut entry = RawEntry::stored("a.xml", b"x");
        entry.method = 12; // bzip2 — unsupported
        let err = read(&build_zip(&[entry], 0, 0, None))
            .expect_err("unsupported compression method must fail");
        assert!(matches!(err, Error::EditRoundtripFailed(_)));
    }
}
