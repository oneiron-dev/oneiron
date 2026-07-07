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
//! handed to a session and to construct test fixtures. ZIP64 and encrypted
//! entries are out of scope and are reported as corruption rather than
//! silently mishandled.
//!
//! This is original code written against the published ZIP appnote and the
//! ECMA-376 OPC part-naming conventions (facts, not expression); it copies no
//! source from any packaging library.

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
    let entry_count = read_u16(bytes, eocd + 10)? as usize;
    let cd_offset = read_u32(bytes, eocd + 16)? as usize;

    let mut parts = Vec::with_capacity(entry_count);
    let mut cursor = cd_offset;
    for _ in 0..entry_count {
        if read_u32(bytes, cursor)? != CENTRAL_DIR_SIGNATURE {
            return Err(Error::EditRoundtripFailed(
                "opc central directory header signature mismatch",
            ));
        }
        let method = read_u16(bytes, cursor + 10)?;
        let comp_size = read_u32(bytes, cursor + 20)? as usize;
        let name_len = read_u16(bytes, cursor + 28)? as usize;
        let extra_len = read_u16(bytes, cursor + 30)? as usize;
        let comment_len = read_u16(bytes, cursor + 32)? as usize;
        let local_offset = read_u32(bytes, cursor + 42)? as usize;
        let name = read_name(bytes, cursor + CENTRAL_DIR_MIN_LEN, name_len)?;

        let data = read_local_entry(bytes, local_offset, method, comp_size)?;
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

    match method {
        ZIP_STORED => Ok(raw.to_vec()),
        ZIP_DEFLATE => inflate(raw),
        _ => Err(Error::EditRoundtripFailed(
            "opc entry uses an unsupported compression method",
        )),
    }
}

fn inflate(raw: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::DeflateDecoder::new(raw);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|_| Error::EditRoundtripFailed("opc deflate entry failed to inflate"))?;
    Ok(out)
}

#[cfg(test)]
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
}
