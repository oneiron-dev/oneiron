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
    let err = read(&build_zip(&[entry], 0, 0, None)).expect_err("declared-size mismatch must fail");
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
    let err = read(&build_zip(&[entry], 0, 0, None)).expect_err("zip64 size sentinel must fail");
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
    let err = read(&build_zip(&[entry], 0, 0, None)).expect_err("entry on another disk must fail");
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
