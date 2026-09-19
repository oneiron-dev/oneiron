use super::*;
const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/retained-opc.zip");

#[test]
fn no_op_is_archive_exact_with_deflate_metadata_unknown_xml_and_comments() -> Result<()> {
    let mut package = Package::open(FIXTURE, Limits::default())?;
    assert_eq!(package.write()?, FIXTURE);
    package.replace(
        "word/document.xml",
        package
            .part("word/document.xml")
            .expect("document")
            .to_vec(),
    )?;
    assert_eq!(package.write()?, FIXTURE);
    Ok(())
}

#[test]
fn edit_preserves_untouched_payload_archive_records_and_unknown_xml_in_place() -> Result<()> {
    let mut package = Package::open(FIXTURE, Limits::default())?;
    let original_xml = package
        .part("word/document.xml")
        .expect("document")
        .to_vec();
    let start = original_xml
        .windows(6)
        .position(|s| s == b"Before")
        .expect("text");
    package.splice("word/document.xml", start..start + 6, b"Before", b"After")?;
    let edited = package.write()?;
    let read_back = Package::open(&edited, Limits::default())?;
    let mut expected = original_xml.clone();
    expected.splice(start..start + 6, b"After".iter().copied());
    assert_eq!(
        read_back.part("word/document.xml"),
        Some(expected.as_slice())
    );
    // Exact original local record, including compressed payload and unknown ZIP extras.
    let original_layout = layout(FIXTURE, Limits::default())?;
    for name in ["customXml/item1.xml", "[Content_Types].xml"] {
        let old = original_layout
            .entries
            .iter()
            .find(|e| e.name == name)
            .expect("old part");
        let new = read_back
            .layout
            .entries
            .iter()
            .find(|e| e.name == name)
            .expect("new part");
        assert_eq!(&FIXTURE[old.local.clone()], &edited[new.local.clone()]);
        assert_eq!(read_back.part(name), package.part(name));
    }
    // Reverting the edit restores the original archive, not just the original XML.
    package.replace("word/document.xml", original_xml)?;
    assert_eq!(package.write()?, FIXTURE);
    Ok(())
}

#[test]
fn limits_and_wrong_edit_base_fail_without_changing_package() -> Result<()> {
    for limits in [
        Limits {
            archive_bytes: FIXTURE.len() - 1,
            ..Limits::default()
        },
        Limits {
            parts: 2,
            ..Limits::default()
        },
        Limits {
            part_bytes: 32,
            ..Limits::default()
        },
        Limits {
            total_part_bytes: 32,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Package::open(FIXTURE, limits),
            Err(Error::InvalidPackage(_))
        ));
    }
    let mut package = Package::open(FIXTURE, Limits::default())?;
    assert!(
        package
            .splice("word/document.xml", 0..1, b"not-the-base", b"oops")
            .is_err()
    );
    assert!(
        package
            .splice("word/document.xml", usize::MAX..usize::MAX, b"", b"oops")
            .is_err()
    );
    assert_eq!(package.write()?, FIXTURE);
    Ok(())
}

#[test]
fn local_header_name_substitution_and_truncation_fail_closed() {
    let mut wrong_name = FIXTURE.to_vec();
    wrong_name[30] ^= 1;
    assert!(Package::open(&wrong_name, Limits::default()).is_err());
    for length in [0, 1, 21, FIXTURE.len() / 2, FIXTURE.len() - 1] {
        assert!(Package::open(&FIXTURE[..length], Limits::default()).is_err());
    }
}

#[test]
fn varying_edit_sizes_keep_every_other_part_unchanged() -> Result<()> {
    for length in [0, 1, 63, 4096, 16384] {
        let mut package = Package::open(FIXTURE, Limits::default())?;
        let bytes = vec![b'x'; length];
        package.replace("word/document.xml", bytes.clone())?;
        let output = package.write()?;
        let edited = Package::open(&output, Limits::default())?;
        assert_eq!(edited.part("word/document.xml"), Some(bytes.as_slice()));
        assert_eq!(
            edited.part("customXml/item1.xml"),
            package.part("customXml/item1.xml")
        );
    }
    Ok(())
}

#[test]
fn inconsistent_sizes_crc_encryption_and_split_disk_headers_fail_closed() -> Result<()> {
    let original = layout(FIXTURE, Limits::default())?;
    let entry = &original.entries[0];
    for field in [14, 18, 22] {
        let mut bytes = FIXTURE.to_vec();
        bytes[entry.local.start + field] ^= 1;
        assert!(Package::open(&bytes, Limits::default()).is_err());
    }
    for flag in [1, 16, 32, 64, 8192, 32768] {
        let mut bytes = FIXTURE.to_vec();
        let flags = read16(&bytes, entry.local.start + 6)? | flag;
        put16(&mut bytes, entry.local.start + 6, flags);
        put16(&mut bytes, entry.central.start + 8, flags);
        assert!(Package::open(&bytes, Limits::default()).is_err());
    }
    let mut bytes = FIXTURE.to_vec();
    put16(&mut bytes, entry.central.start + 34, 1);
    assert!(Package::open(&bytes, Limits::default()).is_err());
    Ok(())
}

#[test]
fn insertion_preserves_every_existing_local_record_and_remains_editable() -> Result<()> {
    let mut package = Package::open(FIXTURE, Limits::default())?;
    package.insert("word/comments.xml", b"<comments/>".to_vec())?;
    package.replace("word/comments.xml", b"<comments>new</comments>".to_vec())?;
    let bytes = package.write()?;
    let reopened = Package::open(&bytes, Limits::default())?;
    assert_eq!(
        reopened.part("word/comments.xml"),
        Some(b"<comments>new</comments>".as_slice())
    );
    assert_eq!(reopened.names().count(), package.names().count());
    let original = layout(FIXTURE, Limits::default())?;
    for entry in original.entries {
        let preserved = reopened
            .layout
            .entries
            .iter()
            .find(|p| p.name == entry.name)
            .expect("retained entry");
        assert_eq!(&bytes[preserved.local.clone()], &FIXTURE[entry.local]);
    }
    assert!(package.insert("word/comments.xml", Vec::new()).is_err());
    assert!(package.insert("../escaped.xml", Vec::new()).is_err());
    assert_eq!(Package::open(&bytes, Limits::default())?.write()?, bytes);
    Ok(())
}

#[test]
fn editing_deflate_entry_clears_method_specific_flags_before_storing() -> Result<()> {
    let mut bytes = FIXTURE.to_vec();
    let parsed = layout(&bytes, Limits::default())?;
    let entry = parsed
        .entries
        .iter()
        .find(|entry| read16(&bytes, entry.central.start + 10).ok() == Some(8))
        .expect("deflate fixture");
    let name = entry.name.clone();
    let flags = read16(&bytes, entry.central.start + 8)? | 6;
    put16(&mut bytes, entry.central.start + 8, flags);
    put16(&mut bytes, entry.local.start + 6, flags);
    let mut package = Package::open(&bytes, Limits::default())?;
    package.replace(&name, b"replacement".to_vec())?;
    let output = package.write()?;
    assert_eq!(
        Package::open(&output, Limits::default())?.part(&name),
        Some(b"replacement".as_slice())
    );
    Ok(())
}
