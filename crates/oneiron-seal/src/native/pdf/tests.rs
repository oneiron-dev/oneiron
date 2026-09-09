//! Inline test mod: fixture loaders, doc builders, validation and writer round-trip tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use lopdf::{Dictionary, Document, Object};

use crate::api::SealResourceLimits;
use crate::error::{FatalCode, InputInvalidCode, SealError};

use sha2::Digest;

use super::*;

fn classic_pdf() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/classic_1page.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

fn stream_pdf() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/stream_1page.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

fn prepared(bytes: &[u8]) -> PreparedInput {
    validate_prepared(bytes, &SealResourceLimits::default()).expect("prepared")
}

fn sign_revision(p: &PreparedInput, capacity: usize) -> DraftRevision {
    let kind = RevisionKind::Signature {
        field_name: field_name_for("unit-op"),
        date_str: pdf_date(1_785_398_400_000),
    };
    append_revision(&p.bytes, &p.state, &kind, capacity).expect("revision")
}

#[test]
fn byterange_patch_is_length_preserving_and_spans_cover_all_but_gap() {
    let p = prepared(&classic_pdf());
    let draft = sign_revision(&p, 1024);
    let br = draft.byte_range.expect("br");
    let (lt, gt) = draft.contents_gap.expect("gap");
    assert_eq!(br[0], 0);
    assert_eq!(br[1] as usize, lt, "span1 ends at the '<'");
    assert_eq!(br[2] as usize, gt + 1, "span2 starts after the '>'");
    assert_eq!(
        (br[2] + br[3]) as usize,
        draft.bytes.len(),
        "span2 ends at final EOF"
    );
    // Hash spans cover everything except the gap, angle brackets included.
    let digest = hash_byte_range(&draft.bytes, br).expect("hash");
    let mut h = sha2::Sha256::new();
    h.update(&draft.bytes[..lt]);
    h.update(&draft.bytes[gt + 1..]);
    assert_eq!(digest, <[u8; 32]>::from(h.finalize()));
}

#[test]
fn append_preserves_prior_bytes_prev_size_root_and_eof() {
    for fixture in [classic_pdf(), stream_pdf()] {
        let p = prepared(&fixture);
        let prev_sx = last_startxref(&fixture).expect("sx");
        let draft = sign_revision(&p, 2048);
        assert!(draft.bytes.starts_with(&fixture), "prior bytes preserved");
        assert!(draft.bytes.ends_with(b"%%EOF"));
        let body = String::from_utf8_lossy(&draft.bytes);
        assert!(
            body.contains(&format!("/Prev {prev_sx} ")),
            "Prev points at the immediately preceding startxref"
        );
        assert!(body.contains("/Root 1 0 R"), "Root preserved");
    }
}

#[test]
fn xref_style_of_revision_matches_input() {
    let classic = prepared(&classic_pdf());
    let d1 = sign_revision(&classic, 1024);
    let tail1 = &d1.bytes[classic.bytes.len()..];
    let sx1 = last_startxref(&d1.bytes).expect("sx1");
    assert_eq!(&d1.bytes[sx1 as usize..sx1 as usize + 4], b"xref");
    assert!(tail1.windows(7).any(|w| w == b"trailer"));

    let stream = prepared(&stream_pdf());
    let d2 = sign_revision(&stream, 1024);
    let sx2 = last_startxref(&d2.bytes).expect("sx2");
    assert_ne!(&d2.bytes[sx2 as usize..sx2 as usize + 4], b"xref");
}

#[test]
fn patch_contents_overflow_reports_capacity_not_truncation() {
    let p = prepared(&classic_pdf());
    let mut draft = sign_revision(&p, 64);
    let der = vec![0xABu8; 65];
    let err = patch_contents(&mut draft, &der).unwrap_err();
    assert!(matches!(
        err,
        SealError::Fatal {
            code: FatalCode::ContentsCapacityExceeded,
            ..
        }
    ));
    // Fitting DER lands at the start with zero padding after.
    let der = vec![0xCDu8; 40];
    patch_contents(&mut draft, &der).expect("patch");
    let (lt, _gt) = draft.contents_gap.expect("gap");
    assert_eq!(draft.bytes[lt + 1], b'C');
    assert_eq!(draft.bytes[lt + 2], b'D');
    assert_eq!(draft.bytes[lt + 1 + 80], b'0');
}

#[test]
fn field_name_is_deterministic_and_op_scoped() {
    let p = prepared(&classic_pdf());
    let emitted_name = |operation_id: &str| {
        let kind = RevisionKind::Signature {
            field_name: field_name_for(operation_id),
            date_str: pdf_date(1_785_398_400_000),
        };
        let draft = append_revision(&p.bytes, &p.state, &kind, 1024).expect("revision");
        let doc = Document::load_mem(&draft.bytes).expect("reload");
        let catalog = doc.catalog().expect("catalog");
        let (_, af) = doc
            .dereference(catalog.get(b"AcroForm").expect("acroform"))
            .expect("resolve acroform");
        let fields = af
            .as_dict()
            .expect("acroform dict")
            .get(b"Fields")
            .and_then(Object::as_array)
            .expect("fields");
        let names: Vec<_> = fields
            .iter()
            .filter_map(|f| {
                let (_, field) = doc.dereference(f).ok()?;
                let field = field.as_dict().ok()?;
                if !field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig")) {
                    return None;
                }
                Some(
                    field
                        .get(b"T")
                        .and_then(Object::as_str)
                        .expect("name")
                        .to_vec(),
                )
            })
            .collect();
        assert_eq!(names.len(), 1, "one emitted signature field");
        assert!(!names[0].is_empty());
        names[0].clone()
    };
    let a = emitted_name("op-a");
    assert_eq!(a, emitted_name("op-a"));
    assert_ne!(a, emitted_name("op-b"));
}

#[test]
fn stream_dictionary_sig_marker_is_rejected() {
    // A /Type /Sig hidden in a STREAM object's dictionary is the same
    // existing-signature violation as a plain dictionary.
    let mut doc = Document::with_version("1.4");
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"Sig".to_vec()));
    dict.set("ByteRange", Object::Array(vec![Object::Integer(0)]));
    dict.set("Contents", Object::string_literal(b"x".to_vec()));
    doc.add_object(Object::Stream(lopdf::Stream::new(dict, Vec::new())));
    let err = scan_objects(&doc).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::ExistingSignature
        }
    ));
}

#[test]
fn signature_revision_appends_widget_to_page_annots() {
    let p = prepared(&classic_pdf());
    let draft = sign_revision(&p, 1024);
    let doc = Document::load_mem(&draft.bytes).expect("reparse");
    let pages = doc.get_pages();
    let page_id = *pages.values().next().expect("page");
    let page = doc
        .get_object(page_id)
        .and_then(Object::as_dict)
        .expect("page dict");
    let annots = page
        .get(b"Annots")
        .and_then(Object::as_array)
        .expect("Annots array");
    let widget_present = annots.iter().any(|a| {
        let Object::Reference(r) = a else {
            return false;
        };
        doc.get_object(*r)
            .and_then(Object::as_dict)
            .is_ok_and(|d| d.get(b"Subtype").is_ok_and(|s| name_is(s, b"Widget")))
    });
    assert!(
        widget_present,
        "widget annotation must be on the page /Annots"
    );
}

#[test]
fn max_obj_respects_trailer_size_beyond_referenced_objects() {
    let bytes = classic_pdf();
    let mut doc = Document::load_mem(&bytes).expect("load");
    let referenced_max = doc.objects.keys().map(|(n, _)| *n).max().unwrap_or(0);
    let size = i64::from(referenced_max) + 11;
    doc.trailer.set("Size", Object::Integer(size));
    let state = revision_state(&doc, &bytes).expect("state");
    let kind = RevisionKind::Signature {
        field_name: field_name_for("unit-op"),
        date_str: pdf_date(1_785_398_400_000),
    };
    let draft = append_revision(&bytes, &state, &kind, 1024).expect("revision");
    let out = Document::load_mem(&draft.bytes).expect("reload");
    let new_numbers: Vec<_> = out
        .objects
        .keys()
        .filter(|id| !doc.objects.contains_key(id))
        .map(|(n, _)| *n)
        .collect();
    assert!(!new_numbers.is_empty(), "revision must allocate objects");
    assert!(new_numbers.iter().all(|n| i64::from(*n) >= size));
}

#[test]
fn xref_helpers_never_overflow_on_extreme_offsets() {
    let input = classic_pdf();
    let marker = input
        .windows(b"startxref".len())
        .rposition(|w| w == b"startxref")
        .expect("startxref");
    for offset in [u64::MAX, u64::from(u32::MAX)] {
        let mut bytes = input[..marker].to_vec();
        bytes.extend_from_slice(format!("startxref\n{offset}\n%%EOF").as_bytes());
        assert!(matches!(
            validate_prepared(&bytes, &SealResourceLimits::default()),
            Err(SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref,
            })
        ));
    }
}

#[test]
fn pdf_date_format() {
    assert_eq!(pdf_date(1_785_398_400_000), "D:20260730080000Z");
}

#[test]
fn bare_eof_input_gets_exactly_one_eol_boundary() {
    let input = classic_pdf();
    assert!(input.ends_with(b"%%EOF"), "fixture must end in bare %%EOF");
    let p = prepared(&input);
    let draft = sign_revision(&p, 1024);
    assert!(matches!(draft.bytes[input.len()], b'\n' | b'\r'));
    let check_output = |input: &[u8], draft: &DraftRevision| {
        assert!(draft.bytes.starts_with(input));
        let appended = std::str::from_utf8(&draft.bytes[input.len()..]).expect("classic revision");
        let header = appended
            .lines()
            .find(|line| !line.trim().is_empty())
            .expect("first object header");
        let parts: Vec<_> = header.split_whitespace().collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].parse::<u32>().expect("object number") > 0);
        parts[1].parse::<u16>().expect("generation");
        assert_eq!(parts[2], "obj");
        reparse_revision(&draft.bytes, &SealResourceLimits::default())
            .expect("revision must reparse");
        let doc = Document::load_mem(&draft.bytes).expect("reload");
        let (_, af) = doc
            .dereference(
                doc.catalog()
                    .expect("catalog")
                    .get(b"AcroForm")
                    .expect("acroform"),
            )
            .expect("resolve acroform");
        let fields = af
            .as_dict()
            .expect("acroform dict")
            .get(b"Fields")
            .and_then(Object::as_array)
            .expect("fields");
        assert!(fields.iter().any(|f| {
            doc.dereference(f)
                .ok()
                .and_then(|(_, o)| o.as_dict().ok())
                .is_some_and(|field| field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig")))
        }));
    };
    check_output(&input, &draft);
    let mut eol = classic_pdf();
    eol.push(b'\n');
    let p2 = prepared(&eol);
    let d2 = sign_revision(&p2, 1024);
    check_output(&eol, &d2);
}

/// Minimal in-memory catalog + one-page tree; `page_extra` keys are
/// set on the page dict, `catalog_extra` on the catalog.
fn doc_with_page(
    page_extra: &[(&[u8], Object)],
    catalog_extra: &[(&[u8], Object)],
) -> (Document, Dictionary) {
    let mut doc = Document::with_version("1.4");
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    for (k, v) in page_extra {
        page.set(*k, v.clone());
    }
    let page_id = doc.add_object(Object::Dictionary(page));
    let mut pages = Dictionary::new();
    pages.set("Type", Object::Name(b"Pages".to_vec()));
    pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages.set("Count", Object::Integer(1));
    let pages_id = doc.add_object(Object::Dictionary(pages));
    let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
        panic!("page object");
    };
    p.set("Parent", Object::Reference(pages_id));
    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    for (k, v) in catalog_extra {
        catalog.set(*k, v.clone());
    }
    let catalog_id = doc.add_object(Object::Dictionary(catalog.clone()));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    (doc, catalog)
}

#[test]
fn catalog_and_page_af_are_rejected_as_embedded_files() {
    let af = || Object::Array(vec![Object::Reference((9, 0))]);
    let (doc, catalog) = doc_with_page(&[], &[(b"AF", af())]);
    let err = scan_catalog(&doc, &catalog).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::EmbeddedFilePresent
        }
    ));
    let (doc, catalog) = doc_with_page(&[(b"AF", af())], &[]);
    let err = scan_catalog(&doc, &catalog).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::EmbeddedFilePresent
        }
    ));
}

#[test]
fn acroform_xfa_is_rejected_as_active_content() {
    let mut af = Dictionary::new();
    af.set("XFA", Object::Array(vec![]));
    let (doc, catalog) = doc_with_page(&[], &[(b"AcroForm", Object::Dictionary(af))]);
    let err = scan_catalog(&doc, &catalog).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::ActiveContentPresent
        }
    ));
}

#[test]
fn dts_revision_registers_a_signature_field_in_acroform() {
    let p = prepared(&classic_pdf());
    let signed = sign_revision(&p, 1024);
    let state =
        reparse_revision(&signed.bytes, &SealResourceLimits::default()).expect("reparse signed");
    let dts = append_revision(
        &signed.bytes,
        &state,
        &RevisionKind::DocumentTimestamp,
        1024,
    )
    .expect("dts revision");
    let doc = Document::load_mem(&dts.bytes).expect("load dts output");
    let catalog = doc.catalog().expect("catalog");
    let af = doc
        .dereference(catalog.get(b"AcroForm").expect("acroform"))
        .ok()
        .and_then(|(_, o)| o.as_dict().ok().cloned())
        .expect("acroform dict");
    let fields = af
        .get(b"Fields")
        .and_then(Object::as_array)
        .expect("fields");
    let names: Vec<_> = fields
        .iter()
        .filter_map(|f| {
            let (_, field) = doc.dereference(f).ok()?;
            field.as_dict().ok()?.get(b"T").ok()?.as_str().ok()
        })
        .collect();
    let dts_registered = fields.iter().any(|f| {
        let Ok(field) = doc.dereference(f).map(|(_, o)| o) else {
            return false;
        };
        let Ok(field) = field.as_dict() else {
            return false;
        };
        let ft_ok = field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig"));
        let v_is_dts = field.get(b"V").is_ok_and(|v| {
            doc.dereference(v)
                .ok()
                .and_then(|(_, o)| o.as_dict().ok())
                .is_some_and(|d| d.get(b"Type").is_ok_and(|t| name_is(t, b"DocTimeStamp")))
        });
        let t_named = field.get(b"T").is_ok_and(|t| {
            t.as_str().is_ok_and(|n| {
                !n.is_empty() && names.iter().filter(|other| **other == n).count() == 1
            })
        });
        ft_ok && v_is_dts && t_named
    });
    assert!(
        dts_registered,
        "AcroForm /Fields must contain a uniquely named /FT /Sig field whose /V is the DTS dict",
    );
}

#[test]
fn direct_acroform_dict_fields_survive_signing() {
    let mut doc = Document::with_version("1.4");
    let mut text_field = Dictionary::new();
    text_field.set("FT", Object::Name(b"Tx".to_vec()));
    text_field.set("T", Object::string_literal(b"existing".to_vec()));
    let text_id = doc.add_object(Object::Dictionary(text_field));
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set(
        "MediaBox",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(200),
            Object::Integer(200),
        ]),
    );
    let page_id = doc.add_object(Object::Dictionary(page));
    let mut pages = Dictionary::new();
    pages.set("Type", Object::Name(b"Pages".to_vec()));
    pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages.set("Count", Object::Integer(1));
    let pages_id = doc.add_object(Object::Dictionary(pages));
    let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
        panic!("page");
    };
    p.set("Parent", Object::Reference(pages_id));
    let mut af = Dictionary::new();
    af.set("Fields", Object::Array(vec![Object::Reference(text_id)]));
    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    catalog.set("AcroForm", Object::Dictionary(af));
    let catalog_id = doc.add_object(Object::Dictionary(catalog));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).expect("save");
    let prepared = prepared(&bytes);
    let draft = sign_revision(&prepared, 1024);
    let out = Document::load_mem(&draft.bytes).expect("reload");
    let catalog = out.catalog().expect("catalog");
    let af = out
        .dereference(catalog.get(b"AcroForm").expect("acroform"))
        .ok()
        .and_then(|(_, o)| o.as_dict().ok().cloned())
        .expect("acroform dict");
    let fields = af
        .get(b"Fields")
        .and_then(Object::as_array)
        .expect("fields");
    assert!(
        fields
            .iter()
            .any(|f| matches!(f, Object::Reference(r) if *r == text_id)),
        "the pre-existing text field must survive signing: {fields:?}",
    );
    assert!(fields.iter().any(|f| {
        if matches!(f, Object::Reference(r) if *r == text_id) {
            return false;
        }
        out.dereference(f)
            .ok()
            .and_then(|(_, o)| o.as_dict().ok())
            .is_some_and(|field| field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig")))
    }));
}

#[test]
fn direct_acroform_indirect_fields_array_survives_signing() {
    let mut doc = Document::with_version("1.4");
    let mut text_field = Dictionary::new();
    text_field.set("FT", Object::Name(b"Tx".to_vec()));
    text_field.set("T", Object::string_literal(b"existing".to_vec()));
    let text_id = doc.add_object(Object::Dictionary(text_field));
    let fields_id = doc.add_object(Object::Array(vec![Object::Reference(text_id)]));
    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set(
        "MediaBox",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(200),
            Object::Integer(200),
        ]),
    );
    let page_id = doc.add_object(Object::Dictionary(page));
    let mut pages = Dictionary::new();
    pages.set("Type", Object::Name(b"Pages".to_vec()));
    pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages.set("Count", Object::Integer(1));
    let pages_id = doc.add_object(Object::Dictionary(pages));
    let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
        panic!("page");
    };
    p.set("Parent", Object::Reference(pages_id));
    let mut af = Dictionary::new();
    af.set("Fields", Object::Reference(fields_id));
    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    catalog.set("AcroForm", Object::Dictionary(af));
    let catalog_id = doc.add_object(Object::Dictionary(catalog));
    doc.trailer.set("Root", Object::Reference(catalog_id));
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).expect("save");
    let prepared = prepared(&bytes);
    let draft = sign_revision(&prepared, 1024);
    let out = Document::load_mem(&draft.bytes).expect("reload");
    let catalog = out.catalog().expect("catalog");
    let af = out
        .dereference(catalog.get(b"AcroForm").expect("acroform"))
        .ok()
        .and_then(|(_, o)| o.as_dict().ok().cloned())
        .expect("acroform dict");
    let fields = af
        .get(b"Fields")
        .and_then(Object::as_array)
        .expect("fields");
    assert!(
        fields
            .iter()
            .any(|f| matches!(f, Object::Reference(r) if *r == text_id)),
        "the pre-existing text field must survive signing: {fields:?}",
    );
    assert!(fields.iter().any(|f| {
        if matches!(f, Object::Reference(r) if *r == text_id) {
            return false;
        }
        out.dereference(f)
            .ok()
            .and_then(|(_, o)| o.as_dict().ok())
            .is_some_and(|field| field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig")))
    }));
}

#[test]
fn unresolvable_acroform_fields_fail_closed() {
    // P2-2 fail-closed arm: a present /Fields that does not resolve to
    // an array (dangling reference, wrong type) is malformed input —
    // never rewritten as an empty field list.
    for fields in [
        Object::Reference((99, 0)), // dangling
        Object::Integer(7),         // not an array at all
    ] {
        let mut doc = Document::with_version("1.4");
        let mut page = Dictionary::new();
        page.set("Type", Object::Name(b"Page".to_vec()));
        let page_id = doc.add_object(Object::Dictionary(page));
        let mut pages = Dictionary::new();
        pages.set("Type", Object::Name(b"Pages".to_vec()));
        pages.set("Kids", Object::Array(vec![Object::Reference(page_id)]));
        pages.set("Count", Object::Integer(1));
        let pages_id = doc.add_object(Object::Dictionary(pages));
        let Ok(Object::Dictionary(p)) = doc.get_object_mut(page_id) else {
            panic!("page");
        };
        p.set("Parent", Object::Reference(pages_id));
        let mut af = Dictionary::new();
        af.set("Fields", fields);
        let af_id = doc.add_object(Object::Dictionary(af));
        let mut catalog = Dictionary::new();
        catalog.set("Type", Object::Name(b"Catalog".to_vec()));
        catalog.set("Pages", Object::Reference(pages_id));
        catalog.set("AcroForm", Object::Reference(af_id));
        let catalog_id = doc.add_object(Object::Dictionary(catalog));
        doc.trailer.set("Root", Object::Reference(catalog_id));
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).expect("save");
        let err = validate_prepared(&bytes, &SealResourceLimits::default()).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::MalformedXref
            }
        ));
    }
}

#[test]
fn crafted_huge_trailer_size_fails_closed_without_overflow() {
    let bytes = classic_pdf();
    // A size beyond the object-number space must fail during extraction.
    let mut doc = Document::load_mem(&bytes).expect("load");
    doc.trailer.set("Size", Object::Integer(1i64 << 40));
    let err = revision_state(&doc, &bytes).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        }
    ));
    // This boundary permits extraction but must reject allocation.
    let mut doc = Document::load_mem(&bytes).expect("load");
    doc.trailer
        .set("Size", Object::Integer(i64::from(u32::MAX) + 1));
    let state = revision_state(&doc, &bytes).expect("state");
    let kind = RevisionKind::Signature {
        field_name: field_name_for("unit-op"),
        date_str: pdf_date(1_785_398_400_000),
    };
    let err = append_revision(&bytes, &state, &kind, 64).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::ObjectLimitExceeded,
        }
    ));
}
#[test]
fn ef_key_dict_is_rejected_without_filespec_type() {
    // A filespec-shaped dictionary without /Type: the /EF key is the
    // tell and must be rejected as embedded-file content.
    let mut doc = Document::with_version("1.4");
    let mut dict = Dictionary::new();
    dict.set("F", Object::string_literal(b"evil.exe".to_vec()));
    dict.set("UF", Object::string_literal(b"evil.exe".to_vec()));
    dict.set("EF", Object::Dictionary(Dictionary::new()));
    doc.add_object(Object::Dictionary(dict));
    let err = scan_objects(&doc).unwrap_err();
    assert!(matches!(
        err,
        SealError::InputInvalid {
            code: InputInvalidCode::EmbeddedFilePresent
        }
    ));
}
