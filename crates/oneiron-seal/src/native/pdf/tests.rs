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
fn signature_field_is_the_page_widget_with_value_on_the_same_object() {
    let p = prepared(&classic_pdf());
    let draft = sign_revision(&p, 1024);
    let doc = Document::load_mem(&draft.bytes).expect("reparse");
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
    assert_eq!(fields.len(), 1);
    let field_ref = fields[0].as_reference().expect("indirect field");
    let field = doc
        .get_object(field_ref)
        .and_then(Object::as_dict)
        .expect("field");
    assert!(field.get(b"FT").is_ok_and(|ft| name_is(ft, b"Sig")));
    assert!(field.get(b"Subtype").is_ok_and(|s| name_is(s, b"Widget")));
    assert!(field.get(b"V").is_ok_and(|v| v.as_reference().is_ok()));
    assert!(!field.has(b"Kids"));
    assert!(!field.has(b"Parent"));
    let page = doc
        .get_object(p.state.first_page)
        .and_then(Object::as_dict)
        .expect("page");
    let annots = page
        .get(b"Annots")
        .and_then(Object::as_array)
        .expect("annotations");
    assert!(annots.iter().any(|a| *a == Object::Reference(field_ref)));
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
fn security_scan_resolves_multi_hop_names_and_rejects_broken_links() {
    let (mut doc, _) = doc_with_page(&[], &[]);
    let mut names = Dictionary::new();
    names.set("JavaScript", Object::Dictionary(Dictionary::new()));
    let terminal = doc.add_object(Object::Dictionary(names));
    let middle = doc.add_object(Object::Reference(terminal));
    let catalog_id = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_object_mut(catalog_id)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Names", Object::Reference(middle));
    for gate in [true, false] {
        let err = analyze_security(&doc, gate).unwrap_err();
        assert!(matches!(
            err,
            SealError::InputInvalid {
                code: InputInvalidCode::ActiveContentPresent
            }
        ));
    }
    doc.objects.insert(middle, Object::Reference((900_000, 0)));
    assert!(matches!(
        analyze_security(&doc, true),
        Err(SealError::InputInvalid {
            code: InputInvalidCode::ActiveContentPresent
        })
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

/// Sol R12 on #1379: the writer re-emitted the catalog with six decimal
/// places, so a DSS revision turned a catalog value of 0.0000004 into 0,
/// and the verifier, comparing catalogs, refused the organ's own B-LT seal.
/// What the signature and DSS revisions re-emit reads back as it was.
#[test]
fn revisions_keep_the_numbers_of_the_catalog_they_re_emit() {
    let mut intent = Dictionary::new();
    intent.set("S", Object::Name(b"GTS_PDFA1".to_vec()));
    intent.set("VendorThreshold", Object::Real(0.000_000_4));
    let media = Object::Array(vec![
        Object::Integer(0),
        Object::Integer(0),
        Object::Real(200.125),
        Object::Integer(200),
    ]);
    let (mut doc, _) = doc_with_page(
        &[(b"MediaBox", media)],
        &[(
            b"OutputIntents",
            Object::Array(vec![Object::Dictionary(intent)]),
        )],
    );
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).expect("save");
    let signed = sign_revision(&prepared(&bytes), 1024);
    let state =
        reparse_revision(&signed.bytes, &SealResourceLimits::default()).expect("reparse signed");
    let dss_obj = state.max_obj + 1;
    let kind = RevisionKind::Dss {
        material_objects: vec![(dss_obj, b"<< /Type /DSS >>".to_vec())],
        dss_obj,
    };
    let dss = append_revision(&signed.bytes, &state, &kind, 0).expect("dss revision");
    for out in [&signed.bytes, &dss.bytes] {
        let doc = Document::load_mem(out).expect("reload");
        let catalog = doc.catalog().expect("catalog");
        let intents = catalog
            .get(b"OutputIntents")
            .and_then(Object::as_array)
            .expect("intents");
        let threshold = intents[0]
            .as_dict()
            .and_then(|intent| intent.get(b"VendorThreshold"))
            .and_then(Object::as_float)
            .expect("threshold");
        assert_eq!(threshold.to_bits(), 0.000_000_4_f32.to_bits());
    }
}

/// A classic-xref PDF from its object bodies, numbered from 1; object 1 is
/// the catalog. lopdf writes 1.0 as `1`, so a real with no fraction needs
/// hand-written bytes.
fn classic(objects: &[&str]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (number, body) in (1..).zip(objects) {
        offsets.push(out.len());
        out.extend_from_slice(format!("{number} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    let size = objects.len() + 1;
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    out
}

/// Sol R13 on #1379: with an indirect AcroForm the signature leaves the
/// catalog alone, so the DSS revision is the first to re-emit it. `0` would
/// read its 0.0 back as an integer, and the verifier, comparing catalogs by
/// value and type, would refuse the organ's own B-LT seal.
#[test]
fn a_dss_revision_keeps_a_catalog_real_a_real() {
    let pdf = classic(&[
        "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /Threshold 0.0 >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        "<< /Fields [] >>",
    ]);
    let signed = sign_revision(&prepared(&pdf), 1024);
    let state =
        reparse_revision(&signed.bytes, &SealResourceLimits::default()).expect("reparse signed");
    let dss_obj = state.max_obj + 1;
    let kind = RevisionKind::Dss {
        material_objects: vec![(dss_obj, b"<< /Type /DSS >>".to_vec())],
        dss_obj,
    };
    let dss = append_revision(&signed.bytes, &state, &kind, 0).expect("dss revision");
    let doc = Document::load_mem(&dss.bytes).expect("reload");
    let catalog = doc.catalog().expect("catalog");
    assert!(catalog.has(b"DSS"), "the DSS revision's own catalog");
    let threshold = catalog.get(b"Threshold");
    assert!(
        matches!(threshold, Ok(Object::Real(zero)) if zero.to_bits() == 0.0_f32.to_bits()),
        "{threshold:?}"
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
