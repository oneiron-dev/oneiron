//! The engine's signature revision re-emits the first page, the catalog and
//! the AcroForm; what it re-emits must read back as it was.
use lopdf::dictionary;

use super::*;

/// A one-page PDF, written by lopdf with a classic xref table as the
/// prepare step writes it, whose page boxes are `boxed`.
fn one_page(boxed: &[Object]) -> Vec<u8> {
    let mut pdf = Document::with_version("1.7");
    pdf.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let pages = pdf.new_object_id();
    let page = pdf.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages,
        "MediaBox" => boxed.to_vec(),
        "CropBox" => boxed.to_vec(),
    });
    pdf.objects.insert(
        pages,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::from(page)],
            "Count" => 1,
        }),
    );
    let catalog = pdf.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
    pdf.trailer.set("Root", catalog);
    let mut out = Vec::new();
    pdf.save_to(&mut out).expect("the PDF saves");
    out
}

/// Sol R7 on #1379: the page was re-emitted with six decimal places, so a
/// page box 0.0000004 wide became 0 wide in the revision the key signs.
/// Every revision's page boxes read back as the prepared PDF's.
#[test]
fn the_signature_revision_keeps_the_numbers_of_the_page_it_re_emits() {
    let boxed = [
        Object::Integer(0),
        Object::Real(-0.5),
        Object::Real(0.000_000_4),
        Object::Real(200.125),
    ];
    let input = EsignSealInput::new(one_page(&boxed), "op", 0).expect("the revisions");
    let numbers = |object: &Object| -> Vec<f32> {
        object
            .as_array()
            .expect("a box")
            .iter()
            .map(|number| number.as_float().expect("a number"))
            .collect()
    };
    let expected = numbers(&Object::Array(boxed.to_vec()));
    for revision in &input.revisions {
        let bytes = [input.pdf.as_slice(), revision.suffix.as_slice()].concat();
        let doc = Document::load_mem(&bytes).expect("the revision reads");
        let page = *doc.get_pages().values().next().expect("a page");
        let dict = doc.get_dictionary(page).expect("the page");
        assert!(dict.has(b"Annots"), "the revision's own page");
        for key in [b"MediaBox".as_slice(), b"CropBox".as_slice()] {
            assert_eq!(numbers(dict.get(key).expect("a box")), expected);
        }
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

/// Sol R13 on #1379: `1` would read a real 1.0 back as an integer. A real
/// the page holds reads back as the same real in every revision.
#[test]
fn the_signature_revision_keeps_a_real_a_real() {
    let pdf = classic(&[
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200.0 200] /UserUnit 1.0 >>",
    ]);
    let input = EsignSealInput::new(pdf, "op", 0).expect("the revisions");
    for revision in &input.revisions {
        let bytes = [input.pdf.as_slice(), revision.suffix.as_slice()].concat();
        let doc = Document::load_mem(&bytes).expect("the revision reads");
        let page = *doc.get_pages().values().next().expect("a page");
        let dict = doc.get_dictionary(page).expect("the page");
        assert!(dict.has(b"Annots"), "the revision's own page");
        let unit = dict.get(b"UserUnit");
        assert!(
            matches!(unit, Ok(Object::Real(unit)) if unit.to_bits() == 1.0_f32.to_bits()),
            "{unit:?}"
        );
        let media = dict
            .get(b"MediaBox")
            .and_then(Object::as_array)
            .expect("a box");
        assert!(
            matches!(media[2], Object::Real(width) if width.to_bits() == 200.0_f32.to_bits()),
            "{media:?}"
        );
    }
}
