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
