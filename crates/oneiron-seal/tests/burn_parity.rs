//! Both e-sign field burn-in ports draw one field set identically. Canon
//! ARCH-0064 [SGN-07] has the pre-seal burn-in "drawn with THIS row's shared
//! renderer rather than a second drawing path"; main has two ports, the
//! engine's `render::fields::burn_fields` and this organ's
//! `work_burn::burn_fields` ("Behavior-identical except admission and
//! bounds", FIX 7980/8157). Each door burns the same rows into a fresh
//! document; the encoded content streams and the saved documents must match
//! byte for byte (FIX [ESIGN-BURN-TWO-PORTS]). The organ's rows are the
//! engine's, lent as the organ host lends them (item 1's fields, every
//! current value, every decoded raster).
//!
//! Each case prints `PIN burn-p<page>-<rejected|accepted>-<content|pdf>
//! <sha256>`, so a later move of the drawing code can show the same bytes
//! before and after it, and `PIN burn-p<page>-<rejected|accepted>-admitted
//! <bytes>`, the organ ledger's net admission, so the move can show the same
//! admitted units (bytes alone cannot).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-seal --test burn_parity`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::blob_artifact::esign::render::{SignatureRaster, esign_burn};
use oneiron::blob_artifact::esign::{EsignField, FieldGeometry, FieldMeta, FieldValue};
use oneiron_seal::test_doors::{self as organ, LentField, LentRaster, LentValue};
use sha2::{Digest, Sha256};

/// The page box both ports burn into: not at the origin, so every mark is
/// offset by the crop.
const CROP: [f64; 4] = [10., 20., 610., 820.];
const IMAGE_A: &str = "5a1b2c3d4e5f60718293a4b5c6d7e8f9";
const IMAGE_B: &str = "6b2c3d4e5f60718293a4b5c6d7e8f90a";

fn field(id: &str, page: u32, at: [f64; 4], meta: FieldMeta) -> EsignField {
    EsignField {
        id: id.to_owned(),
        item: 1,
        recipient: "signer".to_owned(),
        required: false,
        geometry: FieldGeometry {
            page,
            x_percent: at[0],
            y_percent: at[1],
            width_percent: at[2],
            height_percent: at[3],
        },
        meta,
    }
}

/// Every arm the burn draws: one-line text, multi-line Win1252 text, a
/// checked and an unchecked box, two signature fields sharing one raster
/// (written once) and one with its own, an unfilled field (no marks), and a
/// filled field on the second page (left out of the first page's burn).
fn engine_rows() -> (
    Vec<EsignField>,
    BTreeMap<String, FieldValue>,
    BTreeMap<String, SignatureRaster>,
) {
    let text = FieldMeta::Text { max_bytes: 80 };
    let fields = vec![
        field("text", 1, [10., 20., 30., 10.], text.clone()),
        field("lines", 1, [50., 20., 40., 12.], text.clone()),
        field("checked", 1, [10., 35., 5., 4.], FieldMeta::Checkbox),
        field("unchecked", 1, [20., 35., 5., 4.], FieldMeta::Checkbox),
        field("signature", 1, [10., 50., 30., 10.], FieldMeta::Signature),
        field("initials", 1, [50., 50., 10., 5.], FieldMeta::Initials),
        field("cosign", 1, [65., 50., 30., 10.], FieldMeta::Signature),
        field("unfilled", 1, [10., 65., 30., 8.], text.clone()),
        field("second_page", 2, [10., 20., 30., 10.], text),
    ];
    let signature = |image_ref: &str| FieldValue::Signature {
        image_ref: image_ref.to_owned(),
    };
    let values = BTreeMap::from([
        (
            "text".to_owned(),
            FieldValue::Text("Accepted terms".to_owned()),
        ),
        (
            "lines".to_owned(),
            FieldValue::Text("Café\nAccepted".to_owned()),
        ),
        ("checked".to_owned(), FieldValue::Checked(true)),
        ("unchecked".to_owned(), FieldValue::Checked(false)),
        ("signature".to_owned(), signature(IMAGE_A)),
        ("initials".to_owned(), signature(IMAGE_B)),
        ("cosign".to_owned(), signature(IMAGE_A)),
        (
            "second_page".to_owned(),
            FieldValue::Text("Page two".to_owned()),
        ),
    ]);
    let rasters = BTreeMap::from([
        (
            IMAGE_A.to_owned(),
            SignatureRaster {
                width: 2,
                height: 1,
                rgba: vec![10, 20, 30, 255, 40, 50, 60, 64],
            },
        ),
        (
            IMAGE_B.to_owned(),
            SignatureRaster {
                width: 1,
                height: 2,
                rgba: vec![200, 100, 50, 128, 0, 0, 0, 255],
            },
        ),
    ]);
    (fields, values, rasters)
}

/// The engine rows as the organ host lends them to the organ.
fn lent_rows(
    fields: &[EsignField],
    values: &BTreeMap<String, FieldValue>,
    rasters: &BTreeMap<String, SignatureRaster>,
) -> (
    Vec<LentField>,
    BTreeMap<String, LentValue>,
    BTreeMap<String, LentRaster>,
) {
    let fields = fields
        .iter()
        .filter(|field| field.item == 1)
        .map(|field| LentField {
            id: field.id.clone(),
            page: field.geometry.page,
            x_percent: field.geometry.x_percent,
            y_percent: field.geometry.y_percent,
            width_percent: field.geometry.width_percent,
            height_percent: field.geometry.height_percent,
        })
        .collect();
    let values = values
        .iter()
        .map(|(id, value)| {
            let value = match value {
                FieldValue::Text(text) => LentValue::Text(text.clone()),
                FieldValue::Checked(checked) => LentValue::Checked(*checked),
                FieldValue::Signature { image_ref } => LentValue::Signature {
                    image_ref: image_ref.clone(),
                },
            };
            (id.clone(), value)
        })
        .collect();
    let rasters = rasters
        .iter()
        .map(|(image_ref, raster)| {
            (
                image_ref.clone(),
                LentRaster {
                    width: raster.width,
                    height: raster.height,
                    rgba: raster.rgba.clone(),
                },
            )
        })
        .collect();
    (fields, values, rasters)
}

/// The first byte where `engine` and `organ` differ, with the bytes around
/// it from each, for the failure message.
fn first_difference(engine: &[u8], organ: &[u8]) -> String {
    let at = engine
        .iter()
        .zip(organ)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| engine.len().min(organ.len()));
    let window = |bytes: &[u8]| {
        let start = at.saturating_sub(40);
        let end = (at + 40).min(bytes.len());
        String::from_utf8_lossy(&bytes[start.min(end)..end]).into_owned()
    };
    format!(
        "first difference at byte {at} (engine {} bytes, organ {} bytes)\nengine: {:?}\norgan:  {:?}",
        engine.len(),
        organ.len(),
        window(engine),
        window(organ)
    )
}

#[test]
fn both_burn_ports_draw_one_field_set_identically() {
    let (fields, values, rasters) = engine_rows();
    let (lent_fields, lent_values, lent_rasters) = lent_rows(&fields, &values, &rasters);
    for page in [1, 2] {
        for rejected in [false, true] {
            let engine =
                esign_burn::burn_page_fields(CROP, page, &fields, &values, &rasters, rejected)
                    .expect("the engine port burns the field set");
            let organ = organ::burn_page_fields(
                CROP,
                page,
                &lent_fields,
                &lent_values,
                &lent_rasters,
                rejected,
            )
            .expect("the organ port burns the field set");
            assert!(
                !engine.content.is_empty(),
                "page {page} (rejected {rejected}) burns marks"
            );
            assert!(
                engine.content == organ.content,
                "page {page} (rejected {rejected}): the content streams differ, {}",
                first_difference(&engine.content, &organ.content)
            );
            assert!(
                engine.pdf == organ.pdf,
                "page {page} (rejected {rejected}): the saved documents differ, {}",
                first_difference(&engine.pdf, &organ.pdf)
            );
            let case = if rejected { "rejected" } else { "accepted" };
            println!(
                "PIN burn-p{page}-{case}-content {:x}",
                Sha256::digest(&engine.content)
            );
            println!(
                "PIN burn-p{page}-{case}-pdf {:x}",
                Sha256::digest(&engine.pdf)
            );
            println!("PIN burn-p{page}-{case}-admitted {}", organ.admitted);
        }
    }
}
