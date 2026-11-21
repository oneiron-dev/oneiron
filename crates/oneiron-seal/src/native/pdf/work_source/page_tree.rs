//! Page-tree traversal and inherited page geometry.

use super::*;

pub(in crate::native::pdf) fn pages<'a>(
    doc: &'a Document,
    id: ObjectId,
    mut inherited: BTreeMap<&'static [u8], &'a Object>,
    seen: &mut BTreeSet<ObjectId>,
    out: &mut Vec<BTreeMap<&'static [u8], &'a Object>>,
    depth: usize,
    limits: &WorkLimits,
) -> Result<()> {
    // A node met twice is a cycle. The depth guard bounds this recursion,
    // not the pages: a page tree of fanout two holds 2^64 pages at it.
    if depth > 64 {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    btree::<ObjectId, ()>(limits.ledger, 1)?;
    if !seen.insert(id) {
        return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
    }
    let node = doc
        .get_dictionary(id)
        .map_err(|err| lopdf_error(limits, err))?;
    for key in [b"MediaBox".as_slice(), b"CropBox", b"Resources", b"Rotate"] {
        if let Ok(value) = node.get(key) {
            btree::<&[u8], &Object>(limits.ledger, 1)?;
            inherited.insert(key, value);
        }
    }
    match name(doc, node, b"Type", limits)? {
        Some(b"Pages") => {
            let before = out.len();
            let kids = resolved(
                doc,
                node.get(b"Kids").map_err(|err| lopdf_error(limits, err))?,
                limits,
            )?
            .as_array()
            .map_err(|err| lopdf_error(limits, err))?;
            for child in kids {
                let child_id = child
                    .as_reference()
                    .map_err(|err| lopdf_error(limits, err))?;
                btree::<&[u8], &Object>(limits.ledger, inherited.len())?;
                pages(
                    doc,
                    child_id,
                    inherited.clone(),
                    seen,
                    out,
                    depth + 1,
                    limits,
                )?;
            }
            let count = node
                .get(b"Count")
                .map_err(|err| lopdf_error(limits, err))?
                .as_i64()
                .map_err(|err| lopdf_error(limits, err))?;
            if count != (out.len() - before) as i64 {
                return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf));
            }
        }
        Some(b"Page") => {
            for key in [
                b"Contents".as_slice(),
                b"Annots",
                b"UserUnit",
                b"Group",
                b"TrimBox",
                b"BleedBox",
                b"ArtBox",
            ] {
                if let Ok(value) = node.get(key) {
                    btree::<&[u8], &Object>(limits.ledger, 1)?;
                    inherited.insert(key, value);
                }
            }
            push(limits.ledger, out, inherited)?;
        }
        _ => return Err(WorkError::Invalid(InputInvalidCode::MalformedPdf)),
    }
    Ok(())
}

/// Visible boxes are the CropBox/MediaBox intersection (PDF 32000-1 14.11.2).
pub(in crate::native::pdf) fn page_geometry(
    doc: &Document,
    page: &BTreeMap<&[u8], &Object>,
    limits: &WorkLimits,
) -> Result<PageGeometry> {
    let media = pdf_box(
        doc,
        page.get(b"MediaBox".as_slice())
            .ok_or(WorkError::Invalid(InputInvalidCode::MalformedPdf))?,
        limits,
    )?;
    let mut crop = page
        .get(b"CropBox".as_slice())
        .map(|value| pdf_box(doc, value, limits))
        .transpose()?
        .unwrap_or(media);
    crop = [
        crop[0].max(media[0]),
        crop[1].max(media[1]),
        crop[2].min(media[2]),
        crop[3].min(media[3]),
    ];
    let rotation = page
        .get(b"Rotate".as_slice())
        .map(|value| number(doc, value, limits))
        .transpose()?
        .unwrap_or(0.);
    if rotation.fract() != 0. || rotation % 90. != 0. {
        return Err(WorkError::Invalid(InputInvalidCode::InvalidGeometry));
    }
    let geometry = PageGeometry {
        crop,
        rotation: rotation.rem_euclid(360.) as u16,
        user_unit: page
            .get(b"UserUnit".as_slice())
            .map(|value| number(doc, value, limits))
            .transpose()?
            .unwrap_or(1.),
    };
    geometry.display_box()?;
    Ok(geometry)
}
