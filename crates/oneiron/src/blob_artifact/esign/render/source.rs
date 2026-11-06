//! Static page-tree and resource-graph admission and copying.
use super::streams::decoded;
use super::*;

mod copy;

pub(super) fn resolved<'a>(doc: &'a Document, object: &'a Object) -> Result<&'a Object> {
    Ok(doc.dereference(object)?.1)
}
fn name<'a>(doc: &'a Document, dict: &'a Dictionary, key: &[u8]) -> Result<Option<&'a [u8]>> {
    dict.get(key)
        .ok()
        .map(|v| Ok(resolved(doc, v)?.as_name()?))
        .transpose()
}
pub(super) fn number(doc: &Document, value: &Object) -> Result<f64> {
    match resolved(doc, value)? {
        Object::Integer(v) => Ok(*v as f64),
        Object::Real(v) if v.is_finite() => Ok(f64::from(*v)),
        _ => Err(PdfPreparationError::MalformedPdf),
    }
}
pub(super) fn pdf_box(doc: &Document, value: &Object) -> Result<[f64; 4]> {
    let values = resolved(doc, value)?.as_array()?;
    if values.len() != 4 {
        return Err(PdfPreparationError::InvalidGeometry);
    }
    let result = [
        number(doc, &values[0])?,
        number(doc, &values[1])?,
        number(doc, &values[2])?,
        number(doc, &values[3])?,
    ];
    render_field_geometry(
        &FieldGeometry {
            page: 1,
            x_percent: 0.0,
            y_percent: 0.0,
            width_percent: 100.0,
            height_percent: 100.0,
        },
        result,
    )?;
    Ok(result)
}

// Scan even unreachable and nested dictionaries before discarding anything.
// The walk keeps its own stack, so every object the file holds is scanned,
// however many and however deep lopdf's parser let them nest.
pub(super) fn reject_signatures(doc: &Document) -> Result<()> {
    let mut stack: Vec<_> = doc.objects.values().collect();
    while let Some(value) = stack.pop() {
        let dict = match value {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            Object::Array(a) => {
                stack.extend(a.iter());
                continue;
            }
            _ => continue,
        };
        if matches!(name(doc, dict, b"Type")?, Some(b"Sig" | b"DocTimeStamp"))
            || name(doc, dict, b"FT")? == Some(b"Sig")
            || [
                b"ByteRange".as_slice(),
                b"Lock",
                b"DocMDP",
                b"FieldMDP",
                b"UR3",
            ]
            .iter()
            .any(|k| dict.has(k))
        {
            return Err(PdfPreparationError::AlreadySigned);
        }
        stack.extend(dict.iter().map(|(_, v)| v));
    }
    Ok(())
}
pub(super) fn pages<'a>(
    doc: &'a Document,
    id: ObjectId,
    inherited: BTreeMap<&'static [u8], &'a Object>,
    seen: &mut BTreeSet<ObjectId>,
    out: &mut Vec<BTreeMap<&'static [u8], &'a Object>>,
    stage: &super::admitted::Stage,
) -> Result<()> {
    enum Visit<'a> {
        Node(ObjectId, BTreeMap<&'static [u8], &'a Object>),
        Children {
            node: &'a Dictionary,
            children: std::slice::Iter<'a, Object>,
            inherited: BTreeMap<&'static [u8], &'a Object>,
            before: usize,
        },
    }

    let mut backing = stage.nested();
    let mut pending = Vec::new();
    stage.reserve(&mut pending, 1, &mut backing)?;
    pending.push(Visit::Node(id, inherited));
    while let Some(visit) = pending.pop() {
        match visit {
            Visit::Node(id, mut inherited) => {
                if !seen.insert(id) {
                    return Err(PdfPreparationError::MalformedPdf);
                }
                let node = doc.get_dictionary(id)?;
                for key in [b"MediaBox".as_slice(), b"CropBox", b"Resources", b"Rotate"] {
                    if let Ok(value) = node.get(key) {
                        inherited.insert(key, value);
                    }
                }
                match name(doc, node, b"Type")? {
                    Some(b"Pages") => {
                        let children = resolved(doc, node.get(b"Kids")?)?.as_array()?.iter();
                        stage.reserve(&mut pending, 1, &mut backing)?;
                        pending.push(Visit::Children {
                            node,
                            children,
                            inherited,
                            before: out.len(),
                        });
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
                                inherited.insert(key, value);
                            }
                        }
                        out.push(inherited);
                    }
                    _ => return Err(PdfPreparationError::MalformedPdf),
                }
            }
            Visit::Children {
                node,
                mut children,
                inherited,
                before,
            } => {
                if let Some(child) = children.next() {
                    let id = child.as_reference()?;
                    stage.reserve(&mut pending, 2, &mut backing)?;
                    let child_inherited = inherited.clone();
                    pending.push(Visit::Children {
                        node,
                        children,
                        inherited,
                        before,
                    });
                    pending.push(Visit::Node(id, child_inherited));
                } else if node.get(b"Count")?.as_i64()? != (out.len() - before) as i64 {
                    return Err(PdfPreparationError::MalformedPdf);
                }
            }
        }
    }
    Ok(())
}

// Copy only the static visual graph into a fresh document, never catalog,
// annotation, form, metadata, action or attachment graphs. Cycles fail closed.
// Each indirect object is copied once, however many pages share it, so the
// copy grows with the source and is never budgeted (Rule 5).
pub(super) struct VisualCopy<'a> {
    pub(super) source: &'a Document,
    pub(super) ids: BTreeMap<ObjectId, ObjectId>,
    pub(super) active: BTreeSet<ObjectId>,
    pub(super) bound: StreamBound,
    /// Each source resource dictionary copied so far, by its address in the
    /// source this preparation borrows (FIX 3810): pages that share one copy
    /// it once, and each takes its own top-level map naming the same members.
    pub(super) copied_resources: BTreeMap<*const Dictionary, Dictionary>,
}
/// The page contents admitted so far, each by the streams it names in order,
/// and every content stream decoded so far, by its id: content that many
/// pages share is checked once, and a stream named many times, on one page or
/// across pages, decodes once for the whole preparation.
#[derive(Default)]
pub(super) struct PageContents {
    checked: BTreeSet<Vec<ObjectId>>,
    decoded: BTreeMap<ObjectId, Vec<u8>>,
}
impl PageContents {
    /// Admits a page's `/Contents` (a stream or an array of streams, ISO
    /// 32000-1 section 7.7.3.3, Table 30) and returns its streams, in order,
    /// a stream the page names twice included twice. Each distinct stream
    /// decodes once under its own bound, and the page's streams are checked
    /// as the one program a reader concatenates them into, in naming order,
    /// repeats included: a fragment is never checked for balance alone.
    pub(super) fn admit(
        &mut self,
        doc: &Document,
        value: &Object,
        bound: StreamBound,
    ) -> Result<Vec<ObjectId>> {
        let stream = |value: &Object| -> Result<ObjectId> {
            match doc.dereference(value)? {
                (Some(id), Object::Stream(stream)) if !stream.dict.has(b"F") => Ok(id),
                (Some(_), Object::Stream(_)) => Err(PdfPreparationError::UnsupportedPdf),
                _ => Err(PdfPreparationError::MalformedPdf),
            }
        };
        let streams = match doc.dereference(value)? {
            (_, Object::Array(values)) => values.iter().map(stream).collect::<Result<Vec<_>>>()?,
            _ => vec![stream(value)?],
        };
        if self.checked.contains(&streams) {
            return Ok(streams);
        }
        let mut content = Vec::new();
        for id in &streams {
            let bytes = match self.decoded.entry(*id) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(decoded(doc.get_object(*id)?.as_stream()?, bound)?)
                }
            };
            content.extend_from_slice(bytes);
            content.push(b'\n');
        }
        check_content(&content)?;
        self.checked.insert(streams.clone());
        Ok(streams)
    }
}
fn check_content(bytes: &[u8]) -> Result<()> {
    reject_inline_images(bytes)?;
    let content = Content::decode_strict(bytes)?;
    let (mut graphics, mut marked, mut text) = (0i32, 0i32, false);
    for op in content.operations {
        match op.operator.as_str() {
            "q" => graphics += 1,
            "Q" => graphics -= 1,
            "BT" if !text => text = true,
            "ET" if text => text = false,
            "BT" | "ET" => return Err(PdfPreparationError::UnsupportedPdf),
            "BMC" | "BDC" => {
                if op.operands.first().and_then(|v| v.as_name().ok()) == Some(b"OC") {
                    return Err(PdfPreparationError::UnsupportedPdf);
                }
                marked += 1;
            }
            "EMC" => marked -= 1,
            "BI" | "BX" | "EX" | "PS" => return Err(PdfPreparationError::UnsupportedPdf),
            "cm" | "w" | "J" | "j" | "M" | "d" | "ri" | "i" | "gs" | "m" | "l" | "c" | "v"
            | "y" | "h" | "re" | "S" | "s" | "f" | "F" | "f*" | "B" | "B*" | "b" | "b*" | "n"
            | "W" | "W*" | "Tc" | "Tw" | "Tz" | "TL" | "Tf" | "Tr" | "Ts" | "Td" | "TD" | "Tm"
            | "T*" | "Tj" | "TJ" | "'" | "\"" | "d0" | "d1" | "CS" | "cs" | "SC" | "SCN" | "sc"
            | "scn" | "G" | "g" | "RG" | "rg" | "K" | "k" | "sh" | "Do" | "MP" | "DP" => {}
            _ => return Err(PdfPreparationError::UnsupportedPdf),
        }
        if !(0..=64).contains(&graphics) || !(0..=64).contains(&marked) {
            return Err(PdfPreparationError::MalformedPdf);
        }
    }
    if graphics != 0 || marked != 0 || text {
        return Err(PdfPreparationError::MalformedPdf);
    }
    Ok(())
}

// lopdf's inline-image parser can recover by skipping bytes and assumes some
// dimensions/colorspaces. Refuse that grammar before invoking it, not after.
pub(super) fn reject_inline_images(bytes: &[u8]) -> Result<()> {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                while i < bytes.len() && !matches!(bytes[i], b'\r' | b'\n') {
                    i += 1;
                }
            }
            b'(' => {
                i += 1;
                let mut depth = 1;
                while i < bytes.len() && depth > 0 {
                    match bytes[i] {
                        b'\\' => {
                            i += 1;
                        }
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'<' if bytes.get(i + 1) != Some(&b'<') => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
            b'/' => {
                i += 1;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !b"()<>[]{}/%".contains(&bytes[i])
                {
                    i += 1;
                }
            }
            b if b.is_ascii_whitespace() || b"<>[]{}".contains(&b) => {
                i += 1;
            }
            _ => {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !b"()<>[]{}/%".contains(&bytes[i])
                {
                    i += 1;
                }
                if &bytes[start..i] == b"BI" {
                    return Err(PdfPreparationError::UnsupportedPdf);
                }
            }
        }
    }
    Ok(())
}

/// Visible boxes are the CropBox/MediaBox intersection (PDF 32000-1 14.11.2).
pub(super) fn page_geometry(
    doc: &Document,
    page: &BTreeMap<&[u8], &Object>,
) -> Result<PageGeometry> {
    let media = pdf_box(
        doc,
        page.get(b"MediaBox".as_slice())
            .ok_or(PdfPreparationError::MalformedPdf)?,
    )?;
    let mut crop = page
        .get(b"CropBox".as_slice())
        .map(|v| pdf_box(doc, v))
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
        .map(|v| number(doc, v))
        .transpose()?
        .unwrap_or(0.);
    if rotation.fract() != 0. || rotation % 90. != 0. {
        return Err(PdfPreparationError::InvalidGeometry);
    }
    let geometry = PageGeometry {
        crop,
        rotation: rotation.rem_euclid(360.) as u16,
        user_unit: page
            .get(b"UserUnit".as_slice())
            .map(|v| number(doc, v))
            .transpose()?
            .unwrap_or(1.),
    };
    geometry.display_box()?;
    Ok(geometry)
}
