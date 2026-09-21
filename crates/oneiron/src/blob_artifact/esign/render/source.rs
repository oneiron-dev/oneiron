//! Static page-tree and resource-graph admission and copying.
use super::streams::decode_stream;
use super::*;

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
pub(super) fn reject_signatures(doc: &Document) -> Result<()> {
    let mut stack: Vec<_> = doc.objects.values().map(|v| (v, 0)).collect();
    let mut nodes = 0;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > 64 {
            return Err(PdfPreparationError::Limit);
        }
        let dict = match value {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            Object::Array(a) => {
                stack.extend(a.iter().map(|v| (v, depth + 1)));
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
        stack.extend(dict.iter().map(|(_, v)| (v, depth + 1)));
    }
    Ok(())
}
pub(super) fn pages<'a>(
    doc: &'a Document,
    id: ObjectId,
    mut inherited: BTreeMap<&'static [u8], &'a Object>,
    seen: &mut BTreeSet<ObjectId>,
    out: &mut Vec<BTreeMap<&'static [u8], &'a Object>>,
    depth: usize,
) -> Result<()> {
    if depth > 64 || seen.len() >= MAX_OBJECTS || !seen.insert(id) {
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
            let before = out.len();
            for child in resolved(doc, node.get(b"Kids")?)?.as_array()? {
                pages(
                    doc,
                    child.as_reference()?,
                    inherited.clone(),
                    seen,
                    out,
                    depth + 1,
                )?;
            }
            if node.get(b"Count")?.as_i64()? != (out.len() - before) as i64 {
                return Err(PdfPreparationError::MalformedPdf);
            }
        }
        Some(b"Page") => {
            if out.len() >= MAX_PAGES {
                return Err(PdfPreparationError::Limit);
            }
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
    Ok(())
}

// Copy only the static visual graph into a fresh document, never catalog,
// annotation, form, metadata, action or attachment graphs. Cycles fail closed.
pub(super) struct VisualCopy<'a> {
    pub(super) source: &'a Document,
    pub(super) ids: BTreeMap<ObjectId, ObjectId>,
    pub(super) active: BTreeSet<ObjectId>,
    pub(super) nodes: usize,
    pub(super) bytes: usize,
}
impl VisualCopy<'_> {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(PdfPreparationError::Limit)?;
        if self.bytes > MAX_OUTPUT {
            return Err(PdfPreparationError::Limit);
        }
        Ok(())
    }
    pub(super) fn copy(
        &mut self,
        out: &mut Document,
        value: &Object,
        depth: usize,
    ) -> Result<Object> {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > 64 {
            return Err(PdfPreparationError::Limit);
        }
        Ok(match value {
            Object::Reference(id) => {
                if let Some(mapped) = self.ids.get(id) {
                    return Ok((*mapped).into());
                }
                if !self.active.insert(*id) {
                    return Err(PdfPreparationError::UnsupportedPdf);
                }
                let object = self
                    .source
                    .objects
                    .get(id)
                    .ok_or(PdfPreparationError::MalformedPdf)?;
                let copied = self.copy(out, object, depth + 1)?;
                let mapped = out.add_object(copied);
                self.active.remove(id);
                self.ids.insert(*id, mapped);
                mapped.into()
            }
            Object::Array(values) => Object::Array(
                values
                    .iter()
                    .map(|v| self.copy(out, v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Object::Dictionary(dict) => self.dictionary(out, dict, depth)?.into(),
            Object::Stream(stream) => {
                self.bytes = self
                    .bytes
                    .checked_add(stream.content.len())
                    .ok_or(PdfPreparationError::Limit)?;
                if self.bytes > MAX_OUTPUT {
                    return Err(PdfPreparationError::Limit);
                }
                if stream.dict.has(b"F") {
                    return Err(PdfPreparationError::UnsupportedPdf);
                }
                // Form and tiling-pattern streams are executable page content,
                // not opaque bytes. Apply the same static-content admission.
                if name(self.source, &stream.dict, b"Subtype")? == Some(b"Form")
                    || stream.dict.has(b"PatternType")
                {
                    let mut decoded = Vec::new();
                    page_content(self.source, value, &mut decoded, 0, &mut 0)?;
                    self.bytes = self
                        .bytes
                        .checked_add(decoded.len())
                        .ok_or(PdfPreparationError::Limit)?;
                    if self.bytes > MAX_OUTPUT {
                        return Err(PdfPreparationError::Limit);
                    }
                    check_content(&decoded)?;
                }
                Object::Stream(Stream::new(
                    self.dictionary(out, &stream.dict, depth)?,
                    stream.content.clone(),
                ))
            }
            Object::String(bytes, _) | Object::Name(bytes) => {
                self.bytes = self
                    .bytes
                    .checked_add(bytes.len())
                    .ok_or(PdfPreparationError::Limit)?;
                if self.bytes > MAX_OUTPUT {
                    return Err(PdfPreparationError::Limit);
                }
                value.clone()
            }
            _ => value.clone(),
        })
    }
    pub(super) fn resources(
        &mut self,
        out: &mut Document,
        value: &Object,
        depth: usize,
    ) -> Result<Dictionary> {
        if depth > 64 {
            return Err(PdfPreparationError::Limit);
        }
        let resources = resolved(self.source, value)?.as_dict()?;
        let mut copied = Dictionary::new();
        for (kind, members) in resources {
            self.charge(kind.len())?;
            if kind == b"ProcSet" {
                copied.set(kind.clone(), self.copy(out, members, depth + 1)?);
                continue;
            }
            if !matches!(
                kind.as_slice(),
                b"Font"
                    | b"XObject"
                    | b"ExtGState"
                    | b"ColorSpace"
                    | b"Pattern"
                    | b"Shading"
                    | b"Properties"
            ) {
                return Err(PdfPreparationError::UnsupportedPdf);
            }
            let mut map = Dictionary::new();
            for (key, object) in resolved(self.source, members)?.as_dict()? {
                self.charge(key.len())?;
                if kind == b"XObject" {
                    let stream = resolved(self.source, object)?.as_stream()?;
                    if !matches!(
                        name(self.source, &stream.dict, b"Subtype")?,
                        Some(b"Form" | b"Image")
                    ) {
                        return Err(PdfPreparationError::UnsupportedPdf);
                    }
                }
                map.set(key.clone(), self.copy(out, object, depth + 1)?);
            }
            copied.set(kind.clone(), map);
        }
        Ok(copied)
    }
    fn dictionary(
        &mut self,
        out: &mut Document,
        dict: &Dictionary,
        depth: usize,
    ) -> Result<Dictionary> {
        if [
            b"AA".as_slice(),
            b"A",
            b"OpenAction",
            b"JS",
            b"JavaScript",
            b"EF",
            b"AF",
            b"EmbeddedFiles",
            b"XFA",
            b"AcroForm",
            b"Annots",
            b"OC",
            b"OCProperties",
            b"Ref",
            b"Alternates",
            b"OPI",
        ]
        .iter()
        .any(|key| dict.has(key))
            || matches!(
                name(self.source, dict, b"Type")?,
                Some(
                    b"Filespec"
                        | b"EmbeddedFile"
                        | b"Annot"
                        | b"Action"
                        | b"OCG"
                        | b"OCMD"
                        | b"Catalog"
                        | b"Page"
                        | b"Pages"
                        | b"ObjStm"
                        | b"XRef"
                )
            )
            || matches!(
                name(self.source, dict, b"Subtype")?,
                Some(b"PS" | b"RichMedia" | b"Movie" | b"Sound" | b"Screen" | b"3D")
            )
            || name(self.source, dict, b"S")?.is_some_and(|s| {
                !(matches!(s, b"Transparency" | b"Alpha" | b"Luminosity")
                    || dict.has_type(b"OutputIntent")
                        && matches!(s, b"GTS_PDFX" | b"GTS_PDFA1" | b"ISO_PDFE1"))
            })
        {
            return Err(PdfPreparationError::UnsupportedPdf);
        }
        let mut copied = Dictionary::new();
        for (key, value) in dict {
            self.charge(key.len())?;
            if !matches!(key.as_slice(), b"Length" | b"Metadata" | b"PieceInfo") {
                let object = if key == b"Resources" {
                    self.resources(out, value, depth + 1)?.into()
                } else if key == b"CharProcs" {
                    let mut glyphs = Dictionary::new();
                    for (name, glyph) in resolved(self.source, value)?.as_dict()? {
                        self.charge(name.len())?;
                        let mut content = Vec::new();
                        page_content(self.source, glyph, &mut content, 0, &mut 0)?;
                        self.charge(content.len())?;
                        check_content(&content)?;
                        glyphs.set(name.clone(), self.copy(out, glyph, depth + 1)?);
                    }
                    glyphs.into()
                } else {
                    self.copy(out, value, depth + 1)?
                };
                copied.set(key.clone(), object);
            }
        }
        Ok(copied)
    }
}
pub(super) fn page_content(
    doc: &Document,
    value: &Object,
    bytes: &mut Vec<u8>,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    *nodes += 1;
    if depth > 32 || *nodes > MAX_NODES {
        return Err(PdfPreparationError::Limit);
    }
    match resolved(doc, value)? {
        Object::Array(values) => {
            for v in values {
                page_content(doc, v, bytes, depth + 1, nodes)?;
            }
        }
        Object::Stream(stream) => {
            if stream.dict.has(b"F") {
                return Err(PdfPreparationError::UnsupportedPdf);
            }
            bytes.extend(decode_stream(
                stream,
                MAX_INPUT.saturating_sub(bytes.len()),
            )?);
            bytes.push(b'\n');
            if bytes.len() > MAX_INPUT {
                return Err(PdfPreparationError::Limit);
            }
        }
        _ => return Err(PdfPreparationError::MalformedPdf),
    }
    Ok(())
}
pub(super) fn check_content(bytes: &[u8]) -> Result<()> {
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
