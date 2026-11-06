//! Stack-safe copying of the static visual graph.
use super::*;

enum CopyTask<'a> {
    Value(&'a Object),
    Dictionary(&'a Dictionary),
    DictionaryMember(&'a [u8], &'a Object),
    Resources(&'a Object),
    ResourceKind(&'a [u8], &'a Object),
    ResourceMember(&'a [u8], &'a [u8], &'a Object),
    Glyphs(&'a Object),
    Glyph(&'a [u8], &'a Object),
    Insert(&'a [u8]),
    InsertResource(&'a [u8]),
    Append,
    Reference(ObjectId),
    Stream(&'a [u8]),
    CacheResources(*const Dictionary),
}

impl<'source> VisualCopy<'source> {
    pub(in super::super) fn copy(&mut self, out: &mut Document, value: &Object) -> Result<Object> {
        self.walk(out, CopyTask::Value(value))
    }

    /// Direct composite members become indirect once, while the cached
    /// resource map keeps the same member ids for every page that shares it.
    pub(in super::super) fn resources(
        &mut self,
        out: &mut Document,
        value: &Object,
    ) -> Result<Dictionary> {
        let mut copied = self.walk(out, CopyTask::Resources(value))?;
        Ok(std::mem::take(copied.as_dict_mut()?))
    }

    fn walk<'a>(&mut self, out: &mut Document, first: CopyTask<'a>) -> Result<Object>
    where
        'source: 'a,
    {
        let mut pending = vec![first];
        let mut values = Vec::<Object>::new();
        let mut active_resources = BTreeSet::new();
        while let Some(task) = pending.pop() {
            match task {
                CopyTask::Value(value) => match value {
                    Object::Reference(id) => {
                        if let Some(mapped) = self.ids.get(id) {
                            values.push((*mapped).into());
                            continue;
                        }
                        if !self.active.insert(*id) {
                            return Err(PdfPreparationError::UnsupportedPdf);
                        }
                        let object = self
                            .source
                            .objects
                            .get(id)
                            .ok_or(PdfPreparationError::MalformedPdf)?;
                        pending.push(CopyTask::Reference(*id));
                        pending.push(CopyTask::Value(object));
                    }
                    Object::Array(array) => {
                        values.push(Object::Array(Vec::new()));
                        for value in array.iter().rev() {
                            pending.push(CopyTask::Append);
                            pending.push(CopyTask::Value(value));
                        }
                    }
                    Object::Dictionary(dict) => pending.push(CopyTask::Dictionary(dict)),
                    Object::Stream(stream) => {
                        if stream.dict.has(b"F") {
                            return Err(PdfPreparationError::UnsupportedPdf);
                        }
                        if name(self.source, &stream.dict, b"Subtype")? == Some(b"Form")
                            || stream.dict.has(b"PatternType")
                        {
                            let mut content = decoded(stream, self.bound)?;
                            content.push(b'\n');
                            check_content(&content)?;
                        }
                        pending.push(CopyTask::Stream(&stream.content));
                        pending.push(CopyTask::Dictionary(&stream.dict));
                    }
                    _ => values.push(value.clone()),
                },
                CopyTask::Reference(id) => {
                    let copied = values.pop().expect("copied indirect object");
                    let mapped = out.add_object(copied);
                    self.active.remove(&id);
                    self.ids.insert(id, mapped);
                    values.push(mapped.into());
                }
                CopyTask::Append => {
                    let value = values.pop().expect("copied array member");
                    values
                        .last_mut()
                        .expect("copy array frame")
                        .as_array_mut()
                        .expect("copy array frame")
                        .push(value);
                }
                CopyTask::Dictionary(dict) => {
                    self.check_dictionary(dict)?;
                    values.push(Dictionary::new().into());
                    for (key, value) in dict.iter().rev() {
                        if !matches!(key.as_slice(), b"Length" | b"Metadata" | b"PieceInfo") {
                            pending.push(CopyTask::DictionaryMember(key, value));
                        }
                    }
                }
                CopyTask::DictionaryMember(key, value) => {
                    pending.push(CopyTask::Insert(key));
                    pending.push(match key {
                        b"Resources" => CopyTask::Resources(value),
                        b"CharProcs" => CopyTask::Glyphs(value),
                        _ => CopyTask::Value(value),
                    });
                }
                CopyTask::Stream(content) => {
                    let mut dictionary = values.pop().expect("copied stream dictionary");
                    let dictionary =
                        std::mem::take(dictionary.as_dict_mut().expect("copied stream dictionary"));
                    values.push(Object::Stream(Stream::new(dictionary, content.to_vec())));
                }
                CopyTask::Resources(value) => {
                    let resources = resolved(self.source, value)?.as_dict()?;
                    let address: *const Dictionary = resources;
                    if let Some(copied) = self.copied_resources.get(&address) {
                        values.push(copied.clone().into());
                        continue;
                    }
                    // Resources resolves its reference before ordinary copying,
                    // so unfinished resource maps need their own active path.
                    if !active_resources.insert(address) {
                        return Err(PdfPreparationError::UnsupportedPdf);
                    }
                    values.push(Dictionary::new().into());
                    pending.push(CopyTask::CacheResources(address));
                    for (kind, members) in resources.iter().rev() {
                        pending.push(CopyTask::ResourceKind(kind, members));
                    }
                }
                CopyTask::ResourceKind(kind, members) => {
                    if kind == b"ProcSet" {
                        pending.push(CopyTask::Insert(kind));
                        pending.push(CopyTask::Value(members));
                        continue;
                    }
                    if !matches!(
                        kind,
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
                    let members = resolved(self.source, members)?.as_dict()?;
                    values.push(Dictionary::new().into());
                    pending.push(CopyTask::Insert(kind));
                    for (key, object) in members.iter().rev() {
                        pending.push(CopyTask::ResourceMember(kind, key, object));
                    }
                }
                CopyTask::ResourceMember(kind, key, object) => {
                    if kind == b"XObject" {
                        let stream = resolved(self.source, object)?.as_stream()?;
                        if !matches!(
                            name(self.source, &stream.dict, b"Subtype")?,
                            Some(b"Form" | b"Image")
                        ) {
                            return Err(PdfPreparationError::UnsupportedPdf);
                        }
                    }
                    pending.push(CopyTask::InsertResource(key));
                    pending.push(CopyTask::Value(object));
                }
                CopyTask::InsertResource(key) => {
                    let member = values.pop().expect("copied resource member");
                    let member = match member {
                        member @ (Object::Dictionary(_) | Object::Array(_) | Object::Stream(_)) => {
                            out.add_object(member).into()
                        }
                        member => member,
                    };
                    values
                        .last_mut()
                        .expect("copy resource map")
                        .as_dict_mut()
                        .expect("copy resource map")
                        .set(key.to_vec(), member);
                }
                CopyTask::CacheResources(address) => {
                    let copied = values
                        .last()
                        .expect("copied resource dictionary")
                        .as_dict()
                        .expect("copied resource dictionary");
                    self.copied_resources.insert(address, copied.clone());
                    active_resources.remove(&address);
                }
                CopyTask::Glyphs(value) => {
                    let glyphs = resolved(self.source, value)?.as_dict()?;
                    values.push(Dictionary::new().into());
                    for (name, glyph) in glyphs.iter().rev() {
                        pending.push(CopyTask::Glyph(name, glyph));
                    }
                }
                CopyTask::Glyph(name, glyph) => {
                    let mut content = Vec::new();
                    glyph_content(self.source, glyph, &mut content, self.bound)?;
                    check_content(&content)?;
                    pending.push(CopyTask::Insert(name));
                    pending.push(CopyTask::Value(glyph));
                }
                CopyTask::Insert(key) => {
                    let value = values.pop().expect("copied dictionary member");
                    values
                        .last_mut()
                        .expect("copy dictionary frame")
                        .as_dict_mut()
                        .expect("copy dictionary frame")
                        .set(key.to_vec(), value);
                }
            }
        }
        Ok(values.pop().expect("copied visual object"))
    }

    fn check_dictionary(&self, dict: &Dictionary) -> Result<()> {
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
        Ok(())
    }
}

/// Decode glyph arrays in source order; repeated siblings are not cycles.
fn glyph_content(
    doc: &Document,
    value: &Object,
    bytes: &mut Vec<u8>,
    bound: StreamBound,
) -> Result<()> {
    enum Visit<'a> {
        Value(&'a Object),
        LeaveArray(*const Vec<Object>),
    }
    let mut pending = vec![Visit::Value(value)];
    let mut active = BTreeSet::new();
    while let Some(visit) = pending.pop() {
        match visit {
            Visit::Value(value) => match resolved(doc, value)? {
                Object::Array(values) => {
                    let address: *const Vec<Object> = values;
                    if !active.insert(address) {
                        return Err(PdfPreparationError::MalformedPdf);
                    }
                    pending.push(Visit::LeaveArray(address));
                    pending.extend(values.iter().rev().map(Visit::Value));
                }
                Object::Stream(stream) => {
                    if stream.dict.has(b"F") {
                        return Err(PdfPreparationError::UnsupportedPdf);
                    }
                    bytes.extend(decoded(stream, bound)?);
                    bytes.push(b'\n');
                }
                _ => return Err(PdfPreparationError::MalformedPdf),
            },
            Visit::LeaveArray(address) => {
                active.remove(&address);
            }
        }
    }
    Ok(())
}
