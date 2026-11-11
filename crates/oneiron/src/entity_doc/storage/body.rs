//! Shared document-map encoding and exact output-length measurement.

use std::io::{self, Write};

use loro::LoroText;

use super::TextField;
use crate::entity_doc::document::BODY;
use crate::entity_doc::metadata::is_metadata_field;
use crate::entity_doc::{EntityDoc, invalid};
use crate::error::{Error, Result};

/// A typed read projection of the body and metadata at one document version.
pub(crate) fn body_with_document(
    field: &TextField,
    body: &[u8],
    doc: &EntityDoc,
) -> Result<Vec<u8>> {
    match field {
        TextField::Utf8Body => Ok(doc.text().into_bytes()),
        TextField::MapField(field) => {
            let mut out = Vec::new();
            write_map(&mut out, field, body, doc)?;
            Ok(out)
        }
    }
}

pub(super) fn body_len_with_document(
    field: &TextField,
    body: &[u8],
    doc: &EntityDoc,
) -> Result<u64> {
    match field {
        TextField::Utf8Body => Ok(doc.doc.get_text(BODY).len_utf8() as u64),
        TextField::MapField(field) => {
            let mut count = ByteCount::default();
            write_map(&mut count, field, body, doc)?;
            Ok(count.0)
        }
    }
}

fn write_map(out: &mut impl BodyOutput, field: &str, body: &[u8], doc: &EntityDoc) -> Result<()> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
        .map_err(|_| Error::CorruptedIndex("document pointer row"))?;
    let rmpv::Value::Map(mut fields) = value else {
        return Err(Error::CorruptedIndex("document pointer row"));
    };
    fields.retain(|(key, _)| {
        key.as_str() != Some("entity_doc_ref")
            && key.as_str() != Some(field)
            && !key.as_str().is_some_and(is_metadata_field)
    });
    let body_index = fields.len();
    // The text is emitted by the sink, not stored in this projection.
    fields.push((rmpv::Value::from(field), rmpv::Value::Nil));
    let record_fields = doc.record_fields()?;
    for (key, value) in doc.metadata()? {
        if key == field {
            return Err(Error::CorruptedIndex(
                "body field duplicated in document metadata",
            ));
        }
        if record_fields.contains(&key) {
            fields.push((rmpv::Value::from(key), value));
        }
    }
    let text = doc.doc.get_text(BODY);
    rmp::encode::write_map_len(out, fields.len() as u32)
        .map_err(|_| invalid("document view encoding"))?;
    for (index, (key, value)) in fields.iter().enumerate() {
        rmpv::encode::write_value(out, key).map_err(|_| invalid("document view encoding"))?;
        if index == body_index {
            out.text(&text)?;
        } else {
            rmpv::encode::write_value(out, value).map_err(|_| invalid("document view encoding"))?;
        }
    }
    Ok(())
}

trait BodyOutput: Write {
    fn text(&mut self, text: &LoroText) -> Result<()>;
}

impl BodyOutput for Vec<u8> {
    fn text(&mut self, text: &LoroText) -> Result<()> {
        rmp::encode::write_str(self, &text.to_string())
            .map_err(|_| invalid("document view encoding"))
    }
}

#[derive(Default)]
struct ByteCount(u64);

impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BodyOutput for ByteCount {
    fn text(&mut self, text: &LoroText) -> Result<()> {
        let len = text.len_utf8();
        rmp::encode::write_str_len(self, len as u32)
            .map_err(|_| invalid("document view encoding"))?;
        // Loro's iter snapshots owned strings; length measurement must not call it.
        self.0 += len as u64;
        Ok(())
    }
}
