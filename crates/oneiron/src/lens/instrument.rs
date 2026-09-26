//! The single escaped Instrument renderer for a validated atom stream.

use super::validate::{LensBudget, validate_lens_collection_len};
use super::{LensAtom, LensRenderFrame, LensTextSpan};
use crate::claim::ScopedRead;
use crate::{Error, Result};

const MAX_INSTRUMENT_HTML_BYTES: usize = 1024 * 1024;

/// A validated atom stream. There is no raw HTML, JS, URL, eval or write leaf.
#[derive(Debug, Clone)]
pub struct InstrumentAtoms(Vec<LensAtom>);

impl InstrumentAtoms {
    pub fn new(atoms: Vec<LensAtom>) -> Result<Self> {
        validate_lens_collection_len("instrument atoms", atoms.len())?;
        let mut budget = LensBudget::default();
        for atom in &atoms {
            atom.validate()?;
            atom.count_collection_items(&mut budget)?;
        }
        Ok(Self(atoms))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(Error::InvalidConfig("instrument exceeds byte bound".into()));
        }
        let atoms = serde_json::from_slice(bytes)
            .map_err(|_| Error::InvalidConfig("invalid instrument atom stream".into()))?;
        Self::new(atoms)
    }
}

/// Ephemeral view output. This type has no serialization or persistence door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentView {
    pub html: String,
}

/// Render vault values only now, through the frame's principal and scope. The
/// same function renders a brief and a generated lens. All interpolated values
/// cross exactly one escaped text leaf; no input can change the structure.
pub fn render_instrument(
    atoms: &InstrumentAtoms,
    frame: &LensRenderFrame,
    read: &ScopedRead<'_>,
) -> Result<InstrumentView> {
    let mut html = String::from("<article data-instrument=\"1\">");
    for atom in &atoms.0 {
        html.push_str("<section data-atom=\"");
        html.push_str(atom.kind()); // closed Rust enum, not caller text
        html.push_str("\">");
        match atom {
            LensAtom::TextBlock(text) => {
                for span in &text.spans {
                    match span {
                        LensTextSpan::Literal(text) => escape(&mut html, text.as_str()),
                        LensTextSpan::Interpolation { key, fallback } => {
                            let backing = frame
                                .backing_refs()
                                .iter()
                                .find(|r| r.handle() == key)
                                .ok_or_else(|| {
                                Error::InvalidConfig("instrument handle is not host-bound".into())
                            })?;
                            let backing = frame.resolve_backing_ref_token(read, backing.token())?;
                            let value = frame.scoped_body(read, backing.target().entity_id())?;
                            if let Some(value) = value {
                                escape(&mut html, &display_body(&value));
                            } else {
                                escape(&mut html, fallback.as_str());
                            }
                        }
                    }
                    check_render_size(&html)?;
                }
            }
            _ => escape(&mut html, atom.default_fallback_text().as_str()),
        }
        html.push_str("</section>");
        check_render_size(&html)?;
    }
    html.push_str("</article>");
    check_render_size(&html)?;
    Ok(InstrumentView { html })
}

fn check_render_size(html: &str) -> Result<()> {
    if html.len() > MAX_INSTRUMENT_HTML_BYTES {
        return Err(Error::InvalidConfig(
            "instrument render exceeds byte bound".into(),
        ));
    }
    Ok(())
}

pub(super) fn display_body(bytes: &[u8]) -> String {
    if let Ok(body) = crate::claim::decode_claim_body(bytes, true) {
        return body.value.to_string();
    }
    if let Ok(body) = crate::note::decode_note_body(bytes) {
        // ScopedRead already projected the live document in its admitted
        // snapshot. Never open a second unscoped read from the renderer.
        return body.markdown;
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn escape(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
}
