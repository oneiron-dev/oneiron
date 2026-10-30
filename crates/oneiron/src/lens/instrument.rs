//! The single escaped Instrument renderer for a validated atom stream.

use super::{LensAtom, LensRenderFrame, LensTextSpan};
use crate::claim::{ScopedRead, ScopedReadReceipt};

use crate::{Error, Result};

/// A validated atom stream. There is no raw HTML, JS, URL, eval or write leaf.
#[derive(Debug, Clone)]
pub struct InstrumentAtoms(Vec<LensAtom>);

impl InstrumentAtoms {
    /// Every atom validated, however many (FIX 9900).
    pub fn new(atoms: Vec<LensAtom>) -> Result<Self> {
        for atom in &atoms {
            atom.validate()?;
        }
        Ok(Self(atoms))
    }

    /// An atom stream of any length, every atom validated (FIX 11257): its
    /// caller holds the bytes whole already.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let atoms = serde_json::from_slice(bytes)
            .map_err(|_| Error::InvalidConfig("invalid instrument atom stream".into()))?;
        Self::new(atoms)
    }
}

/// Ephemeral view output. This type has no serialization or persistence door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentView {
    pub html: String,
    /// The folded receipt of every interpolated scoped read; `None` when the
    /// atoms interpolate nothing. A fallback rendered for a withheld value is
    /// counted here.
    pub receipt: Option<ScopedReadReceipt>,
}

/// Render vault values only now, through the frame's principal and scope. The
/// same function renders a brief and a generated lens. All interpolated values
/// cross exactly one escaped text leaf; no input can change the structure.
/// The view is as long as its atoms make it: no total ends a render (FIX
/// 9898).
pub fn render_instrument(
    atoms: &InstrumentAtoms,
    frame: &LensRenderFrame,
    read: &ScopedRead<'_>,
) -> Result<InstrumentView> {
    let mut html = String::from("<article data-instrument=\"1\">");
    let mut receipt: Option<ScopedReadReceipt> = None;
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
                            match &mut receipt {
                                Some(receipt) => receipt.restrict_with(&value.receipt),
                                None => receipt = Some(value.receipt),
                            }
                            if let Some(value) = value.value {
                                escape(&mut html, &display_body(&value));
                            } else {
                                escape(&mut html, fallback.as_str());
                            }
                        }
                    }
                }
            }
            _ => escape(&mut html, atom.default_fallback_text().as_str()),
        }
        html.push_str("</section>");
    }
    html.push_str("</article>");
    Ok(InstrumentView { html, receipt })
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
