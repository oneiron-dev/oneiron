//! Span-grain selection handles over Loro cursors, and the quote pointer triple.
//!
//! OF-248 at the span grain (RD-23 v86): a span handle resolves to a Loro cursor
//! on the entity document, carries the version it was taken at, and re-proves at
//! use time through the single resolution path
//! ([`LensRenderFrame::resolve_read_handle`](crate::lens::LensRenderFrame::resolve_read_handle)).
//! The CROSS-ARCH-0010 quote amendment rides the same grain: a quote is
//! `replyToMessageId + replyToRevisionId + replyToRange`, a pointer, never a copy,
//! with half-open `[start, end)` offsets in Unicode scalar values.
//!
//! # What the "entity document" is here
//!
//! The vault stores no per-entity Loro history: MESSAGE rows are immutable
//! canonical envelopes and ASSET_TEXT rows are plain mutable bytes. There is no
//! native historical Loro store to check a cursor out of, so the engine derives a
//! transient Loro document deterministically from the pinned body bytes at both
//! ends — select time and use time — and binds it to the exact entity/body
//! revision with a content pin. The pin, not the cursor, is what makes a
//! stale-version handle fail closed: Loro frontiers track op identity, so two
//! same-length texts share a shape the pin distinguishes.
//!
//! # Trust
//!
//! Selection is not approval and nothing here is self-executing, exactly as at
//! the atom grain. The client request names what was pointed at (card, atom,
//! handle, scalar offsets) and nothing else; every other field a span handle
//! carries — the short ref, the revision pin, the cursors — is engine-derived at
//! issue time and re-derived at use time, compared whole by the existing
//! `resolve_read_handle` derivation. There is no second authority path: the span
//! and quote readers below re-proof through that one door first.

use loro::{
    LoroDoc, LoroText,
    cursor::{Cursor, PosType, Side},
};

use crate::claim::ScopedRead;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::lens::generated_ui::GeneratedUiRender;
use crate::lens::wire_ids::{LensAtomId, LensHandleName, LensRenderId};
use crate::registry::{ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_MESSAGE};

use super::{LensReadHandle, LensRenderFrame};

/// Root container holding the pinned text inside a derived span document.
const SPAN_TEXT_CONTAINER: &str = "span_text";

/// Fixed peer for derived span documents. The doc is rebuilt from pinned bytes at
/// both ends, so the peer carries no identity — but it must be constant, or two
/// builds of the same bytes would mint different op ids and the cursors taken at
/// select time would not resolve at use time.
const SPAN_DOC_PEER_ID: u64 = 0x5eed;

/// Domain tag for the span revision pin. The pin binds (entity id, body bytes);
/// the tag keeps the hash from colliding with any other blake3 use in the crate.
const SPAN_REVISION_DOMAIN: &[u8] = b"oneiron.lens.span_revision.v0";

/// Client-authored span selection: the atom triple plus half-open scalar offsets.
/// Deny-unknown-fields, exactly like [`super::LensAtomSelectionRequest`]: no entity
/// id, no body text, no revision, no cursor is expressible here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSpanSelectionRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
    /// Half-open `[start, end)` in Unicode scalar values over the pinned text.
    pub start: u32,
    pub end: u32,
}

/// The engine-issued span grain riding inside a [`LensReadHandle`].
///
/// Serialize-only with no public constructor, exactly like the handle itself: the
/// only way to hold one is to have passed
/// [`LensRenderFrame::select_span`](crate::lens::LensRenderFrame::select_span).
/// It carries the revision pin and the scalar range — never body text and never a
/// cursor over anything but the derived document the pin names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LensSpanGrain {
    pub(super) revision: String,
    pub(super) start: u32,
    pub(super) end: u32,
}

impl LensSpanGrain {
    /// The pinned body revision (blake3 hex) the range was taken from.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Half-open `[start, end)` in Unicode scalar values.
    #[must_use]
    pub fn range(&self) -> (u32, u32) {
        (self.start, self.end)
    }
}

/// The CROSS-ARCH-0010 quote pointer: `replyToMessageId + replyToRevisionId +
/// replyToRange`. Engine-issued from a span handle only
/// ([`LensRenderFrame::quote_from_span`](crate::lens::LensRenderFrame::quote_from_span));
/// the quoted text is rendered from the pinned revision at read time, never
/// stored beside the pointer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensQuoteTriple {
    reply_to_message_id: String,
    reply_to_revision_id: String,
    reply_to_range: LensQuoteRange,
}

/// Half-open `[start, end)` in Unicode scalar values. A struct, not a tuple: the
/// wire shape is `{start, end}` and a bare pair would accept the wrong order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensQuoteRange {
    pub start: u32,
    pub end: u32,
}

impl LensQuoteTriple {
    /// TEST-ONLY: build a triple from parts. Production code issues triples only
    /// through [`LensRenderFrame::quote_from_span`]; this seam exists so tests can
    /// forge well-shaped triples (unknown revisions, inverted ranges) and prove
    /// `resolve_quote` refuses them.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        reply_to_message_id: String,
        reply_to_revision_id: String,
        start: u32,
        end: u32,
    ) -> Self {
        Self {
            reply_to_message_id,
            reply_to_revision_id,
            reply_to_range: LensQuoteRange { start, end },
        }
    }

    /// The quoted message, 32 lowercase hex.
    #[must_use]
    pub fn reply_to_message_id(&self) -> &str {
        &self.reply_to_message_id
    }

    /// The revision the range was taken from (the span pin, blake3 hex).
    #[must_use]
    pub fn reply_to_revision_id(&self) -> &str {
        &self.reply_to_revision_id
    }

    /// Half-open `[start, end)` in Unicode scalar values.
    #[must_use]
    pub fn reply_to_range(&self) -> (u32, u32) {
        (self.reply_to_range.start, self.reply_to_range.end)
    }
}

/// The span a proved handle reaches: the resolved cursors at the pinned revision.
/// Engine-owned output with no serde impls, so no client can submit or forge one.
/// The cursors resolve to the echoed range in the derived document the revision
/// names; quoted text itself renders through
/// [`LensRenderFrame::resolve_quote`](crate::lens::LensRenderFrame::resolve_quote).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensResolvedSpan {
    /// Cursors over the derived document built from the pinned text.
    pub cursors: (Cursor, Cursor),
    /// The pinned revision the cursors were resolved at.
    pub revision: String,
    /// The scalar range, echoed from the proved handle.
    pub range: (u32, u32),
}

impl LensRenderFrame {
    /// Turn a client span selection into engine-issued read reach at the span grain.
    ///
    /// The request names no target and no revision. The atom/handle half resolves
    /// exactly as [`Self::select_atom`](crate::lens::LensRenderFrame::select_atom)
    /// does — node lookup in the exact render, advertised handle, host-row token,
    /// target re-hydration under the acting principal's selected read key — and the
    /// span half pins the body's current revision and proves the scalar range
    /// against the pinned text before any handle is issued.
    pub fn select_span(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        request: &LensSpanSelectionRequest,
    ) -> Result<LensReadHandle> {
        self.ensure_scoped_read_actor(scoped_read)?;
        self.ensure_render_is_ours(render)?;
        if request.card_id != render.card_id {
            return Err(Error::InvalidConfig(
                "lens span selection must name the card it was rendered from".to_string(),
            ));
        }
        let row = self
            .backing_refs
            .iter()
            .find(|backing_ref| backing_ref.handle == request.handle)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens selection handle was not host-bound for this render".to_string(),
                )
            })?;
        let resolved = self.resolve_backing_ref_token(scoped_read, &row.token)?;
        let pinned = pin_span_body(scoped_read, &resolved.target)?;
        let grain = LensSpanGrain::prove(&pinned, request.start, request.end)?;
        self.issue_span_handle(render, &request.atom_id, &resolved, Some(grain))
    }

    /// Re-derive the span grain a handle's `(atom, backing row)` proves *right now*.
    ///
    /// This is the span half of the one shared derivation: issuance
    /// ([`Self::select_span`]) and re-resolution ([`Self::resolve_read_handle`](crate::lens::LensRenderFrame::resolve_read_handle))
    /// both pass through here, so a presented handle's span fields are re-proved
    /// rather than trusted. The current body is pinned and the handle's own range
    /// re-proved against it; a body that moved since issue pins a different
    /// revision, the grains differ, and the whole-handle comparison in
    /// `resolve_read_handle` fails closed. There is no span-specific resolve door:
    /// spans re-proof through the atom path or not at all.
    pub(super) fn reresolve_span_grain(
        &self,
        scoped_read: &ScopedRead<'_>,
        handle: &LensReadHandle,
        resolved: &super::LensHostBackingRef,
    ) -> Result<Option<LensSpanGrain>> {
        let Some(presented) = handle.span() else {
            return Ok(None);
        };
        let pinned = pin_span_body(scoped_read, &resolved.target)?;
        Ok(Some(LensSpanGrain::prove(
            &pinned,
            presented.start,
            presented.end,
        )?))
    }

    /// Resolve a proved span handle to its Loro cursors at the pinned revision.
    ///
    /// A read door, not an authority path: the handle is re-proved through
    /// [`Self::resolve_read_handle`](crate::lens::LensRenderFrame::resolve_read_handle)
    /// first, and only then are the cursors derived from the pinned text. The
    /// returned cursors resolve to the handle's scalar range in the derived
    /// document; anything the handle no longer proves fails before a cursor exists.
    pub fn resolve_span_cursors(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        handle: &LensReadHandle,
    ) -> Result<LensResolvedSpan> {
        let resolved = self.resolve_read_handle(scoped_read, render, handle)?;
        let presented = handle.span().ok_or_else(|| {
            Error::InvalidConfig("lens read handle carries no span grain".to_string())
        })?;
        let pinned = pin_span_body(scoped_read, &resolved.target)?;
        if pinned.revision != presented.revision {
            return Err(Error::InvalidConfig(
                "lens span revision no longer matches the pinned body".to_string(),
            ));
        }
        let doc = derive_span_doc(&pinned.text)?;
        let text = doc.get_text(SPAN_TEXT_CONTAINER);
        let start = scalar_to_event(&text, presented.start)?;
        let end = scalar_to_event(&text, presented.end)?;
        let start_cursor = text.get_cursor(start, Side::Left).ok_or_else(|| {
            Error::InvalidConfig("lens span start does not resolve to a cursor".to_string())
        })?;
        let end_cursor = text.get_cursor(end, Side::Right).ok_or_else(|| {
            Error::InvalidConfig("lens span end does not resolve to a cursor".to_string())
        })?;
        // The cursors must round-trip to the proved range: a cursor that resolves
        // elsewhere is not the handle's span, whatever anchored it.
        let start_back = event_to_scalar(&text, &doc, &start_cursor)?;
        let end_back = event_to_scalar(&text, &doc, &end_cursor)?;
        if start_back != presented.start || end_back != presented.end {
            return Err(Error::InvalidConfig(
                "lens span cursors do not resolve to the proved range".to_string(),
            ));
        }
        Ok(LensResolvedSpan {
            cursors: (start_cursor, end_cursor),
            revision: pinned.revision,
            range: (presented.start, presented.end),
        })
    }

    /// Issue the quote pointer for a proved span handle: `replyToMessageId +
    /// replyToRevisionId + replyToRange`, pointer never copy.
    ///
    /// The message id is the span target's own entity id — never a client-supplied
    /// value — and the revision and range are the handle's re-proved span grain.
    /// Only MESSAGE targets quote: a quote answers a message, and an ASSET_TEXT row
    /// is not one.
    pub fn quote_from_span(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        handle: &LensReadHandle,
    ) -> Result<LensQuoteTriple> {
        let resolved = self.resolve_read_handle(scoped_read, render, handle)?;
        let (kind, _, _) = scoped_read
            .get_entity_parts(resolved.target.entity_id())?
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens quote target is not readable by the acting principal".to_string(),
                )
            })?;
        if kind != ENTITY_TYPE_MESSAGE {
            return Err(Error::InvalidConfig(
                "lens quotes answer messages, not asset text".to_string(),
            ));
        }
        let presented = handle.span().ok_or_else(|| {
            Error::InvalidConfig("lens read handle carries no span grain".to_string())
        })?;
        Ok(LensQuoteTriple {
            reply_to_message_id: resolved.target.entity_id().to_hex(),
            reply_to_revision_id: presented.revision.clone(),
            reply_to_range: LensQuoteRange {
                start: presented.start,
                end: presented.end,
            },
        })
    }

    /// Re-prove a quote triple at use time and render the text it points at.
    ///
    /// The message must still hydrate under the acting principal, its current body
    /// must still pin the quoted revision (a moved message fails closed — the quote
    /// names the revision it was taken from, and "edited since" is a flag for the
    /// app, not a silent re-point), and the range must still prove against the
    /// pinned text. Pointer never copy holds at both ends: the triple carries no
    /// text, and the text returned here is rendered from the pinned revision.
    pub fn resolve_quote(
        &self,
        scoped_read: &ScopedRead<'_>,
        quote: &LensQuoteTriple,
    ) -> Result<String> {
        self.ensure_scoped_read_actor(scoped_read)?;
        let message_id = EntityId::from_hex(&quote.reply_to_message_id).map_err(|_| {
            Error::InvalidConfig("lens quote names no resolvable message".to_string())
        })?;
        let pinned = pin_message_body(scoped_read, &message_id)?;
        if pinned.revision != quote.reply_to_revision_id {
            return Err(Error::InvalidConfig(
                "lens quote revision is missing or the message moved past it".to_string(),
            ));
        }
        let (start, end) = (quote.reply_to_range.start, quote.reply_to_range.end);
        LensSpanGrain::prove(&pinned, start, end)?;
        slice_scalars(&pinned.text, start, end)
    }
}

impl LensSpanGrain {
    /// Prove a scalar range against pinned text: ordered, in range, and both ends
    /// on scalar boundaries. The pin is engine-derived; the range re-proves here at
    /// both issue time and use time.
    fn prove(pinned: &PinnedSpanBody, start: u32, end: u32) -> Result<Self> {
        if start > end {
            return Err(Error::InvalidConfig(
                "lens span start must not pass its end".to_string(),
            ));
        }
        if end > pinned.scalar_len {
            return Err(Error::InvalidConfig(
                "lens span range passes the pinned text".to_string(),
            ));
        }
        // Every offset in `[0, scalar_len]` is a scalar boundary by construction
        // — one `char` is one scalar value — so ordering plus the length bound is
        // the whole proof. Byte and UTF-16 cuts never enter: slicing walks chars,
        // and the cursor round-trip in `resolve_span_cursors` re-proves the range
        // through the derived document.
        Ok(Self {
            revision: pinned.revision.clone(),
            start,
            end,
        })
    }
}

/// The pinned body a span proves against: the exact bytes, their text, and the
/// revision pin binding both to the entity.
struct PinnedSpanBody {
    revision: String,
    text: String,
    scalar_len: u32,
}

/// Pin the body behind a span target: read the live row under the acting
/// principal and bind (entity id, body bytes) into the revision. MESSAGE and
/// ASSET_TEXT are the text-bearing kinds; anything else has no span to select.
///
/// The short-ref binding is not re-checked here: both callers arrive through the
/// single resolution path (`select_span` via `resolve_backing_ref_token`,
/// re-proof via `resolve_read_handle`), which already hydrates the short ref and
/// rejects a target that stopped resolving to the bound entity.
fn pin_span_body(
    scoped_read: &ScopedRead<'_>,
    target: &super::LensBackingTarget,
) -> Result<PinnedSpanBody> {
    let entity_id = *target.entity_id();
    let (kind, _, body) = scoped_read.get_entity_parts(&entity_id)?.ok_or_else(|| {
        Error::InvalidConfig("lens span target is not readable by the acting principal".to_string())
    })?;
    let text = span_text_for_kind(kind, &body)?;
    Ok(PinnedSpanBody {
        revision: span_revision(&entity_id, &body),
        scalar_len: text.chars().count().try_into().map_err(|_| {
            Error::InvalidConfig("lens span text passes the scalar ceiling".to_string())
        })?,
        text,
    })
}

/// Pin a MESSAGE body for quote re-proof: the message must still read under the
/// acting principal and still be a MESSAGE, or there is no quoted revision. A
/// message that moved past the quoted revision pins a different revision here,
/// which is what makes the triple fail closed instead of drifting.
fn pin_message_body(scoped_read: &ScopedRead<'_>, message_id: &EntityId) -> Result<PinnedSpanBody> {
    let (kind, _, body) = scoped_read.get_entity_parts(message_id)?.ok_or_else(|| {
        Error::InvalidConfig(
            "lens quote message is not readable by the acting principal".to_string(),
        )
    })?;
    if kind != ENTITY_TYPE_MESSAGE {
        return Err(Error::InvalidConfig(
            "lens quote message must resolve to a message entity".to_string(),
        ));
    }
    let text = message_content(&body)?;
    Ok(PinnedSpanBody {
        revision: span_revision(message_id, &body),
        scalar_len: text.chars().count().try_into().map_err(|_| {
            Error::InvalidConfig("lens span text passes the scalar ceiling".to_string())
        })?,
        text,
    })
}

/// The text a span kind carries: a MESSAGE's `content` cell, an ASSET_TEXT's whole
/// body as UTF-8. Anything else fails closed — claims, turns, and people have no
/// span text.
fn span_text_for_kind(kind: u8, body: &[u8]) -> Result<String> {
    match kind {
        ENTITY_TYPE_MESSAGE => message_content(body),
        ENTITY_TYPE_ASSET_TEXT => std::str::from_utf8(body)
            .map_err(|_| Error::InvalidConfig("lens span asset text is not UTF-8".to_string()))
            .map(str::to_owned),
        _ => Err(Error::InvalidConfig(
            "lens spans reach message and asset text only".to_string(),
        )),
    }
}

/// A MESSAGE body's `content` cell. The bytes must decode as the canonical
/// envelope map and the cell must be a string; nothing else about the envelope is
/// trusted here — the write door owns admission, this owns extraction.
fn message_content(body: &[u8]) -> Result<String> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidConfig("lens span message body is not decodable".to_string()))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidConfig(
            "lens span message body carries trailing bytes".to_string(),
        ));
    }
    let rmpv::Value::Map(entries) = value else {
        return Err(Error::InvalidConfig(
            "lens span message body is not an envelope".to_string(),
        ));
    };
    for (key, entry) in &entries {
        if key.as_str() == Some("content") {
            return entry.as_str().map(str::to_owned).ok_or_else(|| {
                Error::InvalidConfig("lens span message content is not text".to_string())
            });
        }
    }
    Err(Error::InvalidConfig(
        "lens span message body carries no content".to_string(),
    ))
}

/// The span revision pin: blake3 over (domain, entity id, body bytes), hex.
/// Full-content binding, not a length or a Loro shape: an equal-length edit pins
/// a different revision, and a different entity's identical bytes pin a different
/// revision too.
fn span_revision(entity_id: &EntityId, body: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SPAN_REVISION_DOMAIN);
    hasher.update(entity_id.as_bytes());
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    bytes_to_hex_lower(hasher.finalize().as_bytes())
}

/// Derive the transient span document deterministically from pinned text: one
/// fresh doc, one fixed peer, one text container, one insert, one commit. Same
/// bytes in, same op ids out — so cursors taken at select time resolve at use
/// time, and only at the pinned revision.
fn derive_span_doc(text: &str) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    doc.set_peer_id(SPAN_DOC_PEER_ID)
        .map_err(|_| Error::InvalidConfig("lens span document cannot take its peer".to_string()))?;
    doc.get_text(SPAN_TEXT_CONTAINER)
        .insert(0, text)
        .map_err(|_| {
            Error::InvalidConfig("lens span text cannot enter its document".to_string())
        })?;
    doc.commit();
    Ok(doc)
}

/// Map a Unicode scalar offset to the event index `get_cursor` consumes.
/// Without the wasm build the two coincide, but the conversion is the contract,
/// not the coincidence: JS callers count UTF-16, the engine counts scalars, and
/// only an explicit conversion keeps Japanese text plus emoji from disagreeing.
fn scalar_to_event(text: &LoroText, scalar: u32) -> Result<usize> {
    let scalar = usize::try_from(scalar).map_err(|_| {
        Error::InvalidConfig("lens span offset passes the address ceiling".to_string())
    })?;
    text.convert_pos(scalar, PosType::Unicode, PosType::Event)
        .ok_or_else(|| Error::InvalidConfig("lens span offset is not addressable".to_string()))
}

/// Map a resolved cursor back to the scalar offset it proves.
fn event_to_scalar(text: &LoroText, doc: &LoroDoc, cursor: &Cursor) -> Result<u32> {
    let event = doc
        .get_cursor_pos(cursor)
        .map_err(|_| Error::InvalidConfig("lens span cursor does not resolve".to_string()))?;
    let scalar = text
        .convert_pos(event.current.pos, PosType::Event, PosType::Unicode)
        .ok_or_else(|| {
            Error::InvalidConfig("lens span cursor resolves outside the text".to_string())
        })?;
    u32::try_from(scalar)
        .map_err(|_| Error::InvalidConfig("lens span cursor passes the scalar ceiling".to_string()))
}

/// Slice half-open `[start, end)` scalar offsets out of pinned text. Both ends
/// already proved scalar boundaries by [`LensSpanGrain::prove`]; this walks chars
/// rather than trusting byte arithmetic.
fn slice_scalars(text: &str, start: u32, end: u32) -> Result<String> {
    let mut bytes = [None::<usize>, None::<usize>];
    let mut count = 0_u32;
    for (byte, _) in text.char_indices() {
        if count == start {
            bytes[0] = Some(byte);
        }
        if count == end {
            bytes[1] = Some(byte);
        }
        count += 1;
    }
    if count == start {
        bytes[0] = Some(text.len());
    }
    if count == end {
        bytes[1] = Some(text.len());
    }
    match bytes {
        [Some(from), Some(to)] if from <= to => Ok(text[from..to].to_owned()),
        _ => Err(Error::InvalidConfig(
            "lens span range does not slice the pinned text".to_string(),
        )),
    }
}
