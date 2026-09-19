//! Fresh brief views: current ledger state, cursor drift, and one renderer.

use super::document::invalid;
use super::{NoteKind, NoteSpanResolution};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ScopedRead};
use crate::lens::{
    InstrumentAtoms, InstrumentView, LensAtom, LensRenderFrame, LensText, LensTextSpan,
    TextBlockAtom, render_instrument,
};
use crate::{EntityId, Result, Vault};

#[derive(Debug, Clone, PartialEq)]
pub struct BriefCitationView {
    pub claim: EntityId,
    pub stale: bool,
    pub drifted: bool,
    pub redacted: bool,
    pub confidence: Option<f32>,
    pub lifecycle: Option<ClaimLifecycleStatus>,
    pub quote: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BriefView {
    pub instrument: InstrumentView,
    pub citations: Vec<BriefCitationView>,
}

impl Vault {
    /// Resolves a vault-resident brief every time it is viewed. The returned
    /// Instrument is not a stored format and no edit/regeneration occurs here.
    pub fn render_brief(
        &self,
        id: EntityId,
        frame: &LensRenderFrame,
        read: &ScopedRead<'_>,
    ) -> Result<Option<BriefView>> {
        self.render_brief_with_claims(id, frame, read, None)
    }

    /// The existing share evaluator remains the single authorization evaluator;
    /// candidate references come from the stored document, not from the caller.
    pub fn render_shared_brief(
        &self,
        share_id: EntityId,
        viewer: EntityId,
        narrowing: Option<&crate::share::ShareViewerScope>,
        frame: &LensRenderFrame,
        read: &ScopedRead<'_>,
    ) -> Result<Option<BriefView>> {
        if read.actor_key().actor_ref() != viewer.to_hex() {
            return Err(invalid("brief viewer key mismatch"));
        }
        let Some(share) = self.get_share(&share_id)? else {
            return Ok(None);
        };
        let id = EntityId::from_hex(&share.brief_ref)
            .map_err(|_| invalid("brief handle must name a vault NOTE"))?;
        let document = self.note_document(id)?;
        let refs: Vec<_> = document.pins.iter().map(|pin| pin.claim).collect();
        let Some(resolved) = self.resolve_share_for_view(&share_id, &viewer, narrowing, &refs)?
        else {
            return Ok(None);
        };
        self.render_brief_with_claims(id, frame, read, Some(&resolved.visible_claim_refs))
    }

    fn render_brief_with_claims(
        &self,
        id: EntityId,
        frame: &LensRenderFrame,
        read: &ScopedRead<'_>,
        visible: Option<&[EntityId]>,
    ) -> Result<Option<BriefView>> {
        if !std::ptr::eq(self, read.vault()) {
            return Err(invalid("brief read frame belongs to another vault"));
        }
        let Some(raw) = frame.scoped_body(read, &id)? else {
            return Ok(None);
        };
        if super::decode_note_body(&raw)?.kind != NoteKind::Plugin("brief".into()) {
            return Err(invalid("NOTE is not a brief"));
        }
        if self.brief_kind_contract()?.is_none() {
            return Err(invalid("brief kind is not person-stamped"));
        }
        let document = self.note_document(id)?;
        let mut citations = Vec::new();
        for pin in &document.pins {
            let allowed = visible.is_none_or(|ids| ids.contains(&pin.claim))
                && frame.scoped_body(read, &pin.claim)?.is_some()
                && frame.scoped_body(read, &pin.document)?.is_some();
            if !allowed {
                // A redacted reference reveals neither current lifecycle nor
                // whether hidden evidence was edited or erased.
                citations.push(BriefCitationView {
                    claim: pin.claim,
                    stale: false,
                    drifted: false,
                    redacted: true,
                    confidence: None,
                    lifecycle: None,
                    quote: None,
                });
                continue;
            }
            let live = self.get_claim(&pin.claim)?;
            let resolved = self.resolve_note_pin(pin);
            let drifted = !matches!(&resolved, Ok(NoteSpanResolution::Mapped { .. }));
            let source_moved = self
                .note_document(pin.document)
                .is_ok_and(|doc| doc.frontier != pin.frontier);
            let stale = source_moved
                || live
                    .as_ref()
                    .is_none_or(|claim| claim.lifecycle != ClaimLifecycleStatus::Active);
            let (confidence, lifecycle) = if allowed {
                live.as_ref().map_or((None, None), |body: &ClaimBody| {
                    (Some(body.confidence), Some(body.lifecycle))
                })
            } else {
                (None, None)
            };
            citations.push(BriefCitationView {
                claim: pin.claim,
                stale,
                drifted,
                redacted: !allowed,
                confidence,
                lifecycle,
                quote: allowed.then(|| pin.quote_text.clone()),
            });
        }
        // Authored markdown is a text atom, not trusted HTML. Splitting by line
        // respects the atom leaf bound while retaining exactly the authored text.
        let mut atoms = Vec::new();
        for line in document.markdown.lines() {
            atoms.push(LensAtom::TextBlock(TextBlockAtom {
                spans: vec![LensTextSpan::Literal(LensText::new(if line.is_empty() {
                    " "
                } else {
                    line
                })?)],
            }));
        }
        let instrument = render_instrument(&InstrumentAtoms::new(atoms)?, frame, read)?;
        Ok(Some(BriefView {
            instrument,
            citations,
        }))
    }
}
