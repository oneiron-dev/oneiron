//! Vault access and policy admission for slide reviews.
//! Entry: `Vault::review_blob_artifact_slides`.
//! Review model types remain in the parent module.

use super::*;

impl Vault {
    /// Review one artifact head through the host's decide() ladder. Keep/discard
    /// through the existing consume-once edit-settle door; a changed head is
    /// retained as a stale preview. A deck with a live body has each unit's
    /// text read on its projection at its head, as a wake reads it; the
    /// images stay the caller's (FIX 12019).
    pub fn review_blob_artifact_slides(
        &self,
        artifact: &EntityId,
        request: &SlideReviewRequest<'_>,
    ) -> std::result::Result<SlideReviewRun, SlideReviewError> {
        let snapshot = self.slide_review_snapshot(artifact)?;
        self.review_blob_artifact_slides_pinned(artifact, snapshot, request)
    }

    /// The head a slide review reads, read once (FIX 9624): its version, that
    /// version's bytes and the rows they were read from, and a live body's
    /// deck at its head with the pin read before it. A host that renders the
    /// units' images draws them from this snapshot and reviews the same one,
    /// so pixels, text and the judgment's version never come from two heads.
    pub(crate) fn slide_review_snapshot(
        &self,
        artifact: &EntityId,
    ) -> std::result::Result<SlideReviewSnapshot, SlideReviewError> {
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if super::OfficeFormat::from_media_type(&body.media_type)? != super::OfficeFormat::Pptx {
            return Err(PptxError::InvalidPatch.into());
        }
        let (bytes, read_rows) = self
            .read_blob_artifact_version_listing(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let live = self.live_head_deck(artifact)?;
        Ok(SlideReviewSnapshot {
            version: head.version,
            bytes,
            read_rows,
            live,
        })
    }

    /// Where each of `slides`, numbered as the head version's own deck
    /// numbers them, is drawn in `snapshot`'s shown deck: the 1-based place
    /// of the slide of the same part and id there, which a reorder the live
    /// body has not exported moves. `None` for one that deck no longer holds,
    /// and for each when a deck does not read: such a unit is drawn nowhere
    /// and read for its structure only, so its image is never another
    /// slide's.
    pub(crate) fn slide_review_shown_numbers(
        &self,
        snapshot: &SlideReviewSnapshot,
        slides: &[u64],
    ) -> Vec<Option<u64>> {
        let Some((_, live)) = &snapshot.live else {
            return slides.iter().copied().map(Some).collect();
        };
        let decks = || -> Option<(DeckView, DeckView)> {
            let limits = self.docedit_package_limits().ok()?;
            let resources = crate::office_body::document_resources();
            let read =
                |bytes: &[u8]| DeckView::read(&Package::open(bytes, limits, &resources).ok()?).ok();
            Some((read(snapshot.bytes.as_slice())?, read(live.as_slice())?))
        };
        let Some((version, shown)) = decks() else {
            return vec![None; slides.len()];
        };
        slides
            .iter()
            .map(|&number| {
                let index = usize::try_from(number.checked_sub(1)?).ok()?;
                let slide = version.slides.get(index)?;
                let at = shown
                    .slides
                    .iter()
                    .position(|shown| shown.part == slide.part && shown.sld_id == slide.sld_id)?;
                u64::try_from(at + 1).ok()
            })
            .collect()
    }

    /// [`Self::review_blob_artifact_slides`] over the head `snapshot` read
    /// (FIX 9624).
    pub(crate) fn review_blob_artifact_slides_pinned(
        &self,
        artifact: &EntityId,
        snapshot: SlideReviewSnapshot,
        request: &SlideReviewRequest<'_>,
    ) -> std::result::Result<SlideReviewRun, SlideReviewError> {
        let SlideReviewSnapshot {
            version,
            bytes,
            read_rows,
            live,
        } = snapshot;
        let run = self.review_blob_artifact_slides_at(
            artifact,
            version,
            &bytes,
            live.as_ref().map(|(pin, deck)| (pin, deck.as_slice())),
            request,
        )?;
        Ok(SlideReviewRun { read_rows, ..run })
    }

    /// [`Self::review_blob_artifact_slides`] over one version's `bytes`; or,
    /// with `shown`, over a live deck's projection at its head and the pin
    /// read before it, where the units' texts are read (FIX 11981, 12019),
    /// the comments still landing on `bytes`.
    pub(crate) fn review_blob_artifact_slides_at(
        &self,
        artifact: &EntityId,
        version: u64,
        bytes: &[u8],
        shown: Option<(&crate::office_body::LivePin, &[u8])>,
        request: &SlideReviewRequest<'_>,
    ) -> std::result::Result<SlideReviewRun, SlideReviewError> {
        // The policy read ends before any provider call starts.
        let (vault_limits, route) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            let vault_limits = policy
                .slide_review_limits(request.principal)
                .ok_or_else(|| invalid("slide review policy manifest is invalid"))?;
            let route = policy
                .slide_review_route(request.principal)
                .ok_or_else(|| invalid("slide review route manifest is invalid"))?;
            (vault_limits, route)
        };
        let owner_dial = DecisionDial {
            first: route.first,
            ceiling: route.ceiling,
            band: request.dial.band,
        };
        let effective = SlideReviewRequest {
            limits: vault_limits.restrict(request.limits),
            dial: owner_dial.narrow(request.dial)?,
            ..*request
        };
        let base = SlideReviewBase {
            bytes,
            version: Some(version),
            artifact: *artifact,
            package_limits: self.docedit_package_limits()?,
            shown: shown.map(|(_, deck)| deck),
        };
        // The deck's live body as the review starts (FIX 2115), or the one
        // the units were read on.
        let judged_live = match shown {
            Some((pin, _)) => Some(pin.clone()),
            None => self.office_body_pin(artifact)?,
        };
        let mut run = review_slides(&base, &effective)?;
        if let Some(proposal) = &mut run.proposal {
            for row in &mut proposal.manifest.slide_judgments {
                row.judged_live.clone_from(&judged_live);
            }
            self.measure_pptx_comment_patches(proposal);
        }
        // The units the ladder left unanswered or refused name the live body
        // they were read on, when they were read on one (FIX 12051).
        let read_live = shown.map(|(pin, _)| pin.clone());
        for unit in &mut run.abstained {
            unit.judged_live.clone_from(&read_live);
        }
        for unit in &mut run.refused {
            unit.judged_live.clone_from(&read_live);
        }
        Ok(run)
    }
}
