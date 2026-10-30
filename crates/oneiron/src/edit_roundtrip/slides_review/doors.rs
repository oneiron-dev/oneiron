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
        let run = self.review_blob_artifact_slides_at(
            artifact,
            head.version,
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
        Ok(run)
    }
}
