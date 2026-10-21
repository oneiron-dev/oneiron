//! Asset serving through the bound actor's lane.
//! Entry: Memory::resolve_asset.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AssetConsumer, ClaimReadStatus, EngineLimit, EntityView, ImagePick, ImageViewRequest, Memory,
    MemoryError, MemoryResult, PulledImage, ReadTargetSlot, ResolvedAsset, ScopedRead,
    ScopedReadReceipt, ScopedReadResult, asset_forms_in_lane, no_form, pull_image,
    serve_hydrated_views,
};

impl Memory<'_> {
    /// OF-329's resolve verb: the rung of `asset_ref` this consumer is
    /// served, read whole through the bound actor's lane as a single-entity
    /// read is, after the host's `pick` when it gives one. An asset that is
    /// absent, withheld, not an ASSET, or has no form for this consumer is
    /// `NOT_FOUND` under the read's receipt. Every rung served is first
    /// recorded as a served-form receipt naming the lane's holder
    /// ([`ScopedRead::commit_served_forms`]); a failed record fails the read.
    pub fn resolve_asset(
        &self,
        asset_ref: &str,
        consumer: &AssetConsumer,
        pick: Option<&ImagePick<'_>>,
    ) -> MemoryResult<ScopedReadResult<ResolvedAsset>> {
        let ScopedReadResult { mut value, receipt } =
            self.serve_images(&[asset_ref.to_owned()], consumer, pick, Some(u64::MAX))?;
        let value = value.pop().ok_or_else(|| no_form(asset_ref))?;
        Ok(ScopedReadResult { value, receipt })
    }

    /// OF-329's serving for one model call's context: each of `asset_refs`,
    /// in order, down its ladder within `room` bytes of served forms (the
    /// vault's `limits.image_room_bytes` when `None`), each image that reads
    /// in full first asking the host's `pick` whether the task needs it so.
    /// An image no form of which fits the room left is served as its handle
    /// alone, and the vault asks whether everything is okay. The rungs
    /// served are recorded, in one write, before the call answers; the first
    /// ref that is absent, withheld or has no form fails the call
    /// `NOT_FOUND`.
    pub fn serve_images(
        &self,
        asset_refs: &[String],
        consumer: &AssetConsumer,
        pick: Option<&ImagePick<'_>>,
        room: Option<u64>,
    ) -> MemoryResult<ScopedReadResult<Vec<ResolvedAsset>>> {
        self.serve_assets_with_receipts(asset_refs, consumer, pick, room)
            .map(|(served, _)| served)
    }

    /// The same serving, beside the refs its committed served-form records carry.
    pub(in crate::memory) fn serve_assets_with_receipts(
        &self,
        asset_refs: &[String],
        consumer: &AssetConsumer,
        pick: Option<&ImagePick<'_>>,
        room: Option<u64>,
    ) -> MemoryResult<(ScopedReadResult<Vec<ResolvedAsset>>, Vec<String>)> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let watch = self.vault.limit_watch();
        let bound = room.unwrap_or_else(|| watch.bound(EngineLimit::ImageRoomBytes));
        let mut left = bound;
        let mut admits = |len: usize| match left.checked_sub(u64::try_from(len).unwrap_or(u64::MAX))
        {
            Some(rest) => {
                left = rest;
                true
            }
            None => false,
        };
        let mut receipt: Option<ScopedReadReceipt> = None;
        let mut served = Vec::with_capacity(asset_refs.len());
        let mut forms = Vec::with_capacity(asset_refs.len());
        for asset_ref in asset_refs {
            let asset = self.resolve_ref_in_lane(&lane, asset_ref)?;
            let ScopedReadResult {
                value,
                receipt: read,
            } = asset_forms_in_lane(&lane, asset, false, &mut admits)?;
            if let Some(receipt) = &mut receipt {
                receipt.restrict_with(&read);
            } else {
                receipt = Some(read);
            }
            let resolved = match value {
                Some(forms) => forms.resolved(consumer, pick, &mut admits)?,
                None => None,
            };
            let Some((resolved, form, needed)) = resolved else {
                let error = no_form(asset_ref);
                return Err(match receipt {
                    Some(receipt) => error.with_read_receipt(receipt),
                    None => error,
                });
            };
            if let Some(needed) = needed {
                watch.crossed(EngineLimit::ImageRoomBytes, bound, needed);
            }
            forms.push(form);
            served.push(resolved);
        }
        let Some(receipt) = receipt else {
            return Err(MemoryError::bad_request("a serve names at least one asset"));
        };
        let refs = lane.commit_served_forms_listing(&forms)?;
        Ok((
            ScopedReadResult {
                value: served,
                receipt,
            },
            refs,
        ))
    }

    /// `vault.images.view`: the full pixels behind an image's handle (the
    /// whole image, a crop or a zoom), read through the bound actor's lane
    /// and recorded as a pull before they return.
    pub fn view_image(&self, request: &ImageViewRequest) -> MemoryResult<PulledImage> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(pull_image(&lane, request, false)?.value)
    }

    /// Hydrate's half of OF-329: each live image ASSET among `views` with a
    /// text this reader admits is served as [`hydrated_asset`](super::hydrated_asset) serves a
    /// reader that declared no image input ([`serve_hydrated_views`]). Every
    /// other view keeps its body. The rungs served are recorded, in one
    /// write, before the hydrate answers.
    pub(in crate::memory) fn serve_hydrated_assets(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
        views: &mut [EntityView],
        receipt: &mut ScopedReadReceipt,
    ) -> MemoryResult<()> {
        let served_forms = serve_hydrated_views(lane, targets, views, receipt)?;
        lane.commit_served_forms(&served_forms)?;
        Ok(())
    }
}
