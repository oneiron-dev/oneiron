//! Asset reads through a caller's lane.
//! Entry: pull_image.
//! Definitions: this module owns the listed functions; types stay in the parent.

use base64::Engine as _;

use super::{
    AssetConsumer, AssetForms, AudioRef, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, EdgeDirection,
    EdgeKind, EdgeStoreRead, EntityId, EvidenceVersion, HydratedAsset, ImageBytes, ImageHandle,
    ImagePick, ImageRef, ImageViewRequest, MemoryError, MemoryResult, PixelPull, PixelRegion,
    PointRead, PulledImage, ResolvedMedia, ScopedRead, ScopedReadResult, ServedForm, audio_of,
    image_of, no_form, region_pixels, text_of,
};

/// The pixels behind `request`'s handle, read through `lane`: the whole
/// image, a crop or a zoom of it. An `ask` pull fetches them for a small
/// vision model answering about them (`ask_image`) rather than for the
/// reader. The pull is recorded as a served-form receipt naming the lane's
/// holder before the pixels return; a handle whose asset is absent,
/// withheld, holds no image or no longer holds the bytes it names is
/// `NOT_FOUND`.
pub fn pull_image(
    lane: &ScopedRead<'_>,
    request: &ImageViewRequest,
    ask: bool,
) -> MemoryResult<ScopedReadResult<PulledImage>> {
    let handle = ImageHandle::parse(&request.handle)?;
    // No text is decoded: a pull serves pixels alone.
    let ScopedReadResult { value, receipt } =
        asset_forms_in_lane(lane, handle.asset, true, &mut |_| false)?;
    let Some(image) = value
        .and_then(|forms| forms.image)
        .filter(|image| handle.names(image))
    else {
        return Err(no_form(&request.handle).with_read_receipt(receipt));
    };
    let pull = match (ask, request.region, request.edge) {
        (true, ..) => PixelPull::AskImage,
        (false, None, None) => PixelPull::View,
        (false, Some(_), None) => PixelPull::Crop,
        (false, _, Some(_)) => PixelPull::Zoom,
    };
    let (pixels, width, height) = region_pixels(&image, request.region, request.edge)?;
    lane.commit_served_forms(&[ServedForm::pulled(handle.asset, pull)])?;
    Ok(ScopedReadResult {
        value: PulledImage {
            asset_ref: handle.asset.to_hex(),
            pull: pull.as_str().to_owned(),
            mime_type: pixels.media_type.clone(),
            bytes: base64::engine::general_purpose::STANDARD.encode(&pixels.bytes),
            width,
            height,
            image: Some(pixels),
        },
        receipt,
    })
}

/// The image a decision reads by `handle` (owner point 3), through `lane`: the ASSET's
/// own bytes, whole or `frame`d, and the ref that pins them, the asset at the full hash
/// of its bytes, their type and size. The read is recorded as an `ask_image` pull before
/// the pixels return. A handle whose asset is absent, withheld, holds no image or no
/// longer holds the bytes it names is `NOT_FOUND`; no thumbnail or text form stands in.
pub fn resolve_image_ref(
    lane: &ScopedRead<'_>,
    name: &str,
    handle: &str,
    frame: Option<PixelRegion>,
) -> MemoryResult<ScopedReadResult<ResolvedMedia>> {
    let parsed = ImageHandle::parse(handle)?;
    let ScopedReadResult { value, receipt } =
        asset_forms_in_lane(lane, parsed.asset, true, &mut |_| false)?;
    let Some(image) = value
        .and_then(|forms| forms.image)
        .filter(|image| parsed.names(image))
    else {
        return Err(no_form(handle).with_read_receipt(receipt));
    };
    let evidence = EvidenceVersion {
        id: parsed.asset,
        body_hash: *blake3::hash(&image.bytes).as_bytes(),
    };
    let reference = ImageRef::of(evidence, &image, frame).map_err(|_| {
        MemoryError::bad_request("an image a decision reads is PNG or JPEG, its frame inside it")
    })?;
    let (pixels, ..) = region_pixels(&image, frame, None)?;
    lane.commit_served_forms(&[ServedForm::pulled(parsed.asset, PixelPull::AskImage)])?;
    Ok(ScopedReadResult {
        value: ResolvedMedia::Image {
            name: name.to_owned(),
            reference,
            image: pixels,
        },
        receipt,
    })
}

/// The audio a decision reads by `reference` (owner point 3), through `lane`: the
/// ASSET's own audio bytes, refused as `NOT_FOUND` when the asset is absent, withheld,
/// holds no audio or no longer holds the bytes the ref names.
pub fn resolve_audio_ref(
    lane: &ScopedRead<'_>,
    name: &str,
    reference: &AudioRef,
) -> MemoryResult<ScopedReadResult<ResolvedMedia>> {
    let asset = reference.evidence.id;
    let ScopedReadResult { value, receipt } = lane.read(&[PointRead::id(asset)], None)?;
    let bytes = value
        .into_iter()
        .flatten()
        .find(|row| row.entity_type == ENTITY_TYPE_ASSET)
        .and_then(|row| row.body)
        .as_deref()
        .map(audio_of)
        .transpose()?
        .flatten()
        .filter(|(bytes, media_type)| {
            *blake3::hash(bytes).as_bytes() == reference.evidence.body_hash
                && media_type.eq_ignore_ascii_case(&reference.media_type)
        });
    let Some((bytes, _)) = bytes else {
        return Err(no_form(&asset.to_hex()).with_read_receipt(receipt));
    };
    Ok(ScopedReadResult {
        value: ResolvedMedia::Audio {
            name: name.to_owned(),
            reference: reference.clone(),
            bytes,
        },
        receipt,
    })
}

/// Hydrate's half of OF-329, for every door that reads through its own
/// lane: what `asset`, an ASSET `lane` admitted live, serves `consumer`, its
/// ASSET_TEXT read through the same lane, down the image's ladder. Each
/// text's stored body, and then each rung's body, is charged to `admits`
/// before it decodes or serves, so a door that bounds the bodies it decodes
/// bounds these too: an image past the bound steps down to its thumbnail,
/// then its text, and with nothing left that fits is omitted, and the vault
/// asks. The host's `pick` runs before the full image is charged.
pub fn hydrated_asset(
    lane: &ScopedRead<'_>,
    asset: EntityId,
    consumer: &AssetConsumer,
    pick: Option<&ImagePick<'_>>,
    admits: &mut dyn FnMut(usize) -> bool,
) -> MemoryResult<ScopedReadResult<HydratedAsset>> {
    let ScopedReadResult { value, receipt } = asset_forms_in_lane(lane, asset, true, admits)?;
    let value = match value {
        Some(forms) if forms.image.is_some() => forms.hydrated(lane, consumer, pick, admits)?,
        _ => HydratedAsset::Stored,
    };
    Ok(ScopedReadResult { value, receipt })
}

/// The image `asset` holds, read through `lane` with no text decoded and no
/// pull recorded: `None` when the lane withholds the asset, it is no ASSET,
/// or it holds no image. A caller that hands the pixels to a model records
/// the pull itself, as [`pull_image`] does.
pub(crate) fn asset_image_in_lane(
    lane: &ScopedRead<'_>,
    asset: EntityId,
) -> MemoryResult<Option<ImageBytes>> {
    Ok(asset_forms_in_lane(lane, asset, true, &mut |_| false)?
        .value
        .and_then(|forms| forms.image))
}

/// The audio clip `asset` holds, as its media type and encoded bytes, read
/// through `lane` with no text decoded: `None` when the lane withholds the
/// asset, it is no ASSET, or it holds no audio. The bytes are checked against
/// the body's recorded content hash. No transcript stands in for the clip.
pub(crate) fn asset_audio_in_lane(
    lane: &ScopedRead<'_>,
    asset: EntityId,
) -> MemoryResult<Option<(String, Vec<u8>)>> {
    let Some(row) = lane
        .read(&[PointRead::id(asset)], None)?
        .value
        .into_iter()
        .next()
        .flatten()
        .filter(|row| row.entity_type == ENTITY_TYPE_ASSET)
    else {
        return Ok(None);
    };
    let Some(body) = row.body else {
        return Ok(None);
    };
    Ok(audio_of(&body)?.map(|(bytes, mime)| (mime, bytes)))
}

/// Reads the forms of `asset` through `lane`. The lane admits the ASSET and
/// each ASSET_TEXT derived from it; only admitted rows become forms. With
/// `images_only`, an ASSET that holds no image reads no text. Texts decode
/// newest first until one holds text, each stored body charged to `admits`
/// first; one it refuses leaves the forms `omitted`. The texts' receipt joins
/// the read's only when a text is served. `None` is an asset that is absent,
/// withheld, or not an ASSET.
pub(crate) fn asset_forms_in_lane(
    lane: &ScopedRead<'_>,
    asset: EntityId,
    images_only: bool,
    admits: &mut dyn FnMut(usize) -> bool,
) -> MemoryResult<ScopedReadResult<Option<AssetForms>>> {
    let vault = lane.vault();
    let ScopedReadResult {
        value: (row, derived),
        mut receipt,
    } = lane.read_projected(&[PointRead::id(asset)], None, |txn, rows| {
        let row = rows
            .into_iter()
            .next()
            .flatten()
            .filter(|row| row.entity_type == ENTITY_TYPE_ASSET)
            .and_then(|row| row.body);
        let mut derived = Vec::new();
        if row.is_some() {
            for edge in vault.store.port_edges(
                txn,
                &asset,
                EdgeDirection::In,
                Some(EdgeKind::DerivedFrom),
                None,
            )? {
                derived.push(edge?.target);
            }
        }
        Ok::<_, MemoryError>((row, derived))
    })?;
    let Some(body) = row else {
        return Ok(ScopedReadResult {
            value: None,
            receipt,
        });
    };
    let mut forms = AssetForms {
        asset,
        image: image_of(&body)?,
        audio: audio_of(&body)?,
        text: None,
        omitted: None,
    };
    if !(derived.is_empty() || (images_only && forms.image.is_none())) {
        let reads: Vec<_> = derived.iter().map(|id| PointRead::id(*id)).collect();
        let texts = lane.read(&reads, None)?;
        let mut rows: Vec<_> = texts
            .value
            .into_iter()
            .flatten()
            .filter(|row| row.entity_type == ENTITY_TYPE_ASSET_TEXT)
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse((row.learned_at, row.id)));
        for row in rows {
            let Some(stored) = row.body.as_deref() else {
                continue;
            };
            if !admits(stored.len()) {
                forms.omitted = Some(stored.len());
                break;
            }
            if let Some(text) = text_of(stored) {
                forms.text = Some((row.id, text));
                receipt.restrict_with(&texts.receipt);
                break;
            }
        }
    }
    Ok(ScopedReadResult {
        value: Some(forms),
        receipt,
    })
}
