//! Generated images and the form each consumer reads (OF-328, OF-329).
//!
//! A generated image lands as one ASSET, its metadata, holding its bytes as a
//! blob by reference (FIX 9949, `blob`), with its ASSET_TEXT written in the
//! same commit, so every form is ready before anyone reads it.
//! The resolver then serves each image lazily, down a ladder, per read: the
//! full image to a reader that takes images in, when it fits the read's room;
//! else a thumbnail beside the ASSET_TEXT and the image's view handle; else
//! the text and the handle; and when nothing fits, the handle alone, and the
//! vault asks whether everything is okay (OF-520). A host's fast per-image
//! pick, through the host's own decision ladder, may step an image that would
//! fit down from full; an unsure pick sends it. The handle fetches the full
//! pixels later (view, crop, zoom, or `ask_image` through a small vision
//! model), and every rung served and every pull is a served-form receipt. It
//! only serves forms of what the reader's scope already admits; a read no
//! form fits fails closed.

use std::time::{Duration, Instant};

use base64::Engine as _;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::support::encode_rmpv;
use super::*;

use super::read_lane::ReadTargetSlot;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::limit_ask::EngineLimit;
use crate::llm::decision::catalogue::IMAGE_FULL;
use crate::llm::decision::{
    AnswerContract, AudioRef, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    EvidenceVersion, ImageRef, ResolvedMedia, Reversibility, cut_text, fit_state,
};
use crate::llm::image::{ImageBytes, ImageCatalog, ImageIntent, ImageResponse};
use crate::llm::media::{AiMediaDoor, AiOperation, MediaPart, MediaRequest};
use crate::llm::{BudgetLease, CallPurpose, LlmCapability, ModelId};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::receipt::{PixelPull, ServedForm};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::retrieval_depth::RetrievalDeadline;
use crate::temporal::TimeRange;

mod blob;
mod generation;
mod hydrated;
mod reads;
mod serving;
mod types;
pub(crate) use blob::{asset_media_in, release_asset_blob_in_txn};
pub(super) use generation::asset_body;
#[cfg(test)]
pub(crate) use generation::generated_asset_body;
pub(super) use hydrated::serve_hydrated_views;
pub(crate) use reads::{asset_audio_in_lane, asset_forms_in_lane, asset_image_in_lane};
pub use reads::{hydrated_asset, pull_image, resolve_audio_ref, resolve_image_ref};
pub use types::{
    AssetConsumer, HydratedAsset, ImageViewRequest, LandedImage, PixelRegion, PulledImage,
    ResolvedAsset, ServedAssetForm,
};

/// The ASSET body field that holds the bytes' media type.
const BODY_MEDIA_TYPE: &str = "mime_type";
/// The ASSET body field that holds the bytes' BLAKE3 content hash.
const BODY_BLAKE3: &str = "blake3";
/// The longer edge, in pixels, of the thumbnail an image is served as when
/// its full bytes do not fit.
const THUMBNAIL_EDGE: u32 = 384;
/// The JPEG quality a thumbnail is encoded at.
const THUMBNAIL_QUALITY: u8 = 70;
/// The hex digits of an image's content hash its view handle carries.
const HANDLE_HASH_HEX: usize = 16;
/// The longest edge, in pixels, a zoom scales a region to.
const MAX_ZOOM_EDGE: u32 = 4096;

impl AssetConsumer {
    /// A consumer that declared no capability: it is served text.
    #[must_use]
    pub fn text_only(purpose: CallPurpose) -> Self {
        Self {
            capabilities: Vec::new(),
            purpose,
        }
    }

    /// The reader a hydrate door serves: it reads for an answer, and reads
    /// images only when its request says its model takes them in.
    #[must_use]
    pub fn hydrate_reader(image_input: bool) -> Self {
        Self {
            capabilities: if image_input {
                vec![LlmCapability::ImageInput]
            } else {
                Vec::new()
            },
            purpose: CallPurpose::AnswerGen,
        }
    }

    fn reads_images(&self) -> bool {
        self.capabilities.contains(&LlmCapability::ImageInput)
    }
}

/// The host's fast per-image pick (OF-329): its ladder, the principal the
/// read is for, the dial and learned bands, its wording of "does this task
/// need this image in full?", the task the images serve, and each pick's
/// anytime budget. A provider reads the task and the image's description as
/// the call's bounded state. Only an in-band "no" steps an image down from
/// full; an abstain, an answer outside the band or a failed ladder sends it.
pub struct ImagePick<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub task: String,
    pub budget: Duration,
}

impl ImagePick<'_> {
    /// Whether `asset`, described by `text`, goes in full for `purpose`.
    fn wants_full(
        &self,
        asset: EntityId,
        purpose: &CallPurpose,
        text: Option<&(EntityId, String)>,
    ) -> bool {
        let purpose = serde_json::to_string(purpose).unwrap_or_default();
        let Ok(question) = IMAGE_FULL.question(
            &[purpose.as_bytes()],
            self.wording.clone(),
            AnswerContract::Noul,
        ) else {
            return true;
        };
        let description = text.map_or("", |(_, text)| text.as_str());
        let state = fit_state(self.task.len().max(description.len()), |cut| {
            json!({
                "question": question.id.to_hex(),
                "asset_ref": asset.to_hex(),
                "task": cut_text(&self.task, cut),
                "description": cut_text(description, cut),
                "cut_at_bytes": cut,
            })
        });
        let evidence: Vec<EntityId> = std::iter::once(asset)
            .chain(text.map(|(id, _)| *id))
            .collect();
        self.ladder
            .run(
                &question,
                self.principal,
                &evidence,
                &state,
                self.dial,
                &self.bands,
                Reversibility::ReversibleRead,
                &RetrievalDeadline::hard(Instant::now(), self.budget),
            )
            .map_or(true, |decision| {
                !(decision.in_band && matches!(decision.answer, DecisionAnswer::Noul(false)))
            })
    }
}

/// An image's view handle, served with it at every rung: its ASSET and the
/// leading hex of its content hash, as `<asset>@<hash>`. A handle is a
/// locator, not a grant: a fetch through it reads the asset through the
/// fetcher's own lane, and refuses an asset whose bytes are no longer the
/// ones it names. A bare 32-hex asset ref reads as a handle naming any bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHandle {
    pub asset: EntityId,
    content: String,
}

impl ImageHandle {
    fn of(asset: EntityId, image: &ImageBytes) -> Self {
        let mut content = blake3::hash(&image.bytes).to_hex().to_string();
        content.truncate(HANDLE_HASH_HEX);
        Self { asset, content }
    }

    /// The handle `handle` spells.
    pub fn parse(handle: &str) -> MemoryResult<Self> {
        let (asset, content) = handle.split_once('@').unwrap_or((handle, ""));
        let asset = EntityId::from_hex(asset.trim())
            .map_err(|_| MemoryError::bad_request("an image handle is <asset>@<hash>"))?;
        let content = content.trim().to_ascii_lowercase();
        if content.len() > 64 || !content.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(MemoryError::bad_request(
                "an image handle is <asset>@<hash>",
            ));
        }
        Ok(Self { asset, content })
    }

    fn names(&self, image: &ImageBytes) -> bool {
        blake3::hash(&image.bytes)
            .to_hex()
            .starts_with(self.content.as_str())
    }
}

impl std::fmt::Display for ImageHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.asset.to_hex(), self.content)
    }
}

/// The audio bytes and type an ASSET's blob holds, as
/// [`blob::resolve_asset_blob_in_lane`] read and checked them.
fn audio_of((media_type, bytes): &(String, Vec<u8>)) -> Option<(Vec<u8>, String)> {
    (!bytes.is_empty() && media_type.starts_with("audio/"))
        .then(|| (bytes.clone(), media_type.clone()))
}

fn no_form(asset_ref: &str) -> MemoryError {
    MemoryError::not_found(format!(
        "asset {asset_ref:?} has no form this consumer reads"
    ))
}

/// The image and thumbnail rungs' body.
#[derive(Serialize)]
struct ImageFormBody<'a> {
    form: ServedAssetForm,
    mime_type: &'a str,
    /// Standard base64.
    bytes: String,
    /// The thumbnail's size in pixels; absent for the full image.
    #[serde(skip_serializing_if = "Option::is_none")]
    width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_text_ref: Option<String>,
    /// The admitted caption beside the pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    handle: &'a str,
}

/// The text rung's body.
#[derive(Serialize)]
struct TextFormBody<'a> {
    form: ServedAssetForm,
    asset_text_ref: String,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
}

/// `body` as a named MessagePack map.
fn form_body(body: &impl Serialize) -> MemoryResult<Vec<u8>> {
    rmp_serde::to_vec_named(body)
        .map_err(|_| MemoryError::bad_request("body is not MessagePack-encodable"))
}

/// Standard base64.
fn base64_of(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The forms one admitted ASSET holds.
pub(crate) struct AssetForms {
    asset: EntityId,
    image: Option<ImageBytes>,
    audio: Option<(Vec<u8>, String)>,
    /// The newest admitted ASSET_TEXT derived from the asset.
    text: Option<(EntityId, String)>,
    /// The stored size of a text refused before it decoded.
    omitted: Option<usize>,
}

/// A thumbnail of an image.
struct Thumbnail {
    image: ImageBytes,
    width: u32,
    height: u32,
}

/// The rung one image is served at, with the body a door projects for it.
enum Rung {
    Full(Vec<u8>),
    Thumbnail(Thumbnail, Vec<u8>),
    Description(Vec<u8>, EntityId),
    /// Nothing fit: the smallest form needed this many bytes.
    Ask(u64),
}

/// One image down its ladder: its rung, and what the host's pick answered
/// when it ran.
struct Climb {
    rung: Rung,
    pick: Option<bool>,
}

impl AssetForms {
    /// `image`, this asset's, down its ladder for `consumer` within
    /// `admits`. `None` is an image with no form for this consumer and none
    /// refused for room: no pixels it reads and no text.
    fn climb(
        &self,
        image: &ImageBytes,
        consumer: &AssetConsumer,
        pick: Option<&ImagePick<'_>>,
        admits: &mut dyn FnMut(usize) -> bool,
    ) -> MemoryResult<Option<Climb>> {
        let handle = ImageHandle::of(self.asset, image).to_string();
        let caption = self.text.as_ref().map(|(id, _)| id.to_hex());
        let mut picked = None;
        let mut needed = self.omitted;
        let mut refused = |len: usize| {
            needed = Some(needed.map_or(len, |needed| needed.min(len)));
        };
        if consumer.reads_images() {
            let full = match pick {
                Some(pick) => {
                    let full = pick.wants_full(self.asset, &consumer.purpose, self.text.as_ref());
                    picked = Some(full);
                    full
                }
                None => true,
            };
            if full {
                let body = form_body(&ImageFormBody {
                    form: ServedAssetForm::Image,
                    mime_type: &image.media_type,
                    bytes: base64_of(&image.bytes),
                    width: None,
                    height: None,
                    asset_text_ref: caption.clone(),
                    text: self.text.as_ref().map(|(_, text)| text.as_str()),
                    handle: &handle,
                })?;
                if admits(body.len()) {
                    return Ok(Some(Climb {
                        rung: Rung::Full(body),
                        pick: picked,
                    }));
                }
                refused(body.len());
            }
            if let Some(thumbnail) = thumbnail_of(image) {
                let body = form_body(&ImageFormBody {
                    form: ServedAssetForm::Thumbnail,
                    mime_type: &thumbnail.image.media_type,
                    bytes: base64_of(&thumbnail.image.bytes),
                    width: Some(thumbnail.width),
                    height: Some(thumbnail.height),
                    asset_text_ref: caption.clone(),
                    text: self.text.as_ref().map(|(_, text)| text.as_str()),
                    handle: &handle,
                })?;
                if admits(body.len()) {
                    return Ok(Some(Climb {
                        rung: Rung::Thumbnail(thumbnail, body),
                        pick: picked,
                    }));
                }
                refused(body.len());
            }
        }
        // The text's stored body was charged before it decoded.
        if let Some((asset_text, text)) = &self.text {
            let body = form_body(&TextFormBody {
                form: ServedAssetForm::AssetText,
                asset_text_ref: asset_text.to_hex(),
                text,
                handle: Some(&handle),
            })?;
            return Ok(Some(Climb {
                rung: Rung::Description(body, *asset_text),
                pick: picked,
            }));
        }
        Ok(needed.map(|needed| Climb {
            rung: Rung::Ask(u64::try_from(needed).unwrap_or(u64::MAX)),
            pick: picked,
        }))
    }

    /// The served-form record `climb` makes.
    fn served_form(&self, climb: &Climb) -> ServedForm {
        let text = self.text.as_ref().map(|(id, _)| *id);
        let form = match &climb.rung {
            Rung::Full(_) => ServedForm::image(self.asset),
            Rung::Thumbnail(..) => ServedForm::thumbnail(self.asset, text),
            Rung::Description(_, asset_text) => ServedForm::text(self.asset, *asset_text),
            Rung::Ask(_) => ServedForm::ask(self.asset),
        };
        match climb.pick {
            Some(full) => form.picked(full),
            None => form,
        }
    }

    /// What [`hydrated_asset`] serves of an asset that holds an image: the
    /// rung its ladder reaches within `admits`, the ask raised on `lane`'s
    /// vault when nothing fit, and with no form the stored body.
    fn hydrated(
        self,
        lane: &ScopedRead<'_>,
        consumer: &AssetConsumer,
        pick: Option<&ImagePick<'_>>,
        admits: &mut dyn FnMut(usize) -> bool,
    ) -> MemoryResult<HydratedAsset> {
        let Some(image) = &self.image else {
            return Ok(HydratedAsset::Stored);
        };
        let Some(climb) = self.climb(image, consumer, pick, admits)? else {
            return Ok(HydratedAsset::Stored);
        };
        let form = self.served_form(&climb);
        let text = self.text.as_ref().map(|(id, _)| *id);
        Ok(match climb.rung {
            Rung::Full(body) | Rung::Thumbnail(_, body) | Rung::Description(body, _) => {
                HydratedAsset::Served { body, text, form }
            }
            Rung::Ask(needed) => {
                let watch = lane.vault().limit_watch();
                watch.crossed(
                    EngineLimit::ImageRoomBytes,
                    watch.bound(EngineLimit::ImageRoomBytes),
                    needed,
                );
                HydratedAsset::Omitted { form }
            }
        })
    }

    /// The asset as `consumer` is served it within `admits`, its served-form
    /// record, and, for the ask rung, the bytes its smallest form needed.
    /// `None` fails closed. An ASSET that holds no image is served its text.
    fn resolved(
        self,
        consumer: &AssetConsumer,
        pick: Option<&ImagePick<'_>>,
        admits: &mut dyn FnMut(usize) -> bool,
    ) -> MemoryResult<Option<(ResolvedAsset, ServedForm, Option<u64>)>> {
        let asset_ref = self.asset.to_hex();
        if consumer.capabilities.contains(&LlmCapability::AudioInput)
            && let Some((bytes, mime)) = &self.audio
            && admits(bytes.len())
        {
            return Ok(Some((
                ResolvedAsset {
                    asset_ref,
                    form: ServedAssetForm::Audio,
                    image: None,
                    audio: Some((mime.clone(), bytes.clone())),
                    text: None,
                    asset_text_ref: None,
                    handle: Some(format!(
                        "{}@{}",
                        self.asset.to_hex(),
                        &blake3::hash(bytes).to_hex()[..HANDLE_HASH_HEX]
                    )),
                },
                ServedForm::audio(self.asset),
                None,
            )));
        }
        let Some(image) = self.image.clone() else {
            return Ok(self.text.map(|(asset_text, text)| {
                (
                    ResolvedAsset {
                        asset_ref,
                        form: ServedAssetForm::AssetText,
                        image: None,
                        audio: None,
                        text: Some(text),
                        asset_text_ref: Some(asset_text.to_hex()),
                        handle: self.audio.as_ref().map(|(bytes, _)| {
                            format!(
                                "{}@{}",
                                self.asset.to_hex(),
                                &blake3::hash(bytes).to_hex()[..HANDLE_HASH_HEX],
                            )
                        }),
                    },
                    ServedForm::text(self.asset, asset_text),
                    None,
                )
            }));
        };
        let Some(climb) = self.climb(&image, consumer, pick, admits)? else {
            return Ok(None);
        };
        let served = self.served_form(&climb);
        let handle = Some(ImageHandle::of(self.asset, &image).to_string());
        let (form, pixels, needed) = match climb.rung {
            Rung::Full(_) => (ServedAssetForm::Image, Some(image), None),
            Rung::Thumbnail(thumbnail, _) => {
                (ServedAssetForm::Thumbnail, Some(thumbnail.image), None)
            }
            Rung::Description(..) => (ServedAssetForm::AssetText, None, None),
            Rung::Ask(needed) => (ServedAssetForm::Ask, None, Some(needed)),
        };
        let (text, asset_text_ref) = match self.text {
            Some((asset_text, text)) if form != ServedAssetForm::Ask => {
                (Some(text), Some(asset_text.to_hex()))
            }
            _ => (None, None),
        };
        Ok(Some((
            ResolvedAsset {
                asset_ref,
                form,
                image: pixels,
                audio: None,
                text,
                asset_text_ref,
                handle,
            },
            served,
            needed,
        )))
    }
}

/// A thumbnail of `image`, its longer edge at most [`THUMBNAIL_EDGE`]
/// pixels, as JPEG. `None` is bytes the engine's codecs do not decode.
fn thumbnail_of(image: &ImageBytes) -> Option<Thumbnail> {
    let decoded = image::load_from_memory(&image.bytes).ok()?;
    let small = if decoded.width().max(decoded.height()) > THUMBNAIL_EDGE {
        decoded.thumbnail(THUMBNAIL_EDGE, THUMBNAIL_EDGE)
    } else {
        decoded
    };
    let small = image::DynamicImage::ImageRgb8(small.to_rgb8());
    let mut bytes = Vec::new();
    small
        .write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
            &mut bytes,
            THUMBNAIL_QUALITY,
        ))
        .ok()?;
    Some(Thumbnail {
        image: ImageBytes {
            bytes,
            media_type: "image/jpeg".to_owned(),
        },
        width: small.width(),
        height: small.height(),
    })
}

/// The pixels a pull fetches of `image`: the bytes themselves for the whole
/// image, else `region` cropped and, with `edge`, scaled so its longer side
/// is `edge` pixels, as PNG. With the pixels' size when it reads.
fn region_pixels(
    image: &ImageBytes,
    region: Option<PixelRegion>,
    edge: Option<u32>,
) -> MemoryResult<(ImageBytes, Option<u32>, Option<u32>)> {
    if region.is_none() && edge.is_none() {
        let size = image::ImageReader::new(std::io::Cursor::new(&image.bytes))
            .with_guessed_format()
            .ok()
            .and_then(|reader| reader.into_dimensions().ok());
        return Ok((
            image.clone(),
            size.map(|(width, _)| width),
            size.map(|(_, height)| height),
        ));
    }
    let decoded = image::load_from_memory(&image.bytes)
        .map_err(|_| MemoryError::bad_request("this image's bytes do not decode for a crop"))?;
    let mut view = match region {
        Some(region) => {
            if region.width == 0
                || region.height == 0
                || region.x >= decoded.width()
                || region.y >= decoded.height()
            {
                return Err(MemoryError::bad_request(
                    "the region lies outside the image",
                ));
            }
            decoded.crop_imm(
                region.x,
                region.y,
                region.width.min(decoded.width() - region.x),
                region.height.min(decoded.height() - region.y),
            )
        }
        None => decoded,
    };
    if let Some(edge) = edge {
        if edge == 0 || edge > MAX_ZOOM_EDGE {
            return Err(MemoryError::bad_request(format!(
                "a zoom's edge is 1 to {MAX_ZOOM_EDGE} pixels"
            )));
        }
        view = view.resize(edge, edge, image::imageops::FilterType::Triangle);
    }
    let mut bytes = Vec::new();
    view.write_to(
        &mut std::io::Cursor::new(&mut bytes),
        image::ImageFormat::Png,
    )
    .map_err(|_| MemoryError::bad_request("the region does not encode as PNG"))?;
    Ok((
        ImageBytes {
            bytes,
            media_type: "image/png".to_owned(),
        },
        Some(view.width()),
        Some(view.height()),
    ))
}

/// The image an ASSET's blob holds, as [`blob::resolve_asset_blob_in_lane`]
/// read and checked it against the hash the ASSET names. `None` is an ASSET
/// that holds no image: a document, or bytes of no image type.
fn image_of((media_type, bytes): &(String, Vec<u8>)) -> Option<ImageBytes> {
    (!bytes.is_empty() && media_type.starts_with("image/")).then(|| ImageBytes {
        bytes: bytes.clone(),
        media_type: media_type.clone(),
    })
}

/// An ASSET_TEXT's text as a memory read releases it: a map body's `text`
/// field, else the UTF-8 body, each through the read's credential filter.
fn text_of(body: &[u8]) -> Option<String> {
    let released = match decode_whole(body) {
        Some(value @ Value::Map(_)) => {
            crate::batch::export::served_stored_messagepack_json(body, value)
                .get("text")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        }
        _ => None,
    };
    let text = match released {
        Some(text) => text,
        None => {
            let plain = String::from_utf8(body.to_vec()).ok()?;
            crate::batch::export::served_messagepack_json(Value::from(plain))
                .as_str()?
                .to_owned()
        }
    };
    (!text.trim().is_empty()).then_some(text)
}

/// The MessagePack value `body` holds, when it holds exactly one.
fn decode_whole(body: &[u8]) -> Option<Value> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    cursor.is_empty().then_some(value)
}
