//! Generated images and the form each consumer reads (OF-328, OF-329).
//!
//! A generated image lands as one ASSET holding its bytes, with its ASSET_TEXT
//! written in the same commit, so every form is ready before anyone reads it.
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

use super::support::{decode_body_json, encode_rmpv};
use super::*;

use super::read_lane::ReadTargetSlot;
use super::structural::kind_string_for_type;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::limit_ask::EngineLimit;
use crate::llm::decision::catalogue::QuestionFamily;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionClass, DecisionDial,
    DecisionLadder, Reversibility, cut_text, fit_state,
};
use crate::llm::image::{ImageBytes, ImageCatalog, ImageIntent, ImageResponse};
use crate::llm::media::{AiMediaDoor, AiOperation, MediaPart, MediaRequest};
use crate::llm::{BudgetLease, CallPurpose, LlmCapability, ModelId};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::receipt::{PixelPull, ServedForm};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::retrieval_depth::RetrievalDeadline;
use crate::temporal::TimeRange;
use crate::vault::ReadMode;

/// The ASSET body field that holds the bytes.
const BODY_BYTES: &str = "bytes";
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

/// The family of the host's per-image pick (OF-329): does the task this
/// read serves need this image in full? Keyed by the read's purpose; the
/// wording is the host's.
pub const IMAGE_FULL: QuestionFamily = QuestionFamily {
    name: "memory.image_full",
    version: 1,
    class: DecisionClass::Triage,
};

/// The rung of the lazy-image ladder an asset read serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServedAssetForm {
    /// The image bytes, with the newest ASSET_TEXT beside them as a caption.
    Image,
    /// A thumbnail of the image, beside its newest ASSET_TEXT and its view
    /// handle.
    Thumbnail,
    /// The newest ASSET_TEXT and the image's view handle; no bytes.
    AssetText,
    /// Nothing fit: the view handle alone.
    Ask,
}

/// Who reads an asset: what the consumer's model takes in, and the call
/// purpose the read serves, which the host's per-image pick reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetConsumer {
    /// The consumer's input capabilities; image bytes need `image_input`.
    #[serde(default)]
    pub capabilities: Vec<LlmCapability>,
    /// The purpose the read serves.
    pub purpose: CallPurpose,
}

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

/// One asset as served to one consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsset {
    /// 32-hex ASSET id.
    pub asset_ref: String,
    /// The rung served.
    pub form: ServedAssetForm,
    /// The pixels served: the full image's bytes, or its thumbnail's.
    pub image: Option<ImageBytes>,
    /// The ASSET_TEXT served: the whole text form, or the image's caption.
    pub text: Option<String>,
    /// 32-hex id of the ASSET_TEXT in `text`.
    pub asset_text_ref: Option<String>,
    /// The image's view handle; `None` for an ASSET that holds no image.
    pub handle: Option<String>,
}

/// A region of an image, in its own pixels from its top-left corner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PixelRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// `vault.images.view`'s request: the handle an image was served with, and
/// what of its full pixels to fetch. No region and no edge is the whole
/// image (a view); a region is a crop at the image's own resolution; an edge
/// scales the region, or the whole image, so its longer side is that many
/// pixels (a zoom).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageViewRequest {
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<PixelRegion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<u32>,
}

/// Pixels fetched through an image's handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PulledImage {
    /// 32-hex ASSET id.
    pub asset_ref: String,
    /// `view`, `crop`, `zoom` or `ask_image`, as its receipt records it.
    pub pull: String,
    pub mime_type: String,
    /// Standard base64.
    pub bytes: String,
    /// The pixels' size, when their encoding says it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// The raw pixels, for an in-process caller that sends them on.
    #[serde(skip)]
    #[schemars(skip)]
    pub image: Option<ImageBytes>,
}

/// The rows one generated image landed as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandedImage {
    /// 32-hex ASSET id; the ref every consumer resolves.
    pub asset_ref: String,
    /// 32-hex id of its precomputed ASSET_TEXT.
    pub asset_text_ref: String,
}

impl Memory<'_> {
    /// Generates `intent` through `catalog` and lands the image the adapter
    /// returns ([`Self::land_generated_image`]). A generation draws what its
    /// instruction describes, so the instruction is the precomputed text.
    pub async fn generate_image_asset(
        &self,
        catalog: &ImageCatalog,
        intent: ImageIntent,
        lease: &BudgetLease,
        occurred_at: u64,
    ) -> MemoryResult<LandedImage> {
        let description = intent.instruction.clone();
        let response = catalog.render(intent, None, lease).await.map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!("image generation failed: {error}"),
                &[],
            )
        })?;
        self.land_generated_image(&response, &description, occurred_at)
    }

    /// Generates one image through the host's `ai.image` door, admitted,
    /// sent and settled under its run, and lands it
    /// ([`Self::land_generated_image`]). Each of `reference_assets` is read
    /// as an image through the bound actor's lane and sent, in order, as a
    /// reference: the call is then an edit, and an edit's instruction does
    /// not describe its result, so its caller's `description` is required.
    /// A generation without one is described by its instruction.
    pub async fn render_image_asset(
        &self,
        door: &dyn AiMediaDoor,
        mut request: MediaRequest,
        reference_assets: &[String],
        description: Option<&str>,
        occurred_at: u64,
    ) -> MemoryResult<LandedImage> {
        if request.operation != AiOperation::Image {
            return Err(MemoryError::bad_request(
                "an image asset renders an image call",
            ));
        }
        let reader = AssetConsumer {
            capabilities: vec![LlmCapability::ImageInput],
            purpose: request.envelope.purpose.clone(),
        };
        for asset_ref in reference_assets {
            let image = self
                .resolve_asset(asset_ref, &reader, None)?
                .value
                .image
                .ok_or_else(|| no_form(asset_ref))?;
            request.references.push(MediaPart::Image {
                media_type: image.media_type,
                bytes: image.bytes,
            });
        }
        let description = match description {
            Some(description) => description.to_owned(),
            None if request.references.is_empty() => request.text(),
            None => {
                return Err(MemoryError::bad_request(
                    "an image edit lands with its caller's description of the result",
                ));
            }
        };
        let response = door.call(request).await.map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!("image generation failed: {error}"),
                &[],
            )
        })?;
        let image = response.image().ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "image generation returned no image".to_owned(),
                &[],
            )
        })?;
        let response = ImageResponse {
            image,
            model: response.model,
            metadata: std::collections::BTreeMap::new(),
        };
        self.land_generated_image(&response, &description, occurred_at)
    }

    /// Lands one generated image as the bound actor: the bytes as an ASSET,
    /// and `description` as its ASSET_TEXT, derived from it and born under
    /// the image's facet, in one write. A text-only consumer is served that
    /// text, so an image with no description is refused rather than landed
    /// without one. An edit's instruction does not describe its result; its
    /// caller describes it.
    pub fn land_generated_image(
        &self,
        response: &ImageResponse,
        description: &str,
        occurred_at: u64,
    ) -> MemoryResult<LandedImage> {
        let description = description.trim();
        if description.is_empty()
            || response.image.bytes.is_empty()
            || !response.image.media_type.starts_with("image/")
        {
            return Err(MemoryError::bad_request(
                "a generated image lands with image bytes and a description",
            ));
        }
        let body = generated_asset_body(&response.image, &response.model)?;
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        let weight = EdgeKind::DerivedFrom.default_weight().unwrap_or(1.0);
        self.vault.ensure_text_index_trusted()?;
        self.with_actor_content_write_txn(|content| {
            let asset = self.vault.store.clock.entity_id()?;
            let text = self.vault.store.clock.entity_id()?;
            content.apply_batch(
                self.vault
                    .batch_in()
                    .put(&asset, ENTITY_TYPE_ASSET, occurred, occurred_at, &body)
                    .asset_text_birth(
                        &text,
                        occurred,
                        occurred_at,
                        description.as_bytes(),
                        &[(asset, weight)],
                    )
                    .text(&text, &[("text", description)]),
            )?;
            Ok(LandedImage {
                asset_ref: asset.to_hex(),
                asset_text_ref: text.to_hex(),
            })
        })
    }

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
        lane.commit_served_forms(&forms)?;
        Ok(ScopedReadResult {
            value: served,
            receipt,
        })
    }

    /// `vault.images.view`: the full pixels behind an image's handle (the
    /// whole image, a crop or a zoom), read through the bound actor's lane
    /// and recorded as a pull before they return.
    pub fn view_image(&self, request: &ImageViewRequest) -> MemoryResult<PulledImage> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(pull_image(&lane, request, false)?.value)
    }

    /// Hydrate's half of OF-329: each live image ASSET among `views` with a
    /// text this reader admits is served as [`hydrated_asset`] serves a
    /// reader that declared no image input. Every other view keeps its body.
    /// The rungs served are recorded, in one write, before the hydrate
    /// answers.
    pub(super) fn serve_hydrated_assets(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
        views: &mut [EntityView],
        receipt: &mut ScopedReadReceipt,
    ) -> MemoryResult<()> {
        let asset_kind = kind_string_for_type(ENTITY_TYPE_ASSET);
        let consumer = AssetConsumer::hydrate_reader(false);
        let mut served_forms = Vec::new();
        for (target, view) in targets.iter().zip(views) {
            let Some((asset, ReadMode::Live)) = target else {
                continue;
            };
            if view.kind != asset_kind {
                continue;
            }
            let served = hydrated_asset(lane, *asset, &consumer, None, &mut |_| true)?;
            receipt.restrict_with(&served.receipt);
            if let HydratedAsset::Served { body, form, .. } = served.value {
                view.body = decode_body_json(&body);
                served_forms.push(form);
            }
        }
        lane.commit_served_forms(&served_forms)?;
        Ok(())
    }
}

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

fn no_form(asset_ref: &str) -> MemoryError {
    MemoryError::not_found(format!(
        "asset {asset_ref:?} has no form this consumer reads"
    ))
}

/// What a hydrate serves, for one ASSET its lane admitted live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydratedAsset {
    /// The door's stored body: an ASSET that holds no image, an image with no
    /// form this reader is served (its body still names the image, bytes
    /// nulled), or an asset gone since the door read it.
    Stored,
    /// A generated image, served at one rung of its ladder: its bytes, its
    /// thumbnail beside its text, or its text, each with its view handle.
    Served {
        /// The rung's body as MessagePack, any pixels as standard base64 so
        /// a JSON door carries them where it nulls a binary: the body the
        /// door projects in place of the stored one.
        body: Vec<u8>,
        /// The ASSET_TEXT the body names, a row the reader did not name.
        text: Option<EntityId>,
        /// The served-form record the door commits before it answers.
        form: ServedForm,
    },
    /// Nothing fit what the door may still decode: the door omits the
    /// ASSET's body, its ref (the image's handle) reads it whole, and the
    /// vault was asked whether everything is okay.
    Omitted {
        /// The served-form record the door commits before it answers.
        form: ServedForm,
    },
}

impl HydratedAsset {
    /// The served-form record this serving makes; `None` for a stored body.
    #[must_use]
    pub fn served_form(&self) -> Option<ServedForm> {
        match self {
            Self::Stored => None,
            Self::Served { form, .. } | Self::Omitted { form } => Some(*form),
        }
    }
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
    /// The description beside a thumbnail; the full image names its
    /// caption by ref alone.
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
                    text: None,
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
        let Some(image) = self.image.clone() else {
            return Ok(self.text.map(|(asset_text, text)| {
                (
                    ResolvedAsset {
                        asset_ref,
                        form: ServedAssetForm::AssetText,
                        image: None,
                        text: Some(text),
                        asset_text_ref: Some(asset_text.to_hex()),
                        handle: None,
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
                text,
                asset_text_ref,
                handle,
            },
            served,
            needed,
        )))
    }
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

/// The ASSET body for generated bytes: the canon asset fields beside the
/// bytes themselves. A plain memory read serves the fields and nulls the bytes.
pub(crate) fn generated_asset_body(image: &ImageBytes, model: &ModelId) -> MemoryResult<Vec<u8>> {
    let byte_size = u64::try_from(image.bytes.len())
        .map_err(|_| MemoryError::bad_request("generated image is too large"))?;
    encode_rmpv(&Value::Map(vec![
        (Value::from("kind"), Value::from("image")),
        (
            Value::from(BODY_MEDIA_TYPE),
            Value::from(image.media_type.as_str()),
        ),
        (
            Value::from(BODY_BLAKE3),
            Value::from(blake3::hash(&image.bytes).to_hex().as_str()),
        ),
        (Value::from("byte_size"), Value::from(byte_size)),
        (Value::from("model"), Value::from(model.as_str())),
        (Value::from("source"), Value::from("generated")),
        (Value::from(BODY_BYTES), Value::Binary(image.bytes.clone())),
    ]))
}

/// The image an ASSET body holds, checked against its recorded content hash.
/// `None` is an ASSET that holds no image: a document, or bytes of no image type.
fn image_of(body: &[u8]) -> MemoryResult<Option<ImageBytes>> {
    let Some(Value::Map(entries)) = decode_whole(body) else {
        return Ok(None);
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let (Some(Value::Binary(bytes)), Some(media_type)) = (
        field(BODY_BYTES),
        field(BODY_MEDIA_TYPE).and_then(Value::as_str),
    ) else {
        return Ok(None);
    };
    if bytes.is_empty() || !media_type.starts_with("image/") {
        return Ok(None);
    }
    if let Some(recorded) = field(BODY_BLAKE3)
        && recorded.as_str() != Some(blake3::hash(bytes).to_hex().as_str())
    {
        return Err(crate::error::Error::CorruptedIndex("asset content hash").into());
    }
    Ok(Some(ImageBytes {
        bytes: bytes.clone(),
        media_type: media_type.to_owned(),
    }))
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
