//! Generated images and the form each consumer reads (OF-328, OF-329).
//!
//! A generated image lands as one ASSET holding its bytes, with its ASSET_TEXT
//! written in the same commit, so every form is ready before anyone reads it.
//! The resolver then picks, per read, which form a consumer is served: image
//! bytes for a consumer that reads images, the precomputed text for one that
//! does not, and the text under budget pressure. It only picks the form of
//! what the reader's scope already admits; a read no form fits fails closed.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::support::{decode_body_json, encode_rmpv};
use super::*;

use super::read_lane::ReadTargetSlot;
use super::structural::kind_string_for_type;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::llm::image::{ImageBytes, ImageCatalog, ImageIntent, ImageResponse};
use crate::llm::{BudgetLease, BudgetRead, BudgetThreshold, CallPurpose, LlmCapability, ModelId};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::temporal::TimeRange;
use crate::vault::ReadMode;

/// The ASSET body field that holds the bytes.
const BODY_BYTES: &str = "bytes";
/// The ASSET body field that holds the bytes' media type.
const BODY_MEDIA_TYPE: &str = "mime_type";
/// The ASSET body field that holds the bytes' BLAKE3 content hash.
const BODY_BLAKE3: &str = "blake3";

/// The form an asset read serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServedAssetForm {
    /// The image bytes, with the newest ASSET_TEXT beside them as a caption.
    Image,
    /// The newest ASSET_TEXT alone; no bytes.
    AssetText,
}

/// Who reads an asset: what the consumer's model takes in, and the call
/// purpose whose policy row says where budget pressure starts.
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

    fn reads_images(&self) -> bool {
        self.capabilities.contains(&LlmCapability::ImageInput)
    }
}

/// One asset as served to one consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsset {
    /// 32-hex ASSET id.
    pub asset_ref: String,
    /// The form served.
    pub form: ServedAssetForm,
    /// The bytes, for the image form only.
    pub image: Option<ImageBytes>,
    /// The ASSET_TEXT served: the whole text form, or the image's caption.
    pub text: Option<String>,
    /// 32-hex id of the ASSET_TEXT in `text`.
    pub asset_text_ref: Option<String>,
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

    /// OF-329's resolve verb: the form of `asset_ref` this consumer is
    /// served under `budget`, read through the bound actor's lane. An asset
    /// that is absent, withheld, not an ASSET, or has no form for this
    /// consumer is `NOT_FOUND` under the read's receipt.
    pub fn resolve_asset(
        &self,
        asset_ref: &str,
        consumer: &AssetConsumer,
        budget: Option<&BudgetRead>,
    ) -> MemoryResult<ScopedReadResult<ResolvedAsset>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let asset = self.resolve_ref_in_lane(&lane, asset_ref)?;
        let ScopedReadResult { value, receipt } =
            asset_forms_in_lane(&lane, asset, consumer, false, &mut |_| true)?;
        match value.and_then(|forms| forms.serve(consumer, budget)) {
            Some(value) => Ok(ScopedReadResult { value, receipt }),
            None => Err(no_form(asset_ref).with_read_receipt(receipt)),
        }
    }

    /// Hydrate's half of OF-329: each live image ASSET among `views` with a
    /// text this reader admits is served as [`hydrated_asset`] serves it.
    /// Every other view keeps its body.
    pub(super) fn serve_hydrated_assets(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
        views: &mut [EntityView],
        receipt: &mut ScopedReadReceipt,
    ) -> MemoryResult<()> {
        let asset_kind = kind_string_for_type(ENTITY_TYPE_ASSET);
        for (target, view) in targets.iter().zip(views) {
            let Some((asset, ReadMode::Live)) = target else {
                continue;
            };
            if view.kind != asset_kind {
                continue;
            }
            let served = hydrated_asset(lane, *asset, &mut |_| true)?;
            receipt.restrict_with(&served.receipt);
            if let HydratedAsset::Text { body, .. } = served.value {
                view.body = decode_body_json(&body);
            }
        }
        Ok(())
    }
}

fn no_form(asset_ref: &str) -> MemoryError {
    MemoryError::not_found(format!(
        "asset {asset_ref:?} has no form this consumer reads"
    ))
}

/// What a hydrate serves, for one ASSET its lane admitted live, to a reader
/// that declared no image input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydratedAsset {
    /// The door's stored body: an ASSET that holds no image, an image with no
    /// text this reader admits (its body still names the image, bytes
    /// nulled), or an asset gone since the door read it.
    Stored,
    /// A generated image, served as its text form.
    Text {
        /// `{form, asset_text_ref, text}` as MessagePack: the body the door
        /// projects in place of the stored one.
        body: Vec<u8>,
        /// The ASSET_TEXT served, a row the reader did not name.
        asset_text: EntityId,
    },
    /// The text's stored body is past what the door may still decode: the
    /// door omits the ASSET's body, and its ref reads it whole.
    Omitted,
}

/// The text form's body.
#[derive(Serialize)]
struct TextFormBody<'a> {
    form: ServedAssetForm,
    asset_text_ref: String,
    text: &'a str,
}

/// Hydrate's half of OF-329, for every door that reads through its own
/// lane: what `asset`, an ASSET `lane` admitted live, serves a reader that
/// declared no image input, its ASSET_TEXT read through the same lane. Each
/// text's stored body is charged to `admits` before it decodes, so a door
/// that bounds the bodies it decodes bounds these too. The bytes go only
/// through [`Memory::resolve_asset`].
pub fn hydrated_asset(
    lane: &ScopedRead<'_>,
    asset: EntityId,
    admits: &mut dyn FnMut(usize) -> bool,
) -> MemoryResult<ScopedReadResult<HydratedAsset>> {
    let consumer = AssetConsumer::text_only(CallPurpose::AnswerGen);
    let ScopedReadResult { value, receipt } =
        asset_forms_in_lane(lane, asset, &consumer, true, admits)?;
    let value = match value {
        Some(forms) if forms.omitted => HydratedAsset::Omitted,
        Some(forms) if forms.image.is_some() => match (forms.form(&consumer, None), forms.text) {
            (Some(ServedAssetForm::AssetText), Some((asset_text, text))) => {
                let body = rmp_serde::to_vec_named(&TextFormBody {
                    form: ServedAssetForm::AssetText,
                    asset_text_ref: asset_text.to_hex(),
                    text: &text,
                })
                .map_err(|_| MemoryError::bad_request("body is not MessagePack-encodable"))?;
                HydratedAsset::Text { body, asset_text }
            }
            _ => HydratedAsset::Stored,
        },
        _ => HydratedAsset::Stored,
    };
    Ok(ScopedReadResult { value, receipt })
}

/// The forms one admitted ASSET holds, and where budget pressure starts for
/// the consumer's purpose.
pub(crate) struct AssetForms {
    asset: EntityId,
    image: Option<ImageBytes>,
    /// The newest admitted ASSET_TEXT derived from the asset.
    text: Option<(EntityId, String)>,
    /// Whether a text's stored body was refused before it decoded.
    omitted: bool,
    rung: BudgetThreshold,
}

impl AssetForms {
    /// The form `consumer` is served under `budget`; `None` fails closed.
    fn form(
        &self,
        consumer: &AssetConsumer,
        budget: Option<&BudgetRead>,
    ) -> Option<ServedAssetForm> {
        choose_form(
            consumer.reads_images(),
            under_pressure(budget, self.rung),
            self.image.is_some(),
            self.text.is_some(),
        )
    }

    /// The asset as `consumer` is served it under `budget`; `None` fails closed.
    pub(crate) fn serve(
        self,
        consumer: &AssetConsumer,
        budget: Option<&BudgetRead>,
    ) -> Option<ResolvedAsset> {
        let form = self.form(consumer, budget)?;
        Some(ResolvedAsset {
            asset_ref: self.asset.to_hex(),
            form,
            image: self.image.filter(|_| form == ServedAssetForm::Image),
            asset_text_ref: self.text.as_ref().map(|(id, _)| id.to_hex()),
            text: self.text.map(|(_, text)| text),
        })
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
    consumer: &AssetConsumer,
    images_only: bool,
    admits: &mut dyn FnMut(usize) -> bool,
) -> MemoryResult<ScopedReadResult<Option<AssetForms>>> {
    let vault = lane.vault();
    let ScopedReadResult {
        value: (row, derived, rung),
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
        let rung = crate::llm::read_effective_defaults(&vault.store, txn)?
            .table()
            .asset_text_at(&consumer.purpose);
        Ok::<_, MemoryError>((row, derived, rung))
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
        omitted: false,
        rung,
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
                forms.omitted = true;
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

/// Image bytes go only to a consumer that reads images, of an asset that
/// holds one, outside budget pressure. Otherwise the precomputed text;
/// otherwise nothing, and the read fails closed.
fn choose_form(
    reads_images: bool,
    under_pressure: bool,
    has_image: bool,
    has_text: bool,
) -> Option<ServedAssetForm> {
    if reads_images && has_image && !under_pressure {
        Some(ServedAssetForm::Image)
    } else if has_text {
        Some(ServedAssetForm::AssetText)
    } else {
        None
    }
}

/// Pressure starts once the budget has crossed the purpose's rung.
fn under_pressure(budget: Option<&BudgetRead>, rung: BudgetThreshold) -> bool {
    budget.is_some_and(|read| {
        read.fired_thresholds.contains(&rung) || read.depleted_percent() >= rung.percent()
    })
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
