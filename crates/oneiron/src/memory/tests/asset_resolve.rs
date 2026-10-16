//! OF-328 / OF-329 acceptance: a generated image lands as ASSET plus a
//! precomputed ASSET_TEXT, and the resolver serves each consumer the form it
//! reads (ONE-2328, ONE-2329).

use super::*;
use crate::llm::image::{
    ImageBackend, ImageBytes, ImageCatalog, ImageCatalogRow, ImageFuture, ImageIntent,
    ImageResponse,
};
use crate::llm::{
    BudgetExhaustionPolicy, BudgetLease, BudgetRead, BudgetThreshold, CallPurpose, LlmCapability,
    ModelId,
};
use crate::memory::{AssetConsumer, LandedImage, ResolvedAsset, ServedAssetForm};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

const PIXELS: &[u8] = b"\x89PNG\r\n\x1a\nfake generated pixels";
const INSTRUCTION: &str = "a lighthouse at dusk over a calm grey sea";

/// The fake adapter: answers every intent with the same PNG bytes.
struct FakeImageBackend;

impl ImageBackend for FakeImageBackend {
    fn generate<'a>(&'a self, intent: ImageIntent, _lease: &'a BudgetLease) -> ImageFuture<'a> {
        Box::pin(async move {
            Ok(ImageResponse {
                image: ImageBytes {
                    bytes: PIXELS.to_vec(),
                    media_type: "image/png".into(),
                },
                model: intent.model,
                metadata: std::collections::BTreeMap::new(),
            })
        })
    }

    fn reference_edit<'a>(
        &'a self,
        intent: ImageIntent,
        _references: Vec<ImageBytes>,
        lease: &'a BudgetLease,
    ) -> ImageFuture<'a> {
        self.generate(intent, lease)
    }
}

/// The fake adapter answers at once, so one poll drives the door.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fake adapter answers without waiting"),
    }
}

/// The embedded owner reads every row it lands.
fn owner_vault() -> (tempfile::TempDir, crate::Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    (dir, vault, owner)
}

fn model() -> ModelId {
    ModelId::new("fake/image-1@1").expect("model id")
}

fn catalog() -> ImageCatalog {
    let adapters: std::collections::BTreeMap<String, Arc<dyn ImageBackend>> = [(
        "fake".to_owned(),
        Arc::new(FakeImageBackend) as Arc<dyn ImageBackend>,
    )]
    .into();
    ImageCatalog::new(
        vec![ImageCatalogRow {
            model: model(),
            adapter: "fake".into(),
            generate: true,
            reference_edit: false,
            max_pixels: 1024 * 1024,
        }],
        adapters,
    )
    .expect("catalog")
}

fn generate(memory: &Memory<'_>) -> LandedImage {
    let intent = ImageIntent {
        model: model(),
        instruction: INSTRUCTION.into(),
        width: 512,
        height: 512,
        params: std::collections::BTreeMap::new(),
    };
    let lease = BudgetLease::for_test("image-lease");
    ready(memory.generate_image_asset(&catalog(), intent, &lease, 100)).expect("landed")
}

fn consumer(capabilities: &[LlmCapability], purpose: CallPurpose) -> AssetConsumer {
    AssetConsumer {
        capabilities: capabilities.to_vec(),
        purpose,
    }
}

/// A budget `used` units into a 100-unit limit, with the rungs it crossed.
fn budget(used: u64) -> BudgetRead {
    BudgetRead {
        attempt_id: "attempt".into(),
        limit_units: 100,
        cap_units: 100,
        used_units: used,
        reserved_units: 0,
        remaining_units: 100 - used,
        on_budget_exhausted: BudgetExhaustionPolicy::Suspend,
        fired_thresholds: [
            BudgetThreshold::Silent50,
            BudgetThreshold::Plan80,
            BudgetThreshold::Land95,
        ]
        .into_iter()
        .filter(|rung| used >= rung.percent())
        .collect(),
    }
}

fn resolve(
    memory: &Memory<'_>,
    asset: &str,
    consumer: &AssetConsumer,
    budget: Option<&BudgetRead>,
) -> MemoryResult<ResolvedAsset> {
    memory
        .resolve_asset(asset, consumer, budget)
        .map(|read| read.value)
}

#[test]
fn fake_adapter_generation_lands_asset_and_precomputed_asset_text_in_vault() {
    let (_dir, vault, owner) = owner_vault();
    let landed = generate(&facade_for(&vault, owner));

    let asset = EntityId::from_hex(&landed.asset_ref).expect("asset id");
    let text = EntityId::from_hex(&landed.asset_text_ref).expect("text id");
    assert_eq!(
        vault.get_entity_type(&asset).unwrap(),
        Some(ENTITY_TYPE_ASSET)
    );
    assert_eq!(
        vault.get_entity_type(&text).unwrap(),
        Some(ENTITY_TYPE_ASSET_TEXT)
    );
    let raw = vault.get_raw(&text).unwrap().expect("ASSET_TEXT row");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], INSTRUCTION.as_bytes());
    // The text names its source the way every ASSET_TEXT reader finds it.
    let txn = vault.store.env.read_txn().unwrap();
    let derived: Vec<EntityId> = crate::ports::EdgeStoreRead::port_edges(
        &vault.store,
        &txn,
        &asset,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::DerivedFrom),
        None,
    )
    .unwrap()
    .map(|edge| edge.unwrap().target)
    .collect();
    assert_eq!(derived, vec![text]);
}

#[test]
fn resolve_serves_image_to_vision_consumer_asset_text_to_text_only_and_text_under_budget_pressure()
{
    let (_dir, vault, owner) = owner_vault();
    let memory = facade_for(&vault, owner);
    let landed = generate(&memory);
    let vision = consumer(&[LlmCapability::ImageInput], CallPurpose::AnswerGen);
    let text_only = consumer(&[LlmCapability::ToolCalling], CallPurpose::AnswerGen);

    let served = resolve(&memory, &landed.asset_ref, &vision, None).unwrap();
    assert_eq!(served.form, ServedAssetForm::Image);
    let image = served.image.expect("image bytes");
    assert_eq!(image.bytes, PIXELS);
    assert_eq!(image.media_type, "image/png");
    // The caption rides beside the bytes.
    assert_eq!(served.text.as_deref(), Some(INSTRUCTION));

    let served = resolve(&memory, &landed.asset_ref, &text_only, None).unwrap();
    assert_eq!(served.form, ServedAssetForm::AssetText);
    assert_eq!(served.image, None);
    assert_eq!(served.text.as_deref(), Some(INSTRUCTION));
    assert_eq!(
        served.asset_text_ref.as_deref(),
        Some(landed.asset_text_ref.as_str())
    );

    // Budget pressure: the purpose's rung (Plan80 by default) forces text.
    let calm = resolve(&memory, &landed.asset_ref, &vision, Some(&budget(60))).unwrap();
    assert_eq!(calm.form, ServedAssetForm::Image);
    let pressed = resolve(&memory, &landed.asset_ref, &vision, Some(&budget(85))).unwrap();
    assert_eq!(pressed.form, ServedAssetForm::AssetText);
    assert_eq!(pressed.image, None);

    // The per-purpose row decides where pressure starts for that purpose only.
    let mut table = vault.purpose_default_table().unwrap();
    table
        .asset_text_at
        .insert(CallPurpose::AutoCheck, BudgetThreshold::Silent50);
    vault.set_purpose_default_table(&table).unwrap();
    let checker = consumer(&[LlmCapability::ImageInput], CallPurpose::AutoCheck);
    let served = resolve(&memory, &landed.asset_ref, &checker, Some(&budget(60))).unwrap();
    assert_eq!(served.form, ServedAssetForm::AssetText);
    let served = resolve(&memory, &landed.asset_ref, &vision, Some(&budget(60))).unwrap();
    assert_eq!(served.form, ServedAssetForm::Image);
}

#[test]
fn resolve_fails_closed_when_no_form_matches() {
    let (_dir, vault, owner) = owner_vault();
    let memory = facade_for(&vault, owner);
    // An image ASSET whose ASSET_TEXT was never written.
    let bare = EntityId::from_bytes([0xC7; 16]).unwrap();
    let body = crate::memory::asset_resolve::generated_asset_body(
        &ImageBytes {
            bytes: PIXELS.to_vec(),
            media_type: "image/png".into(),
        },
        &model(),
    )
    .unwrap();
    vault
        .put_entity(&bare, ENTITY_TYPE_ASSET, test_time(1), 1, &body)
        .unwrap();
    let vision = consumer(&[LlmCapability::ImageInput], CallPurpose::AnswerGen);
    let text_only = consumer(&[], CallPurpose::AnswerGen);

    assert_eq!(
        resolve(&memory, &bare.to_hex(), &vision, None)
            .unwrap()
            .form,
        ServedAssetForm::Image
    );
    for (who, pressure) in [(&text_only, None), (&vision, Some(budget(90)))] {
        let refused = resolve(&memory, &bare.to_hex(), who, pressure.as_ref()).unwrap_err();
        assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
    }
    // A ref to something that is not an ASSET serves no form at all.
    let refused = resolve(&memory, &owner.to_hex(), &vision, None).unwrap_err();
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND);
}
