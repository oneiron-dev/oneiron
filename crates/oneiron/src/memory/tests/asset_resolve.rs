//! OF-328 / OF-329 acceptance: a generated image lands as ASSET plus a
//! precomputed ASSET_TEXT, and the resolver serves each consumer the form it
//! reads (ONE-2328, ONE-2329).

use super::*;
use crate::llm::decision::{DecisionProvider, HeldLadder, RuleDecisionProvider};
use crate::llm::image::{
    ImageBackend, ImageBytes, ImageCatalog, ImageCatalogRow, ImageFuture, ImageIntent,
    ImageResponse,
};
use crate::llm::{BudgetLease, CallPurpose, LlmCapability, ModelId};
use crate::memory::{AssetConsumer, ImagePick, LandedImage, ResolvedAsset, ServedAssetForm};
use crate::model_decision::catalogue::IMAGE_FULL;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    ProviderDecision,
};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const PIXELS: &[u8] = b"\x89PNG\r\n\x1a\nfake generated pixels";
const INSTRUCTION: &str = "a lighthouse at dusk over a calm grey sea";
/// A read's room for every form of the generated image.
const CALM_ROOM: u64 = 1 << 20;
/// A read's room for the caption's stored text, and not for the image form
/// beside it, which carries the caption, the pixels and the handle.
const PRESSED_ROOM: u64 = 2 * INSTRUCTION.len() as u64;
/// The host's wording of the per-image question (OF-329).
const PICK_WORDING: &str = "Does this task need this image in full?";

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
        _mask: Option<ImageBytes>,
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

/// The host's rule table for its per-image pick (OF-329): an in-band "no"
/// to the question keyed by `stepped_down`, and no row for any other
/// purpose, so the table abstains there and the image goes in full.
fn pick_rules(stepped_down: &CallPurpose) -> HeldLadder {
    let purpose = serde_json::to_string(stepped_down).expect("purpose");
    let question = IMAGE_FULL
        .question(
            &[purpose.as_bytes()],
            PICK_WORDING.to_owned(),
            AnswerContract::Noul,
        )
        .expect("image question");
    let mut rules =
        RuleDecisionProvider::new("test-image-pick".into(), "1".into()).expect("rule table");
    rules
        .insert(
            &question,
            ProviderDecision {
                answer: DecisionAnswer::Noul(false),
                // Inside the dial's band (0.35 to 0.65).
                probability: Some(0.4),
                paired: None,
                person: None,
                served: None,
                cost_per_thousand: None,
            },
        )
        .expect("rule row");
    let mut held = HeldLadder::unstaffed();
    held.rule = Some(Arc::new(rules) as Arc<dyn DecisionProvider>);
    held
}

/// The host's per-image pick on `held`'s rule rung alone.
fn image_pick(held: &HeldLadder, principal: EntityId) -> ImagePick<'_> {
    ImagePick {
        ladder: held.ladder(),
        principal,
        dial: DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::Rule,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: PICK_WORDING.to_owned(),
        task: "check the generated image against its instruction".into(),
        budget: Duration::from_secs(60),
    }
}

/// `asset` as `consumer` is served it, after the host's `pick` when it gives
/// one: the single-image read, or with `room` one call's serving within that
/// many bytes of served forms.
fn resolve(
    memory: &Memory<'_>,
    asset: &str,
    consumer: &AssetConsumer,
    pick: Option<&ImagePick<'_>>,
    room: Option<u64>,
) -> MemoryResult<ResolvedAsset> {
    match room {
        None => memory
            .resolve_asset(asset, consumer, pick)
            .map(|read| read.value),
        Some(room) => memory
            .serve_images(&[asset.to_owned()], consumer, pick, Some(room))
            .map(|mut read| read.value.remove(0)),
    }
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

    let served = resolve(&memory, &landed.asset_ref, &vision, None, None).unwrap();
    assert_eq!(served.form, ServedAssetForm::Image);
    let image = served.image.expect("image bytes");
    assert_eq!(image.bytes, PIXELS);
    assert_eq!(image.media_type, "image/png");
    // The caption rides beside the bytes.
    assert_eq!(served.text.as_deref(), Some(INSTRUCTION));

    let served = resolve(&memory, &landed.asset_ref, &text_only, None, None).unwrap();
    assert_eq!(served.form, ServedAssetForm::AssetText);
    assert_eq!(served.image, None);
    assert_eq!(served.text.as_deref(), Some(INSTRUCTION));
    assert_eq!(
        served.asset_text_ref.as_deref(),
        Some(landed.asset_text_ref.as_str())
    );

    // Budget pressure (OF-329): a room that holds the text and not the image
    // serves the text. The fake pixels decode to no thumbnail.
    let calm = resolve(&memory, &landed.asset_ref, &vision, None, Some(CALM_ROOM)).unwrap();
    assert_eq!(calm.form, ServedAssetForm::Image);
    let pressed = resolve(
        &memory,
        &landed.asset_ref,
        &vision,
        None,
        Some(PRESSED_ROOM),
    )
    .unwrap();
    assert_eq!(pressed.form, ServedAssetForm::AssetText);
    assert_eq!(pressed.image, None);

    // The host's pick, keyed by purpose, steps the image down for that
    // purpose only.
    let held = pick_rules(&CallPurpose::AutoCheck);
    let pick = image_pick(&held, owner);
    let checker = consumer(&[LlmCapability::ImageInput], CallPurpose::AutoCheck);
    let served = resolve(
        &memory,
        &landed.asset_ref,
        &checker,
        Some(&pick),
        Some(CALM_ROOM),
    )
    .unwrap();
    assert_eq!(served.form, ServedAssetForm::AssetText);
    let served = resolve(
        &memory,
        &landed.asset_ref,
        &vision,
        Some(&pick),
        Some(CALM_ROOM),
    )
    .unwrap();
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
        resolve(&memory, &bare.to_hex(), &vision, None, None)
            .unwrap()
            .form,
        ServedAssetForm::Image
    );
    // A reader that takes no image gets no form of it, at any room.
    for room in [None, Some(0)] {
        let refused = resolve(&memory, &bare.to_hex(), &text_only, None, room).unwrap_err();
        assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
    }
    // OF-329: a vision reader whose room fits no form gets the image's view
    // handle alone (the ask rung), never its pixels or a text.
    let asked = resolve(&memory, &bare.to_hex(), &vision, None, Some(0)).unwrap();
    assert_eq!(asked.form, ServedAssetForm::Ask, "{asked:?}");
    assert_eq!(asked.image, None);
    assert_eq!(asked.text, None);
    assert_eq!(asked.asset_text_ref, None);
    assert!(
        asked
            .handle
            .as_deref()
            .is_some_and(|handle| handle.starts_with(&format!("{}@", bare.to_hex()))),
        "{asked:?}"
    );
    // A ref to something that is not an ASSET serves no form at all.
    let refused = resolve(&memory, &owner.to_hex(), &vision, None, None).unwrap_err();
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND);
}
