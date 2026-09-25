use super::*;
use std::task::{Context, Poll, Waker};
fn run<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("fake pending"),
    }
}
struct Fake;
impl ImageBackend for Fake {
    fn generate<'a>(&'a self, intent: ImageIntent, _: &'a BudgetLease) -> ImageFuture<'a> {
        Box::pin(async move {
            Ok(ImageResponse {
                model: intent.model,
                image: ImageBytes {
                    bytes: vec![1, 2],
                    media_type: "image/png".into(),
                },
                metadata: BTreeMap::from([("verb".into(), serde_json::json!("generate"))]),
            })
        })
    }
    fn reference_edit<'a>(
        &'a self,
        intent: ImageIntent,
        references: Vec<ImageBytes>,
        _: &'a BudgetLease,
    ) -> ImageFuture<'a> {
        Box::pin(async move {
            Ok(ImageResponse {
                model: intent.model,
                image: references[0].clone(),
                metadata: BTreeMap::from([("verb".into(), serde_json::json!("edit"))]),
            })
        })
    }
}
#[test]
fn catalog_routes_generate_and_reference_edit_and_denies_unsupported() {
    let model = ModelId::new("fake/image@1").unwrap();
    let row = ImageCatalogRow {
        model: model.clone(),
        adapter: "fake".into(),
        generate: true,
        reference_edit: true,
        max_pixels: 4096,
    };
    let catalog = ImageCatalog::new(
        vec![row],
        BTreeMap::from([("fake".into(), Arc::new(Fake) as Arc<dyn ImageBackend>)]),
    )
    .unwrap();
    let intent = ImageIntent {
        model,
        instruction: "test image".into(),
        width: 32,
        height: 32,
        params: BTreeMap::new(),
    };
    let lease = BudgetLease::for_test("image");
    let generated = run(catalog.render(intent.clone(), None, &lease)).unwrap();
    assert_eq!(generated.metadata["verb"], serde_json::json!("generate"));
    let edited =
        run(catalog.render(intent.clone(), Some(vec![generated.image.clone()]), &lease)).unwrap();
    assert_eq!(edited.image, generated.image);
    assert_eq!(edited.metadata["verb"], serde_json::json!("edit"));
    assert!(run(catalog.render(intent, Some(vec![]), &lease)).is_err());
}
