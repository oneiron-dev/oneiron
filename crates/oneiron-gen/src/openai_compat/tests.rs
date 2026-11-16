//! The direct image wire's reply decoding.
use std::collections::BTreeMap;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use oneiron::{BudgetLease, ModelId};
use serde_json::json;

const MODEL: &str = "fake/teacher@v1";

fn ready<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fake transport answers at once"),
    }
}

/// An image transport that answers every request with one canned reply.
struct CannedImage(serde_json::Value);

impl super::OpenAiImageTransport for CannedImage {
    fn execute<'a>(
        &'a self,
        _request: super::OpenAiImageHttpRequest,
        _lease: &'a BudgetLease,
    ) -> super::OpenAiImageTransportFuture<'a> {
        let body = self.0.clone();
        Box::pin(async move {
            Ok(super::OpenAiImageHttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body,
            })
        })
    }
}

fn generate_from(b64_json: String) -> oneiron::LlmResult<oneiron::llm::image::ImageResponse> {
    use oneiron::llm::image::{ImageBackend, ImageIntent};
    let backend = super::DirectOpenAiImageBackend::new(CannedImage(
        json!({ "created": 1, "data": [{ "b64_json": b64_json }] }),
    ));
    let intent = ImageIntent {
        model: ModelId::new(MODEL).expect("model"),
        instruction: "a lighthouse".to_owned(),
        width: 1024,
        height: 1024,
        params: BTreeMap::new(),
    };
    ready(backend.generate(intent, &BudgetLease::for_test("image")))
}

// F04 H366: a provider reply carrying an image past the 64 MiB ceiling is
// refused from its encoded length, before it is decoded. Main decoded it and
// returned it.
#[test]
fn a_provider_image_past_the_ceiling_is_refused_before_it_is_decoded() {
    use base64::Engine as _;
    const CEILING: usize = 64 << 20;
    let encode = |len: usize| base64::engine::general_purpose::STANDARD.encode(vec![7u8; len]);

    let at_ceiling = generate_from(encode(CEILING)).expect("at the ceiling");
    assert_eq!(at_ceiling.image.bytes.len(), CEILING);
    assert_eq!(at_ceiling.metadata.get("created"), Some(&json!(1)));

    // Ruled (FIX 8615, c39a7de7a4a): "a successful image over 64 MiB was
    // discarded as EmptyResponse. FIXED: replies are kept whole"; "The 64 MiB
    // image discard and the 512 MiB transport refusal are gone." The same
    // reply past the former ceiling now decodes whole.
    let past = generate_from(encode(CEILING + 1));
    assert_eq!(past.map(|reply| reply.image.bytes.len()), Ok(CEILING + 1));
}
