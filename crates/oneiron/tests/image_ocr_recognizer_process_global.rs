//! The image text recognizer is per seat, not per process: a fresh seat never
//! sees the process default, while the registry's shared seat still honors it
//! for hosts that configure OCR once at startup.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::{
    ingest::IMAGE_SOURCE_ID, ingest::INGEST_SOURCE_REGISTRY, ingest::ImageIngestSource,
    ingest::ImageTextRecognizer, ingest::IngestResult, ingest::IngestSource, ingest::LocalityRung,
    ingest::RecognizedText, ingest::register_image_text_recognizer,
};

struct SeatOne;
impl ImageTextRecognizer for SeatOne {
    fn locality(&self) -> LocalityRung {
        LocalityRung::HostLocal
    }
    fn recognize(&self, _bytes: &[u8]) -> IngestResult<RecognizedText> {
        Ok(RecognizedText {
            text: "seat one text".to_owned(),
        })
    }
}

static SEAT_ONE: SeatOne = SeatOne;
const RECEIPT: &[u8] = include_bytes!("fixtures/image_receipt.jpg");

#[test]
fn fresh_seats_ignore_the_process_default_the_registry_honors() {
    // This binary's only registration: the process default exists, so a seat
    // that consulted it would answer "seat one text".
    register_image_text_recognizer(&SEAT_ONE).expect("binary registers once");

    // The shared registry seat honors the process default (host compat).
    let batch = INGEST_SOURCE_REGISTRY
        .normalize_binary(IMAGE_SOURCE_ID, RECEIPT)
        .expect("receipt normalizes");
    assert!(batch.entities[0].body.contains("seat one text"));
    assert_eq!(
        batch.entities[0].recognizer_locality,
        Some(LocalityRung::HostLocal)
    );

    // A fresh seat never sees the process default: it reads with the built-in
    // OCR, which here is unconfigured (OcrUnavailable) or, without the OCR
    // feature, reads no text at OnDevice locality.
    for seat in [ImageIngestSource::new(), ImageIngestSource::default()] {
        match seat.normalize_binary(RECEIPT) {
            Ok(batch) => {
                assert!(
                    !batch.entities[0].body.contains("seat one text"),
                    "fresh seat must not see the process default: {}",
                    batch.entities[0].body
                );
                assert_eq!(
                    batch.entities[0].recognizer_locality,
                    Some(LocalityRung::OnDevice)
                );
            }
            Err(oneiron::ingest::IngestError::OcrUnavailable { .. }) => {}
            Err(other) => panic!("fresh seat reads built-in OCR, got {other:?}"),
        }
    }
}
