//! Own test binary (ruling T0F-P12R-REDS id 10 = A): the image-text recognizer is
//! process-global, so a recognizer another `it` test registers would answer this
//! test first. Body moved from it/image_station_injection.rs; only the fixture
//! path changes, because include_bytes! is relative to this file.
#![cfg(feature = "image-station-ocr")]

use oneiron::{ingest::IMAGE_SOURCE_ID, ingest::INGEST_SOURCE_REGISTRY};

// F04 H240: with the built-in OCR compiled in but no models configured, the
// refusal comes before any decode. The bytes below are a PNG header with no
// image data: main decoded first and refused them as corrupt.
#[cfg(feature = "image-station-ocr")]
#[test]
fn unconfigured_builtin_ocr_refuses_before_decoding_the_image() {
    if std::env::var_os("ONEIRON_OCR_DETECTION_MODEL").is_some()
        || std::env::var_os("ONEIRON_OCR_RECOGNITION_MODEL").is_some()
    {
        return;
    }
    let header_only = &include_bytes!("fixtures/image_screenshot.png")[..33];
    let refused = INGEST_SOURCE_REGISTRY
        .normalize_binary(IMAGE_SOURCE_ID, header_only)
        .expect_err("no OCR models");
    assert!(
        matches!(refused, oneiron::ingest::IngestError::OcrUnavailable { .. }),
        "{refused:?}"
    );
}
