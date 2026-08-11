//! Local, binary image normalization for the OF-014 ingest station.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::OnceLock;

use chrono::{NaiveDateTime, TimeZone, Utc};

use super::{IngestError, IngestResult, IngestSource, NormalizedIngestBatch};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use crate::temporal::TimeRange;

pub const IMAGE_SOURCE_ID: &str = "image-asset";

/// The declared execution locality of a recognizer under the OF-124 ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalityRung {
    OnDevice = 0,
    HostLocal = 1,
    Remote(u8),
}

impl LocalityRung {
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::OnDevice => 0,
            Self::HostLocal => 1,
            Self::Remote(rung) => rung,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExifEvidence {
    pub occurred_at: Option<TimeRange>,
    pub location: Option<GeoPoint>,
    pub raw_tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognizedText {
    pub text: String,
}

/// A host-provided or engine-local OCR implementation. Implementations must
/// declare their locality so an asset records whether its text left the device.
pub trait ImageTextRecognizer: Send + Sync {
    fn locality(&self) -> LocalityRung;
    fn recognize(&self, image_bytes: &[u8]) -> IngestResult<RecognizedText>;
}

/// An optional caption model. Unlike OCR, no caption is generated until a host
/// explicitly registers one.
pub trait ImageCaptionRecognizer: Send + Sync {
    fn locality(&self) -> LocalityRung;
    fn caption(&self, image_bytes: &[u8]) -> IngestResult<String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedIngestEntity {
    pub entity_type: u8,
    pub body: String,
    pub recognizer_locality: Option<LocalityRung>,
}

/// The statically registered image source uses process-global, once-set host
/// injection doors rather than carrying generic recognizers in the registry.
pub struct ImageIngestSource;

impl ImageIngestSource {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ImageIngestSource {
    fn default() -> Self {
        Self::new()
    }
}

pub static RECOGNIZER: OnceLock<&'static dyn ImageTextRecognizer> = OnceLock::new();
pub static CAPTION_RECOGNIZER: OnceLock<&'static dyn ImageCaptionRecognizer> = OnceLock::new();

pub fn register_image_text_recognizer(
    recognizer: &'static dyn ImageTextRecognizer,
) -> Result<(), &'static str> {
    RECOGNIZER
        .set(recognizer)
        .map_err(|_| "image text recognizer is already registered")
}

pub fn register_image_caption_recognizer(
    recognizer: &'static dyn ImageCaptionRecognizer,
) -> Result<(), &'static str> {
    CAPTION_RECOGNIZER
        .set(recognizer)
        .map_err(|_| "image caption recognizer is already registered")
}

#[cfg(not(feature = "image-station-ocr"))]
struct DefaultRecognizer;

#[cfg(not(feature = "image-station-ocr"))]
impl ImageTextRecognizer for DefaultRecognizer {
    fn locality(&self) -> LocalityRung {
        LocalityRung::OnDevice
    }

    fn recognize(&self, _image_bytes: &[u8]) -> IngestResult<RecognizedText> {
        // The feature-off fallback is deliberately no-network and preserves
        // EXIF-only ingestion on minimal builds.
        Ok(RecognizedText {
            text: String::new(),
        })
    }
}

#[cfg(feature = "image-station-ocr")]
struct DefaultRecognizer;

#[cfg(feature = "image-station-ocr")]
impl ImageTextRecognizer for DefaultRecognizer {
    fn locality(&self) -> LocalityRung {
        LocalityRung::OnDevice
    }

    fn recognize(&self, image_bytes: &[u8]) -> IngestResult<RecognizedText> {
        let decoded =
            image::load_from_memory(image_bytes).map_err(|error| IngestError::InvalidDocument {
                source_id: IMAGE_SOURCE_ID,
                message: format!("corrupt image: {error}"),
            })?;
        let detection_path = std::env::var("ONEIRON_OCR_DETECTION_MODEL").ok();
        let recognition_path = std::env::var("ONEIRON_OCR_RECOGNITION_MODEL").ok();
        let (Some(detection_path), Some(recognition_path)) = (detection_path, recognition_path)
        else {
            return Err(IngestError::OcrUnavailable {
                source_id: IMAGE_SOURCE_ID,
                message: "set ONEIRON_OCR_DETECTION_MODEL and ONEIRON_OCR_RECOGNITION_MODEL to local .rten model files".to_owned(),
            });
        };
        let detection_model = rten::Model::load_file(detection_path).map_err(|error| {
            IngestError::OcrUnavailable {
                source_id: IMAGE_SOURCE_ID,
                message: format!("unable to load detection model: {error}"),
            }
        })?;
        let recognition_model = rten::Model::load_file(recognition_path).map_err(|error| {
            IngestError::OcrUnavailable {
                source_id: IMAGE_SOURCE_ID,
                message: format!("unable to load recognition model: {error}"),
            }
        })?;
        let engine = ocrs::OcrEngine::new(ocrs::OcrEngineParams {
            detection_model: Some(detection_model),
            recognition_model: Some(recognition_model),
            ..Default::default()
        })
        .map_err(|error| IngestError::OcrUnavailable {
            source_id: IMAGE_SOURCE_ID,
            message: format!("unable to initialize local OCR: {error}"),
        })?;
        let rgb = decoded.into_rgb8();
        let input =
            ocrs::ImageSource::from_bytes(rgb.as_raw(), rgb.dimensions()).map_err(|error| {
                IngestError::InvalidDocument {
                    source_id: IMAGE_SOURCE_ID,
                    message: format!("unable to prepare image for OCR: {error}"),
                }
            })?;
        let input = engine
            .prepare_input(input)
            .map_err(|error| IngestError::OcrUnavailable {
                source_id: IMAGE_SOURCE_ID,
                message: format!("unable to prepare local OCR input: {error}"),
            })?;
        let text = engine
            .get_text(&input)
            .map_err(|error| IngestError::OcrUnavailable {
                source_id: IMAGE_SOURCE_ID,
                message: format!("local OCR failed: {error}"),
            })?;
        Ok(RecognizedText { text })
    }
}

static DEFAULT_RECOGNIZER: DefaultRecognizer = DefaultRecognizer;

impl IngestSource for ImageIngestSource {
    fn normalize(&self, _input: &str) -> IngestResult<NormalizedIngestBatch> {
        Err(IngestError::UnsupportedInput)
    }

    fn normalize_binary(&self, bytes: &[u8]) -> IngestResult<NormalizedIngestBatch> {
        let recognizer = RECOGNIZER.get().copied().unwrap_or(&DEFAULT_RECOGNIZER);
        normalize_image(bytes, recognizer, CAPTION_RECOGNIZER.get().copied())
    }
}

fn normalize_image(
    bytes: &[u8],
    recognizer: &dyn ImageTextRecognizer,
    captioner: Option<&dyn ImageCaptionRecognizer>,
) -> IngestResult<NormalizedIngestBatch> {
    validate_image(bytes)?;
    let exif = parse_exif_evidence(bytes)?;
    let locality = recognizer.locality();
    let recognized = recognizer.recognize(bytes)?;
    let mut body = format!("[PROVENANCE recognizer_locality={}]\n", locality.value());
    if !recognized.text.trim().is_empty() {
        body.push_str("[OCR]\n");
        body.push_str(recognized.text.trim());
        body.push('\n');
    }
    append_exif_section(&mut body, &exif);
    if let Some(captioner) =
        captioner.filter(|captioner| captioner.locality().value() <= locality.value())
    {
        let caption = captioner.caption(bytes)?;
        if !caption.trim().is_empty() {
            body.push_str(&format!(
                "[PROVENANCE caption_locality={}]\n",
                captioner.locality().value()
            ));
            body.push_str("[CAPTION source=caption_model]\n");
            body.push_str(caption.trim());
            body.push('\n');
        }
    }
    Ok(NormalizedIngestBatch {
        source_id: IMAGE_SOURCE_ID,
        records: Vec::new(),
        claims: Vec::new(),
        entities: vec![NormalizedIngestEntity {
            entity_type: ENTITY_TYPE_ASSET_TEXT,
            body,
            recognizer_locality: Some(locality),
        }],
        note_fallback: None,
    })
}

/// Parses only evidence actually encoded in EXIF. Missing tags remain absent.
pub fn parse_exif_evidence(image_bytes: &[u8]) -> IngestResult<ExifEvidence> {
    validate_image(image_bytes)?;
    let mut raw_tags = BTreeMap::new();
    let exif = exif::Reader::new().read_from_container(&mut Cursor::new(image_bytes));
    let Ok(exif) = exif else {
        return Ok(ExifEvidence {
            occurred_at: None,
            location: None,
            raw_tags,
        });
    };

    for field in exif.fields() {
        raw_tags.insert(field.tag.to_string(), field.display_value().to_string());
    }
    let occurred_at = exif
        .get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY)
        .and_then(exif_datetime_field_to_range);
    let location = gps_location(&exif);

    Ok(ExifEvidence {
        occurred_at,
        location,
        raw_tags,
    })
}

fn validate_image(bytes: &[u8]) -> IngestResult<()> {
    let is_png = bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 33;
    let is_jpeg =
        bytes.starts_with(&[0xff, 0xd8]) && bytes.ends_with(&[0xff, 0xd9]) && bytes.len() > 4;
    if !is_png && !is_jpeg {
        return Err(IngestError::InvalidDocument {
            source_id: IMAGE_SOURCE_ID,
            message: "corrupt or unsupported image".to_owned(),
        });
    }
    // Even minimal builds reject a JPEG that never reaches its compressed scan.
    if is_jpeg && !bytes.windows(2).any(|marker| marker == [0xff, 0xda]) {
        return Err(IngestError::InvalidDocument {
            source_id: IMAGE_SOURCE_ID,
            message: "corrupt JPEG missing scan data".to_owned(),
        });
    }
    #[cfg(feature = "image-station-ocr")]
    image::load_from_memory(bytes).map_err(|error| IngestError::InvalidDocument {
        source_id: IMAGE_SOURCE_ID,
        message: format!("corrupt image: {error}"),
    })?;
    Ok(())
}

fn exif_datetime_field_to_range(field: &exif::Field) -> Option<TimeRange> {
    let exif::Value::Ascii(values) = &field.value else {
        return None;
    };
    let value = std::str::from_utf8(values.first()?).ok()?;
    exif_datetime_to_range(value)
}

fn exif_datetime_to_range(value: &str) -> Option<TimeRange> {
    let value = value.trim().trim_matches('"');
    let datetime = NaiveDateTime::parse_from_str(value, "%Y:%m:%d %H:%M:%S").ok()?;
    let timestamp = Utc
        .from_utc_datetime(&datetime)
        .timestamp()
        .try_into()
        .ok()?;
    Some(TimeRange {
        start: timestamp,
        end: timestamp,
    })
}

fn gps_location(exif: &exif::Exif) -> Option<GeoPoint> {
    let lat = gps_coordinate(exif, exif::Tag::GPSLatitude, exif::Tag::GPSLatitudeRef)?;
    let lon = gps_coordinate(exif, exif::Tag::GPSLongitude, exif::Tag::GPSLongitudeRef)?;
    Some(GeoPoint { lat, lon })
}

fn gps_coordinate(exif: &exif::Exif, coordinate: exif::Tag, reference: exif::Tag) -> Option<f64> {
    let field = exif.get_field(coordinate, exif::In::PRIMARY)?;
    let exif::Value::Rational(values) = &field.value else {
        return None;
    };
    if values.len() != 3 || values.iter().any(|value| value.denom == 0) {
        return None;
    }
    let degrees = values[0].num as f64 / values[0].denom as f64;
    let minutes = values[1].num as f64 / values[1].denom as f64;
    let seconds = values[2].num as f64 / values[2].denom as f64;
    let mut result = degrees + minutes / 60.0 + seconds / 3600.0;
    let reference = exif.get_field(reference, exif::In::PRIMARY)?;
    let sign = reference.display_value().to_string();
    if sign.contains('S') || sign.contains('W') {
        result = -result;
    }
    Some(result)
}

fn append_exif_section(body: &mut String, evidence: &ExifEvidence) {
    body.push_str("[EXIF]\n");
    if let Some(occurred_at) = evidence.occurred_at {
        body.push_str(&format!("DateTimeOriginal={}\n", occurred_at.start));
    }
    if let Some(location) = evidence.location {
        body.push_str(&format!("GPS={},{}\n", location.lat, location.lon));
    }
    for (tag, value) in &evidence.raw_tags {
        body.push_str(tag);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIPT: &[u8] = include_bytes!("../../tests/fixtures/image_receipt.jpg");
    const STRIPPED: &[u8] = include_bytes!("../../tests/fixtures/image_stripped_exif.jpg");
    const SCREENSHOT: &[u8] = include_bytes!("../../tests/fixtures/image_screenshot.png");

    #[test]
    fn parses_only_exif_evidence_present_in_the_image() {
        let evidence = parse_exif_evidence(RECEIPT).expect("receipt fixture parses");
        assert!(evidence.occurred_at.is_some());
        let location = evidence.location.expect("GPS evidence");
        assert!((location.lat - 37.7749).abs() < 0.0001);
        assert!((location.lon + 122.4194).abs() < 0.0001);
        assert!(!evidence.raw_tags.is_empty());

        let stripped = parse_exif_evidence(STRIPPED).expect("stripped fixture parses");
        assert_eq!(stripped.occurred_at, None);
        assert_eq!(stripped.location, None);
    }

    struct CannedOcr;
    impl ImageTextRecognizer for CannedOcr {
        fn locality(&self) -> LocalityRung {
            LocalityRung::OnDevice
        }
        fn recognize(&self, _bytes: &[u8]) -> IngestResult<RecognizedText> {
            Ok(RecognizedText {
                text: "receipt total 12.50".to_owned(),
            })
        }
    }
    struct CannedCaption;
    impl ImageCaptionRecognizer for CannedCaption {
        fn locality(&self) -> LocalityRung {
            LocalityRung::OnDevice
        }
        fn caption(&self, _bytes: &[u8]) -> IngestResult<String> {
            Ok("a receipt".to_owned())
        }
    }

    #[test]
    fn image_source_normalizes_assets_with_canned_ocr_and_exif() {
        let batch = normalize_image(RECEIPT, &CannedOcr, None).expect("valid image");
        let entity = &batch.entities[0];
        assert_eq!(batch.source_id, IMAGE_SOURCE_ID);
        assert_eq!(entity.entity_type, ENTITY_TYPE_ASSET_TEXT);
        assert!(entity.body.contains("[OCR]\nreceipt total 12.50"));
        assert!(entity.body.contains("[EXIF]"));
        assert!(entity.body.contains("DateTimeOriginal="));
        assert!(entity.body.contains("GPS="));
        assert!(entity.body.contains("[PROVENANCE recognizer_locality=0]"));
        assert_eq!(entity.recognizer_locality, Some(LocalityRung::OnDevice));
        assert!(!entity.body.contains("source=caption_model"));

        let handwritten = normalize_image(
            include_bytes!("../../tests/fixtures/image_handwritten.jpg"),
            &CannedOcr,
            None,
        )
        .expect("handwritten jpeg");
        assert!(handwritten.entities[0].body.contains("receipt total 12.50"));
        let screenshot = normalize_image(SCREENSHOT, &CannedOcr, None).expect("screenshot png");
        assert!(screenshot.entities[0].body.contains("[OCR]"));
    }

    #[test]
    fn caption_is_marked_and_locality_policy_is_honored() {
        let batch = normalize_image(SCREENSHOT, &CannedOcr, Some(&CannedCaption)).expect("caption");
        assert!(
            batch.entities[0]
                .body
                .contains("[CAPTION source=caption_model]")
        );
        assert!(
            batch.entities[0]
                .body
                .contains("[PROVENANCE caption_locality=0]")
        );
    }

    #[test]
    fn corrupt_signed_jpeg_is_rejected() {
        let corrupt = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02, 0xff, 0xd9];
        assert!(matches!(
            normalize_image(&corrupt, &CannedOcr, None),
            Err(IngestError::InvalidDocument { .. })
        ));
    }

    #[cfg(feature = "image-station-ocr")]
    #[test]
    fn default_ocr_reports_unprovisioned_models() {
        if std::env::var("ONEIRON_OCR_DETECTION_MODEL").is_err()
            && std::env::var("ONEIRON_OCR_RECOGNITION_MODEL").is_err()
        {
            assert!(matches!(
                ImageIngestSource::new().normalize_binary(SCREENSHOT),
                Err(IngestError::OcrUnavailable { .. })
            ));
        }
    }

    #[test]
    fn image_source_rejects_text_input() {
        assert_eq!(
            ImageIngestSource::new().normalize("text"),
            Err(IngestError::UnsupportedInput)
        );
    }

    #[test]
    fn registry_contains_the_image_source_once() {
        let ids: Vec<_> = crate::ingest::INGEST_SOURCE_REGISTRY.source_ids().collect();
        assert!(ids.contains(&IMAGE_SOURCE_ID));
        assert_eq!(ids.len(), 4);
        let unique: std::collections::HashSet<_> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
    }
}
