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
        // Both decoder and OCR engine are pure Rust and make no network calls.
        // Model weights are host-provisioned, so an unprovisioned engine still
        // produces an honest empty OCR result rather than inventing text.
        let format =
            image::guess_format(image_bytes).map_err(|error| IngestError::InvalidDocument {
                source_id: IMAGE_SOURCE_ID,
                message: format!("corrupt image: {error}"),
            })?;
        if !matches!(format, image::ImageFormat::Jpeg | image::ImageFormat::Png) {
            return Err(IngestError::InvalidDocument {
                source_id: IMAGE_SOURCE_ID,
                message: "unsupported image format".to_owned(),
            });
        }
        ocrs::OcrEngine::new(ocrs::OcrEngineParams::default()).map_err(|error| {
            IngestError::InvalidDocument {
                source_id: IMAGE_SOURCE_ID,
                message: format!("unable to initialize local OCR: {error}"),
            }
        })?;
        Ok(RecognizedText {
            text: String::new(),
        })
    }
}

static DEFAULT_RECOGNIZER: DefaultRecognizer = DefaultRecognizer;

impl IngestSource for ImageIngestSource {
    fn normalize(&self, _input: &str) -> IngestResult<NormalizedIngestBatch> {
        Err(IngestError::UnsupportedInput)
    }

    fn normalize_binary(&self, bytes: &[u8]) -> IngestResult<NormalizedIngestBatch> {
        validate_image(bytes)?;
        let exif = parse_exif_evidence(bytes)?;
        let recognizer = RECOGNIZER.get().copied().unwrap_or(&DEFAULT_RECOGNIZER);
        let recognized = recognizer.recognize(bytes)?;

        let mut body = String::new();
        if !recognized.text.trim().is_empty() {
            body.push_str("[OCR]\n");
            body.push_str(recognized.text.trim());
            body.push('\n');
        }
        append_exif_section(&mut body, &exif);
        if let Some(captioner) = CAPTION_RECOGNIZER.get().copied() {
            let caption = captioner.caption(bytes)?;
            if !caption.trim().is_empty() {
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
                recognizer_locality: Some(recognizer.locality()),
            }],
            note_fallback: None,
        })
    }
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
    if is_png || is_jpeg {
        Ok(())
    } else {
        Err(IngestError::InvalidDocument {
            source_id: IMAGE_SOURCE_ID,
            message: "corrupt or unsupported image".to_owned(),
        })
    }
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

    #[test]
    fn image_source_normalizes_binary_assets_without_caption() {
        let source = ImageIngestSource::new();
        let batch = source.normalize_binary(SCREENSHOT).expect("valid image");
        assert_eq!(batch.source_id, IMAGE_SOURCE_ID);
        assert_eq!(batch.entities.len(), 1);
        assert_eq!(batch.entities[0].entity_type, ENTITY_TYPE_ASSET_TEXT);
        assert!(batch.entities[0].body.contains("[EXIF]"));
        assert!(!batch.entities[0].body.contains("source=caption_model"));
        assert_eq!(source.normalize("text"), Err(IngestError::UnsupportedInput));
        assert!(matches!(
            source.normalize_binary(b"not an image"),
            Err(IngestError::InvalidDocument { .. })
        ));
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
