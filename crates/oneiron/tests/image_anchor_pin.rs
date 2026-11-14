//! Comments pinned to a region of an image (L4-16; ASK IOB-ANCHOR A): an
//! `image_pixel` locator pins by geometry on an image artifact's version,
//! once the region lies inside the canvas its header reads after EXIF
//! orientation. It names no words, so its quote is null, and a thread opens
//! on it and reads back where it was pinned. A region outside the canvas or
//! empty, an overlay (`image_object`: no stored image body holds one), and an
//! image locator on a text artifact are refused, and open nothing.
//!
//! The locators go in as JSON, so this file also builds against an engine
//! whose locator has no image variants (the red run).
//!
//! Run with: `cargo test --locked -p oneiron --all-features --test
//! image_anchor_pin`.

use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder};
use oneiron::anchored_annotation::{
    AnnotationPinRequest, AnnotationResolution, AnnotationThreadOpenRequest,
    AnnotationThreadRequest,
};
use oneiron::blob_artifact::{ArtifactRefRequest, BlobArtifactBody, BlobVersionProvenance};
use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open_unseeded_for_test(dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    fn owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// A new artifact holding `bytes` as its version 1.
    fn artifact(&self, name: &str, media_type: &str, bytes: &[u8]) -> TestResult<EntityId> {
        let artifact = EntityId::now();
        self.vault.put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(name, media_type),
            at(1),
            1,
        )?;
        let version = self.vault.append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            at(2),
            2,
        )?;
        assert_eq!(version.version, 1, "FIXTURE: the first version");
        Ok(artifact)
    }

    /// The pin request for `locator` on version 1 of `artifact`.
    fn pin_request(artifact: EntityId, locator: &Value) -> TestResult<AnnotationPinRequest> {
        Ok(serde_json::from_value(json!({
            "artifact_ref": artifact.to_hex(),
            "version": 1,
            "locator": locator,
        }))?)
    }

    /// The owner's pin of `locator` on version 1: the refusal's words, or
    /// `None` when it pins. The request must parse.
    fn pin_refusal(&self, artifact: EntityId, locator: &Value) -> TestResult<Option<String>> {
        let request = Self::pin_request(artifact, locator)?;
        Ok(self
            .owner()
            .artifacts_anchors_pin(&request)
            .err()
            .map(|refusal| refusal.to_string()))
    }

    fn threads(&self, artifact: EntityId) -> TestResult<usize> {
        Ok(self
            .owner()
            .artifacts_threads_list(&ArtifactRefRequest {
                artifact_ref: artifact.to_hex(),
            })?
            .len())
    }
}

fn png(w: u32, h: u32) -> TestResult<Vec<u8>> {
    let rgba: Vec<u8> = (0..w * h)
        .flat_map(|at| [(at % 251) as u8, 40, 200, 255])
        .collect();
    let mut out = Vec::new();
    PngEncoder::new(&mut out).write_image(&rgba, w, h, ExtendedColorType::Rgba8)?;
    Ok(out)
}

/// A flat JPEG whose EXIF says `orientation`.
fn jpeg(w: u32, h: u32, orientation: u16) -> TestResult<Vec<u8>> {
    let mut exif = b"MM\0\x2a".to_vec();
    exif.extend(8u32.to_be_bytes());
    exif.extend(1u16.to_be_bytes());
    exif.extend(0x0112u16.to_be_bytes());
    exif.extend(3u16.to_be_bytes());
    exif.extend(1u32.to_be_bytes());
    exif.extend(orientation.to_be_bytes());
    exif.extend([0, 0]);
    exif.extend(0u32.to_be_bytes());
    let rgb: Vec<u8> = (0..w * h).flat_map(|_| [200, 40, 40]).collect();
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, 95);
    encoder.set_exif_metadata(exif)?;
    encoder.write_image(&rgb, w, h, ExtendedColorType::Rgb8)?;
    Ok(out)
}

fn region(x: u32, y: u32, w: u32, h: u32) -> Value {
    json!({ "format": "image_pixel", "x": x, "y": y, "w": w, "h": h })
}

#[test]
fn a_pixel_region_of_an_image_version_pins_and_a_thread_opens_on_it() -> TestResult {
    let fixture = Fixture::new()?;
    let photo = fixture.artifact("photo.png", "image/png", &png(40, 20)?)?;
    let sign = region(4, 2, 32, 16);
    let request = match Fixture::pin_request(photo, &sign) {
        Ok(request) => request,
        Err(err) => panic!("FAILBEFORE: an image pixel locator is a locator: {err}"),
    };
    let pin = fixture.owner().artifacts_anchors_pin(&request)?;
    assert_eq!((pin.artifact_id, pin.version), (photo, 1));
    assert_eq!(
        serde_json::to_value(&pin.locator)?,
        sign,
        "the pin keeps the region as asked"
    );
    assert_eq!(pin.quote, None, "a region names no words");
    assert!(
        fixture.pin_refusal(photo, &region(0, 0, 40, 20))?.is_none(),
        "the whole canvas pins"
    );

    let opened = fixture
        .owner()
        .artifacts_threads_open(&serde_json::from_value::<AnnotationThreadOpenRequest>(
            json!({
                "artifact_ref": photo.to_hex(),
                "version": 1,
                "locator": sign,
                "text": "The sign is cut off here.",
            }),
        )?)?;
    assert_eq!(opened.resolution, AnnotationResolution::Pinned);
    assert_eq!(serde_json::to_value(&opened.anchor.locator)?, sign);
    assert_eq!(opened.anchor.quote, None);

    // The stored head decodes back to the same region.
    let read = fixture
        .owner()
        .artifacts_threads_read(&AnnotationThreadRequest {
            artifact_ref: photo.to_hex(),
            thread_ref: opened.thread_id.to_hex(),
        })?
        .ok_or("the thread reads back")?;
    assert_eq!(read.thread_id, opened.thread_id);
    assert_eq!((read.origin.version, read.anchor.version), (1, 1));
    assert_eq!(serde_json::to_value(&read.origin.locator)?, sign);
    assert_eq!(serde_json::to_value(&read.anchor.locator)?, sign);
    assert_eq!(read.resolution, AnnotationResolution::Pinned);
    assert_eq!(read.comments.len(), 1, "the opening comment");
    assert_eq!(fixture.threads(photo)?, 1);
    Ok(())
}

#[test]
fn an_image_pin_outside_the_canvas_an_overlay_or_on_a_text_artifact_is_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let photo = fixture.artifact("photo.png", "image/png", &png(40, 20)?)?;
    let past = match fixture.pin_refusal(photo, &region(30, 0, 11, 20)) {
        Ok(refusal) => refusal,
        Err(err) => panic!("FAILBEFORE: an image pixel locator is a locator: {err}"),
    };
    let past = past.ok_or("a region past the right edge is refused")?;
    assert!(past.contains("outside the image"), "{past}");
    let below = fixture
        .pin_refusal(photo, &region(0, 19, 40, 2))?
        .ok_or("a region past the bottom edge is refused")?;
    assert!(below.contains("outside the image"), "{below}");
    assert!(
        fixture.pin_refusal(photo, &region(4, 2, 0, 16))?.is_some(),
        "an empty region is refused"
    );
    assert!(
        fixture
            .pin_refusal(photo, &region(u32::MAX, 0, 2, 2))?
            .is_some(),
        "a region whose edge overflows is refused"
    );
    let overlay = fixture
        .pin_refusal(photo, &json!({ "format": "image_object", "overlay": 0 }))?
        .ok_or("an overlay is refused")?;
    assert!(overlay.contains("overlay"), "{overlay}");
    let words = fixture
        .pin_refusal(
            photo,
            &json!({ "format": "text", "char_start": 0, "char_end": 1 }),
        )?
        .ok_or("a text locator on an image is refused")?;
    assert!(words.contains("does not match"), "{words}");

    // EXIF orientation 6 turns the stored 8 x 6 JPEG into a 6 x 8 canvas.
    let turned = fixture.artifact("turned.jpg", "image/jpeg", &jpeg(8, 6, 6)?)?;
    assert!(
        fixture.pin_refusal(turned, &region(0, 0, 6, 8))?.is_none(),
        "the turned canvas pins whole"
    );
    let stored = fixture
        .pin_refusal(turned, &region(0, 0, 8, 6))?
        .ok_or("the stored, unturned size is outside the canvas")?;
    assert!(stored.contains("outside the image"), "{stored}");

    let note = fixture.artifact("note.txt", "text/plain", b"a note")?;
    let mismatch = fixture
        .pin_refusal(note, &region(0, 0, 1, 1))?
        .ok_or("an image locator on a text artifact is refused")?;
    assert!(mismatch.contains("does not match"), "{mismatch}");

    for artifact in [photo, turned, note] {
        assert_eq!(fixture.threads(artifact)?, 0, "nothing opened");
    }
    Ok(())
}
