use oneiron::{
    IMAGE_SOURCE_ID, INGEST_SOURCE_REGISTRY, ImageTextRecognizer, IngestResult, LocalityRung,
    RecognizedText, register_image_text_recognizer,
};

struct CannedHostLocal;
impl ImageTextRecognizer for CannedHostLocal {
    fn locality(&self) -> LocalityRung {
        LocalityRung::HostLocal
    }
    fn recognize(&self, _bytes: &[u8]) -> IngestResult<RecognizedText> {
        Ok(RecognizedText {
            text: "injected receipt text".to_owned(),
        })
    }
}

static RECOGNIZER: CannedHostLocal = CannedHostLocal;
const RECEIPT: &[u8] = include_bytes!("../tests/fixtures/image_receipt.jpg");

#[test]
fn public_injection_normalizes_with_provenance_and_exif() {
    register_image_text_recognizer(&RECOGNIZER).expect("first registration");
    assert!(register_image_text_recognizer(&RECOGNIZER).is_err());

    let batch = INGEST_SOURCE_REGISTRY
        .normalize_binary(IMAGE_SOURCE_ID, RECEIPT)
        .expect("receipt normalizes");
    let entity = &batch.entities[0];
    assert!(entity.body.contains("[OCR]\ninjected receipt text"));
    assert!(entity.body.contains("[PROVENANCE recognizer_locality=1]"));
    assert_eq!(entity.recognizer_locality, Some(LocalityRung::HostLocal));
    assert!(entity.body.contains("[EXIF]"));
    assert!(entity.body.contains("DateTimeOriginal="));
}

#[test]
fn public_registry_rejects_corrupt_signed_vectors() {
    let jpeg = [0xff, 0xd8, 0xff, 0xda, 0x00, 0x00, 0xff, 0xd9];
    assert!(
        INGEST_SOURCE_REGISTRY
            .normalize_binary(IMAGE_SOURCE_ID, &jpeg)
            .is_err()
    );
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png.resize(33, 0);
    assert!(
        INGEST_SOURCE_REGISTRY
            .normalize_binary(IMAGE_SOURCE_ID, &png)
            .is_err()
    );
}
