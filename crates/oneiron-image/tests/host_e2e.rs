//! The image organ as its own process behind the organ host, over a real
//! vault blob (ART-1 "done means", the agent half): open, crop, annotate and
//! export a PNG the vault holds. The host hashes the export itself, and the
//! bytes decode with the codec crate alone.
#![cfg(unix)]

mod fixtures;

use std::time::Duration;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_image::{VERB_ANNOTATE, VERB_CROP, VERB_EXPORT, VERB_OPEN};
use oneiron_organ_host::{CallClass, HostConfig, OrganCall, OrganHost, OrganInput, OrganSpec};
use oneiron_organ_protocol::{Hash32, TypedBody};
use rmpv::Value;

const ORGAN: &str = env!("CARGO_BIN_EXE_oneiron-image-organ");

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn vault_with(bytes: &[u8], media_type: &str) -> (tempfile::TempDir, Vault, OrganInput) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    let actor = EntityId::now();
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"uploader")
        .expect("actor");
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("photo", media_type),
            at(1),
            1,
        )
        .expect("artifact");
    let version = vault
        .append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(actor, EdgeActorClass::Human),
            at(2),
            2,
        )
        .expect("version");
    let input = OrganInput {
        artifact,
        version: version.version,
    };
    (dir, vault, input)
}

fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn call(verb: &str, args: Value, body: Option<TypedBody>, inputs: Vec<OrganInput>) -> OrganCall {
    OrganCall {
        organ: "image".into(),
        verb: verb.into(),
        schema: 1,
        args,
        body,
        inputs,
        class: CallClass::Interactive,
        deadline: Duration::from_secs(20),
        grant: "photo-edit".into(),
    }
}

#[test]
fn a_vault_image_opens_crops_annotates_and_exports_through_the_host() {
    let (w, h) = (9, 7);
    let png = fixtures::png(
        w,
        h,
        &fixtures::pixels(w, h, fixtures::coded),
        fixtures::Extra::default(),
    );
    let (_dir, vault, source) = vault_with(&png, "image/png");
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("image", ORGAN);
    spec.verbs = [VERB_OPEN, VERB_CROP, VERB_ANNOTATE, VERB_EXPORT]
        .map(String::from)
        .into();
    spec.media_types = vec!["image/png".to_owned()];
    host.install(spec);

    let opened = host
        .call(&vault, call(VERB_OPEN, Value::Nil, None, vec![source]))
        .expect("open");
    assert_eq!(
        opened.receipt.inputs[0].content_hash,
        Hash32(*blake3::hash(&png).as_bytes()),
        "the receipt names the vault's bytes"
    );
    let crop = map(vec![
        ("x", 2.into()),
        ("y", 1.into()),
        ("w", 6.into()),
        ("h", 5.into()),
    ]);
    let cropped = host
        .call(&vault, call(VERB_CROP, crop, opened.body, Vec::new()))
        .expect("crop");
    let line = map(vec![
        (
            "shape",
            map(vec![
                ("type", "freehand".into()),
                (
                    "points",
                    Value::Array(vec![map(vec![
                        ("x", Value::F32(0.5)),
                        ("y", Value::F32(0.5)),
                    ])]),
                ),
            ]),
        ),
        (
            "stroke",
            map(vec![
                (
                    "rgba",
                    Value::Array([0u8, 0, 0, 255].iter().map(|c| Value::from(*c)).collect()),
                ),
                ("width", Value::F32(1.0)),
            ]),
        ),
    ]);
    let annotated = host
        .call(&vault, call(VERB_ANNOTATE, line, cropped.body, Vec::new()))
        .expect("annotate");
    let exported = host
        .call(
            &vault,
            call(
                VERB_EXPORT,
                map(vec![("format", "png".into())]),
                annotated.body,
                vec![source],
            ),
        )
        .expect("export");

    let [output] = exported.outputs.as_slice() else {
        panic!("export makes one output");
    };
    let digest = Hash32(*blake3::hash(output).as_bytes());
    assert_eq!(output.content_hash, digest, "the host hashed what it got");
    assert_eq!(exported.receipt.outputs[0].content_hash, digest);
    assert_eq!(exported.receipt.outputs[0].len, output.len() as u64);
    let losses: Vec<&str> = exported
        .receipt
        .notes
        .losses
        .iter()
        .map(|loss| loss.code.as_str())
        .collect();
    assert_eq!(losses, ["overlays_flattened", "metadata_stripped"]);

    let image = fixtures::decode_png(output);
    assert_eq!(image.dimensions(), (6, 5));
    // The one-point line is a dot on the crop's first pixel; the rest is the source.
    assert_eq!(image.get_pixel(0, 0).0, [0, 0, 0, 255]);
    for (x, y, pixel) in image.enumerate_pixels().skip(1) {
        assert_eq!(pixel.0, fixtures::coded(x + 2, y + 1), "pixel {x},{y}");
    }
}
