//! Every verb of the image organ answers as its own process behind the
//! organ host, under the organ's syscall filter (ARCH-0075 "Syscalls", FIX
//! [ORGAN-SECCOMP-ALLOW-LIST]): inspect, open (PNG, JPEG and WebP), crop,
//! resize, annotate, export, render and preview. The source and the export
//! pass the inline bound, so they cross as regions. A trace run of this
//! file (`--cfg oneiron_test_support` with `ONEIRON_SYSCALL_TRACE`) records
//! the calls the image organ's allow-list names.
#![cfg(unix)]

mod fixtures;

use std::time::Duration;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::SecretSight;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_image::{
    VERB_ANNOTATE, VERB_CROP, VERB_EXPORT, VERB_INSPECT, VERB_OPEN, VERB_PREVIEW, VERB_RENDER,
    VERB_RESIZE,
};
use oneiron_organ_host::{
    CallClass, HostConfig, OrganCall, OrganHost, OrganInput, OrganSpec, SightedInput,
};
use oneiron_organ_protocol::{TypedBody, Value};

const ORGAN: &str = env!("CARGO_BIN_EXE_oneiron-image-organ");

/// The side of the noisy source: its PNG passes the 64 KiB inline bound.
const SIDE: u32 = 256;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn put_image(vault: &Vault, bytes: &[u8], media_type: &str) -> OrganInput {
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
    OrganInput {
        artifact,
        version: version.version,
    }
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
        // The test's vault holds no secret marks, so every sight reads the stored bytes.
        inputs: inputs
            .into_iter()
            .map(|input| SightedInput {
                input,
                sight: SecretSight::Owner,
            })
            .collect(),
        class: CallClass::Interactive,
        deadline: Duration::from_secs(30),
        grant: "photo-edit".into(),
    }
}

/// A pixel no PNG filter predicts, so the source does not compress.
fn noise(x: u32, y: u32) -> [u8; 4] {
    let [r, g, b, _] = (x.wrapping_mul(0x9e37_79b1) ^ y.wrapping_mul(0x85eb_ca77))
        .wrapping_mul(0xc2b2_ae3d)
        .to_le_bytes();
    [r, g, b, 255]
}

fn crop(x: u32, y: u32, w: u32, h: u32) -> Value {
    map(vec![
        ("x", x.into()),
        ("y", y.into()),
        ("w", w.into()),
        ("h", h.into()),
    ])
}

fn resize(w: u32, h: u32, filter: &str) -> Value {
    map(vec![
        ("w", w.into()),
        ("h", h.into()),
        ("filter", filter.into()),
    ])
}

/// One `image.render` op: its name as `op`, beside the op's own args.
fn op(name: &str, args: Value) -> Value {
    let Ok(mut pairs) = args.into_map() else {
        panic!("an op's args are a map");
    };
    pairs.insert(0, ("op".into(), name.into()));
    Value::Map(pairs)
}

fn dot() -> Value {
    map(vec![
        (
            "shape",
            map(vec![(
                "freehand",
                map(vec![(
                    "points",
                    Value::Array(vec![map(vec![
                        ("x", Value::F32(0.5)),
                        ("y", Value::F32(0.5)),
                    ])]),
                )]),
            )]),
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
    ])
}

#[test]
fn every_image_verb_answers_through_the_host() {
    let png = fixtures::png(
        SIDE,
        SIDE,
        &fixtures::pixels(SIDE, SIDE, noise),
        fixtures::Extra::default(),
    );
    assert!(png.len() > 64 * 1024, "the source crosses as a region");
    let jpeg = fixtures::jpeg_flat(32, 24, [200, 120, 40], None);
    let webp = fixtures::webp_lossless(16, 16, &fixtures::pixels(16, 16, fixtures::coded));
    let (_dir, vault) = vault();
    let source = put_image(&vault, &png, "image/png");
    let jpeg = put_image(&vault, &jpeg, "image/jpeg");
    let webp = put_image(&vault, &webp, "image/webp");
    let host = OrganHost::new(HostConfig::default());
    let mut spec = OrganSpec::first_party("image", ORGAN);
    spec.verbs = [
        VERB_INSPECT,
        VERB_OPEN,
        VERB_CROP,
        VERB_RESIZE,
        VERB_ANNOTATE,
        VERB_EXPORT,
        VERB_RENDER,
        VERB_PREVIEW,
    ]
    .map(String::from)
    .into();
    spec.media_types = ["image/png", "image/jpeg", "image/webp"]
        .map(String::from)
        .into();
    host.install(spec);
    let answer = |verb: &str, args: Value, body: Option<TypedBody>, inputs: Vec<OrganInput>| {
        host.call(&vault, call(verb, args, body, inputs))
            .unwrap_or_else(|error| panic!("{verb}: {error:?}"))
    };

    answer(VERB_INSPECT, Value::Nil, None, vec![source]);
    for other in [jpeg, webp] {
        answer(VERB_OPEN, Value::Nil, None, vec![other]);
    }
    let opened = answer(VERB_OPEN, Value::Nil, None, vec![source]);
    let cropped = answer(VERB_CROP, crop(8, 8, 200, 180), opened.body, Vec::new());
    let resized = answer(
        VERB_RESIZE,
        resize(220, 190, "bilinear"),
        cropped.body,
        Vec::new(),
    );
    let annotated = answer(VERB_ANNOTATE, dot(), resized.body, Vec::new());
    let exported = answer(
        VERB_EXPORT,
        map(vec![("format", "png".into())]),
        annotated.body,
        vec![source],
    );
    let [output] = exported.outputs.as_slice() else {
        panic!("export makes one output");
    };
    assert!(output.len() > 64 * 1024, "the export crosses as a region");
    let ops = Value::Array(vec![
        op("crop", crop(4, 4, 128, 96)),
        op("resize", resize(64, 48, "nearest")),
    ]);
    let rendered = answer(
        VERB_RENDER,
        map(vec![("ops", ops.clone()), ("format", "png".into())]),
        None,
        vec![source],
    );
    assert_eq!(rendered.outputs.len(), 1, "render makes one PNG");
    let previewed = answer(
        VERB_PREVIEW,
        map(vec![("ops", ops), ("max_side", 32u32.into())]),
        None,
        vec![source],
    );
    assert_eq!(previewed.outputs.len(), 1, "preview makes one PNG");
}
