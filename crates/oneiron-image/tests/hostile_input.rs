//! Inputs built to slip past the header checks (the second PR2 review
//! round). Each is refused, or read the way its format says, before a
//! decoder allocates for what it claims; and an edit never leaves a body
//! that export then refuses.
#![cfg(unix)]

mod fixtures;

use std::sync::atomic::AtomicBool;

use fixtures::{Extra, coded, pixels, png};
use oneiron_image::{
    ImageBody, ImageOrgan, VERB_ANNOTATE, VERB_CROP, VERB_EXPORT, VERB_INSPECT, VERB_OPEN,
};
use oneiron_organ_protocol::{
    Answer, CallContext, ErrorCode, InputBytes, Limits, Organ, OrganError, TypedBody,
};
use rmpv::Value;

const LIMITS: Limits = Limits {
    threads: 1,
    memory_bytes: 256 * 1024 * 1024,
    max_call_frame: 64 * 1024 * 1024,
    max_reply_frame: 64 * 1024 * 1024,
};

fn call(
    organ: &ImageOrgan,
    verb: &str,
    args: Value,
    body: Option<&TypedBody>,
    inputs: &[InputBytes],
) -> Result<Answer, OrganError> {
    let cancel = AtomicBool::new(false);
    organ.call(&CallContext::new(
        verb, 1, &args, body, inputs, LIMITS, &cancel,
    ))
}

fn open_under(memory_bytes: u64, media_type: &str, bytes: Vec<u8>) -> Result<Answer, OrganError> {
    let inputs = [InputBytes::inline(media_type, bytes)];
    let limits = Limits {
        memory_bytes,
        ..LIMITS
    };
    let cancel = AtomicBool::new(false);
    ImageOrgan::default().call(&CallContext::new(
        VERB_OPEN,
        1,
        &Value::Nil,
        None,
        &inputs,
        limits,
        &cancel,
    ))
}

fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .as_map()
        .and_then(|map| map.iter().find(|(k, _)| k.as_str() == Some(key)))
        .map_or(&Value::Nil, |(_, v)| v)
}

fn code(result: Result<Answer, OrganError>) -> ErrorCode {
    result.expect_err("the organ refuses").code
}

fn inspect(media_type: &str, bytes: Vec<u8>) -> Result<Answer, OrganError> {
    let inputs = [InputBytes::inline(media_type, bytes)];
    call(
        &ImageOrgan::default(),
        VERB_INSPECT,
        Value::Nil,
        None,
        &inputs,
    )
}

fn open(media_type: &str, bytes: Vec<u8>) -> Result<Answer, OrganError> {
    let inputs = [InputBytes::inline(media_type, bytes)];
    call(&ImageOrgan::default(), VERB_OPEN, Value::Nil, None, &inputs)
}

/// sRGB's encoded-to-linear curve (IEC 61966-2-1).
fn srgb_to_linear(v: f64) -> f64 {
    if v <= 0.040_45 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

/// sRGB's curve as a `curv` table of `count` entries.
fn srgb_table(count: u16) -> Vec<u16> {
    (0..count)
        .map(|i| {
            let linear = srgb_to_linear(f64::from(i) / f64::from(count - 1));
            (linear * 65_535.0).round() as u16
        })
        .collect()
}

#[test]
fn tone_curves_that_are_not_srgb_are_refused_whole() {
    let rgba = pixels(2, 2, coded);
    let tagged = |curve: Vec<u8>| {
        let icc = fixtures::icc_profile_with("sRGB IEC61966-2.1", fixtures::SRGB_COLORANTS, curve);
        png(
            2,
            2,
            &rgba,
            Extra {
                exif: None,
                icc: Some(icc),
            },
        )
    };
    // sRGB's curve as a table opens.
    let table = fixtures::curv(&srgb_table(1024));
    assert!(open("image/png", tagged(table)).is_ok());

    let srgb = [2.4, 1.0 / 1.055, 0.055 / 1.055, 1.0 / 12.92, 0.040_45];
    let mut offsets = srgb.to_vec();
    offsets.extend([0.1, 0.1]);
    // Every 32nd entry on sRGB's curve, the ones between held flat: a
    // nine-point sample sees only the anchors.
    let anchors = srgb_table(257);
    let plateau: Vec<u16> = (0..257).map(|i| anchors[i / 32 * 32]).collect();
    let refused = [
        ("a linear two-entry table", fixtures::curv(&[0, 65_535])),
        ("a table flat between its anchors", fixtures::curv(&plateau)),
        ("type 4 with nonzero offsets", fixtures::para(4, &offsets)),
        ("type 4 without its offsets", fixtures::para(4, &srgb)),
        (
            "type 3 with a wrong gamma",
            fixtures::para(3, &[2.2, srgb[1], srgb[2], srgb[3], srgb[4]]),
        ),
    ];
    for (why, curve) in refused {
        assert_eq!(
            code(open("image/png", tagged(curve))),
            ErrorCode::Unsupported,
            "{why}"
        );
    }

    // A tag table that claims more entries than the profile holds.
    let mut profile = fixtures::icc_profile("sRGB IEC61966-2.1", fixtures::SRGB_COLORANTS);
    profile[128..132].copy_from_slice(&4096u32.to_be_bytes());
    let short = png(
        2,
        2,
        &rgba,
        Extra {
            exif: None,
            icc: Some(profile),
        },
    );
    assert_eq!(code(open("image/png", short)), ErrorCode::Unsupported);

    // A LUT transform beside sRGB's colorants and curves: a colour engine
    // uses the LUT, which this check does not read.
    let table = fixtures::curv(&srgb_table(1024));
    let lut = fixtures::icc_profile_tags(
        "sRGB IEC61966-2.1",
        fixtures::SRGB_COLORANTS,
        table,
        vec![(b"A2B0", b"mAB \0\0\0\0".to_vec())],
    );
    let lut = png(
        2,
        2,
        &rgba,
        Extra {
            exif: None,
            icc: Some(lut),
        },
    );
    assert_eq!(code(open("image/png", lut)), ErrorCode::Unsupported);
}

#[test]
fn png_colour_chunks_the_decoder_would_skip_are_refused() {
    let still = png(2, 2, &pixels(2, 2, coded), Extra::default());
    // Linear samples, then a higher-precedence chunk the decoder skips as
    // malformed (PNG 3rd ed.: sRGB holds one byte, cICP four).
    let linear = fixtures::png_insert(&still, b"gAMA", &100_000u32.to_be_bytes());
    let mut bad_crc = fixtures::png_insert(&linear, b"sRGB", &[0]);
    // Signature (8) and IHDR (25), then the sRGB chunk's length, type and byte.
    bad_crc[33 + 8 + 1] ^= 0xff;
    let cases = [
        (
            "an empty sRGB chunk",
            fixtures::png_insert(&linear, b"sRGB", &[]),
        ),
        (
            "a five-byte cICP chunk",
            fixtures::png_insert(&linear, b"cICP", &[1, 13, 0, 1, 0]),
        ),
        ("an sRGB chunk with a bad checksum", bad_crc),
        (
            "a second gAMA chunk",
            fixtures::png_insert(&linear, b"gAMA", &45_455u32.to_be_bytes()),
        ),
    ];
    for (why, bytes) in cases {
        assert_eq!(
            code(inspect("image/png", bytes)),
            ErrorCode::BadRequest,
            "{why}"
        );
    }
}

#[test]
fn webp_chunks_the_decoder_would_read_unchecked_are_refused_first() {
    let still = fixtures::webp_lossless(1, 1, &[10, 20, 30, 255]);
    let vp8l = fixtures::vp8l_of(&still);
    let gibibyte = (1u32 << 30).to_le_bytes();

    // Past the declared end, an ICC chunk header claiming a gibibyte: the
    // decoder sees only the declared RIFF, so the file reads as its pixel.
    let mut trailing = fixtures::webp_of(&[
        (b"VP8X", fixtures::vp8x(0x10, 1, 1)),
        (b"VP8L", vp8l.clone()),
    ]);
    trailing.extend(b"ICCP");
    trailing.extend(gibibyte);
    let report = inspect("image/webp", trailing).expect("inspect").report;
    assert_eq!(field(&report, "width").as_u64(), Some(1));

    // Two frames: the decoder takes the first (16383 wide); one is allowed.
    let big = vec![0x10, 0, 0, 0x9d, 0x01, 0x2a, 0xff, 0x3f, 0xff, 0x3f];
    let small = vec![0x10, 0, 0, 0x9d, 0x01, 0x2a, 0x01, 0, 0x01, 0];
    let two = fixtures::webp_of(&[
        (b"VP8X", fixtures::vp8x(0, 1, 1)),
        (b"VP8 ", big),
        (b"VP8 ", small),
    ]);
    assert_eq!(code(inspect("image/webp", two)), ErrorCode::BadRequest);

    // A frame holding an ICC chunk that claims a gibibyte: refused as an
    // animation with its frames unread, with or without the animation flag.
    let mut anmf = vec![0u8; 16];
    anmf.extend(b"ICCP");
    anmf.extend(gibibyte);
    for (flags, first) in [(0x02, (b"ANIM", vec![0; 6])), (0, (b"VP8L", vp8l))] {
        let animated = fixtures::webp_of(&[
            (b"VP8X", fixtures::vp8x(flags, 1, 1)),
            (first.0, first.1),
            (b"ANMF", anmf.clone()),
        ]);
        let report = inspect("image/webp", animated).expect("inspect").report;
        let refusal = field(&report, "refusal").as_str().unwrap_or_default();
        assert!(refusal.contains("animated"), "{refusal}");
    }

    // A lossless side of 16,384, which the decoder misreads, is named.
    let bits: u32 = 16_383;
    let mut wide = vec![0x2f];
    wide.extend(bits.to_le_bytes());
    wide.extend([0, 0, 0]);
    let wide = fixtures::webp_of(&[(b"VP8L", wide)]);
    assert_eq!(code(inspect("image/webp", wide)), ErrorCode::Unsupported);
}

#[test]
fn a_webp_reads_its_exif_and_its_alpha_as_written() {
    // EXIF behind the "Exif\0\0" prefix some writers add: still read.
    let still = fixtures::webp_lossless(3, 2, &pixels(3, 2, coded));
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend(fixtures::exif_orientation(6));
    let turned = fixtures::webp_of(&[
        (b"VP8X", fixtures::vp8x(0x10 | 0x08, 3, 2)),
        (b"VP8L", fixtures::vp8l_of(&still)),
        (b"EXIF", exif),
    ]);
    let report = inspect("image/webp", turned).expect("inspect").report;
    assert_eq!(field(&report, "orientation").as_u64(), Some(6));
    assert_eq!(field(&report, "width").as_u64(), Some(2));

    // A half-transparent pixel behind a cleared alpha hint (a hint only,
    // per the lossless format): the decoder would drop it, so open refuses.
    let mut hidden = fixtures::webp_lossless(1, 1, &[255, 0, 0, 128]);
    // RIFF (12), the VP8L chunk header (8), the signature byte, then the
    // header's last byte holds the hint at 0x10.
    hidden[12 + 8 + 4] &= !0x10;
    assert_eq!(code(open("image/webp", hidden)), ErrorCode::BadRequest);
    // The same opaque pixel opens.
    let mut opaque = fixtures::webp_lossless(1, 1, &[255, 0, 0, 255]);
    opaque[12 + 8 + 4] &= !0x10;
    assert!(open("image/webp", opaque).is_ok());
}

#[test]
fn a_jpeg_header_past_the_prefix_is_too_large_not_corrupt() {
    // 272 comment segments ahead of a valid 1x1 JPEG's header: 17.8 MB.
    let jpeg = fixtures::jpeg_flat(1, 1, [10, 20, 30], None);
    let mut padded = jpeg[..2].to_vec();
    for _ in 0..272 {
        padded.extend([0xff, 0xfe, 0xff, 0xff]);
        padded.extend(std::iter::repeat_n(b'x', 65_533));
    }
    padded.extend(&jpeg[2..]);
    assert_eq!(code(inspect("image/jpeg", padded)), ErrorCode::TooLarge);

    // A header that ends early, in a long file, is still corrupt.
    let mut early = vec![0xff, 0xd8, 0xff, 0xd9];
    early.resize(18 * 1024 * 1024, 0);
    assert_eq!(code(inspect("image/jpeg", early)), ErrorCode::BadRequest);
}

#[test]
fn a_baseline_jpeg_is_booked_for_rows_not_whole_coefficient_planes() {
    // A single-scan baseline JPEG decodes a row of blocks at a time: at a
    // 64 MiB grant (32 MiB of work), a 2000x1500 one opens. Booked for four
    // whole coefficient planes, it would not.
    let jpeg = fixtures::jpeg_flat(2000, 1500, [90, 120, 150], None);
    open_under(64 * 1024 * 1024, "image/jpeg", jpeg).expect("open");
}

#[test]
fn a_crop_or_a_flag_never_leaves_a_body_export_refuses() {
    let organ = ImageOrgan::default();
    let source = [InputBytes::inline(
        "image/png",
        png(2048, 2048, &pixels(2048, 2048, coded), Extra::default()),
    )];
    let opened = call(&organ, VERB_OPEN, Value::Nil, None, &source).expect("open");
    let opened = opened.body.expect("body");
    // A wide brush dabbed 18 times on one spot, then cropped to one pixel:
    // painting it visits a few pixels, and export must take it.
    let dab = map(vec![("x", Value::F32(512.0)), ("y", Value::F32(512.0))]);
    let args = map(vec![
        (
            "shape",
            map(vec![
                ("type", "freehand".into()),
                ("points", Value::Array(vec![dab; 18])),
            ]),
        ),
        (
            "stroke",
            map(vec![
                (
                    "rgba",
                    Value::Array([0u8, 0, 0, 255].iter().map(|c| Value::from(*c)).collect()),
                ),
                ("width", Value::F32(1024.0)),
            ]),
        ),
    ]);
    let annotated = call(&organ, VERB_ANNOTATE, args, Some(&opened), &[]).expect("annotate");
    let annotated = annotated.body.expect("body");
    let crop = map(vec![
        ("x", 512u32.into()),
        ("y", 512u32.into()),
        ("w", 1u32.into()),
        ("h", 1u32.into()),
    ]);
    let cropped = call(&organ, VERB_CROP, crop, Some(&annotated), &[]).expect("crop");
    let cropped = cropped.body.expect("body");
    let export = map(vec![("format", "png".into())]);
    call(&organ, VERB_EXPORT, export.clone(), Some(&cropped), &source)
        .expect("export takes what crop returned");

    // A body whose overlay denies being clipped, when its bounds cross the
    // canvas edge, is refused.
    let mut lying = ImageBody::from_typed(Some(&cropped)).expect("body");
    lying.overlays[0].clipped = false;
    let lying = lying.to_typed().expect("typed");
    assert_eq!(
        code(call(&organ, VERB_EXPORT, export, Some(&lying), &source)),
        ErrorCode::BadRequest
    );
}
