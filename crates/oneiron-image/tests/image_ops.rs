//! The image organ's first slice, checked against analytic pixels (ART-1
//! plan, "Fixture and oracle gate"): crop and nearest resize land where the
//! geometry says, EXIF orientation turns the canvas first, overlays stay
//! editable until export, and unsupported or hostile input fails before any
//! pixel buffer exists. Exports are decoded back by the codec crate alone.
#![cfg(unix)]

mod fixtures;

use std::sync::atomic::AtomicBool;

use fixtures::{Extra, coded, decode_png, pixels, png};
use oneiron_image::{
    Filter, Icc, ImageBody, ImageOrgan, Shape, Size, Step, VERB_ANNOTATE, VERB_CROP, VERB_EXPORT,
    VERB_INSPECT, VERB_OPEN, VERB_RESIZE, overlay_locator,
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

fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .as_map()
        .and_then(|map| map.iter().find(|(k, _)| k.as_str() == Some(key)))
        .map_or(&Value::Nil, |(_, v)| v)
}

fn body(answer: &Answer) -> TypedBody {
    answer.body.clone().expect("the verb returns a body")
}

fn parsed(body: &TypedBody) -> ImageBody {
    ImageBody::from_typed(Some(body)).expect("the body reads back")
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

fn export_png(
    organ: &ImageOrgan,
    body: &TypedBody,
    inputs: &[InputBytes],
) -> (Answer, image::RgbaImage) {
    let answer = call(
        organ,
        VERB_EXPORT,
        map(vec![("format", "png".into())]),
        Some(body),
        inputs,
    )
    .expect("export");
    let [output] = answer.outputs.as_slice() else {
        panic!("export makes one output");
    };
    assert_eq!(output.media_type, "image/png");
    let decoded = decode_png(&output.bytes);
    (answer, decoded)
}

fn code(result: Result<Answer, OrganError>) -> ErrorCode {
    result.expect_err("the organ refuses").code
}

#[test]
fn crop_and_nearest_resize_land_on_the_analytic_pixels() {
    let (w, h) = (7, 5);
    let source = || {
        [InputBytes::inline(
            "image/png",
            png(w, h, &pixels(w, h, coded), Extra::default()),
        )]
    };
    let organ = ImageOrgan::default();
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &source()).expect("open"));
    assert_eq!(parsed(&opened).canvas.w, 7);

    // Up 2x after a crop: each kept pixel becomes a 2x2 block.
    let cropped =
        body(&call(&organ, VERB_CROP, crop(1, 2, 5, 3), Some(&opened), &[]).expect("crop"));
    let up = body(
        &call(
            &organ,
            VERB_RESIZE,
            resize(10, 6, "nearest"),
            Some(&cropped),
            &[],
        )
        .expect("resize"),
    );
    // A fresh organ has no decoded cache: export decodes the input again.
    let (_, image) = export_png(&ImageOrgan::default(), &up, &source());
    assert_eq!(image.dimensions(), (10, 6));
    for (x, y, pixel) in image.enumerate_pixels() {
        assert_eq!(pixel.0, coded(1 + x / 2, 2 + y / 2), "pixel {x},{y}");
    }

    // Down to 3x2: centre-aligned nearest reads floor((i + 0.5) * from / to).
    let down = body(
        &call(
            &organ,
            VERB_RESIZE,
            resize(3, 2, "nearest"),
            Some(&opened),
            &[],
        )
        .expect("resize"),
    );
    let (_, image) = export_png(&organ, &down, &source());
    let columns = [1, 3, 5];
    let rows = [1, 3];
    for (x, y, pixel) in image.enumerate_pixels() {
        assert_eq!(
            pixel.0,
            coded(columns[x as usize], rows[y as usize]),
            "pixel {x},{y}"
        );
    }
}

#[test]
fn exif_orientation_turns_the_canvas_before_any_coordinate() {
    // Orientation 6 means "rotate 90 degrees clockwise to display".
    let (w, h) = (3, 2);
    let extra = Extra {
        exif: Some(fixtures::exif_orientation(6)),
        icc: None,
    };
    let inputs = [InputBytes::inline(
        "image/png",
        png(w, h, &pixels(w, h, coded), extra),
    )];
    let organ = ImageOrgan::default();
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &inputs).expect("open"));
    let source = parsed(&opened).source;
    assert_eq!((source.width, source.height, source.orientation), (2, 3, 6));
    let (_, image) = export_png(&organ, &opened, &inputs);
    assert_eq!(image.dimensions(), (2, 3));
    for (x, y, pixel) in image.enumerate_pixels() {
        assert_eq!(pixel.0, coded(y, h - 1 - x), "pixel {x},{y}");
    }

    // JPEG carries orientation too (8: rotate 90 degrees counter-clockwise).
    let jpeg = fixtures::jpeg_flat(4, 2, [200, 40, 90], Some(fixtures::exif_orientation(8)));
    let inputs = [InputBytes::inline("image/jpeg", jpeg)];
    let report = call(&organ, VERB_INSPECT, Value::Nil, None, &inputs)
        .expect("inspect")
        .report;
    assert_eq!(field(&report, "width").as_u64(), Some(2));
    assert_eq!(field(&report, "height").as_u64(), Some(4));
    assert_eq!(field(&report, "orientation").as_u64(), Some(8));
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &inputs).expect("open jpeg"));
    let (_, image) = export_png(&organ, &opened, &inputs);
    assert_eq!(image.dimensions(), (2, 4));
    for pixel in image.pixels() {
        let near = pixel
            .0
            .iter()
            .zip([200u8, 40, 90])
            .all(|(a, b)| a.abs_diff(b) <= 4);
        assert!(near, "a flat JPEG stays flat: {:?}", pixel.0);
    }
}

#[test]
fn corrupt_or_truncated_input_is_refused_never_half_read() {
    let organ = ImageOrgan::default();
    let whole = png(64, 64, &pixels(64, 64, coded), Extra::default());

    let header_cut = [InputBytes::inline("image/png", whole[..20].to_vec())];
    assert_eq!(
        code(call(&organ, VERB_INSPECT, Value::Nil, None, &header_cut)),
        ErrorCode::BadRequest
    );
    assert_eq!(
        code(call(&organ, VERB_OPEN, Value::Nil, None, &header_cut)),
        ErrorCode::BadRequest
    );

    // The header survives, the pixel data does not: inspect reads it, open refuses.
    let data_cut = [InputBytes::inline(
        "image/png",
        whole[..whole.len() / 2].to_vec(),
    )];
    let report = call(&organ, VERB_INSPECT, Value::Nil, None, &data_cut)
        .expect("inspect")
        .report;
    assert_eq!(field(&report, "width").as_u64(), Some(64));
    assert_eq!(
        code(call(&organ, VERB_OPEN, Value::Nil, None, &data_cut)),
        ErrorCode::BadRequest
    );

    // An extended WebP whose canvas says 1x1 over a 2x2 frame: the frame
    // is what a decoder would allocate for, so the header is refused.
    let still = fixtures::webp_lossless(2, 2, &pixels(2, 2, coded));
    let lying = [InputBytes::inline(
        "image/webp",
        fixtures::webp_extended(1, 1, &still),
    )];
    assert_eq!(
        code(call(&organ, VERB_INSPECT, Value::Nil, None, &lying)),
        ErrorCode::BadRequest
    );
    let honest = [InputBytes::inline(
        "image/webp",
        fixtures::webp_extended(2, 2, &still),
    )];
    assert!(call(&organ, VERB_OPEN, Value::Nil, None, &honest).is_ok());

    let text = [InputBytes::inline(
        "image/png",
        b"plain text, not an image".to_vec(),
    )];
    assert_eq!(
        code(call(&organ, VERB_OPEN, Value::Nil, None, &text)),
        ErrorCode::Unsupported
    );
}

#[test]
fn an_oversized_header_is_refused_before_any_pixel_buffer() {
    // 60000 x 60000 RGBA is 14.4 GB; the IHDR says so, the data is one pixel.
    let organ = ImageOrgan::default();
    let tiny = png(1, 1, &[1, 2, 3, 255], Extra::default());
    let inputs = [InputBytes::inline(
        "image/png",
        fixtures::png_lying_size(&tiny, 60_000, 60_000),
    )];
    let report = call(&organ, VERB_INSPECT, Value::Nil, None, &inputs)
        .expect("inspect")
        .report;
    assert_eq!(field(&report, "width").as_u64(), Some(60_000));
    assert_eq!(field(&report, "supported").as_bool(), Some(false));
    assert_eq!(
        code(call(&organ, VERB_OPEN, Value::Nil, None, &inputs)),
        ErrorCode::TooLarge
    );
}

#[test]
fn animation_wide_channels_and_foreign_profiles_are_refused() {
    let organ = ImageOrgan::default();
    let rgba = pixels(2, 2, coded);
    let still_png = png(2, 2, &rgba, Extra::default());
    let still_webp = fixtures::webp_lossless(2, 2, &rgba);
    let refused = [
        ("image/png", fixtures::png_animated(&still_png), "animated"),
        (
            "image/webp",
            fixtures::webp_animated(2, 2, &still_webp),
            "animated",
        ),
        ("image/png", fixtures::png_rgb16(2, 2), "16-bit"),
        (
            "image/png",
            png(
                2,
                2,
                &rgba,
                Extra {
                    exif: None,
                    icc: Some(fixtures::icc_profile("Display P3", fixtures::P3_COLORANTS)),
                },
            ),
            "Display P3",
        ),
        // A wide-gamut profile that calls itself sRGB: the name proves nothing.
        (
            "image/png",
            png(
                2,
                2,
                &rgba,
                Extra {
                    exif: None,
                    icc: Some(fixtures::icc_profile(
                        "sRGB IEC61966-2.1",
                        fixtures::P3_COLORANTS,
                    )),
                },
            ),
            "is not sRGB",
        ),
        // Linear samples, said by gAMA alone: not an untagged sRGB image.
        (
            "image/png",
            fixtures::png_insert(&still_png, b"gAMA", &100_000u32.to_be_bytes()),
            "gamma 1.00",
        ),
    ];
    for (media_type, bytes, why) in refused {
        let inputs = [InputBytes::inline(media_type, bytes)];
        let report = call(&organ, VERB_INSPECT, Value::Nil, None, &inputs)
            .expect("inspect")
            .report;
        assert_eq!(field(&report, "supported").as_bool(), Some(false), "{why}");
        let refusal = field(&report, "refusal").as_str().unwrap_or_default();
        assert!(refusal.contains(why), "{why}: {refusal}");
        assert_eq!(
            code(call(&organ, VERB_OPEN, Value::Nil, None, &inputs)),
            ErrorCode::Unsupported,
            "{why}"
        );
    }

    // A still WebP and an sRGB-tagged PNG open; untagged input is named as assumed sRGB.
    let webp = [InputBytes::inline("image/webp", still_webp)];
    assert!(call(&organ, VERB_OPEN, Value::Nil, None, &webp).is_ok());
    let srgb = png(
        2,
        2,
        &rgba,
        Extra {
            exif: None,
            icc: Some(fixtures::icc_profile(
                "a profile by any name",
                fixtures::SRGB_COLORANTS,
            )),
        },
    );
    let opened = call(
        &organ,
        VERB_OPEN,
        Value::Nil,
        None,
        &[InputBytes::inline("image/png", srgb)],
    )
    .expect("srgb");
    assert_eq!(parsed(&body(&opened)).source.icc, Icc::Srgb);
    assert!(opened.notes.warnings.is_empty());
    let untagged = call(
        &organ,
        VERB_OPEN,
        Value::Nil,
        None,
        &[InputBytes::inline("image/png", still_png)],
    )
    .expect("untagged");
    assert_eq!(parsed(&body(&untagged)).source.icc, Icc::None);
    assert!(untagged.notes.warnings.iter().any(|w| w.contains("sRGB")));
}

#[test]
fn overlays_stay_editable_and_are_painted_only_at_export() {
    let organ = ImageOrgan::default();
    let inputs = [InputBytes::inline(
        "image/png",
        fixtures::png_rgb(20, 20, [255, 255, 255]),
    )];
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &inputs).expect("open"));

    let stroke = |rgba: [u8; 4], width: f32| {
        map(vec![
            (
                "rgba",
                Value::Array(rgba.iter().map(|c| Value::from(*c)).collect()),
            ),
            ("width", Value::F32(width)),
        ])
    };
    let rect = map(vec![
        ("type", "rect".into()),
        ("x", 4.into()),
        ("y", 4.into()),
        ("w", 10.into()),
        ("h", 10.into()),
    ]);
    let annotated = call(
        &organ,
        VERB_ANNOTATE,
        map(vec![
            ("shape", rect),
            ("stroke", stroke([255, 0, 0, 255], 2.0)),
        ]),
        Some(&opened),
        &[],
    )
    .expect("annotate");
    assert!(annotated.notes.touched.contains(&overlay_locator(0)));
    let annotated = body(&annotated);

    // The crop moves the rect to the origin; its stroke now crosses the edge.
    let cropped = call(&organ, VERB_CROP, crop(4, 4, 8, 8), Some(&annotated), &[]).expect("crop");
    assert!(cropped.notes.touched.contains(&overlay_locator(0)));
    let cropped = body(&cropped);
    let overlay = parsed(&cropped).overlays.remove(0);
    assert!(overlay.clipped);
    assert!(matches!(overlay.shape, Shape::Rect { x, y, .. } if x == 0.0 && y == 0.0));

    let arrow = map(vec![
        ("type", "arrow".into()),
        ("from", map(vec![("x", 1.into()), ("y", 6.into())])),
        ("to", map(vec![("x", 6.into()), ("y", 1.into())])),
    ]);
    let both = body(
        &call(
            &organ,
            VERB_ANNOTATE,
            map(vec![
                ("shape", arrow),
                ("stroke", stroke([0, 0, 255, 128], 1.0)),
            ]),
            Some(&cropped),
            &[],
        )
        .expect("annotate arrow"),
    );
    assert_eq!(parsed(&both).next_overlay, 2);

    let (answer, image) = export_png(&organ, &both, &inputs);
    assert!(answer.body.is_none(), "export changes no body");
    // On the rect's left edge, clear of the arrow: full red.
    assert_eq!(image.get_pixel(0, 4).0, [255, 0, 0, 255]);
    // On the arrow's shaft (x + y = 7 through pixel centres): half blue over white.
    let mid = image.get_pixel(3, 3).0;
    assert!(
        mid[0].abs_diff(127) <= 1 && mid[1].abs_diff(127) <= 1 && mid[2] == 255,
        "{mid:?}"
    );
    // Off every stroke: untouched.
    assert_eq!(image.get_pixel(7, 7).0, [255, 255, 255, 255]);
    let codes: Vec<&str> = answer
        .notes
        .losses
        .iter()
        .map(|l| l.code.as_str())
        .collect();
    assert_eq!(codes, ["overlays_flattened", "metadata_stripped"]);
    // A source without alpha exports without it, and with no metadata.
    let output = &answer.outputs[0].bytes;
    assert_eq!(
        image::load_from_memory(output).expect("decode").color(),
        image::ColorType::Rgb8
    );
    for chunk in [b"eXIf", b"iCCP", b"tEXt"] {
        assert!(!output.windows(4).any(|w| w == chunk), "no metadata chunk");
    }
}

#[test]
fn bilinear_resize_never_bleeds_colour_out_of_transparent_pixels() {
    // Opaque red beside fully transparent green: straight-alpha filtering would
    // tint the edge green; premultiplied filtering keeps it red.
    let organ = ImageOrgan::default();
    let rgba = [255, 0, 0, 255, 0, 255, 0, 0];
    let inputs = [InputBytes::inline(
        "image/png",
        png(2, 1, &rgba, Extra::default()),
    )];
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &inputs).expect("open"));
    let wide = body(
        &call(
            &organ,
            VERB_RESIZE,
            resize(8, 1, "bilinear"),
            Some(&opened),
            &[],
        )
        .expect("resize"),
    );
    let (_, image) = export_png(&organ, &wide, &inputs);
    let mut partial = 0;
    for pixel in image.pixels() {
        let [r, g, _, a] = pixel.0;
        if a > 0 {
            assert_eq!((r, g), (255, 0), "{:?}", pixel.0);
        }
        if a > 0 && a < 255 {
            partial += 1;
        }
    }
    assert!(partial > 0, "the edge is blended, not cut");
}

#[test]
fn export_needs_its_source_every_time_and_checks_it_against_the_body() {
    let organ = ImageOrgan::default();
    let clear_red = [InputBytes::inline(
        "image/png",
        png(1, 1, &[255, 0, 0, 0], Extra::default()),
    )];
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &clear_red).expect("open"));
    let export = || map(vec![("format", "png".into())]);
    // The organ has the pixels decoded, but this call grants no source.
    assert_eq!(
        code(call(&organ, VERB_EXPORT, export(), Some(&opened), &[])),
        ErrorCode::BadRequest
    );
    // A body that restates its source cannot make a transparent pixel opaque.
    let mut forged = parsed(&opened);
    forged.source.alpha = false;
    let forged = forged.to_typed().expect("encode");
    assert_eq!(
        code(call(
            &organ,
            VERB_EXPORT,
            export(),
            Some(&forged),
            &clear_red
        )),
        ErrorCode::BadRequest
    );
    let (_, image) = export_png(&organ, &opened, &clear_red);
    assert_eq!(image.get_pixel(0, 0).0[3], 0);
}

#[test]
fn sizes_past_the_side_limit_are_refused_before_any_arithmetic() {
    let organ = ImageOrgan::default();
    let one = [InputBytes::inline(
        "image/png",
        png(1, 1, &[1, 2, 3, 255], Extra::default()),
    )];
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &one).expect("open"));
    let huge = 1u32 << 31;
    assert_eq!(
        code(call(
            &organ,
            VERB_RESIZE,
            resize(huge, huge, "nearest"),
            Some(&opened),
            &[]
        )),
        ErrorCode::TooLarge
    );
    // The same step written straight into a body is refused as it is read.
    let mut forged = parsed(&opened);
    forged.steps.push(Step::Resize {
        w: huge,
        h: huge,
        filter: Filter::Nearest,
    });
    forged.canvas = Size { w: huge, h: huge };
    let forged = forged.to_typed().expect("encode");
    assert_eq!(
        code(call(
            &organ,
            VERB_EXPORT,
            map(vec![("format", "png".into())]),
            Some(&forged),
            &one
        )),
        ErrorCode::TooLarge
    );
}

#[test]
fn an_edit_never_returns_a_body_the_next_call_refuses() {
    // A far-off point is allowed, but doubling the canvas would carry it
    // past the coordinate bound: the resize is refused, not returned.
    let organ = ImageOrgan::default();
    let one = [InputBytes::inline(
        "image/png",
        png(1, 1, &[1, 2, 3, 255], Extra::default()),
    )];
    let opened = body(&call(&organ, VERB_OPEN, Value::Nil, None, &one).expect("open"));
    let far = map(vec![
        (
            "shape",
            map(vec![
                ("type", "freehand".into()),
                (
                    "points",
                    Value::Array(vec![map(vec![
                        ("x", Value::F32(16_777_216.0)),
                        ("y", Value::F32(0.0)),
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
    let annotated = body(&call(&organ, VERB_ANNOTATE, far, Some(&opened), &[]).expect("annotate"));
    assert_eq!(
        code(call(
            &organ,
            VERB_RESIZE,
            resize(2, 2, "nearest"),
            Some(&annotated),
            &[]
        )),
        ErrorCode::BadRequest
    );
}
