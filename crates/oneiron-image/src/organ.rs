//! The image organ: six verbs over the `image` body, schema 1.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use image::RgbaImage;
use oneiron_organ_protocol::{
    Answer, CallContext, ErrorCode, Hash32, InputBytes, Loss, Notes, Organ, OrganError,
    OrganIdentity, OutputBytes, VerbSpec,
};
use serde::Deserialize;

use crate::body::{Filter, Format, Icc, ImageBody, KIND, Shape, Source, Stroke, bad, from_value};
use crate::decode::{Header, Profile, check_size, decode, read_header};
use crate::ops::{self, Edited};
use crate::render::{check_paint, encode_png, render};

pub const VERB_INSPECT: &str = "image.inspect";
pub const VERB_OPEN: &str = "image.open";
pub const VERB_CROP: &str = "image.crop";
pub const VERB_RESIZE: &str = "image.resize";
pub const VERB_ANNOTATE: &str = "image.annotate";
pub const VERB_EXPORT: &str = "image.export";

/// Every verb, with whether it reads a body.
const VERBS: [(&str, bool); 6] = [
    (VERB_INSPECT, false),
    (VERB_OPEN, false),
    (VERB_CROP, true),
    (VERB_RESIZE, true),
    (VERB_ANNOTATE, true),
    (VERB_EXPORT, true),
];

const UNTAGGED: &str = "the source has no colour profile; it is read as sRGB";

/// The image organ. It keeps decoded sources by content hash, within a
/// quarter of its memory grant, so an export after `open` does not decode
/// again. Pixel work books from one allowance, half the grant, that every
/// call in flight shares.
#[derive(Debug, Default)]
pub struct ImageOrgan {
    decoded: Mutex<Decoded>,
    /// Bytes of the work allowance the calls in flight hold.
    held: Mutex<u64>,
}

/// Work memory one call holds, given back when it drops.
struct Held<'a> {
    organ: &'a ImageOrgan,
    bytes: u64,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let mut held = lock(&self.organ.held);
        *held = held.saturating_sub(self.bytes);
    }
}

/// What the cache counts for one entry beside its pixels: its key, its
/// `Arc` and image headers, and allocator slack.
const ENTRY_OVERHEAD: u64 = 4096;
/// The most entries the cache keeps, however small.
const MAX_ENTRIES: usize = 64;

#[derive(Debug, Default)]
struct Decoded {
    entries: VecDeque<(Hash32, Arc<RgbaImage>)>,
    bytes: u64,
}

fn entry_bytes(image: &RgbaImage) -> u64 {
    (image.as_raw().capacity() as u64).saturating_add(ENTRY_OVERHEAD)
}

impl Decoded {
    fn get(&mut self, hash: &Hash32) -> Option<Arc<RgbaImage>> {
        let at = self.entries.iter().position(|(key, _)| key == hash)?;
        let entry = self.entries.remove(at)?;
        let image = Arc::clone(&entry.1);
        self.entries.push_back(entry);
        Some(image)
    }

    fn insert(&mut self, hash: Hash32, image: Arc<RgbaImage>, cap: u64) {
        let size = entry_bytes(&image);
        if size > cap || self.entries.iter().any(|(key, _)| *key == hash) {
            return;
        }
        while self.bytes + size > cap || self.entries.len() >= MAX_ENTRIES {
            let Some((_, old)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= entry_bytes(&old);
        }
        self.bytes += size;
        self.entries.push_back((hash, image));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one decoded source may take: a quarter of the grant. The cache
/// holds another quarter, and pixel work (decodes, renders, encodes) books
/// from the shared half.
fn decode_budget(call: &CallContext<'_>) -> u64 {
    call.limits.memory_bytes / 4
}

fn work_budget(call: &CallContext<'_>) -> u64 {
    call.limits.memory_bytes / 2
}

/// The copy of the whole file a decoder may make: a JPEG decoder copies its
/// input first, and a WebP whose alpha the header hides is decoded from a
/// copy.
fn file_copy(header: &Header, input: &InputBytes) -> u64 {
    if header.format == Format::Png {
        0
    } else {
        input.len() as u64
    }
}

/// A JPEG decoder keeps a 16-bit coefficient plane per component (up to
/// four), each padded to whole 32-pixel blocks, beside its output.
fn jpeg_scratch(header: &Header) -> u64 {
    if header.format != Format::Jpeg {
        return 0;
    }
    let padded = |side: u32| u64::from(side).div_ceil(32) * 32;
    let components = if header.channels == 1 { 1 } else { 4 };
    padded(header.stored_width) * padded(header.stored_height) * components * 2
}

/// What decoding `header` holds at its peak. While it decodes: the file
/// copy, the scratch and the decoded pixels (counted at four bytes, the
/// widest a decoder gives). Then the turned copy an EXIF orientation makes,
/// and the RGBA kept beside the decoded pixels it comes from.
fn decode_cost(header: &Header, input: &InputBytes) -> u64 {
    let decoded = header.rgba_bytes();
    let decoding = file_copy(header, input)
        .saturating_add(jpeg_scratch(header))
        .saturating_add(decoded);
    let turning = if header.orientation == 1 {
        0
    } else {
        decoded.saturating_mul(2)
    };
    decoding.max(turning).max(decoded.saturating_mul(2))
}

#[derive(Deserialize)]
struct CropArgs {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

#[derive(Deserialize)]
struct ResizeArgs {
    w: u32,
    h: u32,
    filter: Filter,
}

#[derive(Deserialize)]
struct AnnotateArgs {
    shape: Shape,
    stroke: Stroke,
}

#[derive(Deserialize)]
struct ExportArgs {
    format: String,
}

impl Organ for ImageOrgan {
    fn identity(&self) -> OrganIdentity {
        OrganIdentity {
            name: "image".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn verbs(&self) -> Vec<VerbSpec> {
        VERBS
            .iter()
            .map(|(name, reads_body)| VerbSpec {
                name: (*name).to_owned(),
                schema: 1,
                kinds: if *reads_body {
                    vec![KIND.to_owned()]
                } else {
                    Vec::new()
                },
            })
            .collect()
    }

    fn call(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
        match call.verb {
            VERB_INSPECT => inspect(call),
            VERB_OPEN => self.open(call),
            VERB_CROP => {
                let args: CropArgs = from_value(call.args, "crop args")?;
                let body = ImageBody::from_typed(call.body)?;
                edited(ops::crop(body, args.x, args.y, args.w, args.h)?)
            }
            VERB_RESIZE => {
                let args: ResizeArgs = from_value(call.args, "resize args")?;
                let body = ImageBody::from_typed(call.body)?;
                edited(ops::resize(
                    body,
                    args.w,
                    args.h,
                    args.filter,
                    work_budget(call),
                )?)
            }
            VERB_ANNOTATE => {
                let args: AnnotateArgs = from_value(call.args, "annotate args")?;
                let body = ImageBody::from_typed(call.body)?;
                edited(ops::annotate(body, args.shape, args.stroke)?)
            }
            VERB_EXPORT => self.export(call),
            other => Err(OrganError::new(ErrorCode::UnknownVerb, other)),
        }
    }
}

fn edited(edited: Edited) -> Result<Answer, OrganError> {
    Ok(Answer {
        body: Some(edited.body.to_typed()?),
        notes: Notes {
            touched: edited.touched,
            ..Notes::default()
        },
        ..Answer::default()
    })
}

fn only_input<'a>(call: &'a CallContext<'_>) -> Result<&'a InputBytes, OrganError> {
    match call.inputs {
        [input] => Ok(input),
        _ => Err(bad("this verb reads exactly one image input")),
    }
}

/// `image.inspect`: the header only, no pixels.
fn inspect(call: &CallContext<'_>) -> Result<Answer, OrganError> {
    let input = only_input(call)?;
    let header = read_header(input)?;
    let mut notes = Notes::default();
    note_source(&mut notes, input, &header);
    Ok(Answer {
        report: header_report(&header, check_size(&header, decode_budget(call)).err()),
        notes,
        ..Answer::default()
    })
}

fn note_source(notes: &mut Notes, input: &InputBytes, header: &Header) {
    if header.profile == Profile::Untagged {
        notes.warnings.push(UNTAGGED.to_owned());
    }
    let sniffed = header.format.media_type();
    if input.media_type != sniffed {
        notes.warnings.push(format!(
            "the input says {} but its bytes are {sniffed}",
            input.media_type
        ));
    }
}

fn header_report(header: &Header, too_large: Option<OrganError>) -> rmpv::Value {
    let (width, height) = header.size();
    let (icc, icc_name) = match &header.profile {
        Profile::Untagged => ("none", rmpv::Value::Nil),
        Profile::Srgb => ("srgb", rmpv::Value::Nil),
        Profile::Other(name) => ("other", name.as_str().into()),
    };
    let refusal = header
        .refusal()
        .or_else(|| too_large.map(|err| err.detail))
        .map_or(rmpv::Value::Nil, rmpv::Value::from);
    let pairs: Vec<(&str, rmpv::Value)> = vec![
        ("format", header.format.media_type().into()),
        ("width", width.into()),
        ("height", height.into()),
        ("stored_width", header.stored_width.into()),
        ("stored_height", header.stored_height.into()),
        ("orientation", header.orientation.into()),
        ("depth", header.depth.into()),
        ("channels", header.channels.into()),
        ("alpha", header.alpha.into()),
        ("icc", icc.into()),
        ("icc_name", icc_name),
        ("animated", header.animated.into()),
        ("supported", refusal.is_nil().into()),
        ("refusal", refusal),
    ];
    rmpv::Value::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

/// Refuses what the first slice cannot keep, then checks the size.
fn admit(header: &Header, budget: u64) -> Result<Icc, OrganError> {
    if let Some(refusal) = header.refusal() {
        return Err(OrganError::new(ErrorCode::Unsupported, refusal));
    }
    check_size(header, budget)?;
    header
        .icc()
        .ok_or_else(|| OrganError::new(ErrorCode::Unsupported, "the ICC profile is not sRGB"))
}

/// The body's record of a source, from the source itself.
fn source_from(input: &InputBytes, header: &Header, icc: Icc) -> Source {
    let (width, height) = header.size();
    Source {
        hash: input.content_hash,
        media_type: header.format.media_type().to_owned(),
        format: header.format,
        width,
        height,
        orientation: header.orientation,
        alpha: header.alpha,
        icc,
    }
}

impl ImageOrgan {
    /// Books `bytes` of the shared work allowance, or says why not.
    fn hold(&self, call: &CallContext<'_>, bytes: u64) -> Result<Held<'_>, OrganError> {
        let allowance = work_budget(call);
        if bytes > allowance {
            return Err(OrganError::new(
                ErrorCode::TooLarge,
                format!("this needs {bytes} bytes at once; this organ works in {allowance}"),
            ));
        }
        let mut held = lock(&self.held);
        if held.saturating_add(bytes) > allowance {
            return Err(OrganError::new(
                ErrorCode::Budget,
                "other calls hold the organ's working memory; retry",
            ));
        }
        *held += bytes;
        Ok(Held { organ: self, bytes })
    }

    /// The decoded source: from the cache, or decoded now. The caller
    /// holds work memory for the decode.
    fn decode_and_keep(
        &self,
        call: &CallContext<'_>,
        input: &InputBytes,
        header: &Header,
    ) -> Result<Arc<RgbaImage>, OrganError> {
        if let Some(image) = lock(&self.decoded).get(&input.content_hash) {
            return Ok(image);
        }
        let image = Arc::new(decode(input, header, decode_budget(call))?);
        lock(&self.decoded).insert(input.content_hash, Arc::clone(&image), decode_budget(call));
        Ok(image)
    }

    /// `image.open`: checks the header, decodes once, returns a fresh body.
    fn open(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
        let input = only_input(call)?;
        let header = read_header(input)?;
        let icc = admit(&header, decode_budget(call))?;
        if lock(&self.decoded).get(&input.content_hash).is_none() {
            let _held = self.hold(call, decode_cost(&header, input))?;
            self.decode_and_keep(call, input, &header)?;
        }
        let body = ImageBody::new(source_from(input, &header, icc));
        let mut notes = Notes::default();
        note_source(&mut notes, input, &header);
        Ok(Answer {
            body: Some(body.to_typed()?),
            report: header_report(&header, None),
            notes,
            ..Answer::default()
        })
    }

    /// `image.export {format: png}`: the only verb that makes pixels. The
    /// call must carry the source every time, and the source must be what
    /// the body records: the cache only saves a decode.
    fn export(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
        let args: ExportArgs = from_value(call.args, "export args")?;
        if args.format != "png" {
            return Err(OrganError::new(
                ErrorCode::Unsupported,
                format!("export to {} is not built; png is", args.format),
            ));
        }
        let body = ImageBody::from_typed(call.body)?;
        let peak = ops::render_peak(&body)?;
        check_paint(&body)?;
        let input = call
            .inputs
            .iter()
            .find(|input| input.content_hash == body.source.hash)
            .ok_or_else(|| bad("export needs the source image as an input"))?;
        let header = read_header(input)?;
        let icc = admit(&header, decode_budget(call))?;
        if source_from(input, &header, icc) != body.source {
            return Err(bad("the input does not match the body's source"));
        }
        // A cold source decodes first, then renders: book the larger.
        let _held = self.hold(call, peak.max(decode_cost(&header, input)))?;
        let source = self.decode_and_keep(call, input, &header)?;
        call.check_cancel()?;
        let pixels = render(&source, &body, &|| call.check_cancel())?;
        drop(source);
        call.check_cancel()?;
        let png = encode_png(&pixels, header.alpha)?;
        let report = rmpv::Value::Map(vec![
            ("format".into(), "png".into()),
            ("width".into(), pixels.width().into()),
            ("height".into(), pixels.height().into()),
            ("bytes".into(), (png.len() as u64).into()),
        ]);
        let mut notes = Notes::default();
        if header.profile == Profile::Untagged {
            notes.warnings.push(UNTAGGED.to_owned());
        }
        if !body.overlays.is_empty() {
            notes.losses.push(Loss {
                code: "overlays_flattened".into(),
                detail: format!(
                    "{} overlays are painted into the pixels; the body keeps them editable",
                    body.overlays.len()
                ),
            });
        }
        notes.losses.push(Loss {
            code: "metadata_stripped".into(),
            detail: "the export carries no EXIF, ICC or text metadata".into(),
        });
        Ok(Answer {
            outputs: vec![OutputBytes {
                name: "image.png".into(),
                media_type: "image/png".into(),
                bytes: png,
            }],
            report,
            notes,
            ..Answer::default()
        })
    }
}
