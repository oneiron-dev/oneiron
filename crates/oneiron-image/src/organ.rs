//! The image organ: six verbs over the `image` body, schema 1.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use image::RgbaImage;
use oneiron_organ_protocol::{
    Answer, CallContext, ErrorCode, Hash32, InputBytes, Loss, Notes, Organ, OrganError,
    OrganIdentity, OutputBytes, VerbSpec,
};
use serde::Deserialize;

use crate::body::{
    Filter, Icc, ImageBody, KIND, Shape, Size, Source, Step, Stroke, bad, from_value,
};
use crate::decode::{Header, Profile, check_size, decode, read_header};
use crate::ops::{self, Edited};
use crate::render::{encode_png, render};

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
/// quarter of its memory grant, so a crop or export after `open` does not
/// decode again.
#[derive(Debug, Default)]
pub struct ImageOrgan {
    decoded: Mutex<Decoded>,
}

#[derive(Debug, Default)]
struct Decoded {
    entries: VecDeque<(Hash32, Arc<RgbaImage>)>,
    bytes: u64,
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
        let size = image.as_raw().len() as u64;
        if size > cap || self.entries.iter().any(|(key, _)| *key == hash) {
            return;
        }
        while self.bytes + size > cap {
            let Some((_, old)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= old.as_raw().len() as u64;
        }
        self.bytes += size;
        self.entries.push_back((hash, image));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one decoded source may take: a quarter of the grant. The cache
/// holds another quarter; pixel work at export gets the rest.
fn decode_budget(call: &CallContext<'_>) -> u64 {
    call.limits.memory_bytes / 4
}

fn work_budget(call: &CallContext<'_>) -> u64 {
    call.limits.memory_bytes / 2
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

impl ImageOrgan {
    fn cached(&self, hash: &Hash32) -> Option<Arc<RgbaImage>> {
        lock(&self.decoded).get(hash)
    }

    fn decode_and_keep(
        &self,
        call: &CallContext<'_>,
        input: &InputBytes,
        header: &Header,
    ) -> Result<Arc<RgbaImage>, OrganError> {
        if let Some(image) = self.cached(&input.content_hash) {
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
        self.decode_and_keep(call, input, &header)?;
        let (width, height) = header.size();
        let body = ImageBody::new(Source {
            hash: input.content_hash,
            media_type: header.format.media_type().to_owned(),
            format: header.format,
            width,
            height,
            orientation: header.orientation,
            alpha: header.alpha,
            icc,
        });
        let mut notes = Notes::default();
        note_source(&mut notes, input, &header);
        Ok(Answer {
            body: Some(body.to_typed()?),
            report: header_report(&header, None),
            notes,
            ..Answer::default()
        })
    }

    /// The decoded source of `body`: from the cache, or from the input that
    /// carries its hash.
    fn source_of(
        &self,
        call: &CallContext<'_>,
        body: &ImageBody,
    ) -> Result<Arc<RgbaImage>, OrganError> {
        if let Some(image) = self.cached(&body.source.hash) {
            return Ok(image);
        }
        let input = call
            .inputs
            .iter()
            .find(|input| input.content_hash == body.source.hash)
            .ok_or_else(|| bad("export needs the source image as an input"))?;
        let header = read_header(input)?;
        admit(&header, decode_budget(call))?;
        let fits = header.size() == (body.source.width, body.source.height)
            && header.orientation == body.source.orientation
            && header.format == body.source.format;
        if !fits {
            return Err(bad("the input does not match the body's source"));
        }
        self.decode_and_keep(call, input, &header)
    }

    /// `image.export {format: png}`: the only verb that makes pixels.
    fn export(&self, call: &CallContext<'_>) -> Result<Answer, OrganError> {
        let args: ExportArgs = from_value(call.args, "export args")?;
        if args.format != "png" {
            return Err(OrganError::new(
                ErrorCode::Unsupported,
                format!("export to {} is not built; png is", args.format),
            ));
        }
        let body = ImageBody::from_typed(call.body)?;
        check_work(&body, work_budget(call))?;
        let source = self.source_of(call, &body)?;
        call.check_cancel()?;
        let pixels = render(&source, &body, &|| call.check_cancel())?;
        drop(source);
        call.check_cancel()?;
        let png = encode_png(&pixels, body.source.alpha)?;
        let report = rmpv::Value::Map(vec![
            ("format".into(), "png".into()),
            ("width".into(), pixels.width().into()),
            ("height".into(), pixels.height().into()),
            ("bytes".into(), (png.len() as u64).into()),
        ]);
        let mut notes = Notes::default();
        if body.source.icc == Icc::None {
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

/// Replays the steps' pixel cost, so a body made under a larger grant is
/// refused rather than run out of memory.
fn check_work(body: &ImageBody, max_bytes: u64) -> Result<(), OrganError> {
    let mut canvas = Size {
        w: body.source.width,
        h: body.source.height,
    };
    for step in &body.steps {
        let next = step.apply_to(canvas)?;
        let peak = match step {
            Step::Crop { .. }
            | Step::Resize {
                filter: Filter::Nearest,
                ..
            } => ops::rgba_bytes(next),
            Step::Resize {
                filter: Filter::Bilinear,
                ..
            } => ops::bilinear_bytes(canvas, next),
        };
        if peak > max_bytes {
            return Err(OrganError::new(
                ErrorCode::TooLarge,
                format!("a step needs {peak} bytes; this organ holds {max_bytes}"),
            ));
        }
        canvas = next;
    }
    Ok(())
}
