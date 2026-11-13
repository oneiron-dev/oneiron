//! The image organ's host adapter (ARCH-0078 `#image-built`, L4-15): an
//! edit of an image artifact, crops and resizes, whose PNG lands as one
//! proposal waiting for Keep.
//!
//! It speaks protocol values only and never links the organ crate (the
//! of060 F4 fence, `tests/organ_fence.rs`). One edit is `image.open` on the
//! version, each op on the body that returns, then `image.export` to PNG,
//! submitted as one job ([`OrganRouter::submit`]): its file lands beside
//! the artifact through [`crate::propose_organ_outputs`], or, when no node
//! can run the export now, the export waits beside the artifact with the
//! reason until a redrive runs it. The open and the ops run where a node
//! can (this host first, then the owner's other nodes); when none can, the
//! edit is refused with the reason and nothing waits or lands.
//!
//! The organ exports PNG only. A PNG artifact's edit is its next version
//! once kept. A JPEG or WebP artifact's edit lands on a new `image/png`
//! artifact born from the source version (RULING 09:34 Fri 13 Nov,
//! IO-FORMAT B): the new artifact's `DerivedFrom` edge names the source
//! artifact, its proposal's made_by names the source version it read, and
//! it carries the source's secret taint refs. The source stays as it was.
//! The new artifact is made only once the export has run or waits, so a
//! refused edit leaves nothing behind. No body is stored: the organ's
//! export report carries the schema-1 body it rendered, and the proposal
//! keeps that report (IO-BODY A). The next edit opens the kept PNG.
//!
//! Calls block, as every host call does: run them off any async runtime.

use std::path::PathBuf;
use std::time::Duration;

use oneiron::blob_artifact::{BlobArtifactBody, encode_blob_artifact_body};
use oneiron::provenance::made_by::MadeByTrigger;
use oneiron::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use oneiron::secret_custody::SecretSight;
use oneiron::{EdgeKind, EntityId, TimeRange, Vault, WriteActor};
use oneiron_organ_protocol::{ErrorCode, OrganError, TypedBody, Value};

use crate::error::HostError;
use crate::handlers::AskHandlers;
use crate::route::{OrganRouter, Routed};
use crate::spec::{CallClass, OrganCall, OrganInput, OrganSpec, SightedInput};
use crate::wait::{JobCall, Submitted};

/// The image organ's install name.
pub const IMAGE_ORGAN: &str = "image";
pub const VERB_INSPECT: &str = "image.inspect";
pub const VERB_OPEN: &str = "image.open";
pub const VERB_CROP: &str = "image.crop";
pub const VERB_RESIZE: &str = "image.resize";
pub const VERB_ANNOTATE: &str = "image.annotate";
pub const VERB_EXPORT: &str = "image.export";
/// The typed body the organ reads and writes, and its schema.
pub const IMAGE_BODY_KIND: &str = "image";
pub const IMAGE_BODY_SCHEMA: u32 = 1;
/// The most ops one edit takes.
pub const MAX_IMAGE_OPS: usize = 256;

const PNG: &str = "image/png";
const JPEG: &str = "image/jpeg";
const WEBP: &str = "image/webp";
/// The media types the organ opens.
const IMAGE_MEDIA_TYPES: [&str; 3] = [PNG, JPEG, WEBP];

/// The image organ's install grant: its six verbs, over still PNG, JPEG and
/// WebP, and its `image` body alone. The default memory and frame limits of
/// a first-party organ stand.
#[must_use]
pub fn image_spec(program: impl Into<PathBuf>) -> OrganSpec {
    let mut spec = OrganSpec::first_party(IMAGE_ORGAN, program);
    spec.verbs = [
        VERB_INSPECT,
        VERB_OPEN,
        VERB_CROP,
        VERB_RESIZE,
        VERB_ANNOTATE,
        VERB_EXPORT,
    ]
    .map(String::from)
    .into();
    spec.media_types = IMAGE_MEDIA_TYPES.map(String::from).into();
    spec.kinds = Some(vec![IMAGE_BODY_KIND.to_owned()]);
    spec
}

/// How a resize samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeFilter {
    Nearest,
    Bilinear,
}

impl ResizeFilter {
    const fn name(self) -> &'static str {
        match self {
            Self::Nearest => "nearest",
            Self::Bilinear => "bilinear",
        }
    }
}

/// One step of an edit, in canvas pixels after the steps before it,
/// top-left origin, after EXIF orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageOp {
    Crop {
        x: u32,
        y: u32,
        w: u32,
        h: u32,
    },
    Resize {
        w: u32,
        h: u32,
        filter: ResizeFilter,
    },
}

impl ImageOp {
    const fn verb(self) -> &'static str {
        match self {
            Self::Crop { .. } => VERB_CROP,
            Self::Resize { .. } => VERB_RESIZE,
        }
    }

    fn args(self) -> Value {
        let pairs: Vec<(&str, Value)> = match self {
            Self::Crop { x, y, w, h } => vec![
                ("x", x.into()),
                ("y", y.into()),
                ("w", w.into()),
                ("h", h.into()),
            ],
            Self::Resize { w, h, filter } => vec![
                ("w", w.into()),
                ("h", h.into()),
                ("filter", filter.name().into()),
            ],
        };
        Value::Map(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

/// One edit of an image artifact.
#[derive(Debug, Clone)]
pub struct ImageEdit {
    pub artifact: EntityId,
    /// The version edited; the head when `None`.
    pub version: Option<u64>,
    /// 1 to [`MAX_IMAGE_OPS`] ops, applied in order.
    pub ops: Vec<ImageOp>,
    /// The proposal's ref.
    pub run_ref: String,
    /// The task, ask, run or skill the edit answers.
    pub trigger: Option<MadeByTrigger>,
    /// The authenticated principal who asked for the edit, whose own read
    /// admits the proposal's made_by as it lands (FIX 9310); `None` for a
    /// host's own edit.
    pub submitter: Option<EntityId>,
    /// The sight the source version is read under.
    pub sight: SecretSight,
    /// The grant the calls run under; revoking it stops them.
    pub grant: String,
    pub class: CallClass,
    /// Each call's deadline.
    pub deadline: Duration,
}

/// What became of an edit.
#[derive(Debug)]
pub struct ImageEdited {
    /// The artifact the PNG lands on: the source itself, or a new
    /// `image/png` artifact born from it.
    pub artifact: EntityId,
    /// Whether `artifact` is new, born from a JPEG or WebP source.
    pub born: bool,
    /// The proposal waiting for Keep, or the export held for a node.
    pub submitted: Submitted,
}

/// Why an edit did not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImageEditRefusal {
    #[error("the artifact or its version is not in this vault")]
    NotFound,
    #[error("a {media_type} artifact is not an image this organ opens (png, jpeg, webp)")]
    NotAnImage { media_type: String },
    #[error("an edit names at least one op")]
    NoOps,
    #[error("an edit names at most 256 ops, not {count}")]
    TooManyOps { count: usize },
    /// No node can run the open or an op now; nothing waits.
    #[error("no node can run the image organ now: {reason}")]
    NoNode { reason: String },
    /// The organ refused: its code (`bad_request`, `unsupported`,
    /// `too_large`, ...) and its word.
    #[error("the image organ refused: {0}")]
    Organ(OrganError),
    #[error(transparent)]
    Host(HostError),
}

impl ImageEditRefusal {
    /// The refusal's stable code: the organ's own for its refusals.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotAnImage { .. } => "not_an_image",
            Self::NoOps => "no_ops",
            Self::TooManyOps { .. } => "too_many_ops",
            Self::NoNode { .. } => "no_node",
            Self::Organ(err) => organ_code(err.code),
            Self::Host(_) => "host_error",
        }
    }
}

impl From<HostError> for ImageEditRefusal {
    fn from(err: HostError) -> Self {
        match err {
            HostError::Organ(err) => Self::Organ(err),
            other => Self::Host(other),
        }
    }
}

impl From<oneiron::Error> for ImageEditRefusal {
    fn from(err: oneiron::Error) -> Self {
        Self::Host(HostError::Engine(err))
    }
}

const fn organ_code(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::BadRequest => "bad_request",
        ErrorCode::UnknownVerb => "unknown_verb",
        ErrorCode::SchemaMismatch => "schema_mismatch",
        ErrorCode::Unsupported => "unsupported",
        ErrorCode::TooLarge => "too_large",
        ErrorCode::Budget => "budget",
        ErrorCode::Cancelled => "cancelled",
        ErrorCode::Revoked => "revoked",
        ErrorCode::DeadlineExceeded => "deadline_exceeded",
        ErrorCode::StaleBase => "stale_base",
        ErrorCode::Internal => "internal",
    }
}

impl ImageEdit {
    fn call(
        &self,
        verb: &str,
        args: Value,
        body: Option<TypedBody>,
        source: Option<OrganInput>,
    ) -> OrganCall {
        OrganCall {
            organ: IMAGE_ORGAN.to_owned(),
            verb: verb.to_owned(),
            schema: IMAGE_BODY_SCHEMA,
            args,
            body,
            inputs: source
                .map(|input| SightedInput {
                    input,
                    sight: self.sight,
                })
                .into_iter()
                .collect(),
            class: self.class,
            deadline: self.deadline,
            grant: self.grant.clone(),
        }
    }
}

/// The body one call returns, run where a node can run it now.
fn body_of(
    router: &OrganRouter,
    vault: &Vault,
    call: OrganCall,
    asks: &AskHandlers<'_>,
) -> Result<TypedBody, ImageEditRefusal> {
    let verb = call.verb.clone();
    match router.call_with(vault, call, Vec::new(), asks)? {
        Routed::Done { outcome, .. } => outcome.body.ok_or_else(|| {
            ImageEditRefusal::Host(HostError::ReplyInvalid(format!(
                "{verb} returned no image body"
            )))
        }),
        Routed::Waiting(wait) => Err(ImageEditRefusal::NoNode {
            reason: wait.reason,
        }),
    }
}

/// `name` for a PNG: a `.jpg`, `.jpeg` or `.webp` ending becomes `.png`.
fn png_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    [".jpeg", ".jpg", ".webp"]
        .iter()
        .find(|ending| lower.ends_with(*ending))
        .map_or_else(
            || name.to_owned(),
            |ending| format!("{}.png", &name[..name.len() - ending.len()]),
        )
}

/// Runs `edit` through `router`: opens the version, applies each op, and
/// submits the PNG export as one job made by `actor`. Its file waits for
/// Keep beside the artifact, or beside a new PNG artifact born from a JPEG
/// or WebP source; or the export waits for a node, with the reason.
///
/// # Errors
/// [`ImageEditRefusal`]: no ops or too many; an artifact or version this
/// vault does not hold, or one that is not a PNG, JPEG or WebP; no node to
/// run the open or an op now; the organ's refusal; the host's or the
/// vault's error, the landing's refusal included.
pub fn edit_image(
    router: &OrganRouter,
    vault: &Vault,
    edit: &ImageEdit,
    actor: WriteActor,
    asks: &AskHandlers<'_>,
) -> Result<ImageEdited, ImageEditRefusal> {
    if edit.ops.is_empty() {
        return Err(ImageEditRefusal::NoOps);
    }
    if edit.ops.len() > MAX_IMAGE_OPS {
        return Err(ImageEditRefusal::TooManyOps {
            count: edit.ops.len(),
        });
    }
    let source = vault
        .get_blob_artifact(&edit.artifact)?
        .ok_or(ImageEditRefusal::NotFound)?;
    if !IMAGE_MEDIA_TYPES.contains(&source.media_type.as_str()) {
        return Err(ImageEditRefusal::NotAnImage {
            media_type: source.media_type,
        });
    }
    let version = match edit.version {
        Some(version) => vault
            .blob_artifact_version_metadata(&edit.artifact, version)?
            .map(|record| record.version),
        None => vault
            .blob_artifact_head(&edit.artifact)?
            .map(|head| head.version),
    }
    .ok_or(ImageEditRefusal::NotFound)?;
    let input = OrganInput {
        artifact: edit.artifact,
        version,
    };

    let mut body = body_of(
        router,
        vault,
        edit.call(VERB_OPEN, Value::Nil, None, Some(input)),
        asks,
    )?;
    for op in &edit.ops {
        body = body_of(
            router,
            vault,
            edit.call(op.verb(), op.args(), Some(body), None),
            asks,
        )?;
    }
    let export = Value::Map(vec![("format".into(), "png".into())]);
    let job = JobCall {
        run_ref: edit.run_ref.clone(),
        call: edit.call(VERB_EXPORT, export, Some(body), Some(input)),
        lent: Vec::new(),
        trigger: edit.trigger.clone(),
        submitter: edit.submitter,
    };
    let born = source.media_type != PNG;
    let target = || -> Result<EntityId, HostError> {
        if !born {
            return Ok(edit.artifact);
        }
        let artifact = vault.new_entity_id()?;
        let now = vault.now_recorded_at();
        let body = BlobArtifactBody::new(png_name(&source.name), PNG)
            .with_secret_taint_refs(source.secret_taint_refs.clone());
        vault
            .batch()
            .put(
                &artifact,
                ENTITY_TYPE_BLOB_ARTIFACT,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &encode_blob_artifact_body(&body)?,
            )
            .edge(&artifact, EdgeKind::DerivedFrom, &edit.artifact, 1.0)
            .commit_below_owner()?;
        Ok(artifact)
    };
    let (artifact, submitted) = router.submit_to(vault, job, target, actor, asks)?;
    Ok(ImageEdited {
        artifact,
        born,
        submitted,
    })
}
