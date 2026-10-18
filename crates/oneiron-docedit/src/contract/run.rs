//! The handlers behind [`super::execute`]: each op maps its args onto one
//! native door and the door's refusals onto the contract's codes.

use super::{
    AssetMedia, AssetOrigin, ContractError, CreatedSlide, DOCX_MEDIA_TYPE, DeckAsset,
    DeckCreateArgs, DeckCreated, DeckPlaceholder, DeckRead, DeckShape, DeckSlide,
    DeckTransactionArgs, Done, Editability, ErrorCode, Op, Output, PPTX_MEDIA_TYPE, Ports,
    PptxCommentsArgs, Reply, ShapeKind, SlideCreationId, ThreadAnchor, UnverifiedUnit,
    XLSX_MEDIA_TYPE,
};
use crate::deck::{self, DeckError, DeckView, ShapeView, SlideView};
use crate::design_plan::{
    AssetBinding, Brief, CompileError, KeptBrief, MediaType, Outcome, compile_with_fonts,
};
use crate::docx_body::{project_docx, read_docx_blocks};
use crate::edit::EditRefusal;
use crate::edit::transaction::{
    AssetRef, Assets, DeckTransaction, Digest, IdMarks, StepRefusal, TransactionError,
    run_transaction,
};
use crate::emit::{EmitError, EmitInputs, Names, StoredAsset, emit};
use crate::fonts::{FontBook, FontError};
use crate::graphic::{AssetRecord, GraphicLimits, Origin};
use crate::pptx_comments::{
    PptxError, SlideMints, comment_patch, guid, inspect_pptx, unknown_anchor_threads,
};
use crate::retained_opc::{self, Package};
use crate::xlsx_body::{XlsxBodyError, mark_full_calc, project_xlsx, read_xlsx_cells};
use crate::{
    DoceditError, prepare_revision_transaction, revise_with_notes, validate_blocking_with_limits,
    validate_revision_transaction,
};
use std::collections::BTreeMap;
use stemma::runtime::{ErrorCode as DocxCode, RuntimeError};

pub(super) fn op(op: &Op, inputs: &[&[u8]], ports: Ports<'_>) -> Result<Done, ContractError> {
    match op {
        Op::Describe => Ok(Done::reply(Reply::Described(super::describe()))),
        Op::DocxRead(args) => {
            let blocks = read_docx_blocks(input(inputs, args.document)?, args.limits.archive())
                .map_err(docedit)?;
            Ok(Done::reply(Reply::DocxBlocks { blocks }))
        }
        Op::DocxRevise(args) => {
            let document = input(inputs, args.document)?;
            let prepared =
                prepare_revision_transaction(&args.transaction.to_string()).map_err(docedit)?;
            let (bytes, notes) =
                revise_with_notes(document, &prepared, args.limits.archive()).map_err(docedit)?;
            let transaction = serde_json::from_str(&prepared).map_err(internal)?;
            Ok(Done::with(
                Reply::DocxRevised {
                    transaction,
                    notes: notes.iter().map(ToString::to_string).collect(),
                },
                Output::new("document", DOCX_MEDIA_TYPE, bytes),
            ))
        }
        Op::DocxValidate(args) => {
            let document = input(inputs, args.document)?;
            if let Some(transaction) = &args.transaction {
                validate_revision_transaction(&transaction.to_string()).map_err(docedit)?;
            }
            validate_blocking_with_limits(document, args.limits.archive()).map_err(runtime)?;
            Ok(Done::reply(Reply::Checked))
        }
        Op::DocxProject(args) => {
            let bytes = project_docx(
                input(inputs, args.source)?,
                &args.changes,
                &args.revision,
                args.limits.archive(),
            )
            .map_err(docedit)?;
            Ok(Done::with(
                Reply::Written,
                Output::new("document", DOCX_MEDIA_TYPE, bytes),
            ))
        }
        Op::XlsxRead(args) => {
            let book = read_xlsx_cells(input(inputs, args.workbook)?, args.limits.package())
                .map_err(xlsx)?;
            Ok(Done::reply(Reply::XlsxBook { book }))
        }
        Op::XlsxProject(args) => {
            let bytes = project_xlsx(
                input(inputs, args.source)?,
                &args.changes,
                args.limits.package(),
            )
            .map_err(xlsx)?;
            Ok(Done::with(
                Reply::Written,
                Output::new("workbook", XLSX_MEDIA_TYPE, bytes),
            ))
        }
        Op::XlsxMarkFullCalc(args) => {
            let bytes = mark_full_calc(input(inputs, args.workbook)?, args.limits.package())
                .map_err(xlsx)?;
            Ok(Done::with(
                Reply::Written,
                Output::new("workbook", XLSX_MEDIA_TYPE, bytes),
            ))
        }
        Op::XlsxRecalc(args) => {
            let port = ports.recalc.ok_or_else(|| {
                ContractError::new(
                    ErrorCode::Unavailable,
                    "xlsx.recalc runs through the host's recalculation port, and none is supplied",
                )
            })?;
            let done = port.recalculate(
                input(inputs, args.workbook)?,
                args.limits.package(),
                &args.clock,
                args.location.as_ref(),
            )?;
            Ok(Done::with(
                Reply::Recalculated {
                    engine: done.engine,
                    version: done.version,
                    formula_count: done.formula_count,
                },
                Output::new("workbook", XLSX_MEDIA_TYPE, done.bytes),
            ))
        }
        Op::DeckRead(args) => {
            let package =
                Package::open(input(inputs, args.deck)?, args.limits.package()).map_err(package)?;
            let view = DeckView::read(&package).map_err(deck_error)?;
            Ok(Done::reply(Reply::Deck(read_deck(&package, &view)?)))
        }
        Op::DeckTransaction(args) => deck_transaction(args, inputs),
        Op::DeckCreate(args) => deck_create(args, inputs),
        Op::PptxComments(args) => pptx_comments(args, inputs),
        Op::PptxCommentsInspect(args) => {
            let deck = input(inputs, args.deck)?;
            let inspection = inspect_pptx(deck, &args.limits).map_err(pptx)?;
            let unknown = unknown_anchor_threads(deck, &args.limits).map_err(pptx)?;
            Ok(Done::reply(Reply::PptxCommentsInspected {
                slides: inspection.slides,
                signature_parts: inspection.signature_parts,
                unknown_anchor_threads: unknown.into_iter().map(guid).collect(),
            }))
        }
    }
}

fn pptx_comments(args: &PptxCommentsArgs, inputs: &[&[u8]]) -> Result<Done, ContractError> {
    let base = input(inputs, args.deck)?;
    let replay: Option<Vec<(u64, u32)>> = args
        .slide_creation_ids
        .as_ref()
        .map(|ids| ids.iter().map(|id| (id.slide, id.creation_id)).collect());
    let seed = args.seed.to_le_bytes();
    let mints = match &replay {
        Some(ids) => SlideMints::Replay(ids),
        None => SlideMints::Draw(&seed),
    };
    let effects = comment_patch(base, &args.edits, mints, &args.limits).map_err(pptx)?;
    Ok(Done::with(
        Reply::PptxComments {
            touched_parts: effects.touched_parts.into_iter().collect(),
            slide_creation_ids: effects
                .minted_slide_creation_ids
                .into_iter()
                .map(|(slide, creation_id)| SlideCreationId { slide, creation_id })
                .collect(),
            anchors: effects
                .anchors
                .into_iter()
                .map(|(thread_id, anchor)| ThreadAnchor { thread_id, anchor })
                .collect(),
        },
        Output::new("deck", PPTX_MEDIA_TYPE, effects.new_bytes),
    ))
}

fn input<'a>(inputs: &[&'a [u8]], index: u32) -> Result<&'a [u8], ContractError> {
    usize::try_from(index)
        .ok()
        .and_then(|at| inputs.get(at))
        .copied()
        .ok_or_else(|| bad(format!("input {index} is not supplied")))
}

fn read_deck(package: &Package, view: &DeckView) -> Result<DeckRead, ContractError> {
    let editability = match package.editability() {
        retained_opc::Editability::Unsigned => Editability::Unsigned,
        retained_opc::Editability::Signed => Editability::Signed,
        retained_opc::Editability::MetadataUnsupported => Editability::MetadataUnsupported,
    };
    Ok(DeckRead {
        editability,
        marks: serde_json::to_value(IdMarks::of_deck(view)).map_err(internal)?,
        slides: view.slides.iter().map(slide).collect(),
        ambiguities: view
            .ambiguities
            .iter()
            .map(|ambiguity| format!("{ambiguity:?}"))
            .collect(),
    })
}

fn slide(view: &SlideView) -> DeckSlide {
    DeckSlide {
        part: view.part.clone(),
        sld_id: view.sld_id,
        creation_id: view.creation_id,
        layout: view.layout.clone(),
        content_fingerprint: Digest(view.content_fingerprint).to_hex(),
        shapes: view.shapes.iter().map(shape).collect(),
    }
}

fn shape(view: &ShapeView) -> DeckShape {
    DeckShape {
        id: view.id,
        creation_id: view.creation_id.clone(),
        name: view.name.clone(),
        kind: match view.kind {
            deck::ShapeKind::Shape => ShapeKind::Shape,
            deck::ShapeKind::Picture => ShapeKind::Picture,
            deck::ShapeKind::GraphicFrame => ShapeKind::GraphicFrame,
            deck::ShapeKind::Connector => ShapeKind::Connector,
            deck::ShapeKind::Group => ShapeKind::Group,
        },
        placeholder: view
            .placeholder
            .as_ref()
            .map(|placeholder| DeckPlaceholder {
                kind: placeholder.kind.clone(),
                idx: placeholder.idx,
            }),
        group_path: view.group_path.clone(),
        top_left: view.geometry.slide_space_top_left(),
        extent: view.geometry.extent.value,
        rotation: view.geometry.rotation.value,
        paragraphs: view.text.as_ref().map_or_else(Vec::new, |text| {
            text.paragraphs
                .iter()
                .map(|paragraph| {
                    paragraph
                        .runs
                        .iter()
                        .map(|run| run.text.as_str())
                        .collect::<String>()
                })
                .collect()
        }),
        content_fingerprint: Digest(view.content_fingerprint).to_hex(),
    }
}

/// The call's held assets, resolved by artifact and version.
struct HeldAssets<'a> {
    held: Vec<(&'a DeckAsset, &'a [u8])>,
}

impl Assets for HeldAssets<'_> {
    fn resolve(&self, asset: &AssetRef) -> Option<(AssetRecord, Vec<u8>)> {
        let (held, bytes) = self
            .held
            .iter()
            .find(|(held, _)| held.artifact == asset.artifact && held.version == asset.version)?;
        Some((
            record(held, bytes, asset.description.clone()),
            bytes.to_vec(),
        ))
    }
}

fn record(asset: &DeckAsset, bytes: &[u8], description: String) -> AssetRecord {
    AssetRecord {
        artifact: asset.artifact.clone(),
        version: asset.version,
        content_hash: *blake3::hash(bytes).as_bytes(),
        media: media(asset.media),
        origin: match asset.origin {
            AssetOrigin::Held => Origin::Held,
            AssetOrigin::Web => Origin::Web,
            AssetOrigin::Stock => Origin::Stock,
            AssetOrigin::Diagram => Origin::Diagram,
        },
        provenance: asset.provenance.clone(),
        rights: asset.rights.clone(),
        description,
    }
}

fn media(media: AssetMedia) -> MediaType {
    match media {
        AssetMedia::Png => MediaType::Png,
        AssetMedia::Jpeg => MediaType::Jpeg,
        AssetMedia::Svg => MediaType::Svg,
    }
}

fn deck_transaction(args: &DeckTransactionArgs, inputs: &[&[u8]]) -> Result<Done, ContractError> {
    let base = input(inputs, args.deck)?;
    let transaction =
        DeckTransaction::parse(&args.transaction.to_string()).map_err(transaction_error)?;
    let assets = HeldAssets {
        held: args
            .assets
            .iter()
            .map(|asset| Ok((asset, input(inputs, asset.input)?)))
            .collect::<Result<_, ContractError>>()?,
    };
    let (bytes, report) = run_transaction(base, &transaction, args.limits.package(), &assets)
        .map_err(transaction_error)?;
    Ok(Done::with(
        Reply::DeckTransaction {
            report: serde_json::to_value(&report).map_err(internal)?,
        },
        Output::new("deck", PPTX_MEDIA_TYPE, bytes),
    ))
}

fn deck_create(args: &DeckCreateArgs, inputs: &[&[u8]]) -> Result<Done, ContractError> {
    let bytes = input(inputs, args.brief.input)?;
    let content_hash = match &args.brief.kept_hash {
        Some(hex) => {
            Digest::from_hex(hex)
                .ok_or_else(|| bad("brief.kept_hash is not 64 hex digits"))?
                .0
        }
        None => *blake3::hash(bytes).as_bytes(),
    };
    let kept = KeptBrief {
        version: &args.brief.version,
        content_hash,
        bytes,
    };
    let limits = args.limits.package();
    let template = Package::open(input(inputs, args.template)?, limits).map_err(package)?;
    let mut fonts = FontBook::new();
    for font in &args.fonts {
        fonts
            .add(input(inputs, *font)?.to_vec())
            .map_err(font_error)?;
    }
    let bindings: BTreeMap<String, AssetBinding> = args
        .assets
        .iter()
        .map(|(id, asset)| {
            (
                id.clone(),
                AssetBinding {
                    handle: asset.artifact.clone(),
                    media: media(asset.media),
                },
            )
        })
        .collect();
    let plan = match compile_with_fonts(&kept, &template, &bindings, &fonts).map_err(compile)? {
        Outcome::Ask(decisions) => {
            return Ok(Done::reply(Reply::DeckAsk {
                pages: decisions
                    .into_iter()
                    .map(|decision| decision.page)
                    .collect(),
            }));
        }
        Outcome::Plan(plan) => plan,
    };
    let brief = Brief::parse(bytes).map_err(|error| compile(CompileError::from(error)))?;
    let mut records = BTreeMap::new();
    for (id, asset) in &args.assets {
        let description = brief
            .assets
            .iter()
            .find(|held| held.id == *id)
            .map(|held| held.content.clone())
            .ok_or_else(|| bad(format!("asset {id} is not in the brief")))?;
        let asset_bytes = input(inputs, asset.input)?;
        records.insert(
            id.clone(),
            (record(asset, asset_bytes, description), asset_bytes),
        );
    }
    let stored: BTreeMap<String, StoredAsset<'_>> = records
        .iter()
        .map(|(id, (record, asset_bytes))| {
            (
                id.clone(),
                StoredAsset {
                    record,
                    bytes: Some(*asset_bytes),
                },
            )
        })
        .collect();
    let candidate = emit(
        &plan,
        &EmitInputs {
            kept,
            template: &template,
            assets: &stored,
            names: Names {
                text: &args.names.text,
                table: &args.names.table,
                chart: &args.names.chart,
                picture: &args.names.picture,
                figure: &args.names.figure,
                sheet: &args.names.sheet,
            },
            limits: GraphicLimits::default(),
        },
    )
    .map_err(emit_error)?;
    let created = DeckCreated {
        hash: Digest(candidate.hash).to_hex(),
        slides: candidate
            .report
            .slides
            .iter()
            .map(|slide| CreatedSlide {
                part: slide.part.clone(),
                sld_id: slide.sld_id,
                page: slide.page.clone(),
                layout: slide.layout.clone(),
            })
            .collect(),
        write_set: candidate.report.write_set.clone(),
        omitted: candidate.report.omitted.clone(),
        fit_unverified: candidate.fit.as_ref().err().map_or_else(Vec::new, |fit| {
            fit.units
                .iter()
                .map(|unit| UnverifiedUnit {
                    slide: unit.slide.clone(),
                    block: unit.block.clone(),
                    shape: unit.shape,
                })
                .collect()
        }),
    };
    Ok(Done::with(
        Reply::DeckCreated(created),
        Output::new("deck", PPTX_MEDIA_TYPE, candidate.bytes),
    ))
}

fn bad(detail: impl Into<String>) -> ContractError {
    ContractError::new(ErrorCode::BadRequest, detail)
}

fn internal(error: impl std::fmt::Display) -> ContractError {
    ContractError::new(ErrorCode::Internal, error.to_string())
}

fn docedit(error: DoceditError) -> ContractError {
    match error {
        DoceditError::InvalidTransaction(_) => bad(error.to_string()),
        DoceditError::Document(error) => runtime(error),
    }
}

fn runtime(error: RuntimeError) -> ContractError {
    let code = match error.code {
        DocxCode::StaleEdit => ErrorCode::Stale,
        DocxCode::InvalidDocx | DocxCode::InvalidSnapshot => ErrorCode::InvalidDocument,
        DocxCode::InternalError => ErrorCode::Internal,
        _ => ErrorCode::Refused,
    };
    ContractError::new(code, error.to_string())
}

fn package_code(error: &retained_opc::Error) -> ErrorCode {
    match error {
        retained_opc::Error::Invalid(_) => ErrorCode::InvalidDocument,
        retained_opc::Error::Edit(_) => ErrorCode::Refused,
    }
}

fn package(error: retained_opc::Error) -> ContractError {
    ContractError::new(package_code(&error), error.to_string())
}

fn pptx(error: PptxError) -> ContractError {
    let code = match error {
        PptxError::InvalidPackage | PptxError::InvalidXml | PptxError::InvalidReference => {
            ErrorCode::InvalidDocument
        }
        PptxError::InvalidPatch => ErrorCode::BadRequest,
        PptxError::SignedPackage => ErrorCode::NotEditable,
        PptxError::SlideNotFound
        | PptxError::AmbiguousAnchor
        | PptxError::UnverifiedGeometry
        | PptxError::ThreadNotFound
        | PptxError::DuplicateComment
        | PptxError::NotAuthor
        | PptxError::AuthorConflict
        | PptxError::PartDiffOutsideTransaction
        | PptxError::AnchorReadBack => ErrorCode::Refused,
    };
    ContractError::new(code, error.to_string())
}

fn deck_error(error: DeckError) -> ContractError {
    ContractError::new(ErrorCode::InvalidDocument, error.to_string())
}

fn xlsx(error: XlsxBodyError) -> ContractError {
    let code = match &error {
        XlsxBodyError::Package(error) => package_code(error),
        XlsxBodyError::Xml(_) => ErrorCode::InvalidDocument,
        XlsxBodyError::Refused(_) => ErrorCode::Refused,
    };
    ContractError::new(code, error.to_string())
}

fn transaction_error(error: TransactionError) -> ContractError {
    let code = match &error {
        TransactionError::Invalid(_) => ErrorCode::BadRequest,
        TransactionError::BaseChanged
        | TransactionError::Step {
            refusal: StepRefusal::Edit(EditRefusal::TargetChanged),
            ..
        } => ErrorCode::Stale,
        TransactionError::NotEditable => ErrorCode::NotEditable,
        TransactionError::Step { .. } | TransactionError::PartDiffOutsideTransaction(_) => {
            ErrorCode::Refused
        }
        TransactionError::Package(error) => package_code(error),
        TransactionError::Deck(_) => ErrorCode::InvalidDocument,
    };
    ContractError::new(code, error.to_string())
}

fn compile(error: CompileError) -> ContractError {
    let code = match &error {
        CompileError::StaleBrief | CompileError::StaleTemplate => ErrorCode::Stale,
        CompileError::Brief(_) | CompileError::UnboundAsset(_) => ErrorCode::BadRequest,
        CompileError::Template(_) | CompileError::EmptyTemplate => ErrorCode::InvalidDocument,
        CompileError::PartNames | CompileError::Trace { .. } => ErrorCode::Refused,
    };
    ContractError::new(code, error.to_string())
}

fn emit_error(error: EmitError) -> ContractError {
    let code = match &error {
        EmitError::Plan(error) => return compile(error.clone()),
        EmitError::MissingAsset(_) => ErrorCode::BadRequest,
        EmitError::Package(error) => package_code(error),
        EmitError::Xml(_) | EmitError::Deck(_) => ErrorCode::InvalidDocument,
        EmitError::TemplateSlides(_)
        | EmitError::MissingDataset(_)
        | EmitError::Graphic { .. }
        | EmitError::Native { .. }
        | EmitError::Check { .. } => ErrorCode::Refused,
    };
    ContractError::new(code, error.to_string())
}

fn font_error(error: FontError) -> ContractError {
    bad(format!("font: {error}"))
}
