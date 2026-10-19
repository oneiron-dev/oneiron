//! Emit a checked deck candidate from a `DesignPlan` (ARCH-0077 "Creation
//! result and checks"). The plan is validated against its kept brief and
//! template first. Emission then writes only the planned content into a copy
//! of the template: new slides over their layouts, filled placeholders and
//! ordinary text shapes, verified pictures, native SVG groups, native tables
//! and charts with their workbooks, and the presentation's slide list. The
//! exported bytes are checked independently of the writer: the write set
//! against the plan's package row, relationships, content types, id scopes,
//! and a re-import that reads every unit back where the plan put it.
//!
//! Fit is decided only where geometry decides it. Laid-out text needs the
//! actual fonts and script shaping, which emission does not have, so text,
//! tables and charts come back `FitUnverified`; an estimate chose the slide
//! and never certifies it. `fontScale` and `lnSpcReduction` are never
//! written.
mod check;
mod slide;
#[cfg(test)]
pub(crate) mod tests;

use crate::deck::{DeckError, RetainedNode, TemplateView};
use crate::design_plan::{
    ApprovedInput, BlockContent, Brief, ColumnKind, CompileError, Content, DesignPlan, Destination,
    Estimate, KeptBrief, Pin, Rect, SlidePlan, TraceOutcome,
};
use crate::graphic::{
    AssetRecord, AssetUse, CompiledGraphic, GraphicError, GraphicInput, GraphicLimits, Output,
    compile_graphic,
};
use crate::native_patch::{
    ChartFamily, Frame, NativeEdit, NativeRefusal, NativeReport, insert_frame, native_patch,
};
use crate::ooxml::{DOCUMENT_RELATIONSHIPS as REL, XmlError, XmlTree};
use crate::retained_opc::{self, Package};
use std::collections::{BTreeMap, BTreeSet};

/// Names for what emission creates, from the caller's configuration. An
/// ordinary shape is named `"{stem} {id}"`; a filled placeholder keeps its
/// layout shape's name.
#[derive(Debug, Clone, Copy)]
pub struct Names<'a> {
    pub text: &'a str,
    pub table: &'a str,
    pub chart: &'a str,
    pub picture: &'a str,
    pub figure: &'a str,
    /// The embedded workbooks' one sheet.
    pub sheet: &'a str,
}

/// The engine's record of one placed asset and its stored bytes; `None`
/// while they are not durable.
#[derive(Debug, Clone, Copy)]
pub struct StoredAsset<'a> {
    pub record: &'a AssetRecord,
    pub bytes: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy)]
pub struct EmitInputs<'a> {
    /// The keep the plan is bound to.
    pub kept: KeptBrief<'a>,
    /// The template the plan was compiled against.
    pub template: &'a Package,
    pub assets: &'a BTreeMap<String, StoredAsset<'a>>,
    pub names: Names<'a>,
    pub limits: GraphicLimits,
}

/// One new deck as candidate bytes, the hash that binds them, its report and
/// its fit status.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub bytes: Vec<u8>,
    /// BLAKE3 of `bytes`.
    pub hash: [u8; 32],
    pub report: Report,
    /// `Ok` only when geometry decides every unit's fit.
    pub fit: Result<(), FitUnverified>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// The kept outline version the deck is born from.
    pub born_from: ApprovedInput,
    /// BLAKE3 of the template package.
    pub template: [u8; 32],
    /// Parts the candidate writes differently from the template, as the
    /// independent check read them from the exported bytes.
    pub write_set: Vec<String>,
    pub slides: Vec<EmittedSlide>,
    /// Optional blocks the plan omitted.
    pub omitted: Vec<String>,
    pub assets: Vec<PlacedAsset>,
    /// The native table and chart operations, workbook writes included.
    pub native: Vec<NativeReport>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EmittedSlide {
    pub part: String,
    pub sld_id: u32,
    pub page: String,
    pub layout: String,
    pub units: Vec<Unit>,
}

/// One output unit: the placement trace (block, shape, destination), the
/// claim trace and the fit trace.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    pub block: String,
    /// The unit's `p:cNvPr` id; a figure's is its group's.
    pub shape: u32,
    pub content: Content,
    pub destination: Destination,
    pub claim: Option<ClaimTrace>,
    pub fit: FitTrace,
}

/// A claim's evidence pins, carried to the shape that states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTrace {
    pub evidence: Vec<Pin>,
    /// A pin no longer maps; its quote is kept.
    pub drifted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FitTrace {
    /// Placed geometry inside the planned bounds.
    Exact { placed: Rect },
    /// Laid-out text: the estimate that chose the slide, never a pass.
    Unverified { estimate: Option<Estimate> },
}

/// An asset use with the shape that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedAsset {
    pub slide: String,
    pub shape: u32,
    pub asset: String,
    pub record: AssetUse,
}

/// The units whose fit emission cannot decide: text layout needs the actual
/// fonts and shaping. A clean render does not settle it either.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("fit unverified for {} unit(s)", .units.len())]
pub struct FitUnverified {
    pub units: Vec<Unverified>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverified {
    pub slide: String,
    pub block: String,
    pub shape: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    /// The plan does not hold for this keep and template.
    #[error(transparent)]
    Plan(#[from] CompileError),
    /// A new deck holds only planned slides; v1 has no door that removes a
    /// template's own slides.
    #[error("the template already holds slides: {0:?}")]
    TemplateSlides(Vec<String>),
    #[error("no stored asset for {0}")]
    MissingAsset(String),
    #[error("the plan carries no dataset {0}")]
    MissingDataset(String),
    #[error("asset for {block}: {error}")]
    Graphic { block: String, error: GraphicError },
    #[error("native content for {block}: {refusal}")]
    Native {
        block: String,
        refusal: NativeRefusal,
    },
    #[error("candidate check at {part}: {fault:?}")]
    Check { part: String, fault: CheckFault },
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
    #[error(transparent)]
    Deck(#[from] DeckError),
}

/// What the independent candidate check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckFault {
    /// A part written, or removed, outside the plan's package row.
    OutsideWriteSet,
    /// A planned part or relationship the candidate lacks.
    MissingPlanned,
    /// A relationship the plan does not name, or a template one changed.
    UnplannedRelationship,
    /// An internal relationship target that is not a part.
    DanglingTarget,
    /// A new part declared with another content type.
    ContentType,
    /// A shape or slide id reused in its scope, or a relationship id that
    /// does not resolve.
    IdScope,
    /// A written part carries `fontScale` or `lnSpcReduction`.
    AutofitMetrics,
    /// The re-imported deck differs from the plan.
    Reimport,
}

const SLIDE_REL: &str = "slide";
const LAYOUT_REL: &str = "slideLayout";
const IMAGE_REL: &str = "image";
const CHART_REL: &str = "chart";
const PACKAGE_REL: &str = "package";

/// Emit the plan's deck. The plan is checked first; any refusal leaves
/// nothing behind, since emission writes into a copy of the template.
pub fn emit(plan: &DesignPlan, inputs: &EmitInputs<'_>) -> Result<Candidate, EmitError> {
    let template = inputs.template;
    plan.check(&inputs.kept, template)?;
    let brief = Brief::parse(inputs.kept.bytes).map_err(CompileError::from)?;
    let presentation = TemplateView::read(template)?.presentation;
    check_template(template)?;
    let mut writer = Writer {
        package: template.clone(),
        plan,
        inputs,
        brief: &brief,
        media: BTreeSet::new(),
        assets: Vec::new(),
        native: Vec::new(),
    };
    let mut slides = Vec::new();
    let mut list = Vec::new();
    for (index, planned) in plan.slides().iter().enumerate() {
        let units = writer.slide(planned)?;
        let link =
            writer
                .package
                .relate(&presentation, &format!("{REL}/{SLIDE_REL}"), &planned.part)?;
        let sld_id = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(256))
            .ok_or(retained_opc::Error::Edit("slide id overflow"))?;
        list.push((sld_id, link));
        slides.push(EmittedSlide {
            part: planned.part.clone(),
            sld_id,
            page: planned.page.clone(),
            layout: planned.layout.clone(),
            units,
        });
    }
    slide::write_slide_list(&mut writer.package, &presentation, &list)?;
    let bytes = writer.package.export()?;
    let write_set = check::verify(plan, template, &bytes, &slides)?;
    let unverified: Vec<Unverified> = slides
        .iter()
        .flat_map(|slide| {
            slide.units.iter().filter_map(|unit| match unit.fit {
                FitTrace::Unverified { .. } => Some(Unverified {
                    slide: slide.part.clone(),
                    block: unit.block.clone(),
                    shape: unit.shape,
                }),
                FitTrace::Exact { .. } => None,
            })
        })
        .collect();
    let omitted = plan
        .trace()
        .iter()
        .filter(|entry| entry.outcome == TraceOutcome::Omitted)
        .map(|entry| entry.block.clone())
        .collect();
    Ok(Candidate {
        hash: *blake3::hash(&bytes).as_bytes(),
        bytes,
        report: Report {
            born_from: plan.approved().clone(),
            template: *plan.template(),
            write_set,
            slides,
            omitted,
            assets: writer.assets,
            native: writer.native,
        },
        fit: if unverified.is_empty() {
            Ok(())
        } else {
            Err(FitUnverified { units: unverified })
        },
    })
}

/// The creation template must have no existing slides. Design and emission
/// share this check, so an offered plan is never built over a live deck.
pub fn check_template(template: &Package) -> Result<(), EmitError> {
    let presentation = TemplateView::read(template)?.presentation;
    let held: Vec<String> = template
        .relationships(&presentation)?
        .into_iter()
        .filter(|rel| rel.kind == format!("{REL}/{SLIDE_REL}"))
        .map(|rel| rel.target)
        .collect();
    if !held.is_empty() {
        return Err(EmitError::TemplateSlides(held));
    }
    Ok(())
}

struct Writer<'a> {
    package: Package,
    plan: &'a DesignPlan,
    inputs: &'a EmitInputs<'a>,
    brief: &'a Brief,
    /// Media parts already written.
    media: BTreeSet<String>,
    assets: Vec<PlacedAsset>,
    native: Vec<NativeReport>,
}

impl Writer<'_> {
    /// One slide: its part over its layout, then each placement in order,
    /// shape ids from 2 (1 is the shape tree's own group).
    fn slide(&mut self, planned: &SlidePlan) -> Result<Vec<Unit>, EmitError> {
        let part = planned.part.as_str();
        let plan = self.plan;
        let row = plan.package();
        self.package
            .relate(part, &format!("{REL}/{LAYOUT_REL}"), &planned.layout)?;
        self.package
            .add_part(part, planned_type(plan, part)?, slide::empty_slide())?;
        let targets = |kind: &str| -> Vec<&str> {
            row.relationships
                .iter()
                .filter(|rel| rel.source == part && rel.kind == kind)
                .map(|rel| rel.target.as_str())
                .collect()
        };
        let mut images = targets(IMAGE_REL).into_iter();
        let mut charts = targets(CHART_REL).into_iter();
        let mut next = 2;
        let mut units = Vec::new();
        for placement in &planned.placements {
            let id = next;
            next += 1;
            let block = placement.block.as_str();
            let (placeholder, bounds) = match &placement.destination {
                Destination::Placeholder {
                    placeholder,
                    bounds,
                    ..
                } => (Some(placeholder), *bounds),
                Destination::Shape { bounds } => (None, *bounds),
            };
            let unverified = FitTrace::Unverified {
                estimate: planned
                    .fit
                    .estimates
                    .iter()
                    .find(|estimate| estimate.block == block)
                    .cloned(),
            };
            let fit = match &placement.content {
                Content::Title(text) => {
                    let text = std::slice::from_ref(text);
                    self.text(block, part, id, &placement.destination, text)?;
                    unverified
                }
                Content::Text(paragraphs) => {
                    self.text(block, part, id, &placement.destination, paragraphs)?;
                    unverified
                }
                Content::Picture(asset) | Content::Figure(asset) => {
                    let compiled = self.compile(block, asset, bounds)?;
                    let placed = compiled.record.placed;
                    let names = self.inputs.names;
                    let fragment = match &compiled.output {
                        Output::Image(_) => {
                            let media = images.next().ok_or_else(|| missing(part))?;
                            let embed = self.media(part, media, asset)?;
                            slide::picture(
                                id,
                                &format!("{} {id}", names.picture),
                                &compiled.record.description,
                                placeholder,
                                placed,
                                &embed,
                            )
                        }
                        Output::Shapes(drawing) => {
                            let name = format!("{} {id}", names.figure);
                            let (xml, after) =
                                drawing.drawingml(id, &name, &compiled.record.description);
                            next = after;
                            xml
                        }
                    };
                    self.insert(block, part, id, &fragment)?;
                    self.assets.push(PlacedAsset {
                        slide: part.to_owned(),
                        shape: id,
                        asset: asset.clone(),
                        record: compiled.record,
                    });
                    FitTrace::Exact { placed }
                }
                Content::Table(dataset) | Content::Chart(dataset) | Content::Share(dataset) => {
                    let dataset = plan
                        .data()
                        .iter()
                        .find(|data| data.id == *dataset)
                        .ok_or_else(|| EmitError::MissingDataset(dataset.clone()))?;
                    let names = self.inputs.names;
                    let table = matches!(placement.content, Content::Table(_));
                    let name = format!("{} {id}", if table { names.table } else { names.chart });
                    let frame = Frame {
                        slide: part,
                        id,
                        name: &name,
                        bounds,
                        placeholder,
                    };
                    let edit = if table {
                        NativeEdit::CreateTable {
                            frame,
                            dataset,
                            merges: &dataset.merges,
                        }
                    } else {
                        let chart = charts.next().ok_or_else(|| missing(part))?;
                        let workbook = row
                            .relationships
                            .iter()
                            .find(|rel| rel.source == chart && rel.kind == PACKAGE_REL)
                            .map(|rel| rel.target.as_str())
                            .ok_or_else(|| missing(chart))?;
                        // A share is a pie. Otherwise the brief names no chart
                        // family: a time axis reads as a line, any other
                        // category axis as columns.
                        let family = match dataset.columns.first().map(|column| column.kind) {
                            _ if matches!(placement.content, Content::Share(_)) => ChartFamily::Pie,
                            Some(ColumnKind::Date) => ChartFamily::Line,
                            _ => ChartFamily::Bar,
                        };
                        NativeEdit::CreateChart {
                            frame,
                            family,
                            dataset,
                            chart,
                            workbook,
                            sheet: names.sheet,
                        }
                    };
                    let report = native_patch(&mut self.package, &edit)
                        .map_err(|refusal| native(block, refusal))?;
                    self.native.push(report);
                    unverified
                }
            };
            units.push(Unit {
                block: block.to_owned(),
                shape: id,
                content: placement.content.clone(),
                destination: placement.destination.clone(),
                claim: self.claim(block),
                fit,
            });
        }
        Ok(units)
    }

    /// A filled placeholder keeps the layout shape's name and inherits its
    /// geometry and body properties; an ordinary text shape is placed and
    /// does not autofit.
    fn text(
        &mut self,
        block: &str,
        slide: &str,
        id: u32,
        destination: &Destination,
        paragraphs: &[String],
    ) -> Result<(), EmitError> {
        let body = slide::paragraphs(paragraphs, &self.brief.language);
        let fallback = format!("{} {id}", self.inputs.names.text);
        let fragment = match destination {
            Destination::Placeholder {
                placeholder, shape, ..
            } => {
                let name = layout_name(&self.package, shape)?.unwrap_or(fallback);
                slide::placeholder_text(id, &name, placeholder, &body)
            }
            Destination::Shape { bounds } => slide::text_box(id, &fallback, *bounds, &body),
        };
        self.insert(block, slide, id, &fragment)
    }

    fn insert(
        &mut self,
        block: &str,
        slide: &str,
        id: u32,
        fragment: &str,
    ) -> Result<(), EmitError> {
        insert_frame(&mut self.package, slide, id, fragment)
            .map_err(|refusal| native(block, refusal))
    }

    /// The graphic compiler checks the binding, provenance and bytes.
    fn compile(
        &self,
        block: &str,
        asset: &str,
        bounds: Rect,
    ) -> Result<CompiledGraphic, EmitError> {
        let unknown = || EmitError::MissingAsset(asset.to_owned());
        let stored = self.inputs.assets.get(asset).ok_or_else(unknown)?;
        let binding = self.plan.assets().get(asset).ok_or_else(unknown)?;
        let requested = self
            .brief
            .assets
            .iter()
            .find(|brief| brief.id == asset)
            .map(|brief| brief.kind)
            .ok_or_else(unknown)?;
        compile_graphic(&GraphicInput {
            binding,
            requested,
            record: stored.record,
            bytes: stored.bytes,
            bounds,
            limits: self.inputs.limits,
        })
        .map_err(|error| EmitError::Graphic {
            block: block.to_owned(),
            error,
        })
    }

    /// The slide's relationship to a media part, written at first use.
    fn media(&mut self, slide: &str, media: &str, asset: &str) -> Result<String, EmitError> {
        if self.media.insert(media.to_owned()) {
            let bytes = self
                .inputs
                .assets
                .get(asset)
                .and_then(|stored| stored.bytes)
                .ok_or_else(|| EmitError::MissingAsset(asset.to_owned()))?;
            self.package
                .add_part(media, planned_type(self.plan, media)?, bytes.to_vec())?;
        }
        Ok(self
            .package
            .relate(slide, &format!("{REL}/{IMAGE_REL}"), media)?)
    }

    fn claim(&self, block: &str) -> Option<ClaimTrace> {
        let (_, found) = self.brief.block(block)?;
        let BlockContent::Claim { evidence, .. } = &found.content else {
            return None;
        };
        Some(ClaimTrace {
            evidence: evidence.clone(),
            drifted: self
                .plan
                .trace()
                .iter()
                .any(|entry| entry.block == block && entry.drifted),
        })
    }
}

/// The content type the plan's package row gives a new part.
fn planned_type(plan: &DesignPlan, part: &str) -> Result<&'static str, EmitError> {
    plan.package()
        .new_parts
        .iter()
        .find(|new| new.part == part)
        .map(|new| new.content_type)
        .ok_or_else(|| missing(part))
}

/// The layout shape's own name, in the template's language.
fn layout_name(package: &Package, node: &RetainedNode) -> Result<Option<String>, EmitError> {
    let Some(bytes) = package.part(&node.part)? else {
        return Ok(None);
    };
    let tree = XmlTree::parse(&bytes, package.limits().xml)?;
    let Some(end) = tree.nodes.get(node.index).map(|shape| shape.span.end) else {
        return Ok(None);
    };
    Ok(tree
        .nodes
        .iter()
        .skip(node.index + 1)
        .take_while(|inner| inner.span.start < end)
        .find(|inner| inner.is(slide::PML, "cNvPr"))
        .and_then(|inner| inner.attr("name"))
        .map(str::to_owned))
}

fn missing(part: &str) -> EmitError {
    EmitError::Check {
        part: part.to_owned(),
        fault: CheckFault::MissingPlanned,
    }
}

fn native(block: &str, refusal: NativeRefusal) -> EmitError {
    EmitError::Native {
        block: block.to_owned(),
        refusal,
    }
}
