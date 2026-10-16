//! Compile a kept brief into a validated `DesignPlan` (ARCH-0077, "Create:
//! an approved argument, then a design"). The plan stands between the kept
//! outline and package emission. It is bound to the kept brief version and
//! content hash and to the template's bytes. Its rows are the approved
//! input, template layouts, visual choices, assignments, assets and data,
//! fit, expected package parts and a trace from every output unit back to its
//! source block. Layouts are chosen by capability; when none holds a page the
//! fallback ladder runs, ending in a typed decision rather than a master edit.
mod assembly;
mod brief;
mod capability;
mod ladder;

pub use brief::{
    Asset, AssetKind, Block, BlockContent, Brief, BriefError, Carrier, Cell, Column, ColumnKind,
    Communication, Dataset, Division, Page, Pin, Priority,
};

use crate::deck::{DeckError, Placeholder, RetainedNode, TemplateView};
use crate::retained_opc::Package;
use assembly::Assembly;
use ladder::PageOutcome;
use std::collections::{BTreeMap, BTreeSet};

/// The brief as the person kept it: Keep froze this version and content
/// hash, so any later edit makes a run stale.
#[derive(Debug, Clone, Copy)]
pub struct KeptBrief<'a> {
    pub version: &'a str,
    /// BLAKE3 of `bytes`, taken when the brief was kept.
    pub content_hash: [u8; 32],
    pub bytes: &'a [u8],
}

/// A brief asset bound to stored bytes. Binding verification and asset
/// provenance belong to the graphic compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetBinding {
    pub handle: String,
    pub media: MediaType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Png,
    Jpeg,
    /// Compiled to native DrawingML shapes; no media part.
    Svg,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// The bytes are not the kept brief, or the plan names another keep.
    #[error("the brief changed after it was kept")]
    StaleBrief,
    #[error("the template changed after the plan was compiled")]
    StaleTemplate,
    #[error(transparent)]
    Brief(#[from] BriefError),
    #[error(transparent)]
    Template(#[from] DeckError),
    #[error("brief asset has no binding: {0}")]
    UnboundAsset(String),
    #[error("the template has no layouts")]
    EmptyTemplate,
    /// The plan disagrees with its brief: checked before emission.
    #[error("plan trace fault at {block}: {fault:?}")]
    Trace { block: String, fault: TraceFault },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFault {
    /// A block, or an output unit, without exactly one matching trace entry.
    Untraced,
    RequiredOmitted,
    /// An output unit on a slide of another page.
    OutsidePage,
    /// A slide out of argument order.
    OutOfOrder,
    /// A fixed page on more than one slide.
    FixedPageSplit,
    /// An estimate above its room.
    Overflow,
}

#[derive(Debug)]
pub enum Outcome {
    Plan(Box<DesignPlan>),
    /// Fallback 4: pages no rung could hold, one decision each.
    Ask(Vec<Decision>),
}

/// A typed decision for another template or a design change. Shared masters
/// are never edited to fit one page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub page: String,
    pub options: Vec<DecisionOption>,
    /// The evidence: blocks and why they do not fit.
    pub shortfalls: Vec<Shortfall>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionOption {
    OtherTemplate,
    DesignChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortfall {
    pub block: String,
    pub reason: ShortfallReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortfallReason {
    /// No placeholder or ordinary area in the template suits the content.
    NoSuitableSlot,
    /// Suitable rooms exist, and the block's estimate exceeds each one alone.
    Overflow,
    /// Each block fits alone, but not together on the page.
    Crowded,
}

/// A rectangle in slide space, in EMU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i64,
    pub y: i64,
    pub cx: i64,
    pub cy: i64,
}

impl Rect {
    fn union(self, other: Self) -> Self {
        let (x, y) = (self.x.min(other.x), self.y.min(other.y));
        Self {
            x,
            y,
            cx: (self.x + self.cx).max(other.x + other.cx) - x,
            cy: (self.y + self.cy).max(other.y + other.cy) - y,
        }
    }
}

/// The plan. Only `compile` makes one, and nothing rebinds it.
#[derive(Debug, Clone, PartialEq)]
pub struct DesignPlan {
    approved: ApprovedInput,
    template: [u8; 32],
    visual: VisualChoices,
    slides: Vec<SlidePlan>,
    data: Vec<Dataset>,
    assets: BTreeMap<String, AssetBinding>,
    package: PackagePlan,
    trace: Vec<TraceEntry>,
}

/// The kept outline version and its content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedInput {
    pub version: String,
    pub content_hash: [u8; 32],
}

/// The template's theme and tokens, read and never edited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisualChoices {
    pub master: String,
    pub theme: Option<String>,
    pub major_font: Option<String>,
    pub minor_font: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SlidePlan {
    /// The brief page this slide carries.
    pub page: String,
    /// The new slide part.
    pub part: String,
    pub layout: String,
    /// The ladder step that made this slide; `None` is the capability match.
    pub fallback: Option<Fallback>,
    /// `(index, count)` when the page was split.
    pub split: Option<(usize, usize)>,
    pub placements: Vec<Placement>,
    pub fit: Fit,
}

/// The four fallbacks, in ladder order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// A compatible layout with ordinary shapes under the same theme.
    OrdinaryShapes,
    /// The page split, as the outline permits.
    Split,
    /// A supported template-compatible composition.
    Composition(Composition),
    /// A typed decision for another template or a design change.
    Ask,
}

/// The supported compositions: ordinary shapes over the layout's region,
/// styled by the template's theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Composition {
    /// Blocks stacked full width.
    Rows,
}

/// One output unit: a source block and where it goes.
#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    pub block: String,
    pub content: Content,
    pub destination: Destination,
}

/// What is emitted, as planned; emission adds nothing else.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    Title(String),
    /// A claim and then its qualifications, one paragraph each.
    Text(Vec<String>),
    /// A dataset id.
    Table(String),
    /// A dataset id.
    Chart(String),
    /// An asset id with raster media.
    Picture(String),
    /// An asset id compiled to native shapes.
    Figure(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Fill this layout placeholder by role; the slide shape keeps `p:ph`.
    Placeholder {
        placeholder: Placeholder,
        /// The layout shape the placeholder inherits from.
        shape: RetainedNode,
        bounds: Rect,
    },
    /// An ordinary shape at these bounds.
    Shape { bounds: Rect },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fit {
    pub policy: FitPolicy,
    /// Estimates chose this slide; rendering still has to confirm it.
    pub estimates: Vec<Estimate>,
    /// Ladder steps still open for this page if a render overflows.
    pub alternatives: Vec<Fallback>,
}

/// Overflow is answered by the ladder: type is never shrunk and `fontScale`
/// is never written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FitPolicy {
    NoShrink,
}

/// Heights in EMU: what the block is estimated to need, and its room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Estimate {
    pub block: String,
    pub need: i64,
    pub room: i64,
}

/// The parts emission creates and the existing parts it may change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePlan {
    pub new_parts: Vec<NewPart>,
    pub changed_parts: Vec<String>,
    pub relationships: Vec<PlannedRelationship>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPart {
    pub part: String,
    pub content_type: &'static str,
}

/// A relationship to create; `kind` is the type URI's last segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRelationship {
    pub source: String,
    pub kind: &'static str,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub block: String,
    pub page: String,
    pub outcome: TraceOutcome,
    /// An evidence pin no longer maps; its quote is kept.
    pub drifted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceOutcome {
    /// `(slide, placement)` indices; a split page repeats its title.
    Placed(Vec<(usize, usize)>),
    /// An optional block the page could not hold.
    Omitted,
}

/// Compile the kept brief against `template`. Every page is planned or, when
/// no rung holds it, returned as a decision; a plan is all or nothing.
pub fn compile(
    kept: &KeptBrief<'_>,
    template: &Package,
    assets: &BTreeMap<String, AssetBinding>,
) -> Result<Outcome, CompileError> {
    if *blake3::hash(kept.bytes).as_bytes() != kept.content_hash {
        return Err(CompileError::StaleBrief);
    }
    let brief = Brief::parse(kept.bytes)?;
    for block in brief.pages.iter().flat_map(|page| &page.blocks) {
        if let BlockContent::Asset { asset } = &block.content
            && !assets.contains_key(asset)
        {
            return Err(CompileError::UnboundAsset(asset.clone()));
        }
    }
    let view = TemplateView::read(template)?;
    let identity = identity(template)?;
    let master = view
        .masters
        .iter()
        .find(|master| !master.layouts.is_empty())
        .ok_or(CompileError::EmptyTemplate)?;
    let profiles = capability::Template::read(master);
    let mut pages = Vec::new();
    let mut decisions = Vec::new();
    for page in &brief.pages {
        match ladder::plan_page(&brief, page, &profiles) {
            PageOutcome::Slides(drafts, omitted) => pages.push((page, drafts, omitted)),
            PageOutcome::Ask(shortfalls) => decisions.push(Decision {
                page: page.id.clone(),
                options: vec![DecisionOption::OtherTemplate, DecisionOption::DesignChange],
                shortfalls,
            }),
        }
    }
    if !decisions.is_empty() {
        return Ok(Outcome::Ask(decisions));
    }
    let mut assembly = Assembly::new(template, &view.presentation, assets);
    for (page, drafts, omitted) in pages {
        assembly.page(page, drafts, &omitted);
    }
    let Assembly {
        slides,
        package,
        trace,
        media,
        ..
    } = assembly;
    let data = brief
        .datasets
        .iter()
        .filter(|dataset| {
            slides.iter().flat_map(|slide| &slide.placements).any(|placement| {
                matches!(&placement.content, Content::Table(id) | Content::Chart(id) if *id == dataset.id)
            })
        })
        .cloned()
        .collect();
    Ok(Outcome::Plan(Box::new(DesignPlan {
        approved: ApprovedInput {
            version: kept.version.to_owned(),
            content_hash: kept.content_hash,
        },
        template: identity,
        visual: VisualChoices {
            master: master.part.clone(),
            theme: master.theme.clone(),
            major_font: master.major_font.clone(),
            minor_font: master.minor_font.clone(),
        },
        slides,
        data,
        assets: assets
            .iter()
            .filter(|(asset, _)| media.contains_key(asset.as_str()))
            .map(|(asset, binding)| (asset.clone(), binding.clone()))
            .collect(),
        package,
        trace,
    })))
}

/// The template's identity: BLAKE3 of its exported bytes.
fn identity(template: &Package) -> Result<[u8; 32], CompileError> {
    let bytes = template.export().map_err(DeckError::from)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

impl DesignPlan {
    pub fn approved(&self) -> &ApprovedInput {
        &self.approved
    }
    /// BLAKE3 of the template package the plan was compiled against.
    pub fn template(&self) -> &[u8; 32] {
        &self.template
    }
    pub fn visual(&self) -> &VisualChoices {
        &self.visual
    }
    pub fn slides(&self) -> &[SlidePlan] {
        &self.slides
    }
    /// The datasets the plan's tables and charts carry.
    pub fn data(&self) -> &[Dataset] {
        &self.data
    }
    /// The bindings of the assets the plan places.
    pub fn assets(&self) -> &BTreeMap<String, AssetBinding> {
        &self.assets
    }
    pub fn package(&self) -> &PackagePlan {
        &self.package
    }
    pub fn trace(&self) -> &[TraceEntry] {
        &self.trace
    }

    /// Validate the plan before emission, independently of how it was made:
    /// the same keep and template, slides in argument order inside their
    /// pages, estimates within their rooms, and a trace that accounts for
    /// every block and every output unit, required content never omitted.
    pub fn check(&self, kept: &KeptBrief<'_>, template: &Package) -> Result<(), CompileError> {
        if kept.version != self.approved.version
            || kept.content_hash != self.approved.content_hash
            || *blake3::hash(kept.bytes).as_bytes() != kept.content_hash
        {
            return Err(CompileError::StaleBrief);
        }
        if identity(template)? != self.template {
            return Err(CompileError::StaleTemplate);
        }
        let brief = Brief::parse(kept.bytes)?;
        self.check_slides(&brief)?;
        self.check_trace(&brief)
    }

    fn check_slides(&self, brief: &Brief) -> Result<(), CompileError> {
        let mut last = 0;
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for slide in &self.slides {
            let first = slide
                .placements
                .first()
                .map_or(slide.page.as_str(), |placement| placement.block.as_str());
            let Some(index) = brief.pages.iter().position(|page| page.id == slide.page) else {
                return Err(fault(first, TraceFault::OutsidePage));
            };
            if index < last {
                return Err(fault(first, TraceFault::OutOfOrder));
            }
            last = index;
            let count = seen.entry(slide.page.as_str()).or_default();
            *count += 1;
            if *count > 1 && brief.pages[index].division == Division::Fixed {
                return Err(fault(first, TraceFault::FixedPageSplit));
            }
            for placement in &slide.placements {
                if brief
                    .block(&placement.block)
                    .is_none_or(|(page, _)| page.id != slide.page)
                {
                    return Err(fault(&placement.block, TraceFault::OutsidePage));
                }
            }
            if let Some(over) = slide.fit.estimates.iter().find(|e| e.need > e.room) {
                return Err(fault(&over.block, TraceFault::Overflow));
            }
        }
        Ok(())
    }

    fn check_trace(&self, brief: &Brief) -> Result<(), CompileError> {
        let mut traced = BTreeSet::new();
        for block in brief.pages.iter().flat_map(|page| &page.blocks) {
            let mut entries = self.trace.iter().filter(|entry| entry.block == block.id);
            let (Some(entry), None) = (entries.next(), entries.next()) else {
                return Err(fault(&block.id, TraceFault::Untraced));
            };
            match &entry.outcome {
                TraceOutcome::Omitted if block.priority == Priority::Required => {
                    return Err(fault(&block.id, TraceFault::RequiredOmitted));
                }
                TraceOutcome::Omitted => {}
                TraceOutcome::Placed(at) => {
                    if at.is_empty() {
                        return Err(fault(&block.id, TraceFault::Untraced));
                    }
                    for &(slide, placement) in at {
                        let held = self
                            .slides
                            .get(slide)
                            .and_then(|slide| slide.placements.get(placement));
                        if held.is_none_or(|held| held.block != block.id) {
                            return Err(fault(&block.id, TraceFault::Untraced));
                        }
                        traced.insert((slide, placement));
                    }
                }
            }
        }
        for (index, slide) in self.slides.iter().enumerate() {
            for (at, placement) in slide.placements.iter().enumerate() {
                if !traced.contains(&(index, at)) {
                    return Err(fault(&placement.block, TraceFault::Untraced));
                }
            }
        }
        if let Some(stray) = self
            .trace
            .iter()
            .find(|entry| brief.block(&entry.block).is_none())
        {
            return Err(fault(&stray.block, TraceFault::Untraced));
        }
        Ok(())
    }
}

fn fault(block: &str, fault: TraceFault) -> CompileError {
    CompileError::Trace {
        block: block.to_owned(),
        fault,
    }
}

#[cfg(test)]
pub(crate) mod tests;
