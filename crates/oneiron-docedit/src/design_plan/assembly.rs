//! Plan assembly: part names allocated above the template's high-water
//! marks, the package row's parts and relationships, per-slide fit, and the
//! trace from every block to its output units.
use super::brief::{Block, BlockContent, Division, Page};
use super::capability::Carry;
use super::ladder::Draft;
use super::{
    AssetBinding, CompileError, Composition, Content, Estimate, Fallback, Fit, FitPolicy,
    MediaType, NewPart, PackagePlan, Placement, PlannedRelationship, SlidePlan, TraceEntry,
    TraceOutcome,
};
use crate::retained_opc::Package;
use std::collections::BTreeMap;

const SLIDE_TYPE: &str = "application/vnd.openxmlformats-officedocument.presentationml.slide+xml";
const CHART_TYPE: &str = "application/vnd.openxmlformats-officedocument.drawingml.chart+xml";
const WORKBOOK_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

/// Part names and relationships, allocated above every name the template
/// already uses.
pub(super) struct Assembly<'a> {
    presentation: String,
    assets: &'a BTreeMap<String, AssetBinding>,
    next: Names,
    pub(super) slides: Vec<SlidePlan>,
    pub(super) package: PackagePlan,
    pub(super) trace: Vec<TraceEntry>,
    /// Asset id to media part; SVG assets have none.
    pub(super) media: BTreeMap<&'a str, Option<String>>,
}

/// High-water marks of the numbered part families.
struct Names {
    folder: String,
    slide: u32,
    chart: u32,
    workbook: u32,
    image: u32,
}

impl<'a> Assembly<'a> {
    pub(super) fn new(
        template: &Package,
        presentation: &str,
        assets: &'a BTreeMap<String, AssetBinding>,
    ) -> Result<Self, CompileError> {
        let folder = presentation
            .rsplit_once('/')
            .map_or_else(String::new, |(folder, _)| format!("{folder}/"));
        let high = |family: &str| high_water(template, &format!("{folder}{family}"));
        let next = Names {
            slide: high("slides/slide"),
            chart: high("charts/chart"),
            workbook: high("embeddings/Microsoft_Excel_Worksheet"),
            image: high("media/image"),
            folder,
        };
        // A package holds fewer than 65,536 entries, so no family can need
        // more names than that above its mark.
        if [next.slide, next.chart, next.workbook, next.image]
            .iter()
            .any(|&mark| mark > u32::MAX - 65_536)
        {
            return Err(CompileError::PartNames);
        }
        let rels = match presentation.rsplit_once('/') {
            Some((folder, file)) => format!("{folder}/_rels/{file}.rels"),
            None => format!("_rels/{presentation}.rels"),
        };
        Ok(Self {
            presentation: presentation.to_owned(),
            assets,
            next,
            slides: Vec::new(),
            package: PackagePlan {
                new_parts: Vec::new(),
                changed_parts: vec![
                    presentation.to_owned(),
                    rels,
                    "[Content_Types].xml".to_owned(),
                ],
                relationships: Vec::new(),
            },
            trace: Vec::new(),
            media: BTreeMap::new(),
        })
    }

    pub(super) fn page(&mut self, page: &'a Page, drafts: Vec<Draft>, omitted: &[usize]) {
        let mut placed: Vec<Vec<(usize, usize)>> = vec![Vec::new(); page.blocks.len()];
        let content_blocks = page
            .blocks
            .iter()
            .filter(|block| !matches!(block.content, BlockContent::Title { .. }))
            .count();
        for draft in drafts {
            let index = self.slides.len();
            self.next.slide += 1;
            let part = format!("{}slides/slide{}.xml", self.next.folder, self.next.slide);
            self.package.part(&part, SLIDE_TYPE);
            self.package.relate(&self.presentation, "slide", &part);
            self.package.relate(&part, "slideLayout", &draft.layout);
            let mut placements = Vec::new();
            let mut estimates = Vec::new();
            for placed_block in draft.placements {
                let block = &page.blocks[placed_block.block];
                placed[placed_block.block].push((index, placements.len()));
                let content = self.content(block, placed_block.carry, &part);
                estimates.push(Estimate {
                    block: block.id.clone(),
                    need: placed_block.need,
                    room: placed_block.room,
                });
                placements.push(Placement {
                    block: block.id.clone(),
                    content,
                    destination: placed_block.destination,
                });
            }
            self.slides.push(SlidePlan {
                page: page.id.clone(),
                part,
                layout: draft.layout,
                fallback: draft.fallback,
                split: draft.split,
                placements,
                fit: Fit {
                    policy: FitPolicy::NoShrink,
                    estimates,
                    alternatives: alternatives(draft.fallback, page.division, content_blocks),
                },
            });
        }
        for ((index, block), at) in page.blocks.iter().enumerate().zip(placed) {
            let drifted = match &block.content {
                BlockContent::Claim { evidence, .. } => evidence.iter().any(|pin| pin.drift),
                _ => false,
            };
            self.trace.push(TraceEntry {
                block: block.id.clone(),
                page: page.id.clone(),
                outcome: if omitted.contains(&index) {
                    TraceOutcome::Omitted
                } else {
                    TraceOutcome::Placed(at)
                },
                drifted,
            });
        }
    }

    fn content(&mut self, block: &'a Block, carry: Carry, slide: &str) -> Content {
        match (&block.content, carry) {
            (BlockContent::Title { text }, _) => Content::Title(text.clone()),
            (
                BlockContent::Claim {
                    text,
                    qualifications,
                    ..
                },
                _,
            ) => Content::Text(
                std::iter::once(text)
                    .chain(qualifications)
                    .cloned()
                    .collect(),
            ),
            (BlockContent::Data { dataset, .. }, Carry::Chart) => {
                self.next.chart += 1;
                self.next.workbook += 1;
                let folder = &self.next.folder;
                let chart = format!("{folder}charts/chart{}.xml", self.next.chart);
                let workbook = format!(
                    "{folder}embeddings/Microsoft_Excel_Worksheet{}.xlsx",
                    self.next.workbook
                );
                self.package.part(&chart, CHART_TYPE);
                self.package.part(&workbook, WORKBOOK_TYPE);
                self.package.relate(slide, "chart", &chart);
                self.package.relate(&chart, "package", &workbook);
                Content::Chart(dataset.clone())
            }
            (BlockContent::Data { dataset, .. }, _) => Content::Table(dataset.clone()),
            (BlockContent::Asset { asset }, _) => {
                let media = self.media_part(asset);
                match media {
                    Some(media) => {
                        self.package.relate(slide, "image", &media);
                        Content::Picture(asset.clone())
                    }
                    None => Content::Figure(asset.clone()),
                }
            }
        }
    }

    /// The asset's media part, named at first use.
    fn media_part(&mut self, asset: &'a str) -> Option<String> {
        if let Some(part) = self.media.get(asset) {
            return part.clone();
        }
        let extension = match self.assets.get(asset).map(|binding| binding.media) {
            Some(MediaType::Png) => Some(("png", "image/png")),
            Some(MediaType::Jpeg) => Some(("jpeg", "image/jpeg")),
            Some(MediaType::Svg) | None => None,
        };
        let part = extension.map(|(extension, content_type)| {
            self.next.image += 1;
            let part = format!(
                "{}media/image{}.{extension}",
                self.next.folder, self.next.image
            );
            self.package.part(&part, content_type);
            part
        });
        self.media.insert(asset, part.clone());
        part
    }
}

impl PackagePlan {
    fn part(&mut self, part: &str, content_type: &'static str) {
        self.new_parts.push(NewPart {
            part: part.to_owned(),
            content_type,
        });
    }

    fn relate(&mut self, source: &str, kind: &'static str, target: &str) {
        self.relationships.push(PlannedRelationship {
            source: source.to_owned(),
            kind,
            target: target.to_owned(),
        });
    }
}

/// The ladder steps after `fallback` that this page may still take.
fn alternatives(fallback: Option<Fallback>, division: Division, content: usize) -> Vec<Fallback> {
    let rank = |step: Option<Fallback>| match step {
        None => 0,
        Some(Fallback::OrdinaryShapes) => 1,
        Some(Fallback::Split) => 2,
        Some(Fallback::Composition(_)) => 3,
        Some(Fallback::Ask) => 4,
    };
    let splits = division == Division::Split && content > 1;
    [
        Fallback::OrdinaryShapes,
        Fallback::Split,
        Fallback::Composition(Composition::Rows),
        Fallback::Ask,
    ]
    .into_iter()
    .filter(|&step| rank(Some(step)) > rank(fallback))
    .filter(|&step| step != Fallback::Split || splits)
    .collect()
}

/// The highest number following `prefix` in any part name, compared without
/// case as package names are.
fn high_water(template: &Package, prefix: &str) -> u32 {
    let prefix = prefix.to_ascii_lowercase();
    template
        .names()
        .filter_map(|name| {
            let rest = name.to_ascii_lowercase();
            let digits: String = rest
                .strip_prefix(&prefix)?
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse::<u32>().ok()
        })
        .max()
        .unwrap_or(0)
}
