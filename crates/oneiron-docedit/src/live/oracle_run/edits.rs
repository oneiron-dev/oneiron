//! The path every exported edit takes: apply the operations to the import,
//! project over the retained package, check the part diff and the probes,
//! re-import (step 3), and write the candidate with the checks PowerPoint
//! owes it.

use super::assets::OracleAssets;
use super::checks::{self, Allowed, ProbeSite};
use super::recipes::plan;
use super::record::{
    DOCUMENT, EDIT, Emit, FIXED_POINT, Lane, ORACLE, OfficeCheck, Res, Run, failed, text, verdict,
};
use super::spec::Recipe;
use super::variants::{SHAPE_PROBE, presentation_part};
use crate::edit::{Assets, BREAK, Preset};
use crate::live::deck_export::{ExportOutcome, ExportProfile, project};
use crate::live::{
    DeckOp, GeometryProps, LiveDeck, LiveError, NodeId, NodeKind, NodePayload, Paragraph,
    Run as TextRun, StampedOp, TextBody,
};
use crate::retained_opc::{Limits, Package, rels_name};
use std::collections::{BTreeMap, BTreeSet};

/// Who the runner's operations are stamped by: attribution, never authority.
pub(super) const ACTOR: &str = "deck-oracle";
/// What a text edit appends to the run it changes.
pub(super) const EDIT_MARK: &str = " (oracle edit)";

/// A deck under test: its bytes, retained package and import, and the
/// defects it already had (step 5 charges only new ones).
pub(super) struct Deck {
    pub(super) id: String,
    pub(super) bytes: Vec<u8>,
    pub(super) package: Package,
    pub(super) deck: LiveDeck,
    pub(super) defects: Vec<String>,
}

impl Deck {
    pub(super) fn load(id: &str, bytes: Vec<u8>, limits: Limits) -> Res<Self> {
        let package = Package::open(&bytes, limits).map_err(text)?;
        let deck = LiveDeck::import(&package).map_err(text)?;
        let defects = checks::defects(&bytes, limits);
        Ok(Self {
            id: id.to_owned(),
            bytes,
            package,
            deck,
            defects,
        })
    }
}

/// Where the core mutations land: the first slide and its first bound text
/// shape.
pub(super) struct Anchor {
    pub(super) slide: NodeId,
    pub(super) slide_part: String,
    pub(super) sld_id: u32,
    pub(super) shape: NodeId,
    pub(super) native: u32,
}

pub(super) fn anchor(deck: &LiveDeck) -> Res<Anchor> {
    let slide = *checks::slides(deck)
        .first()
        .ok_or("the deck has no slide")?;
    let binding = deck.nodes[&slide]
        .binding
        .as_ref()
        .ok_or("the first slide is not bound")?;
    let shape = deck
        .descendants(slide)
        .into_iter()
        .find(|id| text_shape(deck, *id))
        .ok_or("the first slide has no bound text shape")?;
    let native = deck.nodes[&shape]
        .binding
        .as_ref()
        .and_then(|bound| bound.native_id)
        .ok_or("the text shape has no native id")?;
    Ok(Anchor {
        slide,
        slide_part: binding.slide_part.clone(),
        sld_id: binding.native_id.ok_or("the first slide has no id")?,
        shape,
        native,
    })
}

/// A bound shape of its own text (no held payload) whose first paragraph
/// has a run.
pub(super) fn text_shape(deck: &LiveDeck, id: NodeId) -> bool {
    deck.nodes.get(&id).is_some_and(|node| {
        node.kind == NodeKind::Shape
            && node.payload.is_none()
            && node
                .binding
                .as_ref()
                .is_some_and(|bound| bound.native_id.is_some())
    }) && deck.texts.get(&id).is_some_and(|body| {
        body.paragraphs
            .first()
            .is_some_and(|paragraph| !paragraph.runs.is_empty())
    })
}

/// Model identities above every node and paragraph the deck holds, so a
/// case's creations never collide with the import or an earlier landing.
pub(super) struct Ids(u64);

impl Ids {
    pub(super) fn above(deck: &LiveDeck) -> Self {
        let nodes = deck.nodes.keys().map(|id| id.0).max().unwrap_or(0);
        let paragraphs = deck
            .texts
            .values()
            .flat_map(|body| &body.paragraphs)
            .map(|paragraph| paragraph.id.0)
            .max()
            .unwrap_or(0);
        Self(deck.next_node.max(nodes + 1).max(paragraphs + 1))
    }

    pub(super) fn mint(&mut self) -> NodeId {
        let id = NodeId(self.0);
        self.0 += 1;
        id
    }
}

pub(super) fn plain_run(text: &str) -> TextRun {
    TextRun {
        text: text.to_owned(),
        bold: None,
        italic: None,
        size: None,
        latin: None,
    }
}

/// One paragraph of plain text.
pub(super) fn body(ids: &mut Ids, text: &str) -> TextBody {
    TextBody {
        paragraphs: vec![Paragraph {
            id: ids.mint(),
            level: 0,
            runs: vec![plain_run(text)],
        }],
    }
}

/// Own offset and extent, in EMU.
pub(super) fn frame(x: i64, y: i64, cx: i64, cy: i64) -> GeometryProps {
    GeometryProps {
        offset: Some((x, y)),
        extent: Some((cx, cy)),
        ..GeometryProps::default()
    }
}

/// The geometry moved half an inch right and down; an inherited frame is
/// owned whole, never half-written.
pub(super) fn shifted(geometry: GeometryProps) -> GeometryProps {
    match (geometry.offset, geometry.extent) {
        (Some((x, y)), Some(extent)) => GeometryProps {
            offset: Some((x + 457_200, y + 457_200)),
            extent: Some(extent),
            ..geometry
        },
        _ => GeometryProps {
            offset: Some((1_828_800, 1_828_800)),
            extent: Some(geometry.extent.unwrap_or((3_657_600, 914_400))),
            ..geometry
        },
    }
}

pub(super) fn add(
    id: NodeId,
    parent: NodeId,
    kind: NodeKind,
    name: &str,
    preset: Option<Preset>,
    payload: Option<NodePayload>,
) -> DeckOp {
    DeckOp::AddNode {
        id: Some(id),
        parent,
        kind,
        name: Some(name.to_owned()),
        index: None,
        preset,
        payload,
    }
}

pub(super) fn stamp(actor: &str, at: usize, op: DeckOp) -> StampedOp {
    StampedOp {
        made_by: actor.to_owned(),
        at: at as u64,
        op,
    }
}

/// Apply `ops` in order; the slide parts their affected nodes live on.
pub(super) fn apply_all(
    deck: &mut LiveDeck,
    ops: &[DeckOp],
) -> Result<BTreeSet<String>, LiveError> {
    let mut touched = BTreeSet::new();
    for (at, op) in ops.iter().enumerate() {
        let before = deck.clone();
        for node in deck.apply(&stamp(ACTOR, at, op.clone()))? {
            if let Some(part) = deck
                .slide_part_of(node)
                .or_else(|| before.slide_part_of(node))
            {
                touched.insert(part);
            }
        }
    }
    Ok(touched)
}

/// Why an edit produced no candidate.
pub(super) enum Refused {
    Model(LiveError),
    Export(LiveError),
}

impl Refused {
    pub(super) fn why(&self) -> String {
        match self {
            Self::Model(error) => format!("the live model refused the mutation: {error}"),
            Self::Export(error) => format!("the export refused the mutation: {error}"),
        }
    }
}

/// An applied and projected edit.
pub(super) struct Exported {
    pub(super) deck: LiveDeck,
    pub(super) touched: BTreeSet<String>,
    pub(super) outcome: ExportOutcome,
}

pub(super) fn export(
    base: &Deck,
    ops: &[DeckOp],
    assets: &dyn Assets,
) -> Result<Exported, Refused> {
    let mut deck = base.deck.clone();
    let touched = apply_all(&mut deck, ops).map_err(Refused::Model)?;
    let outcome = project(
        &deck,
        &base.package,
        DOCUMENT,
        &ExportProfile::default(),
        assets,
    )
    .map_err(Refused::Export)?;
    Ok(Exported {
        deck,
        touched,
        outcome,
    })
}

/// The parts a mutation's kind may add to the slides it touched.
#[derive(Debug, Clone, Copy)]
pub(super) struct Scope {
    /// The touched slides' relationship parts.
    rels: bool,
    /// The content types part.
    types: bool,
    /// The presentation part and its relationships (the slide list).
    presentation: bool,
    /// Parts the baseline did not have.
    new_parts: bool,
}

impl Scope {
    /// Markup on the touched slides only.
    pub(super) const SLIDE: Self = Self {
        rels: false,
        types: false,
        presentation: false,
        new_parts: false,
    };
    /// A new media, chart or workbook part related from the slide.
    pub(super) const RELATED: Self = Self {
        rels: true,
        types: true,
        presentation: false,
        new_parts: true,
    };
    /// A new slide in the slide list.
    pub(super) const LISTED: Self = Self {
        rels: true,
        types: true,
        presentation: true,
        new_parts: true,
    };
}

/// The app properties part the projector recounts after any change.
fn app_part(package: &Package) -> Res<Option<String>> {
    Ok(package
        .relationships("")
        .map_err(text)?
        .into_iter()
        .find(|rel| !rel.external && rel.kind.ends_with("/extended-properties"))
        .map(|rel| rel.target))
}

/// The allowed set, derived from the operations' touched slides and the
/// mutation's kind (ARCH-0077 step 2).
pub(super) fn allowed(scope: Scope, touched: &BTreeSet<String>, package: &Package) -> Res<Allowed> {
    let mut parts = touched.clone();
    if scope.rels {
        for part in touched {
            parts.insert(rels_name(part));
        }
    }
    parts.extend(app_part(package)?);
    if scope.types {
        parts.insert("[Content_Types].xml".to_owned());
    }
    if scope.presentation {
        let presentation = presentation_part(package)?;
        parts.insert(rels_name(&presentation));
        parts.insert(presentation);
    }
    Ok(Allowed {
        parts,
        new_parts: scope.new_parts,
        removed_parts: false,
    })
}

/// The part diff explained by `allowed`.
pub(super) fn diff_explained(before: &Package, after: &Package, allowed: &Allowed) -> Res<()> {
    let unexplained = checks::unexplained(before, after, allowed)?;
    if unexplained.is_empty() {
        Ok(())
    } else {
        Err(format!("unexplained part changes: {unexplained:?}"))
    }
}

/// The text body with `mark` appended to the last run of its first
/// paragraph, and that paragraph's new text as Office reads it.
pub(super) fn appended(body: &TextBody, mark: &str) -> Res<(TextBody, String)> {
    let mut next = body.clone();
    let paragraph = next
        .paragraphs
        .first_mut()
        .ok_or("the text body has no paragraph")?;
    paragraph
        .runs
        .last_mut()
        .ok_or("the first paragraph has no run")?
        .text
        .push_str(mark);
    let edited = office_text(&paragraph.text());
    Ok((next, edited))
}

/// Live text as the Office half reads a paragraph (`deck_gate.py`'s text,
/// each paragraph's `a:t` joined): a soft break, U+000B in live text, reads
/// as nothing.
pub(super) fn office_text(text: &str) -> String {
    text.replace(BREAK, "")
}

/// The subject of the core mutations: the probed baseline, its anchor and
/// where its probes sit.
pub(super) struct Subject<'a> {
    pub(super) deck: &'a Deck,
    pub(super) anchor: &'a Anchor,
    pub(super) probes: &'a BTreeMap<String, ProbeSite>,
}

/// Where a probe must sit after the export: its holder's slide part and,
/// for the shape probe, the holder's native id; `None` when the probe goes
/// with its removed holder.
fn expected_site(
    subject: &Subject<'_>,
    outcome: &ExportOutcome,
    name: &str,
    removed: bool,
) -> Res<Option<(String, Option<u32>)>> {
    let shape = name == SHAPE_PROBE;
    if shape && removed {
        return Ok(None);
    }
    let holder = if shape {
        subject.anchor.shape
    } else {
        subject.anchor.slide
    };
    let bound = outcome
        .bindings
        .get(&holder)
        .ok_or_else(|| format!("probe {name}'s holder has no binding in the export"))?;
    let owner = bound.native_id.filter(|_| shape);
    Ok(Some((bound.slide_part.clone(), owner)))
}

/// Every probe of the baseline sits where its holder now is, byte for byte,
/// and goes only with a removed holder.
fn probes_kept(
    subject: &Subject<'_>,
    output: &Package,
    outcome: &ExportOutcome,
    removed: bool,
) -> Res<()> {
    let after = checks::probes(output)?;
    for (name, site) in subject.probes {
        match (
            expected_site(subject, outcome, name, removed)?,
            after.get(name),
        ) {
            (None, None) => {}
            (None, Some(found)) => {
                return Err(format!(
                    "probe {name} outlived its removed shape in {}",
                    found.part
                ));
            }
            (Some(_), None) => return Err(format!("probe {name} was dropped")),
            (Some((part, owner)), Some(found)) if found.part != part || found.owner != owner => {
                return Err(format!(
                    "probe {name} was displaced from {part}/{owner:?} to {}/{:?}",
                    found.part, found.owner
                ));
            }
            (Some(_), Some(found)) if found.markup != site.markup => {
                return Err(format!("probe {name} was rewritten as {}", found.markup));
            }
            (Some(_), Some(_)) => {}
        }
    }
    match after
        .keys()
        .find(|name| !subject.probes.contains_key(*name))
    {
        Some(extra) => Err(format!("probe {extra} appeared")),
        None => Ok(()),
    }
}

/// One core mutation, end to end (steps 2, 3 and 5; step 6 in PowerPoint).
pub(super) fn edit_case(
    run: &mut Run,
    subject: &Subject<'_>,
    recipe: Recipe,
    assets: &OracleAssets,
) -> Res<()> {
    let case = format!("{}.edit.{}", subject.deck.id, recipe.name());
    run.case(&case, |run| edit_body(run, &case, subject, recipe, assets))
}

fn edit_body(
    run: &mut Run,
    case: &str,
    subject: &Subject<'_>,
    recipe: Recipe,
    assets: &OracleAssets,
) -> Res<()> {
    let mut ids = Ids::above(&subject.deck.deck);
    let plan = match plan(recipe, subject, &mut ids, assets) {
        Ok(plan) => plan,
        Err(why) => {
            run.record(
                EDIT,
                case,
                failed(format!("the case does not fit the baseline: {why}")),
            );
            return Ok(());
        }
    };
    let exported = match export(subject.deck, &plan.ops, assets) {
        Ok(exported) => exported,
        Err(refused) => {
            run.record(EDIT, case, failed(refused.why()));
            return Ok(());
        }
    };
    let output = match Package::open(&exported.outcome.bytes, run.limits) {
        Ok(output) => output,
        Err(error) => {
            run.record(
                EDIT,
                case,
                failed(format!("the export does not reopen: {error}")),
            );
            return Ok(());
        }
    };
    let preserved = allowed(plan.scope, &exported.touched, &subject.deck.package)
        .and_then(|allowed| diff_explained(&subject.deck.package, &output, &allowed))
        .and_then(|()| probes_kept(subject, &output, &exported.outcome, plan.removes_shape));
    run.record(EDIT, case, verdict(preserved));
    run.record(
        FIXED_POINT,
        case,
        checks::fixed_point(
            &exported.deck,
            &subject.deck.package,
            &exported.outcome,
            run.limits,
        ),
    );
    let slides = checks::slides(&exported.deck).len();
    let mut owed = plan.checks;
    owed.push(OfficeCheck::Slides { count: slides });
    owed.push(OfficeCheck::Pages { count: slides });
    run.candidate(Emit {
        id: case,
        bytes: &exported.outcome.bytes,
        steps: &[ORACLE],
        lane: Lane::Core,
        checks: owed,
        baseline: &subject.deck.defects,
        origin: &subject.deck.bytes,
    })
}
