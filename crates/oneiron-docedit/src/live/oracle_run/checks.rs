//! The engine-side checks: package corruption (step 5), the part diff and
//! unknown-XML probes (step 2), the semantic fixed point (step 3) and tree
//! integrity after a merge (step 4). Each reads the exported bytes again
//! through its own path; none trusts what the projector reported.

use super::edits::office_text;
use super::record::{DOCUMENT, Res, failed, text};
use super::schema::SchemaEvidence;
use super::text_check::{Fields, same_text};
use super::variants::{COMMENT_REL, P, P188, PC, PROBE_NS, part_text, presentation_part, xml_tree};
use crate::deck::{DeckView, SlideView};
use crate::edit::NoAssets;
use crate::live::deck_export::{ExportOutcome, ExportProfile, StepOutcome, project};
use crate::live::pptx::draws_categories;
use crate::live::{DeckNode, LiveDeck, NodeId, NodeKind, NodePayload, effective_categories};
use crate::ooxml::{CONTENT_TYPES, DOCUMENT_RELATIONSHIPS};
use crate::retained_opc::{Limits, Package};
use std::collections::{BTreeMap, BTreeSet};

/// The first slide id a presentation may use, and the floor of the master
/// and layout id space (ECMA-376 Part 1, 19.2.1.33 and 19.2.1.34).
const SLIDE_ID_FLOOR: u32 = 256;
const MASTER_ID_FLOOR: u32 = 2_147_483_648;

/// Step 5 on one candidate: only defects its baseline did not already have
/// count, so a regression deck's own damage is not charged to the export.
/// Schema validation is necessary too (ARCH-0077, FIX 8590): clean
/// structural checks pass only beside a schema report bound to these bytes
/// (`sha256`) that charges nothing; without one the step is inconclusive.
pub(super) fn corruption(
    bytes: &[u8],
    limits: Limits,
    baseline: &[String],
    schema: &SchemaEvidence,
    sha256: &str,
) -> StepOutcome {
    let mut found: Vec<String> = defects(bytes, limits)
        .into_iter()
        .filter(|defect| !baseline.contains(defect))
        .collect();
    let open = match schema {
        SchemaEvidence::Validated {
            sha256: bound,
            diagnostics,
            ..
        } if bound == sha256 => {
            found.extend(diagnostics.iter().map(|diagnostic| format!("schema: {diagnostic}")));
            None
        }
        SchemaEvidence::Validated { sha256: bound, .. } => Some(format!(
            "the schema report is for other bytes ({bound}, not {sha256})"
        )),
        SchemaEvidence::Absent { why } => Some(format!("no schema-validation evidence: {why}")),
    };
    match (found.is_empty(), open) {
        (false, _) => failed(found.join("; ")),
        (true, Some(why)) => StepOutcome::Inconclusive(why),
        (true, None) => StepOutcome::Passed,
    }
}

/// Every closure, content-type, id-scope and cross-reference defect in a
/// package. Schema validity is not enough (ARCH-0077 step 5).
pub(super) fn defects(bytes: &[u8], limits: Limits) -> Vec<String> {
    let package = match Package::open(bytes, limits) {
        Ok(package) => package,
        Err(error) => return vec![format!("the package does not open: {error}")],
    };
    let mut out = Vec::new();
    collect(&mut out, closure(&package));
    collect(&mut out, content_types(&package));
    collect(&mut out, presentation_ids(&package));
    match DeckView::read(&package) {
        Ok(view) => {
            if !view.ambiguities.is_empty() {
                out.push(format!("duplicate identities: {:?}", view.ambiguities));
            }
            for slide in &view.slides {
                collect(&mut out, cross_references(&package, slide));
                collect(&mut out, comment_anchors(&package, slide));
            }
        }
        Err(error) => out.push(format!("the deck does not read: {error}")),
    }
    out
}

fn collect(out: &mut Vec<String>, found: Res<Vec<String>>) {
    match found {
        Ok(found) => out.extend(found),
        Err(why) => out.push(why),
    }
}

/// Every internal relationship of every part targets a part that exists,
/// and no source repeats a relationship id.
fn closure(package: &Package) -> Res<Vec<String>> {
    let mut sources = vec![String::new()];
    sources.extend(
        package
            .names()
            .filter(|name| !name.to_ascii_lowercase().ends_with(".rels"))
            .map(str::to_owned),
    );
    let mut out = Vec::new();
    for source in &sources {
        let rels = package.relationships(source).map_err(text)?;
        let mut ids = BTreeSet::new();
        for rel in rels {
            if !ids.insert(rel.id.clone()) {
                out.push(format!("{source:?} repeats relationship id {}", rel.id));
            }
            if !rel.external && package.part(&rel.target).map_err(text)?.is_none() {
                out.push(format!(
                    "{source:?} {} targets the missing part {}",
                    rel.id, rel.target
                ));
            }
        }
    }
    Ok(out)
}

/// Every part has a content type, by override or by its extension's
/// default, and every override names a part that exists.
fn content_types(package: &Package) -> Res<Vec<String>> {
    let xml = part_text(package, "[Content_Types].xml")?;
    let tree = xml_tree(package, &xml)?;
    let mut defaults = BTreeSet::new();
    let mut overrides = BTreeSet::new();
    for node in &tree.nodes {
        if node.is(CONTENT_TYPES, "Default")
            && let Some(extension) = node.attr("Extension")
        {
            defaults.insert(extension.to_ascii_lowercase());
        }
        if node.is(CONTENT_TYPES, "Override")
            && let Some(part) = node.attr("PartName")
        {
            overrides.insert(part.trim_start_matches('/').to_ascii_lowercase());
        }
    }
    let names: BTreeSet<String> = package
        .names()
        .filter(|name| *name != "[Content_Types].xml")
        .map(str::to_ascii_lowercase)
        .collect();
    let mut out = Vec::new();
    for name in &names {
        let extension = name
            .rsplit('/')
            .next()
            .and_then(|file| file.rsplit_once('.'))
            .map(|(_, extension)| extension);
        if !overrides.contains(name) && !extension.is_some_and(|ext| defaults.contains(ext)) {
            out.push(format!("{name} has no content type"));
        }
    }
    for part in overrides.difference(&names) {
        out.push(format!(
            "a content-type override names the missing part {part}"
        ));
    }
    Ok(out)
}

/// Slide ids are unique, in the slide id range, and each names a slide
/// relationship; master ids are unique and above the slide range.
fn presentation_ids(package: &Package) -> Res<Vec<String>> {
    let presentation = presentation_part(package)?;
    let xml = part_text(package, &presentation)?;
    let tree = xml_tree(package, &xml)?;
    let rels: BTreeMap<String, String> = package
        .relationships(&presentation)
        .map_err(text)?
        .into_iter()
        .map(|rel| (rel.id, rel.kind))
        .collect();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for node in &tree.nodes {
        let (floor, ceiling, kind) = if node.is(P, "sldId") {
            (SLIDE_ID_FLOOR, MASTER_ID_FLOOR, "/slide")
        } else if node.is(P, "sldMasterId") {
            (MASTER_ID_FLOOR, u32::MAX, "/slideMaster")
        } else {
            continue;
        };
        let id = node.attr("id").and_then(|id| id.parse::<u32>().ok());
        match id {
            Some(id) if (floor..ceiling).contains(&id) => {
                if !seen.insert(id) {
                    out.push(format!("{} id {id} repeats", node.name));
                }
            }
            _ => out.push(format!(
                "{} id {:?} is out of its range",
                node.name,
                node.attr("id")
            )),
        }
        let target = node.attr_ns(DOCUMENT_RELATIONSHIPS, "id");
        if !target.is_some_and(|rid| rels.get(rid).is_some_and(|found| found.ends_with(kind))) {
            out.push(format!(
                "{} {:?} names no {kind} relationship",
                node.name, target
            ));
        }
    }
    Ok(out)
}

/// On one slide: every relationship id its markup names resolves, every
/// animation target and connector end names a shape on the slide.
fn cross_references(package: &Package, slide: &SlideView) -> Res<Vec<String>> {
    let ids: BTreeSet<String> = package
        .relationships(&slide.part)
        .map_err(text)?
        .into_iter()
        .map(|rel| rel.id)
        .collect();
    let xml = part_text(package, &slide.part)?;
    let tree = xml_tree(package, &xml)?;
    let mut out = Vec::new();
    for node in &tree.nodes {
        for ((ns, name), value) in &node.attrs_ns {
            if ns == DOCUMENT_RELATIONSHIPS && !value.is_empty() && !ids.contains(value) {
                out.push(format!(
                    "{} {}/@r:{name} names the missing relationship {value}",
                    slide.part, node.qualified
                ));
            }
        }
    }
    let shapes: BTreeSet<u32> = slide.shapes.iter().filter_map(|shape| shape.id).collect();
    for target in &slide.animation.targets {
        if !shapes.contains(&target.shape) {
            out.push(format!(
                "{} animates the missing shape {}",
                slide.part, target.shape
            ));
        }
    }
    for connection in &slide.animation.connections {
        for end in [connection.start, connection.end].into_iter().flatten() {
            if !shapes.contains(&end) {
                out.push(format!(
                    "{} glues a connector to the missing shape {end}",
                    slide.part
                ));
            }
        }
    }
    Ok(out)
}

/// Every modern comment on the slide anchors to this slide's id and
/// creation id.
fn comment_anchors(package: &Package, slide: &SlideView) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for rel in package.relationships(&slide.part).map_err(text)? {
        if rel.external || rel.kind != COMMENT_REL {
            continue;
        }
        let xml = part_text(package, &rel.target)?;
        let tree = xml_tree(package, &xml)?;
        for node in &tree.nodes {
            if !node.is(PC, "sldMk") {
                continue;
            }
            let sld_id = node.attr("sldId").and_then(|id| id.parse::<u32>().ok());
            let creation = node.attr("cId").and_then(|id| id.parse::<u32>().ok());
            if sld_id != Some(slide.sld_id) || creation != slide.creation_id {
                out.push(format!(
                    "{} anchors a comment to slide {sld_id:?}/{creation:?}, the slide is {}/{:?}",
                    rel.target, slide.sld_id, slide.creation_id
                ));
            }
        }
        if !tree.nodes.iter().any(|node| node.is(P188, "cm")) {
            out.push(format!("{} holds no comment", rel.target));
        }
    }
    Ok(out)
}

/// What a mutation may change: the slides its operations touched, the app
/// properties the projector recounts, and what its kind adds.
#[derive(Debug, Default)]
pub(super) struct Allowed {
    pub(super) parts: BTreeSet<String>,
    pub(super) new_parts: bool,
    pub(super) removed_parts: bool,
}

/// Parts that differ between `before` and `after` that `allowed` does not
/// explain.
pub(super) fn unexplained(
    before: &Package,
    after: &Package,
    allowed: &Allowed,
) -> Res<Vec<String>> {
    let names: BTreeSet<String> = before
        .names()
        .chain(after.names())
        .map(str::to_owned)
        .collect();
    let mut out = Vec::new();
    for name in &names {
        let was = before.part(name).map_err(text)?;
        let now = after.part(name).map_err(text)?;
        if was == now {
            continue;
        }
        let explained = match (&was, &now) {
            (None, Some(_)) => allowed.new_parts || allowed.parts.contains(name),
            (Some(_), None) => allowed.removed_parts,
            _ => allowed.parts.contains(name),
        };
        if !explained {
            out.push(name.clone());
        }
    }
    Ok(out)
}

/// Where one unknown-XML probe sits: its slide part, the `p:cNvPr` id of
/// the shape holding it (none for the slide's own list), and its whole
/// extension element as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProbeSite {
    pub(super) part: String,
    pub(super) owner: Option<u32>,
    pub(super) markup: String,
}

/// Every probe in the deck's slides, by name.
pub(super) fn probes(package: &Package) -> Res<BTreeMap<String, ProbeSite>> {
    let view = DeckView::read(package).map_err(text)?;
    let mut out = BTreeMap::new();
    for slide in &view.slides {
        let xml = part_text(package, &slide.part)?;
        let tree = xml_tree(package, &xml)?;
        for node in &tree.nodes {
            if !node.is(PROBE_NS, "probe") {
                continue;
            }
            let name = node.attr("n").unwrap_or_default().to_owned();
            let ext = node
                .parent
                .map_or_else(|| node.span.clone(), |up| tree.nodes[up].span.clone());
            let mut owner = None;
            let mut up = node.parent;
            while let Some(index) = up {
                let found = &tree.nodes[index];
                if found.is(P, "cNvPr") {
                    owner = found.attr("id").and_then(|id| id.parse().ok());
                    break;
                }
                up = found.parent;
            }
            let site = ProbeSite {
                part: slide.part.clone(),
                owner,
                markup: xml.get(ext).unwrap_or_default().to_owned(),
            };
            if out.insert(name.clone(), site).is_some() {
                return Err(format!("probe {name} appears twice"));
            }
        }
    }
    Ok(out)
}

/// The plain text of each text shape, per slide in order, as the Office
/// half reads it.
pub(super) fn typed_reads(deck: &LiveDeck) -> Vec<Vec<String>> {
    slides(deck)
        .into_iter()
        .map(|slide| {
            deck.descendants(slide)
                .into_iter()
                .filter_map(|node| deck.texts.get(&node).map(|body| office_text(&body.plain())))
                .collect()
        })
        .collect()
}

/// The deck's slides in presentation order.
pub(super) fn slides(deck: &LiveDeck) -> Vec<NodeId> {
    deck.nodes
        .get(&NodeId(0))
        .map(|root| {
            root.children
                .iter()
                .copied()
                .filter(|id| {
                    deck.nodes
                        .get(id)
                        .is_some_and(|node| node.kind == NodeKind::Slide)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A node's identity across two decks: its kind and the retained element
/// its binding names.
type Key = (String, String, u32);

fn key_of(node: &DeckNode) -> Option<Key> {
    let binding = node.binding.as_ref()?;
    Some((
        format!("{:?}", node.kind),
        binding.slide_part.clone(),
        binding.native_id?,
    ))
}

fn keys(deck: &LiveDeck) -> Res<BTreeMap<Key, NodeId>> {
    let mut out = BTreeMap::new();
    for (id, node) in &deck.nodes {
        if node.kind == NodeKind::Root {
            continue;
        }
        let key = key_of(node).ok_or_else(|| format!("node {} has no native binding", id.0))?;
        if out.insert(key.clone(), *id).is_some() {
            return Err(format!("two nodes bind {key:?}"));
        }
    }
    Ok(out)
}

/// Step 3: re-import the edited output and compare it with the edited
/// model, bound to that output. Supported values, retained structure and
/// identity bindings must match (never the operation counter), and the
/// re-import's own export must be a no-op returning the same bytes, so
/// relationships keep their meaning. `base` is the package the edit was
/// projected over: a run split at a field must keep a field it held.
pub(super) fn fixed_point(
    edited: &LiveDeck,
    base: &Package,
    outcome: &ExportOutcome,
    limits: Limits,
) -> StepOutcome {
    let mut bound = edited.clone();
    if let Err(error) = bound.rebind(outcome) {
        return failed(format!("the export does not rebind: {error}"));
    }
    let package = match Package::open(&outcome.bytes, limits) {
        Ok(package) => package,
        Err(error) => return failed(format!("the export does not reopen: {error}")),
    };
    let reread = match LiveDeck::import(&package) {
        Ok(deck) => deck,
        Err(error) => return failed(format!("the export does not re-import: {error}")),
    };
    let fields = Fields::new(edited, base, &package);
    if let Err(why) = same_model(&bound, &reread, &fields) {
        return failed(why);
    }
    match project(
        &reread,
        &package,
        DOCUMENT,
        &ExportProfile::default(),
        &NoAssets,
    ) {
        Ok(again) if again.noop && again.bytes == outcome.bytes => StepOutcome::Passed,
        Ok(again) => failed(format!(
            "re-exporting the re-import changed {:?}",
            again.changed_parts
        )),
        Err(error) => failed(format!("the re-import does not export: {error}")),
    }
}

fn same_model(model: &LiveDeck, reread: &LiveDeck, fields: &Fields<'_>) -> Res<()> {
    let (left, right) = (keys(model)?, keys(reread)?);
    let only: Vec<&Key> = left
        .keys()
        .filter(|key| !right.contains_key(*key))
        .collect();
    let extra: Vec<&Key> = right
        .keys()
        .filter(|key| !left.contains_key(*key))
        .collect();
    if !only.is_empty() || !extra.is_empty() {
        return Err(format!(
            "nodes differ: only in the model {only:?}, only in the re-import {extra:?}"
        ));
    }
    if model.opaque_parts != reread.opaque_parts {
        return Err("opaque part hashes differ".to_owned());
    }
    for (key, id) in &left {
        let other = right[key];
        same_node(model, *id, reread, other)
            .and_then(|()| {
                same_text(
                    model.texts.get(id),
                    reread.texts.get(&other),
                    &|paragraph, run| fields.kept(*id, (key.1.as_str(), key.2), paragraph, run),
                )
            })
            .map_err(|why| format!("{key:?}: {why}"))?;
    }
    Ok(())
}

/// The re-import's node keyed like `id` is in the model.
fn mapped(model: &LiveDeck, id: NodeId) -> Option<Key> {
    model.nodes.get(&id).and_then(key_of)
}

fn same_node(model: &LiveDeck, id: NodeId, reread: &LiveDeck, other: NodeId) -> Res<()> {
    let (a, b) = (&model.nodes[&id], &reread.nodes[&other]);
    if a.binding
        .as_ref()
        .map(|bind| (&bind.creation_id, bind.fingerprint))
        != b.binding
            .as_ref()
            .map(|bind| (&bind.creation_id, bind.fingerprint))
    {
        return Err("identity binding differs".to_owned());
    }
    let parent = |deck: &LiveDeck, node: &DeckNode| node.parent.and_then(|up| mapped(deck, up));
    if parent(model, a) != parent(reread, b) {
        return Err("parent differs".to_owned());
    }
    let children = |deck: &LiveDeck, node: &DeckNode| -> Vec<Option<Key>> {
        node.children
            .iter()
            .map(|child| mapped(deck, *child))
            .collect()
    };
    if children(model, a) != children(reread, b) {
        return Err("child order differs".to_owned());
    }
    if a.name.is_some() && a.name != b.name {
        return Err(format!("name {:?} reads back as {:?}", a.name, b.name));
    }
    let (ga, gb) = (a.geometry, b.geometry);
    let geometry = [
        ga.offset.is_none() || ga.offset == gb.offset,
        ga.extent.is_none() || ga.extent == gb.extent,
        ga.rotation.is_none() || ga.rotation == gb.rotation,
        ga.flip_h.is_none() || ga.flip_h == gb.flip_h,
        ga.flip_v.is_none() || ga.flip_v == gb.flip_v,
    ];
    if geometry.contains(&false) {
        return Err(format!("geometry {ga:?} reads back as {gb:?}"));
    }
    if a.preset.is_some() && a.preset != b.preset {
        return Err(format!(
            "preset {:?} reads back as {:?}",
            a.preset, b.preset
        ));
    }
    same_payload(model, a.payload.as_ref(), reread, b.payload.as_ref())
}

fn same_payload(
    model: &LiveDeck,
    a: Option<&NodePayload>,
    reread: &LiveDeck,
    b: Option<&NodePayload>,
) -> Res<()> {
    let same = match (a, b) {
        (None, _) => true,
        (Some(NodePayload::Picture { image }), Some(NodePayload::HeldPicture { media })) => {
            image.hash == media.hash
        }
        (
            Some(NodePayload::Connector { preset, start, end }),
            Some(NodePayload::Connector {
                preset: read_preset,
                start: read_start,
                end: read_end,
            }),
        ) => {
            let glue = |deck: &LiveDeck, end: &Option<crate::live::ConnectorEnd>| {
                end.map(|end| (mapped(deck, end.node), end.site))
            };
            (preset.is_none() || preset == read_preset)
                && glue(model, start) == glue(reread, read_start)
                && glue(model, end) == glue(reread, read_end)
        }
        (
            Some(NodePayload::Chart {
                family,
                categories,
                series,
                source,
                ..
            }),
            Some(NodePayload::Chart {
                family: read_family,
                categories: read_categories,
                series: read_series,
                source: read_source,
                ..
            }),
        ) => {
            // Each series draws the same categories by label, level by
            // level: the import names their points afresh, and splits them
            // between the chart and its series by what each draws.
            let drawn = |(a, b): (&crate::live::ChartSeries, &crate::live::ChartSeries)| {
                if !draws_categories(*family, a) {
                    return true;
                }
                let (a, b) = (
                    effective_categories(categories, a),
                    effective_categories(read_categories, b),
                );
                a.depth() == b.depth() && a.same_labels(b)
            };
            family == read_family
                && source == read_source
                && series.len() == read_series.len()
                && (!series.is_empty()
                    || categories.depth() == read_categories.depth()
                        && categories.same_labels(read_categories))
                && series.iter().zip(read_series).all(same_series)
                && series.iter().zip(read_series).all(drawn)
        }
        // A table reads back as its grid and its drawn merges: the import
        // names its rows and columns afresh.
        (Some(NodePayload::Table(table)), Some(NodePayload::Table(read))) => {
            table.grid() == read.grid() && table.effective().spans() == read.effective().spans()
        }
        (Some(a), Some(b)) => a == b,
        (Some(_), None) => false,
    };
    if same {
        Ok(())
    } else {
        Err(format!("payload {a:?} reads back as {b:?}"))
    }
}

/// One chart series reads back unchanged: name, plot family, point count
/// and missing points exactly; values and scatter x by number, since a
/// chart cache holds no JSON number representation (`12` reads back as
/// `12.0`).
fn same_series((a, b): (&crate::live::ChartSeries, &crate::live::ChartSeries)) -> bool {
    let points = |a: &[Option<serde_json::Number>], b: &[Option<serde_json::Number>]| {
        a.len() == b.len()
            && a.iter().zip(b).all(|pair| match pair {
                (None, None) => true,
                (Some(a), Some(b)) => same_number(a, b),
                _ => false,
            })
    };
    a.name == b.name
        && a.family == b.family
        && points(&a.values, &b.values)
        && match (&a.x, &b.x) {
            (None, None) => true,
            (Some(xa), Some(xb)) => points(xa, xb),
            _ => false,
        }
        && match (&a.bubble_size, &b.bubble_size) {
            (None, None) => true,
            (Some(sa), Some(sb)) => points(sa, sb),
            _ => false,
        }
}

/// The same number, with no epsilon: two integers exactly, an integer and
/// a float only when the float is exactly that integer, two floats exactly.
fn same_number(a: &serde_json::Number, b: &serde_json::Number) -> bool {
    let int = |n: &serde_json::Number| {
        n.as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
    };
    // A finite whole float within range converts exactly; `as` saturates
    // beyond i128, past every JSON integer.
    let float_is = |n: &serde_json::Number, whole: i128| {
        n.as_f64()
            .is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f as i128 == whole)
    };
    match (int(a), int(b)) {
        (Some(x), Some(y)) => x == y,
        (Some(whole), None) => float_is(b, whole),
        (None, Some(whole)) => float_is(a, whole),
        (None, None) => a.as_f64().is_some_and(|x| b.as_f64() == Some(x)),
    }
}

/// No dangling references in a live tree: parents and children agree, text
/// bodies and connector glue name nodes that exist.
pub(super) fn dangling(deck: &LiveDeck) -> Res<()> {
    for (id, node) in &deck.nodes {
        if let Some(parent) = node.parent
            && !deck
                .nodes
                .get(&parent)
                .is_some_and(|up| up.children.contains(id))
        {
            return Err(format!(
                "node {} names a parent that does not hold it",
                id.0
            ));
        }
        for child in &node.children {
            if deck.nodes.get(child).and_then(|found| found.parent) != Some(*id) {
                return Err(format!(
                    "node {} holds {} which names another parent",
                    id.0, child.0
                ));
            }
        }
        if let Some(NodePayload::Connector { start, end, .. }) = &node.payload {
            for glued in [start, end].into_iter().flatten() {
                if !deck.nodes.contains_key(&glued.node) {
                    return Err(format!("connector {} is glued to a removed node", id.0));
                }
            }
        }
    }
    if let Some(orphan) = deck.texts.keys().find(|id| !deck.nodes.contains_key(*id)) {
        return Err(format!("a text body names the removed node {}", orphan.0));
    }
    Ok(())
}
