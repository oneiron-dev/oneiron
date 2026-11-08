use super::*;

/// Write what a bound node's preset or payload changed over its retained
/// element: a shape's or connector's preset, a connector's glue (to nodes
/// bound on its slide), new media for a picture or the held media it shows,
/// a table's changed cells or grid, a chart's changed series names,
/// categories and values or its rewrite, and a SmartArt's node text. Each
/// write is one checked verb or a rewrite that reads back; a node whose
/// retained element already reads as the live model writes nothing.
pub(super) fn project_payload(
    work: &mut Work,
    deck: &LiveDeck,
    id: NodeId,
    part: &str,
    native: u32,
    assets: &dyn Assets,
    graphics: GraphicLimits,
) -> Result<(), LiveError> {
    let node = &deck.nodes[&id];
    let view = work.view()?;
    let at = shape_at(&view, part, native)
        .ok_or(LiveError::UnknownNode)?
        .node
        .index;
    let tree = work.slide_tree(part)?;
    let preset = match (&node.payload, node.preset) {
        (Some(NodePayload::Connector { preset, .. }), _) => preset.map(ConnectorPreset::name),
        (_, Some(preset)) if matches!(node.kind, NodeKind::Shape | NodeKind::Picture) => {
            Some(preset.name())
        }
        _ => None,
    };
    if let Some(preset) = preset
        && preset_of(&tree, at) != Some(preset)
    {
        let (_, _, expected) = work.target(id)?;
        work.value(&ValueEdit::SetPreset {
            target: Target {
                slide: part,
                shape: native,
                expected,
            },
            preset,
        })?;
    }
    match &node.payload {
        Some(NodePayload::Connector { start, end, .. }) => {
            let glue = |end: &Option<ConnectorEnd>| {
                let end = (*end)?;
                let kind = deck.nodes.get(&end.node)?.kind;
                let (at, native) = work.at.get(&end.node)?;
                (at == part && !matches!(kind, NodeKind::Slide | NodeKind::Group))
                    .then_some((*native, end.site))
            };
            let wanted = (glue(start), glue(end));
            if glue_of(&tree, at) != wanted {
                let (_, _, expected) = work.target(id)?;
                work.value(&ValueEdit::SetGlue {
                    target: Target {
                        slide: part,
                        shape: native,
                        expected,
                    },
                    start: wanted.0,
                    end: wanted.1,
                })?;
            }
        }
        Some(NodePayload::Picture { image }) => {
            if held::picture_media(&work.package, part, &tree, at).map(|media| media.hash)
                != Some(image.hash)
            {
                let (record, bytes) = resolved(image, assets)?;
                let (_, _, expected) = work.target(id)?;
                work.value(&ValueEdit::SetPicture {
                    target: Target {
                        slide: part,
                        shape: native,
                        expected,
                    },
                    picture: Picture {
                        record: &record,
                        bytes: &bytes,
                        requested: requested(image),
                        limits: graphics,
                    },
                })?;
                // The raster is what the picture shows now: an SVG its blip's
                // extension still names would be what PowerPoint draws.
                if svg_fallback::drop_svg(work.next_mut(), part, native)? {
                    work.changed.insert(part.to_owned());
                }
            }
        }
        Some(NodePayload::Table(body)) => {
            table::project(work, id, node, (part, native), at, &tree, body)?;
        }
        Some(payload @ NodePayload::Chart { .. }) => {
            chart::project(work, id, node, part, (at, &tree), payload)?;
        }
        Some(NodePayload::HeldPicture { media }) => {
            // A picture already showing exactly this part and hash is kept as
            // it is, bytes and blip, whatever its format: only a retarget to
            // other media goes through the admission below.
            let shown = held::picture_media(&work.package, part, &tree, at);
            if shown.as_ref() != Some(media) {
                let (changed, done) =
                    convert::show_held_media(work.next_mut(), part, native, media)?;
                if changed {
                    if !done.is_empty() {
                        work.changed
                            .extend(work.package.changed_parts().into_iter().map(str::to_owned));
                    }
                    work.changed.insert(part.to_owned());
                    work.converted(
                        id,
                        [Conversion::HeldMediaShown {
                            part: media.part.clone(),
                        }]
                        .into_iter()
                        .chain(done),
                    );
                }
            }
        }
        Some(NodePayload::SmartArt { nodes }) => {
            let (changed, done) = diagram::write(work.next_mut(), part, native, nodes)?;
            work.changed.extend(changed);
            work.converted(id, done);
        }
        Some(NodePayload::CustomGeometry { paths }) => {
            if held::custom_paths(&tree, at).as_deref() != Some(paths.as_slice()) {
                let glued = points::glued_sites(deck, id);
                let done = points::write(work.next_mut(), part, native, paths, &glued)?;
                work.changed.insert(part.to_owned());
                work.converted(id, done);
            }
        }
        Some(NodePayload::Ole { .. }) | None => {}
    }
    Ok(())
}

/// A connector's frame from its ends' centres, when both name top-level
/// nodes with own frames: the box between them, flipped to run from the
/// start to the end.
pub(super) fn span(
    deck: &LiveDeck,
    start: Option<ConnectorEnd>,
    end: Option<ConnectorEnd>,
) -> Option<((i64, i64), (i64, i64), (bool, bool))> {
    let centre = |end: Option<ConnectorEnd>| {
        let node = deck.nodes.get(&end?.node)?;
        if deck.nodes.get(&node.parent?)?.kind != NodeKind::Slide {
            return None;
        }
        let ((x, y), (cx, cy)) = (node.geometry.offset?, node.geometry.extent?);
        Some((x.checked_add(cx / 2)?, y.checked_add(cy / 2)?))
    };
    let ((x0, y0), (x1, y1)) = (centre(start)?, centre(end)?);
    let extent = (x1.checked_sub(x0)?.abs(), y1.checked_sub(y0)?.abs());
    Some(((x0.min(x1), y0.min(y1)), extent, (x1 < x0, y1 < y0)))
}

/// Write a live-born table or chart through the native writer, or a
/// SmartArt as the engine's outline list, topmost in `part`'s shape tree
/// under the next id above the slide's mark; its id.
pub(super) fn native_frame(
    work: &mut Work,
    live: NodeId,
    node: &DeckNode,
    part: &str,
    payload: &NodePayload,
) -> Result<u32, LiveError> {
    let id = work
        .shape_mark(part)
        .checked_add(1)
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let (x, y) = node.geometry.offset.unwrap_or((0, 0));
    match payload {
        NodePayload::Table(body) => {
            table::born(work, live, node, (part, id), (x, y), body)?;
        }
        NodePayload::Chart { .. } => {
            chart::born(work, live, node, (part, id), (x, y), payload)?;
            return Ok(id);
        }
        NodePayload::SmartArt { nodes } => {
            let (cx, cy) = node.geometry.extent.unwrap_or(SMART_ART_EXTENT);
            let name = node.name.clone().unwrap_or_else(|| "Diagram".to_owned());
            let changed =
                diagram::born(work.next_mut(), part, (id, &name), (x, y), (cx, cy), nodes)?;
            work.changed.extend(changed);
            work.converted(
                live,
                [Conversion::SmartArtBorn {
                    nodes: u32::try_from(nodes.len()).unwrap_or(u32::MAX),
                }],
            );
            return Ok(id);
        }
        NodePayload::Picture { .. }
        | NodePayload::HeldPicture { .. }
        | NodePayload::Connector { .. }
        | NodePayload::CustomGeometry { .. } => {
            return Err(LiveError::Invalid(
                "the payload does not belong to the node kind",
            ));
        }
        NodePayload::Ole { .. } => {
            return Err(LiveError::Invalid(
                "a live-born graphic frame carries a table, chart or SmartArt",
            ));
        }
    }
    Ok(id)
}

/// A text body as the text mapping takes it: each paragraph's characters,
/// U+000B for a soft break; a body with no paragraph is one empty one.
pub(super) fn paragraph_chars(body: &TextBody) -> Vec<Vec<char>> {
    let mut paragraphs: Vec<Vec<char>> = body
        .paragraphs
        .iter()
        .map(|paragraph| {
            paragraph
                .runs
                .iter()
                .flat_map(|run| run.text.chars())
                .collect()
        })
        .collect();
    if paragraphs.is_empty() {
        paragraphs.push(Vec::new());
    }
    paragraphs
}

/// The live run marks over the package's runs: a live run whose declared
/// marks the package's characters under it do not read is written as one
/// `SetRunProps` over its range, which splits package runs at its edges.
/// A paragraph the package does not read as the live text is left as it is.
/// Ranges count characters over runs and fields as `SetRunProps` does: a
/// soft break (U+000B in live text) holds none, so a break's run writes
/// nothing.
pub(super) fn project_marks(
    work: &mut Work,
    id: NodeId,
    part: &str,
    native: u32,
    body: &TextBody,
) -> Result<(), LiveError> {
    let characters = |text: &str| text.chars().filter(|c| *c != BREAK).count();
    for (index, paragraph) in body.paragraphs.iter().enumerate() {
        let live_text = paragraph.text().replace(BREAK, "");
        let mut from = 0;
        for run in &paragraph.runs {
            let range = (from, from + characters(&run.text));
            from = range.1;
            if range.0 == range.1 {
                continue;
            }
            let view = work.view()?;
            let shape = shape_at(&view, part, native).ok_or(LiveError::UnknownNode)?;
            let Some(held) = shape
                .text
                .as_ref()
                .and_then(|text| text.paragraphs.get(index))
            else {
                break;
            };
            let held_text: String = held.runs.iter().map(|run| run.text.as_str()).collect();
            if held_text != live_text {
                break;
            }
            let mut props = RunProps::default();
            let mut at = 0;
            for under in &held.runs {
                let span = (at, at + under.text.chars().count());
                at = span.1;
                if span.1 <= range.0 || span.0 >= range.1 {
                    continue;
                }
                if run.bold.is_some() && under.bold.value != run.bold {
                    props.bold = run.bold;
                }
                if run.italic.is_some() && under.italic.value != run.italic {
                    props.italic = run.italic;
                }
                if run.size.is_some() && under.size.value != run.size {
                    props.size = run.size;
                }
                if let Some(face) = &run.latin
                    && under
                        .latin
                        .value
                        .as_ref()
                        .map(|font| font.typeface.as_str())
                        != Some(face.as_str())
                {
                    props.latin = Some(face.as_str());
                }
            }
            if props == RunProps::default() {
                continue;
            }
            let (_, _, expected) = work.target(id)?;
            work.value(&ValueEdit::SetRunProps {
                target: Target {
                    slide: part,
                    shape: native,
                    expected,
                },
                paragraph: index,
                range,
                expected: &held_text,
                props,
            })?;
        }
    }
    Ok(())
}
