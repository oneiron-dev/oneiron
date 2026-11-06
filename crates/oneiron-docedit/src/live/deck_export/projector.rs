use super::*;

/// Project `deck` at its current version over its retained `package`;
/// `assets` supply the bytes of its live-born pictures.
pub fn project(
    deck: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
    assets: &dyn Assets,
) -> Result<ExportOutcome, LiveError> {
    let key = export_key(deck, package, document, profile)?;
    // Opaque replacements carry only their hash in the live model; the
    // replacement bytes must already be the retained part's bytes.
    for (part, expected) in &deck.opaque_parts {
        match package.part(part)? {
            Some(bytes) if blake3::hash(&bytes).as_bytes() == expected => {}
            _ => {
                return Err(LiveError::Invalid(
                    "opaque replacement bytes are not in the retained package",
                ));
            }
        }
    }
    let view = Rc::new(DeckView::read(package)?);
    let mut marks = deck.id_marks.clone();
    marks.join(&IdMarks::of_deck(&view));
    let mut work = Work {
        package: package.clone(),
        reads: Reads {
            view: OnceCell::from(Rc::clone(&view)),
            slides: RefCell::default(),
        },
        document: document.to_owned(),
        marks,
        at: BTreeMap::new(),
        changed: BTreeSet::new(),
        effects: Vec::new(),
        series: BTreeMap::new(),
    };
    // Every binding must name its retained element exactly as bound.
    for (id, node) in &deck.nodes {
        if node.kind == NodeKind::Group && node.children.is_empty() {
            return Err(LiveError::Invalid(
                "a group with no members has no native form",
            ));
        }
        let Some(binding) = &node.binding else {
            continue;
        };
        let native = binding
            .native_id
            .ok_or(LiveError::Invalid("a retained element has no native id"))?;
        match node.kind {
            NodeKind::Root => continue,
            NodeKind::Slide => {
                let slide = view
                    .slides
                    .iter()
                    .find(|slide| slide.part == binding.slide_part && slide.sld_id == native)
                    .ok_or(STALE)?;
                if slide.content_fingerprint != binding.fingerprint
                    || slide.creation_id.map(|id| id.to_string()) != binding.creation_id
                {
                    return Err(STALE);
                }
            }
            _ => {
                let shape = shape_at(&view, &binding.slide_part, native).ok_or(STALE)?;
                if shape.content_fingerprint != binding.fingerprint
                    || shape.creation_id != binding.creation_id
                {
                    return Err(STALE);
                }
            }
        }
        work.at.insert(*id, (binding.slide_part.clone(), native));
    }
    let slides: Vec<NodeId> = deck
        .nodes
        .get(&NodeId(0))
        .map(|root| root.children.clone())
        .unwrap_or_default();
    let order = deck.descendants(NodeId(0));

    // 1. Live-born slides, each after its live predecessor, over the
    // predecessor's layout (or the first one any slide uses).
    let mut previous: Option<String> = None;
    for slide in &slides {
        if let Some((part, _)) = work.at.get(slide) {
            previous = Some(part.clone());
            continue;
        }
        let current = work.view()?;
        let layout = previous
            .as_ref()
            .and_then(|part| current.slides.iter().find(|s| &s.part == part))
            .and_then(|s| s.layout.clone())
            .or_else(|| current.slides.iter().find_map(|s| s.layout.clone()))
            .ok_or(LiveError::Invalid(
                "no slide layout to build a live-born slide over",
            ))?;
        let (high, seed) = (work.marks.slide, work.seed(*slide, "slide"));
        let effects = work.structure(&StructureEdit::AddSlide {
            after: previous.as_deref(),
            layout: &layout,
            high_water: high,
            seed: &seed,
        })?;
        let (part, sld_id) = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::SlideAdded { part, sld_id, .. } => Some((part.clone(), *sld_id)),
                _ => None,
            })
            .ok_or(LiveError::Invalid("the slide verb added no slide"))?;
        work.marks.slide = work.marks.slide.max(sld_id);
        work.at.insert(*slide, (part.clone(), sld_id));
        previous = Some(part);
    }
    // The slide part each live node now belongs on.
    let mut home: BTreeMap<NodeId, String> = BTreeMap::new();
    for node in &order {
        let slide = slide_of(deck, *node).ok_or(LiveError::UnknownNode)?;
        let (part, _) = work.at.get(&slide).ok_or(LiveError::UnknownNode)?;
        home.insert(*node, part.clone());
    }

    // 2. Cross-slide moves, outermost first: a copy on the new slide with
    // its relationships; members bound inside it that moved too follow it.
    for node in &order {
        if deck.nodes[node].kind == NodeKind::Slide {
            continue;
        }
        let Some((part, _)) = work.at.get(node).cloned() else {
            continue;
        };
        let to = home[node].clone();
        if part == to {
            continue;
        }
        let (_, native, expected) = work.target(*node)?;
        let (high, seed) = (work.shape_mark(&to), work.seed(*node, "copy"));
        let effects = work.structure(&StructureEdit::CopyToSlide {
            target: Target {
                slide: &part,
                shape: native,
                expected,
            },
            to: &to,
            high_water: high,
            seed: &seed,
        })?;
        let copied: BTreeMap<u32, u32> = effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::ShapeCopied { from, id } => Some((*from, *id)),
                _ => None,
            })
            .collect();
        for id in copied.values() {
            work.raise_shape(&to, *id);
        }
        for (other, place) in work.at.iter_mut() {
            if place.0 == part
                && home.get(other) == Some(&to)
                && let Some(new) = copied.get(&place.1)
            {
                *place = (to.clone(), *new);
            }
        }
    }

    // 3. Live-born shapes, groups, pictures and graphic frames, in
    // model-identity order, topmost in their slide's shape tree; then the
    // live-born connectors, so every node their ends name is bound. The
    // reparent pass puts them in place.
    for connectors in [false, true] {
        for (id, node) in &deck.nodes {
            if matches!(node.kind, NodeKind::Root | NodeKind::Slide)
                || (node.kind == NodeKind::Connector) != connectors
                || work.at.contains_key(id)
            {
                continue;
            }
            let part = home.get(id).cloned().ok_or(LiveError::UnknownNode)?;
            let added = born(&mut work, deck, *id, &part, assets)?;
            work.raise_shape(&part, added);
            work.at.insert(*id, (part, added));
        }
    }

    // 4. Reparents, outermost first, so a parent group is in place before
    // its members join it.
    for node in &order {
        let found = &deck.nodes[node];
        if found.kind == NodeKind::Slide {
            continue;
        }
        let parent = found.parent.ok_or(LiveError::UnknownNode)?;
        let wanted = match deck.nodes.get(&parent).map(|p| p.kind) {
            Some(NodeKind::Slide) => None,
            Some(_) => Some(work.at.get(&parent).ok_or(LiveError::UnknownNode)?.1),
            None => return Err(LiveError::UnknownNode),
        };
        let (part, native, expected) = work.target(*node)?;
        let current = work.view()?;
        let slide = current
            .slides
            .iter()
            .find(|slide| slide.part == part)
            .ok_or(LiveError::UnknownNode)?;
        let shape = shape_at(&current, &part, native).ok_or(LiveError::UnknownNode)?;
        let held = shape
            .group_path
            .last()
            .and_then(|&group| slide.shapes[group].id);
        if held == wanted {
            continue;
        }
        work.structure(&StructureEdit::Reparent {
            target: Target {
                slide: &part,
                shape: native,
                expected,
            },
            parent: wanted,
        })?;
    }

    // 5. Removals: every retained element no live node holds, outermost
    // first, with its animation effects and connector glue.
    let wanted: BTreeSet<(String, u32)> = work.at.values().cloned().collect();
    let kept: BTreeSet<String> = slides
        .iter()
        .filter_map(|slide| work.at.get(slide).map(|(part, _)| part.clone()))
        .collect();
    loop {
        let current = work.view()?;
        let unwanted = current
            .slides
            .iter()
            .filter(|slide| kept.contains(&slide.part))
            .find_map(|slide| {
                slide.shapes.iter().find_map(|shape| {
                    let id = shape.id?;
                    (!wanted.contains(&(slide.part.clone(), id)))
                        .then(|| (slide.part.clone(), id, shape.content_fingerprint))
                })
            });
        let Some((part, shape, expected)) = unwanted else {
            break;
        };
        work.structure(&StructureEdit::DeleteShape {
            target: Target {
                slide: &part,
                shape,
                expected,
            },
            cascade: true,
        })?;
    }

    // 6. Slide removals.
    loop {
        let current = work.view()?;
        let Some(gone) = current
            .slides
            .iter()
            .find(|slide| !kept.contains(&slide.part))
        else {
            break;
        };
        let (part, expected) = (gone.part.clone(), gone.render_fingerprint);
        work.structure(&StructureEdit::DeleteSlide {
            slide: &part,
            expected,
        })?;
    }

    // 7. The slide order.
    let wanted_order: Vec<u32> = slides
        .iter()
        .map(|slide| work.at.get(slide).map(|(_, id)| *id))
        .collect::<Option<_>>()
        .ok_or(LiveError::UnknownNode)?;
    let held_order: Vec<u32> = work.view()?.slides.iter().map(|s| s.sld_id).collect();
    if wanted_order != held_order {
        work.structure(&StructureEdit::ReorderSlides {
            order: &wanted_order,
        })?;
    }

    // 8. Each container's sibling order (z-order).
    for container in &order {
        let found = &deck.nodes[container];
        if !matches!(found.kind, NodeKind::Slide | NodeKind::Group) {
            continue;
        }
        let part = home[container].clone();
        let group = (found.kind == NodeKind::Group)
            .then(|| work.at.get(container).map(|(_, id)| *id))
            .flatten();
        for (index, child) in found.children.iter().enumerate() {
            let (_, native, expected) = work.target(*child)?;
            let current = work.view()?;
            let slide = current
                .slides
                .iter()
                .find(|slide| slide.part == part)
                .ok_or(LiveError::UnknownNode)?;
            let members: Vec<Option<u32>> = slide
                .shapes
                .iter()
                .filter(|shape| {
                    shape.group_path.last().and_then(|&at| slide.shapes[at].id) == group
                        && (group.is_some() || shape.group_path.is_empty())
                })
                .map(|shape| shape.id)
                .collect();
            if members.get(index) == Some(&Some(native)) {
                continue;
            }
            work.structure(&StructureEdit::ReorderShape {
                target: Target {
                    slide: &part,
                    shape: native,
                    expected,
                },
                index,
            })?;
        }
    }

    // 9. Own geometry and text, in model-identity order.
    for (id, node) in &deck.nodes {
        if matches!(node.kind, NodeKind::Root | NodeKind::Slide) {
            continue;
        }
        let (part, native, expected) = work.target(*id)?;
        let current = work.view()?;
        let shape = shape_at(&current, &part, native).ok_or(LiveError::UnknownNode)?;
        let held = geometry_of(shape);
        fn changed<T: PartialEq + Copy>(live: Option<T>, held: Option<T>) -> Option<T> {
            live.filter(|value| Some(*value) != held)
        }
        let xfrm = Xfrm {
            offset: changed(node.geometry.offset, held.offset),
            extent: changed(node.geometry.extent, held.extent),
            rotation: changed(node.geometry.rotation, held.rotation),
            flip_h: changed(node.geometry.flip_h, held.flip_h),
            flip_v: changed(node.geometry.flip_v, held.flip_v),
        };
        // The held text as the text mapping reads it: soft breaks as
        // U+000B, and a line feed inside a run as text.
        let held_text = match (&shape.text, deck.texts.get(id)) {
            (Some(text), Some(_)) => {
                let tree = work.slide_tree(&part)?;
                Some(paragraph_chars(&text_body(text, &tree, || NodeId(0))))
            }
            _ => None,
        };
        if xfrm != Xfrm::default() {
            work.value(&ValueEdit::SetXfrm {
                target: Target {
                    slide: &part,
                    shape: native,
                    expected,
                },
                xfrm,
            })?;
        }
        if let Some(body) = deck.texts.get(id) {
            // The paragraphs go to the writer whole, never through one
            // string split at line feeds.
            let wanted = paragraph_chars(body);
            if held_text.as_ref() != Some(&wanted) {
                let (_, _, expected) = work.target(*id)?;
                work.value(&ValueEdit::SetParagraphs {
                    target: Target {
                        slide: &part,
                        shape: native,
                        expected,
                    },
                    paragraphs: &wanted,
                })?;
            }
            project_marks(&mut work, *id, &part, native, body)?;
        }
        if node.binding.is_some() {
            project_payload(&mut work, deck, *id, &part, native, assets)?;
        }
    }

    // The app properties' words and paragraphs, recounted over the text
    // this export wrote.
    let output = work.view()?;
    if !work.changed.is_empty()
        && let Some(props) = crate::edit::recount_slide_text(work.next_mut(), &output)?
    {
        work.changed.insert(props);
    }

    // The bindings, opaque hashes and allocation history of the output.
    let mut bindings = BTreeMap::new();
    for (id, (part, native)) in &work.at {
        let binding = if deck.nodes[id].kind == NodeKind::Slide {
            let slide = output
                .slides
                .iter()
                .find(|slide| &slide.part == part)
                .ok_or(LiveError::UnknownNode)?;
            NodeBinding {
                slide_part: part.clone(),
                native_id: Some(slide.sld_id),
                creation_id: slide.creation_id.map(|id| id.to_string()),
                fingerprint: slide.content_fingerprint,
                table: None,
                series: None,
            }
        } else {
            let shape = shape_at(&output, part, *native).ok_or(LiveError::UnknownNode)?;
            NodeBinding {
                slide_part: part.clone(),
                native_id: Some(*native),
                creation_id: shape.creation_id.clone(),
                fingerprint: shape.content_fingerprint,
                table: table::binding(&deck.nodes[id]),
                series: chart::binding(&deck.nodes[id], work.series.get(id).map(Vec::as_slice)),
            }
        };
        bindings.insert(*id, binding);
    }
    let slide_parts: BTreeSet<&str> = output.slides.iter().map(|s| s.part.as_str()).collect();
    let mut opaque_parts = BTreeMap::new();
    for name in work.package.names() {
        if slide_parts.contains(name) {
            continue;
        }
        if let Some(bytes) = work.package.part(name)? {
            opaque_parts.insert(name.to_owned(), *blake3::hash(&bytes).as_bytes());
        }
    }
    let mut id_marks = work.marks.clone();
    id_marks.join(&IdMarks::of_deck(&output));
    let changed_parts: Vec<String> = work.changed.into_iter().collect();
    let noop = changed_parts.is_empty();
    let bytes = work.package.export()?;
    Ok(ExportOutcome {
        bytes,
        key,
        document_version: deck.version,
        changed_parts,
        noop,
        bindings,
        opaque_parts,
        id_marks,
        effects: work.effects,
    })
}
