use super::*;

/// Every relationship that differs between two packages, by source part and
/// id: added (`before: None`), removed (`after: None`) or retargeted.
pub fn relationship_changes(
    before: &Package,
    after: &Package,
) -> Result<Vec<RelationshipChange>, LiveError> {
    let mut sources: BTreeSet<String> = BTreeSet::from([String::new()]);
    sources.extend(before.names().map(str::to_owned));
    sources.extend(after.names().map(str::to_owned));
    let mut out = Vec::new();
    for source in &sources {
        if source.to_ascii_lowercase().ends_with(".rels") {
            continue;
        }
        let read = |package: &Package| -> Result<BTreeMap<String, (String, String)>, LiveError> {
            if !source.is_empty() && package.part(source)?.is_none() {
                return Ok(BTreeMap::new());
            }
            Ok(package
                .relationships(source)?
                .into_iter()
                .map(|rel| (rel.id, (rel.kind, rel.target)))
                .collect())
        };
        let (old, new) = (read(before)?, read(after)?);
        let ids: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        for id in ids {
            let (was, now) = (old.get(id), new.get(id));
            if was == now {
                continue;
            }
            out.push(RelationshipChange {
                source: source.clone(),
                id: id.clone(),
                kind: now
                    .or(was)
                    .map(|(kind, _)| kind.clone())
                    .unwrap_or_default(),
                before: was.map(|(_, target)| target.clone()),
                after: now.map(|(_, target)| target.clone()),
            });
        }
    }
    Ok(out)
}

/// Attach the relationship and render components to a preflight: project
/// the current head and the actual merged candidate over the retained
/// package, compare their relationships, pin each side's slide render
/// identities at its version, and narrow the affected slides to those whose
/// render identity the candidate changes. The images come from the review
/// renderer over these named inputs; the pair is stale once the head moves.
pub fn attach_evidence(
    report: &mut PreflightReport,
    head: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
    assets: &dyn Assets,
) -> Result<(), LiveError> {
    let held = project(head, package, document, profile, assets)?;
    let merged = project(&report.candidate, package, document, profile, assets)?;
    let open = |outcome: &ExportOutcome| -> Result<Package, LiveError> {
        Ok(Package::open(
            &outcome.bytes,
            package.limits(),
            package.resources(),
        )?)
    };
    let (held_package, merged_package) = (open(&held)?, open(&merged)?);
    report.diff.relationships = relationship_changes(&held_package, &merged_package)?;
    let side = |deck: &LiveDeck,
                outcome: &ExportOutcome,
                exported: &Package|
     -> Result<RenderSide, LiveError> {
        let view = DeckView::read(exported)?;
        let slides = view
            .slides
            .iter()
            .filter_map(|slide| {
                let (node, _) = outcome.bindings.iter().find(|(id, binding)| {
                    deck.nodes
                        .get(id)
                        .is_some_and(|node| node.kind == NodeKind::Slide)
                        && binding.slide_part == slide.part
                })?;
                Some(SlideRender {
                    slide: *node,
                    part: slide.part.clone(),
                    fingerprint: slide.render_fingerprint,
                })
            })
            .collect();
        Ok(RenderSide {
            version: deck.version,
            state_hash: deck.state_hash(),
            export_key: outcome.key.hash(),
            slides,
        })
    };
    let before = side(head, &held, &held_package)?;
    let after = side(&report.candidate, &merged, &merged_package)?;
    let mut changed: BTreeSet<NodeId> = BTreeSet::new();
    for slide in &after.slides {
        if !before
            .slides
            .iter()
            .any(|held| held.slide == slide.slide && held.fingerprint == slide.fingerprint)
        {
            changed.insert(slide.slide);
        }
    }
    for slide in &before.slides {
        if !after.slides.iter().any(|kept| kept.slide == slide.slide) {
            changed.insert(slide.slide);
        }
    }
    report.diff.affected_slides = changed.iter().copied().collect();
    report.diff.renders = Some(RenderPair {
        head: before,
        candidate: after,
        changed: changed.into_iter().collect(),
    });
    Ok(())
}

/// Run the steps of the eight-step check that hold in-process: baseline
/// preservation (1), the semantic fixed point (3) and package closure (5).
/// Edit preservation (2), concurrency (4), the MacBook oracle (6), non-PDF
/// checks (7) and the regression corpus (8) are reported inconclusive —
/// they need fixtures, a merge harness and the oracle seat, and an
/// unrun step is never a pass.
pub fn roundtrip_check(
    package: &Package,
    original_bytes: &[u8],
    profile: &ExportProfile,
) -> Result<RoundtripReport, LiveError> {
    let deck = LiveDeck::import(package)?;
    let outcome = project(&deck, package, "roundtrip", profile, &NoAssets)?;
    let baseline_preserved = outcome.noop && outcome.bytes == original_bytes;
    let reopened = Package::open(&outcome.bytes, package.limits(), package.resources())?;
    let closure = DeckView::read(&reopened);
    let fixed_point = match &closure {
        Ok(_) => LiveDeck::import(&reopened)?.semantically_eq(&deck),
        Err(_) => false,
    };
    let step = |passed: bool, why: &str| {
        if passed {
            StepOutcome::Passed
        } else {
            StepOutcome::Failed(why.to_owned())
        }
    };
    Ok(RoundtripReport {
        profile: profile.name.clone(),
        steps: vec![
            step(baseline_preserved, "no-op export changed bytes"),
            StepOutcome::Inconclusive("edit-preservation fixtures not run".to_owned()),
            step(fixed_point, "re-import differs from the live model"),
            StepOutcome::Inconclusive("concurrency cases not run".to_owned()),
            step(closure.is_ok(), "exported package does not read back"),
            StepOutcome::Inconclusive("oracle not run".to_owned()),
            StepOutcome::Inconclusive("non-PDF checks not run".to_owned()),
            StepOutcome::Inconclusive("regression corpus not run".to_owned()),
        ],
        baseline_preserved,
        fixed_point,
    })
}
