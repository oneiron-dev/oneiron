//! Ordered deck transaction execution.
//! Entry: `run_transaction`.
//! Definitions live here; transaction forwards the original runner name.

use super::*;

/// Run one transaction over `base` under `limits`, reserving its memory
/// through `resources`. Returns the candidate bytes and the report; nothing
/// is written anywhere.
pub fn run_transaction(
    base: &[u8],
    transaction: &DeckTransaction,
    limits: Limits,
    assets: &dyn Assets,
    resources: &crate::resource::Resources,
) -> Result<(Vec<u8>, DeckTransactionReport), TransactionError> {
    transaction.validate()?;
    if Digest::of(base) != transaction.base {
        return Err(TransactionError::BaseChanged);
    }
    let original = Package::open(base, limits, resources)?;
    // A signed or uninspectable package runs on a scratch copy, and only a
    // run whose candidate is the base byte for byte is accepted: a no-op
    // stands, any change to it refuses as before (FIX 8579).
    let read_only = original.editability() != Editability::Unsigned;
    let mut deck = if read_only {
        original.scratch()?
    } else {
        original.copy()?
    };
    let mut marks = transaction.marks.clone();
    marks.join(&IdMarks::of_deck(&DeckView::read(&deck)?));
    let mut steps = Vec::with_capacity(transaction.steps.len());
    let mut allowed = BTreeSet::new();
    for (index, step) in transaction.steps.iter().enumerate() {
        let seed = step_seed(&transaction.seed, index);
        let report = apply(&mut deck, step, &mut marks, &seed, assets).map_err(|refusal| {
            TransactionError::Step {
                step: index,
                verb: step.verb(),
                refusal,
            }
        })?;
        allowed.extend(report.changed_parts.iter().cloned());
        steps.push(report);
    }
    let bytes = deck.export()?;
    if read_only && bytes != base {
        return Err(TransactionError::NotEditable);
    }
    let candidate = Package::open(&bytes, limits, resources)?;
    let (parts, untouched) = part_diff(&original, &candidate)?;
    if let Some(outside) = parts.iter().find(|change| !allowed.contains(&change.part)) {
        return Err(TransactionError::PartDiffOutsideTransaction(
            outside.part.clone(),
        ));
    }
    marks.join(&IdMarks::of_deck(&DeckView::read(&candidate)?));
    let mut report = DeckTransactionReport {
        schema: DECK_TRANSACTION_SCHEMA,
        base: transaction.base,
        candidate: Digest::of(&bytes),
        steps,
        parts,
        untouched,
        marks,
        handoff: Digest::default(),
    };
    report.handoff = handoff(transaction, &report);
    Ok((bytes, report))
}

pub(super) fn step_seed(seed: &str, index: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron docedit deck step seed v1");
    hasher.update(&(seed.len() as u64).to_le_bytes());
    hasher.update(seed.as_bytes());
    hasher.update(&(index as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub(super) fn value(
    deck: &mut Package,
    verb: &str,
    op: &ValueEdit<'_>,
) -> Result<StepReport, StepRefusal> {
    let report = edit(deck, op)?;
    Ok(StepReport {
        verb: verb.to_owned(),
        changed_parts: report.changed_parts,
        effects: report.effects,
        fit: report.fit.err(),
    })
}

pub(super) fn structural(
    deck: &mut Package,
    verb: &str,
    op: &StructureEdit<'_>,
) -> Result<StepReport, StepRefusal> {
    let report = structure_patch(deck, op)?;
    Ok(StepReport {
        verb: verb.to_owned(),
        changed_parts: report.changed_parts,
        effects: report.effects,
        fit: None,
    })
}

pub(super) fn native(
    deck: &mut Package,
    verb: &str,
    op: &NativeEdit<'_>,
) -> Result<StepReport, StepRefusal> {
    let report = native_patch::native_patch(deck, op)?;
    let mut effects = Vec::new();
    // A table-cell write that cut fields whole (FIX 12227) names them, so
    // the receipt says each dynamic field became static text.
    if !report.cut_fields.is_empty() {
        effects.push(Effect::TableFieldsCut {
            fields: report.cut_fields,
        });
    }
    Ok(StepReport {
        verb: verb.to_owned(),
        changed_parts: report.changed_parts,
        effects,
        fit: None,
    })
}

pub(super) fn apply(
    deck: &mut Package,
    step: &DeckStep,
    marks: &mut IdMarks,
    seed: &[u8; 32],
    assets: &dyn Assets,
) -> Result<StepReport, StepRefusal> {
    let verb = step.verb();
    let report = match step {
        DeckStep::SetText { target, text } => value(
            deck,
            verb,
            &ValueEdit::SetText {
                target: target.target(),
                text,
            },
        )?,
        DeckStep::ReplaceRunText {
            target,
            paragraph,
            run,
            expected,
            text,
        } => value(
            deck,
            verb,
            &ValueEdit::ReplaceRunText {
                target: target.target(),
                paragraph: *paragraph,
                run: *run,
                expected,
                text,
            },
        )?,
        DeckStep::SetXfrm { target, xfrm } => value(
            deck,
            verb,
            &ValueEdit::SetXfrm {
                target: target.target(),
                xfrm: Xfrm {
                    offset: xfrm.offset.map(|[x, y]| (x, y)),
                    extent: xfrm.extent.map(|[x, y]| (x, y)),
                    rotation: xfrm.rotation,
                    flip_h: xfrm.flip_h,
                    flip_v: xfrm.flip_v,
                },
            },
        )?,
        DeckStep::MoveInSlideSpace { target, dx, dy } => value(
            deck,
            verb,
            &ValueEdit::MoveInSlideSpace {
                target: target.target(),
                by: (*dx, *dy),
            },
        )?,
        DeckStep::SetPicture { target, asset } => {
            let (record, bytes) = assets
                .resolve(asset)
                .ok_or(StepRefusal::Asset("unresolved asset"))?;
            if Digest::of(&bytes) != asset.hash
                || record.content_hash != asset.hash.0
                || record.artifact != asset.artifact
                || record.version != asset.version
            {
                return Err(StepRefusal::Asset("asset bytes do not match the reference"));
            }
            value(
                deck,
                verb,
                &ValueEdit::SetPicture {
                    target: target.target(),
                    picture: Picture {
                        record: &record,
                        bytes: &bytes,
                        requested: match asset.kind {
                            StepAssetKind::Factual => AssetKind::Factual,
                            StepAssetKind::Illustration => AssetKind::Illustration,
                        },
                        limits: GraphicLimits::default(),
                    },
                },
            )?
        }
        DeckStep::SetNotes {
            slide,
            expected,
            text,
        } => value(
            deck,
            verb,
            &ValueEdit::SetNotes {
                slide,
                expected: expected.as_deref(),
                text,
            },
        )?,
        DeckStep::AddShape {
            slide,
            preset,
            name,
            offset,
            extent,
        } => structural(
            deck,
            verb,
            &StructureEdit::AddShape {
                slide,
                shape: NewShape {
                    preset: match preset {
                        StepPreset::Rect => Preset::Rect,
                        StepPreset::RoundRect => Preset::RoundRect,
                        StepPreset::Ellipse => Preset::Ellipse,
                        StepPreset::Triangle => Preset::Triangle,
                        StepPreset::RightArrow => Preset::RightArrow,
                    },
                    name,
                    offset: (offset[0], offset[1]),
                    extent: (extent[0], extent[1]),
                    high_water: marks.shape(slide),
                    seed,
                },
            },
        )?,
        DeckStep::DeleteShape { target, cascade } => structural(
            deck,
            verb,
            &StructureEdit::DeleteShape {
                target: target.target(),
                cascade: *cascade,
            },
        )?,
        DeckStep::Reparent { target, parent } => structural(
            deck,
            verb,
            &StructureEdit::Reparent {
                target: target.target(),
                parent: *parent,
            },
        )?,
        DeckStep::DuplicateSlide { slide, expected } => structural(
            deck,
            verb,
            &StructureEdit::DuplicateSlide {
                slide,
                expected: expected.0,
                high_water: marks.slide,
                seed,
            },
        )?,
        DeckStep::ReorderSlides { order } => {
            structural(deck, verb, &StructureEdit::ReorderSlides { order })?
        }
        DeckStep::SetTableCell {
            slide,
            table,
            row,
            col,
            expected,
            value: text,
        } => native(
            deck,
            verb,
            &NativeEdit::SetTableCell {
                slide,
                table: *table,
                row: *row,
                col: *col,
                expected,
                value: text,
            },
        )?,
        DeckStep::SetSeriesValues {
            chart,
            series,
            sequence,
            values,
        } => {
            let values: Vec<Cell> = values
                .iter()
                .map(|cell| match cell {
                    StepCell::Missing => Cell::Missing,
                    StepCell::Number(n) => Cell::Number(*n),
                    StepCell::Text(t) => Cell::Text(t.clone()),
                    StepCell::Date(d) => Cell::Date(d.clone()),
                })
                .collect();
            native(
                deck,
                verb,
                &NativeEdit::SetSeries {
                    chart,
                    series: *series,
                    target: match sequence {
                        StepSequence::Name => native_patch::Target::Name,
                        StepSequence::Categories => native_patch::Target::Categories,
                        StepSequence::Values => native_patch::Target::Values,
                    },
                    values: &values,
                },
            )?
        }
        DeckStep::ReleaseMedia {
            slide,
            relationships,
        } => {
            let (changed_parts, effects) =
                crate::edit::media::release_media(deck, slide, relationships)?;
            StepReport {
                verb: verb.to_owned(),
                changed_parts,
                effects,
                fit: None,
            }
        }
    };
    // Every id a step minted moves its mark: a later step allocates above it.
    for effect in &report.effects {
        match effect {
            Effect::ShapeAdded { id, .. } => {
                if let DeckStep::AddShape { slide, .. } = step {
                    let own = marks.shapes.entry(slide.clone()).or_default();
                    *own = (*own).max(*id);
                }
            }
            Effect::SlideAdded { part, sld_id, .. } => {
                marks.slide = marks.slide.max(*sld_id);
                // The copy keeps its source's shape ids, so it starts at the
                // source's mark.
                if let DeckStep::DuplicateSlide { slide, .. } = step {
                    let source = marks.shape(slide);
                    let own = marks.shapes.entry(part.clone()).or_default();
                    *own = (*own).max(source);
                }
            }
            _ => {}
        }
    }
    Ok(report)
}

pub(super) fn part_diff(
    base: &Package,
    candidate: &Package,
) -> Result<(Vec<PartChange>, usize), retained_opc::Error> {
    let mut changes = Vec::new();
    let mut untouched = 0;
    let names: BTreeSet<&str> = base.names().collect();
    for name in base.names() {
        let before = base.part(name)?.unwrap_or_default();
        match candidate.part(name)? {
            None => changes.push(PartChange {
                part: name.to_owned(),
                change: PartChangeKind::Removed,
                before: Some(Digest::of(&before)),
                after: None,
            }),
            Some(after) if after != before => changes.push(PartChange {
                part: name.to_owned(),
                change: PartChangeKind::Reserialized,
                before: Some(Digest::of(&before)),
                after: Some(Digest::of(&after)),
            }),
            Some(_) => untouched += 1,
        }
    }
    for name in candidate.names() {
        if !names.contains(name) {
            let after = candidate.part(name)?.unwrap_or_default();
            changes.push(PartChange {
                part: name.to_owned(),
                change: PartChangeKind::Added,
                before: None,
                after: Some(Digest::of(&after)),
            });
        }
    }
    Ok((changes, untouched))
}
