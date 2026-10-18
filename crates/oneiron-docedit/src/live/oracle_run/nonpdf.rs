//! Step 7, the checks a PDF cannot show: a modern comment kept through edits
//! of its slide (PowerPoint must still read it), and a paragraph build kept,
//! remapped or refused when its text changes (ARCH-0077, "Verify modern
//! comments in PowerPoint. Exercise animation-sensitive fixtures
//! separately").

use super::assets::OracleAssets;
use super::checks;
use super::edits::{
    self, Anchor, Deck, EDIT_MARK, Exported, Ids, Scope, allowed, appended, body, diff_explained,
    export, shifted,
};
use super::merge::{animation_refusal, built_ranges};
use super::record::{
    EDIT, Emit, FIXED_POINT, Lane, NON_PDF, ORACLE, OfficeCheck, Res, Run, failed, text, verdict,
};
use super::suite::{derive, noop};
use super::variants::{self, AUTHORS, COMMENT_REL, COMMENT_TEXT, CommentSlide};
use crate::deck::DeckView;
use crate::edit::NoAssets;
use crate::live::DeckOp;
use crate::live::deck_export::StepOutcome;
use crate::retained_opc::Package;

/// The commented variant's no-op, then a text edit and a geometry edit of
/// the commented slide's text shape.
pub(super) fn comments(
    run: &mut Run,
    base: &Deck,
    anchor: &Anchor,
    typed: Option<&[Vec<String>]>,
    assets: &OracleAssets,
) -> Res<()> {
    let creation_id = base.deck.nodes[&anchor.slide]
        .binding
        .as_ref()
        .and_then(|bound| bound.creation_id.as_deref())
        .and_then(|id| id.parse().ok());
    let slide = CommentSlide {
        part: &anchor.slide_part,
        sld_id: anchor.sld_id,
        creation_id,
    };
    let commented = match derive(
        run,
        base,
        "commented",
        variants::commented(&base.package, &slide),
    ) {
        Ok(commented) => commented,
        Err(why) => {
            run.record(NON_PDF, &format!("{}.commented", base.id), failed(why));
            return Ok(());
        }
    };
    let comment = OfficeCheck::Comment {
        slide: 1,
        text: COMMENT_TEXT.to_owned(),
    };
    noop(
        run,
        &commented,
        typed,
        Lane::Core,
        &[ORACLE, NON_PDF],
        vec![comment.clone()],
    )?;
    let anchor = edits::anchor(&commented.deck)?;
    let body = commented
        .deck
        .texts
        .get(&anchor.shape)
        .ok_or("the commented shape has no text")?;
    let (edited, line) = appended(body, EDIT_MARK)?;
    let geometry = shifted(commented.deck.nodes[&anchor.shape].geometry);
    let cases = [
        (
            "set_text",
            DeckOp::SetText {
                node: anchor.shape,
                body: edited,
            },
            OfficeCheck::Text {
                slide: 1,
                contains: line,
            },
        ),
        (
            "set_geometry",
            DeckOp::SetGeometry {
                node: anchor.shape,
                geometry,
            },
            OfficeCheck::Shape {
                slide: 1,
                id: anchor.native,
                offset: geometry.offset,
            },
        ),
    ];
    for (name, op, check) in cases {
        let id = format!("{}.{name}", commented.id);
        let exported = match export(&commented, &[op], assets) {
            Ok(exported) => exported,
            Err(refused) => {
                run.record(NON_PDF, &id, failed(refused.why()));
                continue;
            }
        };
        let output = Package::open(&exported.outcome.bytes, run.limits).map_err(text)?;
        let kept = comment_kept(&commented.package, &output, &exported, &anchor);
        run.record(NON_PDF, &id, verdict(kept));
        record_edit(run, &commented, &output, &exported, &id);
        run.candidate(Emit {
            id: &id,
            bytes: &exported.outcome.bytes,
            steps: &[ORACLE, NON_PDF],
            lane: Lane::Core,
            checks: vec![
                comment.clone(),
                check,
                OfficeCheck::Slides { count: 1 },
                OfficeCheck::Pages { count: 1 },
            ],
            baseline: &commented.defects,
        })?;
    }
    Ok(())
}

/// Steps 2 and 3 for an edit over a step-7 fixture: the comment and the
/// timing tree are unknown markup beside the mutation too.
fn record_edit(run: &mut Run, base: &Deck, output: &Package, exported: &Exported, id: &str) {
    let preserved = allowed(Scope::SLIDE, &exported.touched, &base.package)
        .and_then(|allowed| diff_explained(&base.package, output, &allowed));
    run.record(EDIT, id, verdict(preserved));
    run.record(
        FIXED_POINT,
        id,
        checks::fixed_point(&exported.deck, &exported.outcome, run.limits),
    );
}

/// The comment and author parts are byte for byte as they were, the slide
/// still relates its comment part, and its creation id (the anchor) holds.
fn comment_kept(
    before: &Package,
    after: &Package,
    exported: &Exported,
    anchor: &Anchor,
) -> Res<()> {
    let mut comment_parts = Vec::new();
    for name in before.names() {
        if name.starts_with("ppt/comments/") || name == AUTHORS {
            if before.part(name).map_err(text)? != after.part(name).map_err(text)? {
                return Err(format!("{name} changed or was dropped"));
            }
            comment_parts.push(name.to_owned());
        }
    }
    let part = &exported
        .outcome
        .bindings
        .get(&anchor.slide)
        .ok_or("the commented slide has no binding in the export")?
        .slide_part;
    let related = after
        .relationships(part)
        .map_err(text)?
        .into_iter()
        .any(|rel| rel.kind == COMMENT_REL && comment_parts.contains(&rel.target));
    if !related {
        return Err(format!("{part} no longer relates its comment part"));
    }
    let creation = |package: &Package| -> Res<Option<u32>> {
        Ok(DeckView::read(package)
            .map_err(text)?
            .slides
            .iter()
            .find(|slide| slide.part == *part)
            .and_then(|slide| slide.creation_id))
    };
    let (was, now) = (creation(before)?, creation(after)?);
    if was.is_none() || was != now {
        return Err(format!(
            "the slide's creation id moved from {was:?} to {now:?}"
        ));
    }
    Ok(())
}

/// One text change to the built shape and what the export must do with the
/// build.
struct BuildCase {
    name: &'static str,
    /// The paragraph range the build must target after the export.
    range: (u32, u32),
    /// Whether refusing the export is an accepted answer.
    may_refuse: bool,
}

/// The animated variant's no-op, then three text edits of the built shape:
/// within its paragraph (the build holds), a paragraph after it, and a
/// paragraph before it (the build is remapped, or the export refuses).
pub(super) fn animation(run: &mut Run, animated: &Deck, typed: Option<&[Vec<String>]>) -> Res<()> {
    let anchor = edits::anchor(&animated.deck)?;
    let timing = |range: (u32, u32)| OfficeCheck::Timing {
        slide: 1,
        spid: anchor.native,
        paragraphs: Some(range),
    };
    noop(
        run,
        animated,
        typed,
        Lane::Core,
        &[ORACLE, NON_PDF],
        vec![timing((0, 0))],
    )?;
    let original = animated
        .deck
        .texts
        .get(&anchor.shape)
        .ok_or("the animated shape has no text")?;
    let mut ids = Ids::above(&animated.deck);
    let cases = [
        BuildCase {
            name: "retext",
            range: (0, 0),
            may_refuse: false,
        },
        BuildCase {
            name: "append_paragraph",
            range: (0, 0),
            may_refuse: true,
        },
        BuildCase {
            name: "prepend_paragraph",
            range: (1, 1),
            may_refuse: true,
        },
    ];
    for case in cases {
        let id = format!("{}.{}", animated.id, case.name);
        let changed = match case.name {
            "retext" => appended(original, EDIT_MARK)?.0,
            name => {
                let mut changed = original.clone();
                let paragraph = body(&mut ids, "Oracle paragraph").paragraphs.remove(0);
                let at = if name == "prepend_paragraph" {
                    0
                } else {
                    changed.paragraphs.len()
                };
                changed.paragraphs.insert(at, paragraph);
                changed
            }
        };
        let op = DeckOp::SetText {
            node: anchor.shape,
            body: changed,
        };
        let exported = match export(animated, &[op], &NoAssets) {
            Ok(exported) => exported,
            Err(edits::Refused::Export(error)) if case.may_refuse && animation_refusal(&error) => {
                run.record(NON_PDF, &id, StepOutcome::Passed);
                continue;
            }
            Err(refused) => {
                run.record(NON_PDF, &id, failed(refused.why()));
                continue;
            }
        };
        let ranges = built_ranges(&exported.outcome, run.limits, &anchor)?;
        let held = !ranges.is_empty() && ranges.iter().all(|range| *range == case.range);
        run.record(
            NON_PDF,
            &id,
            if held {
                StepOutcome::Passed
            } else {
                failed(format!(
                    "the build targets paragraphs {ranges:?}; it must target {:?}",
                    case.range
                ))
            },
        );
        let output = Package::open(&exported.outcome.bytes, run.limits).map_err(text)?;
        record_edit(run, animated, &output, &exported, &id);
        let slides = checks::slides(&exported.deck).len();
        run.candidate(Emit {
            id: &id,
            bytes: &exported.outcome.bytes,
            steps: &[ORACLE, NON_PDF],
            lane: Lane::Core,
            checks: vec![
                timing(case.range),
                OfficeCheck::Slides { count: slides },
                OfficeCheck::Pages { count: slides },
            ],
            baseline: &animated.defects,
        })?;
    }
    Ok(())
}
