//! Step 8: the preservation corpus and the adversarial fixtures through the
//! same path as the core set (ARCH-0077, "Run preservation and adversarial
//! cases through the same path").

use super::checks;
use super::edits::{Deck, EDIT_MARK, Scope, allowed, appended, diff_explained, export, text_shape};
use super::record::{
    Calibration, Emit, Excluded, Lane, OfficeCheck, REGRESSION, Res, Run, failed, sha256_hex,
    verdict,
};
use super::spec::{
    AdversarialSpec, Arena, CorpusSpec, EngineExpect, FixtureList, Selection, read_json,
};
use super::suite::noop;
use crate::edit::NoAssets;
use crate::live::DeckOp;
use crate::live::deck_export::StepOutcome;
use crate::retained_opc::Package;
use std::path::Path;

/// Each adversarial fixture: the engine refuses or imports it as the case
/// manifest says, and the Office half classifies it against its expected
/// oracle status.
pub(super) fn adversarial(
    run: &mut Run,
    repo: &Path,
    spec: &AdversarialSpec,
    timeout_seconds: u64,
) -> Res<()> {
    let manifest = repo.join(&spec.manifest);
    let (list, _): (FixtureList, _) = read_json(&manifest)?;
    let folder = manifest
        .parent()
        .map(|dir| dir.join("fixtures"))
        .ok_or("the fixture manifest has no folder")?;
    for case in &spec.cases {
        let id = format!("adversarial.{}", case.id);
        let Some(fixture) = list.cases.iter().find(|fixture| fixture.id == case.id) else {
            run.record(
                REGRESSION,
                &id,
                failed("the fixture manifest has no such case"),
            );
            continue;
        };
        let path = folder.join(&fixture.file);
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let actual = sha256_hex(&bytes);
        if actual != fixture.sha256 {
            run.record(
                REGRESSION,
                &id,
                failed(format!(
                    "{} hashes {actual}; its pin is {}",
                    fixture.file, fixture.sha256
                )),
            );
            continue;
        }
        let imported = Deck::load(&id, bytes.clone(), run.limits);
        let outcome = match (case.engine, imported) {
            (EngineExpect::Refuses, Err(_)) | (EngineExpect::Imports, Ok(_)) => StepOutcome::Passed,
            (EngineExpect::Refuses, Ok(_)) => failed("the engine imported a deck it must refuse"),
            (EngineExpect::Imports, Err(why)) => failed(format!("the engine refused it: {why}")),
        };
        run.record(REGRESSION, &id, outcome);
        let file = format!("calibration/{}.pptx", case.id);
        let written = run.write_file(&file, &bytes)?;
        run.calibration.push(Calibration {
            id: case.id.clone(),
            file,
            sha256: written.sha256,
            bytes: written.bytes,
            expected_oracle: fixture.expected_oracle.clone(),
            timeout_seconds: case.timeout_seconds.unwrap_or(timeout_seconds),
        });
    }
    Ok(())
}

/// Every selected PPTArena original through the same path: import, the
/// no-op export, one text edit, the fixed point and the corruption checks,
/// each candidate untrusted (only an isolated account opens it).
pub(super) fn corpus(
    run: &mut Run,
    repo: &Path,
    corpus: Option<&Path>,
    spec: &CorpusSpec,
) -> Res<()> {
    let (arena, _): (Arena, _) = read_json(&repo.join(&spec.manifest))?;
    let excluded: Vec<&str> = spec.exclude.iter().map(|rule| rule.id.as_str()).collect();
    run.excluded
        .extend(spec.exclude.iter().map(|rule| Excluded {
            id: rule.id.clone(),
            reason: rule.reason.clone(),
        }));
    for case in &arena.cases {
        let listed = spec.select == Selection::All || spec.cases.contains(&case.id);
        if !listed || excluded.contains(&case.id.as_str()) {
            continue;
        }
        let Some(corpus) = corpus else {
            run.record(
                REGRESSION,
                &case.id,
                StepOutcome::Inconclusive("no corpus directory was given".to_owned()),
            );
            continue;
        };
        let path = corpus.join(&case.id).join("original.pptx");
        let Ok(bytes) = std::fs::read(&path) else {
            run.record(
                REGRESSION,
                &case.id,
                StepOutcome::Inconclusive(format!("{} was not acquired", path.display())),
            );
            continue;
        };
        let actual = sha256_hex(&bytes);
        if actual != case.original.sha256 {
            run.record(
                REGRESSION,
                &case.id,
                failed(format!(
                    "the original hashes {actual}; its pin is {}",
                    case.original.sha256
                )),
            );
            continue;
        }
        match Deck::load(&case.id, bytes, run.limits) {
            Ok(deck) => {
                noop(run, &deck, None, Lane::Corpus, &[REGRESSION], Vec::new())?;
                corpus_edit(run, &deck)?;
            }
            Err(why) => run.record(
                REGRESSION,
                &case.id,
                failed(format!("does not import: {why}")),
            ),
        }
    }
    Ok(())
}

/// One text edit of a corpus deck: the first bound text shape whose edit
/// the projector takes. A refusal canon accepts (an animated text range)
/// moves on to the next shape.
fn corpus_edit(run: &mut Run, deck: &Deck) -> Res<()> {
    let id = format!("{}.edit.set_text", deck.id);
    let slides = checks::slides(&deck.deck);
    let mut last = None;
    for (at, slide) in slides.iter().enumerate() {
        for shape in deck.deck.descendants(*slide) {
            if !text_shape(&deck.deck, shape) {
                continue;
            }
            let Some(body) = deck.deck.texts.get(&shape) else {
                continue;
            };
            let (edited, line) = appended(body, EDIT_MARK)?;
            let op = DeckOp::SetText {
                node: shape,
                body: edited,
            };
            match export(deck, &[op], &NoAssets) {
                Ok(exported) => {
                    let output = Package::open(&exported.outcome.bytes, run.limits)
                        .map_err(|error| format!("the export does not reopen: {error}"));
                    let preserved = output.and_then(|output| {
                        allowed(Scope::SLIDE, &exported.touched, &deck.package)
                            .and_then(|allowed| diff_explained(&deck.package, &output, &allowed))
                    });
                    run.record(REGRESSION, &format!("{id} edit"), verdict(preserved));
                    run.record(
                        REGRESSION,
                        &format!("{id} fixed point"),
                        checks::fixed_point(&exported.deck, &exported.outcome, run.limits),
                    );
                    return run.candidate(Emit {
                        id: &id,
                        bytes: &exported.outcome.bytes,
                        steps: &[REGRESSION],
                        lane: Lane::Corpus,
                        checks: vec![OfficeCheck::Text {
                            slide: at + 1,
                            contains: line,
                        }],
                        baseline: &deck.defects,
                    });
                }
                Err(super::edits::Refused::Export(error))
                    if super::merge::animation_refusal(&error) =>
                {
                    last = Some(error.to_string());
                }
                Err(refused) => {
                    run.record(REGRESSION, &id, failed(refused.why()));
                    return Ok(());
                }
            }
        }
    }
    let note = last.map_or_else(
        || "no editable text shape; the no-op path only".to_owned(),
        |why| format!("every text shape is animated text the projector refuses to restructure ({why}); the no-op path only"),
    );
    run.record(REGRESSION, &id, StepOutcome::Passed);
    run.note(&id, note);
    Ok(())
}
