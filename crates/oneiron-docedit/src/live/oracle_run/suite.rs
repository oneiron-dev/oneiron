//! One pinned baseline through steps 1 to 7: its no-op export, the probed
//! variant and every mutation over it, the non-PDF fixtures and the merges.

use super::assets::OracleAssets;
use super::checks::{self, typed_reads};
use super::edits::{self, Deck, Subject};
use super::merge;
use super::nonpdf;
use super::record::{
    BASELINE, CONCURRENCY, DOCUMENT, EDIT, Emit, Lane, NON_PDF, ORACLE, OfficeCheck, Res, Run,
    failed, sha256_hex,
};
use super::spec::{BaselineSpec, CaseManifest, NonPdf};
use super::variants;
use crate::edit::NoAssets;
use crate::live::deck_export::{ExportProfile, StepOutcome, project};
use std::path::Path;

pub(super) fn baseline(
    run: &mut Run,
    repo: &Path,
    spec: &BaselineSpec,
    cases: &CaseManifest,
) -> Res<()> {
    let path = repo.join(&spec.path);
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let actual = sha256_hex(&bytes);
    if actual != spec.sha256 {
        run.record(
            BASELINE,
            &spec.id,
            failed(format!(
                "{} hashes {actual}; the manifest pins {}",
                spec.path, spec.sha256
            )),
        );
        return Ok(());
    }
    let base = match Deck::load(&spec.id, bytes, run.limits) {
        Ok(base) => base,
        Err(why) => {
            run.record(
                BASELINE,
                &spec.id,
                failed(format!("the baseline does not import: {why}")),
            );
            return Ok(());
        }
    };
    let typed = Some(spec.typed.as_slice());
    noop(run, &base, typed, Lane::Core, &[ORACLE], Vec::new())?;
    let anchor = match edits::anchor(&base.deck) {
        Ok(anchor) => anchor,
        Err(why) => {
            for step in [EDIT, NON_PDF, CONCURRENCY] {
                run.record(step, &spec.id, failed(format!("no mutation anchor: {why}")));
            }
            return Ok(());
        }
    };
    let assets = OracleAssets::new()?;
    let probed = derive(
        run,
        &base,
        "probed",
        variants::probed(&base.package, &anchor.slide_part, anchor.native),
    );
    match probed {
        Ok(probed) => mutations(run, &probed, typed, cases, &assets)?,
        Err(why) => run.record(EDIT, &format!("{}.probed", spec.id), failed(why)),
    }
    let animated = derive(
        run,
        &base,
        "animated",
        variants::animated(&base.package, &anchor.slide_part, anchor.native),
    );
    for kind in &cases.non_pdf {
        match kind {
            NonPdf::ModernComment => nonpdf::comments(run, &base, &anchor, typed, &assets)?,
            NonPdf::AnimatedText => match &animated {
                Ok(animated) => nonpdf::animation(run, animated, typed)?,
                Err(why) => run.record(
                    NON_PDF,
                    &format!("{}.animated", spec.id),
                    failed(why.clone()),
                ),
            },
        }
    }
    merge::cases(
        run,
        &base,
        &anchor,
        animated.as_ref().ok(),
        &cases.concurrency,
    )
}

/// The probed variant's own no-op, then every listed mutation over it.
fn mutations(
    run: &mut Run,
    probed: &Deck,
    typed: Option<&[Vec<String>]>,
    cases: &CaseManifest,
    assets: &OracleAssets,
) -> Res<()> {
    noop(run, probed, typed, Lane::Core, &[ORACLE], Vec::new())?;
    let probes = match checks::probes(&probed.package) {
        Ok(probes) if !probes.is_empty() => probes,
        Ok(_) => {
            run.record(
                EDIT,
                &probed.id,
                failed("the probed variant holds no probe"),
            );
            return Ok(());
        }
        Err(why) => {
            run.record(EDIT, &probed.id, failed(why));
            return Ok(());
        }
    };
    let anchor = match edits::anchor(&probed.deck) {
        Ok(anchor) => anchor,
        Err(why) => {
            run.record(EDIT, &probed.id, failed(why));
            return Ok(());
        }
    };
    let subject = Subject {
        deck: probed,
        anchor: &anchor,
        probes: &probes,
    };
    for recipe in &cases.edits {
        edits::edit_case(run, &subject, *recipe, assets)?;
    }
    Ok(())
}

/// A variant of `base` built by `bytes`, imported under the run's limits.
pub(super) fn derive(run: &Run, base: &Deck, name: &str, bytes: Res<Vec<u8>>) -> Res<Deck> {
    let bytes = bytes.map_err(|why| format!("the {name} variant cannot be built: {why}"))?;
    Deck::load(&format!("{}.{name}", base.id), bytes, run.limits)
        .map_err(|why| format!("the {name} variant does not import: {why}"))
}

/// Step 1 on one deck: the no-op export is a true no-op returning the
/// archive's own bytes, and the import's typed reads match the fixture's
/// pins, so passthrough cannot hide a broken importer. The no-op export is
/// the deck's candidate.
pub(super) fn noop(
    run: &mut Run,
    deck: &Deck,
    typed: Option<&[Vec<String>]>,
    lane: Lane,
    steps: &[u8],
    owed: Vec<OfficeCheck>,
) -> Res<()> {
    let id = format!("{}.noop", deck.id);
    run.case(&id, |run| {
        noop_case(run, &id, deck, typed, (lane, steps), owed)
    })
}

fn noop_case(
    run: &mut Run,
    id: &str,
    deck: &Deck,
    typed: Option<&[Vec<String>]>,
    (lane, steps): (Lane, &[u8]),
    mut owed: Vec<OfficeCheck>,
) -> Res<()> {
    let outcome = match project(
        &deck.deck,
        &deck.package,
        DOCUMENT,
        &ExportProfile::default(),
        &NoAssets,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            run.record(
                lane.step(BASELINE),
                id,
                failed(format!("the no-op export refused: {error}")),
            );
            return Ok(());
        }
    };
    let reads = typed_reads(&deck.deck);
    let verdict = if !outcome.noop {
        failed(format!(
            "the no-op export changed {:?}",
            outcome.changed_parts
        ))
    } else if outcome.bytes != deck.bytes {
        failed("the no-op export changed the archive's bytes")
    } else if let Some(expected) = typed.filter(|expected| reads.as_slice() != *expected) {
        failed(format!(
            "typed reads {reads:?}; the fixture pins {expected:?}"
        ))
    } else {
        StepOutcome::Passed
    };
    run.record(lane.step(BASELINE), id, verdict);
    if !deck.defects.is_empty() {
        run.note(
            id,
            format!(
                "step 5 judges only new defects; the deck already has: {}",
                deck.defects.join("; ")
            ),
        );
    }
    if lane == Lane::Core {
        owed.push(OfficeCheck::Slides { count: reads.len() });
        owed.push(OfficeCheck::Pages { count: reads.len() });
        for (at, texts) in reads.iter().enumerate() {
            owed.extend(texts.iter().filter_map(|text| {
                let line = text.lines().next().unwrap_or_default();
                (!line.is_empty()).then(|| OfficeCheck::Text {
                    slide: at + 1,
                    contains: line.to_owned(),
                })
            }));
        }
    }
    run.candidate(Emit {
        id,
        bytes: &outcome.bytes,
        steps,
        lane,
        checks: owed,
        baseline: &deck.defects,
        origin: &deck.bytes,
    })
}
