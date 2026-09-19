//! Native Word anchor adapter; pure span transforms belong to the document organ.
use super::{Locator, ReanchorOp, ReanchorOutcome};
use oneiron_docedit::docx::{DocxSpan, replay_span};

pub(super) fn replay_docx_locator(locator: &Locator, ops: &[ReanchorOp]) -> ReanchorOutcome {
    let Locator::Docx {
        para_path,
        char_start,
        char_end,
    } = locator
    else {
        return ReanchorOutcome::Drifted;
    };
    let Ok(span) = DocxSpan::parse(para_path, *char_start, *char_end) else {
        return ReanchorOutcome::Drifted;
    };
    let mut current = span;
    for op in ops {
        let ReanchorOp::Docx(effect) = op else {
            return ReanchorOutcome::Drifted;
        };
        let Some(mapped) = replay_span(current, effect) else {
            return ReanchorOutcome::Drifted;
        };
        current = mapped;
    }
    ReanchorOutcome::Mapped(Locator::Docx {
        para_path: current.para_path(),
        char_start: u64::from(current.start),
        char_end: u64::from(current.end),
    })
}
