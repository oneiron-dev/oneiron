//! Pure pack-to-lens rendering.

use super::pack::{PrepPack, PrepSectionKind};
use crate::error::Result;
use crate::lens::{
    GeneratedLens, GeneratedUiPrebuilt, GeneratedUiSummaryCardPrebuilt, LensText, MetaLineAtom,
};

/// Joins the source refs backing one rendered row.
const PREP_SOURCE_REF_SEPARATOR: &str = " ";

/// Joins rendered rows inside the summary card body.
const PREP_LINE_SEPARATOR: &str = "\n";

/// Machine label for the card's EVENT backing line. A token, not product copy —
/// the same stance CAL-07's check-in card takes.
const PREP_LENS_EVENT_REF_LABEL: &str = "event_ref";

/// The human half of a prep card. Every string is a runtime/config input:
/// engine Rust hardcodes no product prose, persona, or localized text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepLensCopy {
    /// Card title.
    pub title: String,
    /// Heading over [`PrepSectionKind::PriorCommitment`].
    pub commitment_heading: String,
    /// Heading over [`PrepSectionKind::AttendeeThread`].
    pub thread_heading: String,
    /// Heading over [`PrepSectionKind::DossierDelta`].
    pub dossier_heading: String,
}

impl PrepLensCopy {
    /// The caller's heading for one section.
    #[must_use]
    pub fn heading_for(&self, kind: PrepSectionKind) -> &str {
        match kind {
            PrepSectionKind::PriorCommitment => self.commitment_heading.as_str(),
            PrepSectionKind::AttendeeThread => self.thread_heading.as_str(),
            PrepSectionKind::DossierDelta => self.dossier_heading.as_str(),
        }
    }
}

/// Renders one pack as a generated summary-card lens.
///
/// Composition only: the structure is the pack's, every word of chrome is the
/// caller's, and each rendered row carries its backing vault ids as a detail
/// line so nothing on the card is unattributed. There is no rendering path for
/// an absent pack — `Ok(None)` from [`build_prep_pack`] means the caller emits
/// no lens at all.
///
/// # Errors
///
/// [`crate::error::Error::InvalidConfig`] when caller-supplied copy violates the
/// lens text bounds, including an empty title.
pub fn render_prep_lens(pack: &PrepPack, copy: &PrepLensCopy) -> Result<GeneratedLens> {
    let row_count: usize = pack
        .sections
        .iter()
        .map(|section| section.items.len())
        .sum();
    let mut body = String::new();
    let mut details = Vec::with_capacity(row_count + 1);
    details.push(MetaLineAtom {
        label: LensText::new(PREP_LENS_EVENT_REF_LABEL)?,
        value: LensText::new(pack.event_ref.as_str())?,
    });

    for section in &pack.sections {
        let heading = copy.heading_for(section.kind);
        push_prep_line(&mut body, heading);
        for item in &section.items {
            push_prep_line(&mut body, item.text.as_str());
            details.push(MetaLineAtom {
                label: LensText::new(heading)?,
                value: LensText::new(item.source_refs.join(PREP_SOURCE_REF_SEPARATOR))?,
            });
        }
    }

    let card = GeneratedUiPrebuilt::SummaryCard(GeneratedUiSummaryCardPrebuilt {
        title: LensText::new(copy.title.as_str())?,
        body: LensText::new(body)?,
        details,
    });
    GeneratedLens::new(card.expand()?)
}

/// Appends one non-empty line to the card body.
fn push_prep_line(body: &mut String, line: &str) {
    if line.is_empty() {
        return;
    }
    if !body.is_empty() {
        body.push_str(PREP_LINE_SEPARATOR);
    }
    body.push_str(line);
}
