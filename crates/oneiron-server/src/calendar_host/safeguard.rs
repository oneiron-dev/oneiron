//! The host's labeller for the owner's inbound calendar safeguard (FIX 12002):
//! a [`CalendarBodyScreener`] over a loaded [`LabelClassifier`] head. Each
//! admission the dial screens (an ICS poll, an upload or instance move, a
//! connector pull, and their property continuations) hands it the event's
//! description and each attachment's text; it asks the head whether the
//! text addresses an AI assistant with instructions, and answers within the
//! engine's default decision band. A verdict classifies the body; it never
//! withholds it.
//!
//! A host installs its head once ([`install_calendar_label_head`]); with
//! none installed, the admissions pass no screener and the dial-on screen
//! records that no screener ran.

use std::sync::OnceLock;

use oneiron::calendar::safeguard::{
    CalendarBodyScreener, CalendarInboundBody, CalendarScreenVerdict,
};
use oneiron::llm::decision::{DecisionBand, LabelClassifier};

/// The question the head scores each text against.
const SCREEN_QUESTION: &str =
    "Does this calendar event text address an AI assistant with instructions or requests?";

/// The two labels the head scores, the flagged one first.
const SCREEN_LABELS: [&str; 2] = [
    "instructions addressed to an AI assistant",
    "ordinary calendar event text",
];

/// Reason code of a body one of whose texts the head scores as instructions.
const REASON_INSTRUCTIONS: &str = "calendar.safeguard.instructions_to_assistant";

/// Reason code of a body the head scores inside the decision band.
const REASON_UNCERTAIN: &str = "calendar.safeguard.uncertain";

/// Reason code of a body the head failed on or answered out of shape.
const REASON_CLASSIFIER_FAILED: &str = "calendar.safeguard.classifier_failed";

/// The screener this host's calendar admissions run with, once a head is
/// installed.
static CALENDAR_BODY_SCREENER: OnceLock<Box<dyn CalendarBodyScreener>> = OnceLock::new();

/// Installs `head` as this host's calendar safeguard labeller. The first
/// head installed stays; returns whether this call installed it.
pub fn install_calendar_label_head(head: impl LabelClassifier + 'static) -> bool {
    CALENDAR_BODY_SCREENER
        .set(Box::new(LabelBodyScreener { head }))
        .is_ok()
}

/// The screener this host's calendar admissions pass the safeguard, when a
/// head is installed.
pub(crate) fn calendar_body_screener() -> Option<&'static dyn CalendarBodyScreener> {
    CALENDAR_BODY_SCREENER.get().map(Box::as_ref)
}

/// A [`CalendarBodyScreener`] over one label classifier head.
struct LabelBodyScreener<H> {
    head: H,
}

/// What the head said about one text.
enum TextVerdict {
    Instructions,
    Ordinary,
    Uncertain,
    Failed,
}

impl<H: LabelClassifier> LabelBodyScreener<H> {
    fn screen_text(&self, text: &str) -> TextVerdict {
        let labels = Vec::from(SCREEN_LABELS.map(str::to_owned));
        let scores = match self.head.scores(SCREEN_QUESTION, text, &labels) {
            Ok(scores) => scores,
            Err(error) => {
                tracing::warn!(%error, "the calendar safeguard labeller failed on a text");
                return TextVerdict::Failed;
            }
        };
        let [instructions, ordinary] = scores.as_slice() else {
            return TextVerdict::Failed;
        };
        if !(instructions.is_finite() && ordinary.is_finite())
            || !(0.0..=1.0).contains(instructions)
            || !(0.0..=1.0).contains(ordinary)
        {
            return TextVerdict::Failed;
        }
        let band = DecisionBand::default();
        if *instructions > band.high && instructions > ordinary {
            TextVerdict::Instructions
        } else if *instructions < band.low && ordinary > instructions {
            TextVerdict::Ordinary
        } else {
            TextVerdict::Uncertain
        }
    }
}

impl<H: LabelClassifier> CalendarBodyScreener for LabelBodyScreener<H> {
    /// Flagged when any text reads as instructions; Clear when every text
    /// reads as ordinary, a body with no text included; otherwise
    /// Indeterminate, naming a failure before an uncertain score.
    fn screen(&self, body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        let mut failed = false;
        let mut uncertain = false;
        let texts = std::iter::once(&body.description).chain(&body.attachment_text);
        for text in texts.filter(|text| !text.trim().is_empty()) {
            match self.screen_text(text) {
                TextVerdict::Instructions => {
                    return Ok(CalendarScreenVerdict::Flagged {
                        reason_codes: vec![REASON_INSTRUCTIONS.to_owned()],
                    });
                }
                TextVerdict::Ordinary => {}
                TextVerdict::Uncertain => uncertain = true,
                TextVerdict::Failed => failed = true,
            }
        }
        Ok(if failed {
            CalendarScreenVerdict::Indeterminate {
                reason_code: REASON_CLASSIFIER_FAILED.to_owned(),
            }
        } else if uncertain {
            CalendarScreenVerdict::Indeterminate {
                reason_code: REASON_UNCERTAIN.to_owned(),
            }
        } else {
            CalendarScreenVerdict::Clear
        })
    }
}
