//! Optional inbound-body screen for imported calendar content (CAL-09).
//!
//! Shape mirrors the screen-before-admission control flow `skill_hub` runs
//! around `skill.scan_verdict`, but the predicate is NOT reused: a skill body
//! and an ICS description are different content classes with different
//! detectors. What is shared is the ordering guarantee — the verdict is
//! obtained *before* the caller mints its imported claim, and it reaches the
//! caller as a typed [`CalendarAdmissionRequest`] rather than as ambient state.
//!
//! Posture, stated once so no call site has to re-derive it:
//!
//! * The hook is host-injected and config-keyed, and it is OFF by default.
//!   Off means [`CalendarScreenVerdict::Skipped`], not "assume clear".
//! * A `Flagged` or `Indeterminate` verdict never promotes the body, never
//!   interprets it as instructions, and never raises an approval wall. Calendar
//!   bodies are content. The caller may retain the body at the existing
//!   imported trust tier with the verdict attached to admission metadata.
//! * The admission callback takes the request by value and runs exactly once,
//!   so a zero-argument claim closure — which could not see the verdict — is
//!   not part of this contract.
//!
//! CAL-02 (ONE-1784) is the first caller: `calendar::ingest::run_ics_feed_poll`
//! invokes [`screen_then_claim`] immediately before imported-claim admission.
//! Until then the contract is exercised by fixture screeners rather than by a
//! second, invented ingestion path.

use crate::error::Result;

/// Host config key that enables the inbound calendar screen. Absent or false
/// means the screen does not run.
pub const CALENDAR_SAFEGUARD_CONFIG_KEY: &str = "calendar.inbound_safeguard.enabled";

/// Reason code recorded when the dial is on but the host injected no screener.
///
/// This is `Indeterminate`, not `Clear`: an enabled-but-unwired screen has not
/// examined the body, and saying otherwise would launder unscreened content.
pub const CALENDAR_SAFEGUARD_REASON_NO_SCREENER: &str = "calendar.safeguard.screener_absent";

/// The inbound body an imported calendar EVENT carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalendarInboundBody {
    /// Free-text description as the source supplied it.
    pub description: String,
    /// Extracted attachment text, one entry per attachment.
    pub attachment_text: Vec<String>,
}

/// One screen verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarScreenVerdict {
    /// The dial is off; no screen ran.
    Skipped,
    /// The screener examined the body and found nothing.
    Clear,
    /// The screener found something; reason codes are host vocabulary.
    Flagged {
        /// Host-defined reason codes.
        reason_codes: Vec<String>,
    },
    /// The screener could not reach a verdict.
    Indeterminate {
        /// Host-defined reason code.
        reason_code: String,
    },
}

impl CalendarScreenVerdict {
    /// Whether this verdict is a positive statement that the body was examined
    /// and found clean. `Skipped` and `Indeterminate` are both false — absence
    /// of a finding is not a finding of absence.
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        matches!(self, Self::Clear)
    }
}

/// Host-injected screener over inbound calendar bodies.
pub trait CalendarBodyScreener: Send + Sync {
    /// Screens one inbound body.
    fn screen(&self, body: &CalendarInboundBody) -> Result<CalendarScreenVerdict>;
}

/// The typed request an admission callback receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarAdmissionRequest {
    /// The body being admitted, unmodified.
    pub body: CalendarInboundBody,
    /// The verdict the screen produced for that body.
    pub verdict: CalendarScreenVerdict,
}

/// An admitted value plus the verdict that accompanied its admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screened<T> {
    /// Whatever the admission callback produced.
    pub value: T,
    /// The verdict carried alongside it.
    pub verdict: CalendarScreenVerdict,
}

/// Screens `body`, then admits it at the imported trust tier.
///
/// Ordering is the point: when the dial is on, the verdict exists before
/// `claim_imported` is called, and it is handed over inside the request. The
/// callback runs exactly once in every branch — a flagged body is still
/// admitted as imported content, because this hook classifies, it does not
/// adjudicate.
pub fn screen_then_claim<T>(
    enabled: bool,
    screener: Option<&dyn CalendarBodyScreener>,
    body: &CalendarInboundBody,
    claim_imported: impl FnOnce(CalendarAdmissionRequest) -> Result<T>,
) -> Result<Screened<T>> {
    let verdict = match (enabled, screener) {
        (false, _) => CalendarScreenVerdict::Skipped,
        (true, Some(screener)) => screener.screen(body)?,
        (true, None) => CalendarScreenVerdict::Indeterminate {
            reason_code: CALENDAR_SAFEGUARD_REASON_NO_SCREENER.to_owned(),
        },
    };
    let value = claim_imported(CalendarAdmissionRequest {
        body: body.clone(),
        verdict: verdict.clone(),
    })?;
    Ok(Screened { value, verdict })
}
