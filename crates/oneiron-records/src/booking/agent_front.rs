//! Moved from `crates/oneiron/src/booking/agent_front.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::constraint::ConstraintSessionCaps;
use oneiron_lens_wire::lens::atom::LensText;
use oneiron_verb_wire::booking::constraint::BookingError;

/// Every visible string this front can emit. Host-supplied configuration and
/// the localization seam — never shipped prompt or persona text.
pub struct ConstraintFrontCopy {
    pub speaker: String,
    pub slots_line: String,
    pub no_fit_line: String,
    pub off_topic_line: String,
}

impl ConstraintFrontCopy {
    fn validate(&self) -> Result<(), BookingError> {
        for (field, value) in [
            ("speaker", &self.speaker),
            ("slots_line", &self.slots_line),
            ("no_fit_line", &self.no_fit_line),
            ("off_topic_line", &self.off_topic_line),
        ] {
            if value.trim().is_empty() {
                return Err(BookingError::InvalidConfig(format!(
                    "constraint front copy {field} must be configured"
                )));
            }
        }
        Ok(())
    }
}

/// The owner-authored front of one published page (ARCH-0062 §5): the four
/// [`ConstraintFrontCopy`] lines and the per-session dials. A publication that
/// carries none does not serve the front; nothing here has a shipped default.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintFrontConfig {
    pub speaker: String,
    pub slots_line: String,
    pub no_fit_line: String,
    pub off_topic_line: String,
    pub max_turns: u16,
    pub max_model_calls: u16,
}

impl ConstraintFrontConfig {
    #[must_use]
    pub fn copy(&self) -> ConstraintFrontCopy {
        ConstraintFrontCopy {
            speaker: self.speaker.clone(),
            slots_line: self.slots_line.clone(),
            no_fit_line: self.no_fit_line.clone(),
            off_topic_line: self.off_topic_line.clone(),
        }
    }

    #[must_use]
    pub fn caps(&self) -> ConstraintSessionCaps {
        ConstraintSessionCaps {
            max_turns: self.max_turns,
            max_model_calls: self.max_model_calls,
        }
    }

    /// Every line is nonblank and fits a lens text, and each dial admits at
    /// least one turn and one parse pass, so a turn never discovers a bad
    /// publication after it spent a model call.
    pub fn validate(&self) -> Result<(), BookingError> {
        let copy = self.copy();
        copy.validate()?;
        for line in [
            copy.speaker,
            copy.slots_line,
            copy.no_fit_line,
            copy.off_topic_line,
        ] {
            LensText::new(line).map_err(|_| {
                BookingError::InvalidConfig(
                    "constraint front copy exceeds the lens text bound".to_owned(),
                )
            })?;
        }
        if self.max_turns == 0 || self.max_model_calls == 0 {
            return Err(BookingError::InvalidConfig(
                "constraint front caps must admit one turn and one parse pass".to_owned(),
            ));
        }
        Ok(())
    }
}
