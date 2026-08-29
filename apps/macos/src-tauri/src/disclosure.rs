//! The recording-disclosure gate.
//!
//! The product law is one sentence: **nothing is captured until the operator
//! affirms, in the app, that the room has been told.** This module makes that
//! law structural rather than a checked flag someone can forget to check —
//! [`CapturePermit`] is the only key that opens a capture, it cannot be
//! constructed anywhere else in the crate, and starting a capture consumes it.
//! One affirm therefore authorizes exactly one recording session.

use std::fmt;

/// Where the gate stands right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureState {
    /// No affirm outstanding: capture cannot start.
    Required,
    /// The operator affirmed and has not yet spent it on a recording.
    Affirmed,
}

/// Why a capture was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureError {
    /// A capture was attempted with no outstanding affirm.
    NotAffirmed,
}

impl fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAffirmed => f.write_str(crate::copy::START_REFUSED_WITHOUT_DISCLOSURE),
        }
    }
}

impl std::error::Error for DisclosureError {}

/// Proof that the operator affirmed the disclosure for the session that is
/// about to be recorded.
///
/// The field is private to this module, so no other part of the crate — and no
/// consumer of the crate — can forge one. `DualStreamCapture::start` takes it
/// **by value**, which is what makes "one affirm, one recording" a type-level
/// fact instead of a convention.
#[derive(Debug)]
pub struct CapturePermit {
    affirmed_at: u64,
}

impl CapturePermit {
    /// Unix second at which the affirm this permit carries was made.
    #[must_use]
    pub const fn affirmed_at(&self) -> u64 {
        self.affirmed_at
    }
}

/// The per-session gate.
#[derive(Debug, Default)]
pub struct DisclosureGate {
    affirmed_at: Option<u64>,
}

impl DisclosureGate {
    /// A closed gate. Every app launch starts here — an affirm is never
    /// remembered across sessions, because the room is not the same room.
    #[must_use]
    pub const fn new() -> Self {
        Self { affirmed_at: None }
    }

    /// The state the menu bar and the window both render from.
    #[must_use]
    pub const fn state(&self) -> DisclosureState {
        match self.affirmed_at {
            Some(_) => DisclosureState::Affirmed,
            None => DisclosureState::Required,
        }
    }

    /// Records the operator's affirm at `at` (Unix seconds). Affirming twice
    /// without recording in between is not an error; it just refreshes when
    /// the standing affirm was made.
    pub const fn affirm(&mut self, at: u64) {
        self.affirmed_at = Some(at);
    }

    /// Spends the standing affirm, yielding the single permit it authorizes
    /// and closing the gate behind it. A second recording needs a second
    /// affirm.
    ///
    /// # Errors
    ///
    /// [`DisclosureError::NotAffirmed`] when no affirm is outstanding — the
    /// whole point of the module.
    pub fn take_permit(&mut self) -> Result<CapturePermit, DisclosureError> {
        let affirmed_at = self
            .affirmed_at
            .take()
            .ok_or(DisclosureError::NotAffirmed)?;
        Ok(CapturePermit { affirmed_at })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_773_532_800;

    #[test]
    fn a_fresh_gate_refuses_capture() {
        let mut gate = DisclosureGate::new();
        assert_eq!(gate.state(), DisclosureState::Required);
        assert_eq!(
            gate.take_permit().unwrap_err(),
            DisclosureError::NotAffirmed
        );
    }

    #[test]
    fn an_affirm_opens_the_gate_exactly_once() {
        let mut gate = DisclosureGate::new();
        gate.affirm(NOW);
        assert_eq!(gate.state(), DisclosureState::Affirmed);

        let permit = gate.take_permit().expect("the affirm authorizes a capture");
        assert_eq!(permit.affirmed_at(), NOW);

        // Spending the affirm closes the gate: a second recording in the same
        // app session must be disclosed again.
        assert_eq!(gate.state(), DisclosureState::Required);
        assert_eq!(
            gate.take_permit().unwrap_err(),
            DisclosureError::NotAffirmed
        );
    }

    #[test]
    fn re_affirming_refreshes_the_standing_affirm() {
        let mut gate = DisclosureGate::new();
        gate.affirm(NOW);
        gate.affirm(NOW + 30);
        assert_eq!(
            gate.take_permit().expect("affirmed").affirmed_at(),
            NOW + 30
        );
    }
}
