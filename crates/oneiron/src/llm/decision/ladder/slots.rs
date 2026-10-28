//! Decision ladder slots: which rung's provider can take a call, and the ladder a
//! posture leaves.
//! Entry: DecisionLadder.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{DecisionLadder, DecisionProvider, next_rung, takes};
use crate::llm::decision::{
    DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion, DecisionRung,
};

impl DecisionLadder<'_> {
    /// The first rung from `first` up to `ceiling` whose provider reads images when
    /// `images` and audio when `audio`, for a host that starts a media call there. `None`
    /// when no rung in that span reads every medium the call carries: the host abstains
    /// rather than drop one.
    #[must_use]
    pub fn first_media_reader(
        &self,
        first: DecisionRung,
        ceiling: DecisionRung,
        images: bool,
        audio: bool,
    ) -> Option<DecisionRung> {
        let mut rung = first;
        loop {
            if self.slot(rung).is_some_and(|provider| {
                (!images || provider.reads_images()) && (!audio || provider.reads_audio())
            }) {
                return Some(rung);
            }
            if rung >= ceiling || rung == DecisionRung::Human {
                return None;
            }
            rung = next_rung(rung);
        }
    }

    /// The ladder with every slot whose provider leaves the host emptied, when `posture`
    /// keeps unit text local. Text leaves only under MANAGED posture or an explicit
    /// `remote_opt_in`, and never under RELAY ([`crate::llm::decision::SeatRequest::validate_remote`]'s
    /// rule; ARCH-0076 #posture). A step up skips an emptied slot as it skips any absent
    /// one.
    #[must_use]
    pub fn under_posture(
        mut self,
        posture: crate::HostingPrivacyPosture,
        remote_opt_in: bool,
    ) -> Self {
        use crate::HostingPrivacyPosture::{Hosted, Relay};
        if (posture == Hosted || remote_opt_in) && posture != Relay {
            return self;
        }
        for slot in [
            &mut self.rule,
            &mut self.local,
            &mut self.system_one,
            &mut self.escalation,
            &mut self.big,
        ] {
            if slot.is_some_and(|provider| provider.leaves_host()) {
                *slot = None;
            }
        }
        self
    }

    pub(super) fn slot(&self, rung: DecisionRung) -> Option<&dyn DecisionProvider> {
        match rung {
            DecisionRung::Rule => self.rule,
            DecisionRung::Local => self.local,
            DecisionRung::SystemOne => self.system_one,
            DecisionRung::Escalation => self.escalation,
            DecisionRung::Big => self.big,
            DecisionRung::Human => None,
        }
    }

    /// The first rung from `dial.first` to its ceiling, short of the person, whose provider
    /// takes `question` over `images`. The ladder fails a call whose first rung cannot take
    /// it, so a caller with images starts there, or asks without them and says so.
    pub fn first_taking(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
    ) -> Option<DecisionRung> {
        self.first_taking_media(question, dial, images, &[])
    }

    /// [`DecisionLadder::first_taking`] over `images` and `audio` both.
    pub fn first_taking_media(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Option<DecisionRung> {
        let mut rung = dial.first;
        while rung <= dial.ceiling && rung != DecisionRung::Human {
            if self
                .slot(rung)
                .is_some_and(|provider| takes(provider, question, images, audio))
            {
                return Some(rung);
            }
            rung = next_rung(rung);
        }
        None
    }

    /// The next rung above `rung` that can answer `question`, up to `ceiling`. The person's
    /// queue is always present (ARCH-0076 #posture: no house model sends the step to the
    /// big model or the person).
    pub(super) fn next_available(
        &self,
        mut rung: DecisionRung,
        ceiling: DecisionRung,
        question: &DecisionQuestion,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Option<DecisionRung> {
        while rung < ceiling {
            rung = next_rung(rung);
            if rung == DecisionRung::Human
                || self
                    .slot(rung)
                    .is_some_and(|provider| takes(provider, question, images, audio))
            {
                return Some(rung);
            }
        }
        None
    }
}
