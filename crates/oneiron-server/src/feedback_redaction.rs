//! The in-vault text filter over this server's Oneironer tagger (OF-420):
//! what the feedback doors run every free text through before it may leave.
//!
//! [`OneironerFilter`] asks the configured tagger which spans of one text it
//! recognises and replaces them as the engine's span rule says
//! (`oneiron::feedback::apply_recognised_spans`). It runs only on the
//! device: a tagger off it would carry the text away before anything was
//! filtered, so it is refused, as the tagging reconciler refuses one. No
//! tagger, a call that fails or panics, or an answer out of shape is an
//! error, never the text as written; and a tagger that recognised nothing
//! proves nothing about what the text holds.
//!
//! A feedback door filters when the filter runs, and otherwise sends what it
//! sent before the filter existed ([`Unfiltered`]), through
//! [`UnredactedFeedback`] and never labelled filtered: filtering adds to a
//! report the person sends, it does not take one away. Sharing conversation
//! text toward training never falls back; a filter error withholds it
//! (`oneiron::feedback::share_for_publisher_training`).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use oneiron::embed::EmbedderLocality;
use oneiron::feedback::{
    FeedbackBundle, FeedbackRedactionError, FeedbackRedactor, FilteredFeedback, FilteredText,
    TextFilter, TextFilterError, TextFilterIdentity, UnredactedFeedback, apply_recognised_spans,
};
use oneiron::memory::extraction::{EncoderInput, EncoderMessage, ExtractionEncoder};

use crate::server::SyncServer;

/// The turn id of the filter's input: the text is no stored turn, and it is
/// sent alone, with no earlier turn for context.
const FILTER_TURN: &str = "text-filter";

/// The id of the input's one message; spans name it by position, 0.
const FILTER_MESSAGE: &str = "text";

/// The [`TextFilter`] over the server's on-device Oneironer tagger.
pub(crate) struct OneironerFilter {
    /// The tagger slot's tagger; `None` when no tagger is configured.
    encoder: Option<Arc<dyn ExtractionEncoder>>,
}

impl OneironerFilter {
    /// The filter over `server`'s tagger slot.
    pub(crate) fn of_server(server: &SyncServer) -> Self {
        Self {
            encoder: server
                .tagger
                .as_ref()
                .map(|slot| Arc::clone(slot.tagger()) as Arc<dyn ExtractionEncoder>),
        }
    }
}

impl TextFilter for OneironerFilter {
    fn filter(&self, text: &str) -> Result<FilteredText, TextFilterError> {
        let Some(encoder) = self.encoder.as_ref() else {
            return Err(TextFilterError::Unavailable(
                "this server has no Oneironer tagger configured to filter text".to_owned(),
            ));
        };
        // The reconciler's refusal (`TaggingReconciler::new`): a tagger off
        // the device would carry the text away before it is filtered.
        if encoder.locality() != EmbedderLocality::OnDevice {
            return Err(TextFilterError::Unavailable(
                "a tagger off the device would carry the text away before it is filtered"
                    .to_owned(),
            ));
        }
        let input = EncoderInput {
            turn: FILTER_TURN.to_owned(),
            messages: vec![EncoderMessage {
                id: FILTER_MESSAGE.to_owned(),
                text: text.to_owned(),
            }],
            context: Vec::new(),
            language: None,
            speaker: None,
        };
        let output = match catch_unwind(AssertUnwindSafe(|| encoder.infer(&input))) {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                return Err(TextFilterError::Unavailable(format!(
                    "the tagger call failed ({:?})",
                    error.kind()
                )));
            }
            Err(_) => {
                return Err(TextFilterError::Unavailable(
                    "the tagger panicked".to_owned(),
                ));
            }
        };
        apply_recognised_spans(
            text,
            &output.spans,
            TextFilterIdentity {
                model: encoder.model_id().as_str().to_owned(),
                stack_sha16: output.stack_sha16,
            },
        )
    }
}

/// What a door sends when the filter cannot run (no tagger, one off the
/// device, a call that failed or panicked, an answer out of shape): what it
/// sent before the filter existed, as built, through [`UnredactedFeedback`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unfiltered {
    /// The bundle as built: the subject door's report text.
    AsBuilt,
    /// The bundle as built, unless it carries a note: the owner door, where a
    /// note leaves only filtered and is otherwise refused.
    RefuseNote,
}

/// The feedback redaction every server door runs a bundle through: the
/// in-vault filter over the tagger slot, and a door's own fallback
/// ([`Self::door`]).
pub(crate) struct ServerFeedbackRedactor {
    filtered: FilteredFeedback<OneironerFilter>,
}

impl ServerFeedbackRedactor {
    /// This redaction for one door: every free text filtered when the filter
    /// runs, and `unfiltered` when it cannot.
    pub(crate) const fn door(&self, unfiltered: Unfiltered) -> DoorRedactor<'_> {
        DoorRedactor {
            filtered: &self.filtered,
            unfiltered,
        }
    }
}

/// [`ServerFeedbackRedactor`] over `server`'s tagger slot.
pub(crate) fn feedback_redactor(server: &SyncServer) -> ServerFeedbackRedactor {
    ServerFeedbackRedactor {
        filtered: FilteredFeedback::new(OneironerFilter::of_server(server)),
    }
}

/// One door's redactor ([`ServerFeedbackRedactor::door`]). A bundle is
/// either filtered whole or, when the filter cannot run, sent as built;
/// never part of each.
pub(crate) struct DoorRedactor<'a> {
    filtered: &'a FilteredFeedback<OneironerFilter>,
    unfiltered: Unfiltered,
}

impl FeedbackRedactor for DoorRedactor<'_> {
    fn redact(&self, bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError> {
        let as_built = bundle.clone();
        match self.filtered.redact(bundle) {
            Ok(filtered) => Ok(filtered),
            Err(error) => match self.unfiltered {
                Unfiltered::RefuseNote if as_built.user_note.is_some() => Err(error),
                Unfiltered::AsBuilt | Unfiltered::RefuseNote => UnredactedFeedback.redact(as_built),
            },
        }
    }
}
