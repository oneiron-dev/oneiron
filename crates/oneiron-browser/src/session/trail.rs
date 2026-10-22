//! The session's one history (CUA E7): each effect's receipt and each step
//! that stopped, in order, on the session's one sequence; never a second
//! log beside the receipts.
//!
//! An effect's receipt keeps what a replay takes (`crate::replay`): the
//! act's operands as its verb took them, the page and tab it began on, and
//! the tab in front once it settled. A typed text the shared classifier
//! calls a secret, by its field or by its own value (`secret_fields`), goes
//! into the run's custody as the exact text typed, and its receipt keeps
//! the handle and kind; custody that takes none leaves a withheld operand
//! naming why, never the text.
//!
//! A step that stopped is noted where it stopped: an effect verb that
//! failed, before its effect or after it (its receipt then marked failed),
//! and a batch's stop the session's verbs do not see (an unmet check, a
//! wait out of time, a routine step sent up, a Fill the page did not take,
//! no progress, a library run's missed postcondition). A batch's stop of a
//! step whose own verb failed completes that verb's note with the batch's
//! cause, so one failure is one note.

use super::BrowserSession;
use crate::secret::{Entry, bare_handle};
use crate::secret_fields::{FieldFacts, classify};
use crate::{
    BatchStopCause, BrowserError, EffectReceipt, FieldSpec, OperandGap, ReplayAction, Row,
    SecretKind, SecretNote, StepStop, TypeOperand,
};

/// One entry of the session's history.
pub(super) enum Event {
    /// An effect's receipt, as the session kept it.
    Effect(Box<EffectReceipt>),
    /// A step that stopped.
    Stop(Marker),
}

/// A step that stopped, at `seq` of the session's sequence, with the page
/// and tab in front when it was noted.
pub(super) struct Marker {
    pub(super) seq: u64,
    pub(super) stop: StepStop,
    pub(super) url: Option<String>,
    pub(super) origin: Option<String>,
    pub(super) tab: Option<String>,
}

impl Event {
    /// The receipt this entry is, when it is an effect's.
    pub(super) fn receipt(&self) -> Option<&EffectReceipt> {
        match self {
            Self::Effect(receipt) => Some(receipt.as_ref()),
            Self::Stop(_) => None,
        }
    }
}

/// Where an act began: the front page's URL and origin, and its tab.
pub(super) struct Source {
    pub(super) url: Option<String>,
    pub(super) origin: Option<String>,
    pub(super) tab: String,
}

/// What an act's receipt keeps for a replay, set by its verb just before
/// the receipt lands.
pub(super) struct Acted {
    pub(super) action: Option<ReplayAction>,
    pub(super) source: Source,
}

/// The origin (scheme, host and port) of `url`; none for a page with no
/// such origin (`about:blank`, `data:`) or a URL that does not parse.
pub(crate) fn origin_of(url: &str) -> Option<String> {
    let origin = url::Url::parse(url).ok()?.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The kind of secret `text`, typed into `row`, is (`secret_field_policy`,
/// the one classifier): the field's own, as the read before the act found
/// it, else the text's by its value. Empty text is none.
fn typed_secret(row: &Row, text: &str) -> Option<SecretKind> {
    if text.is_empty() {
        return None;
    }
    let field = row.secret.as_ref().map(|secret| secret.kind);
    field.or_else(|| {
        classify(&FieldFacts {
            role: &row.role,
            protected: false,
            input_type: None,
            autocomplete: None,
            label: &row.name,
            description: "",
            value: text,
        })
    })
}

/// The kind of secret a check's `value` is by its value alone, as the one
/// classifier finds it (a card number).
pub(super) fn value_secret(value: &str) -> Option<SecretKind> {
    classify(&FieldFacts {
        role: "",
        protected: false,
        input_type: None,
        autocomplete: None,
        label: "",
        description: "",
        value,
    })
}

/// Why custody gave a secret text no handle, as its operand names it.
pub(super) const fn withheld(note: SecretNote) -> OperandGap {
    match note {
        SecretNote::NoCustody => OperandGap::NoCustody,
        SecretNote::Refused | SecretNote::Concealed => OperandGap::Refused,
    }
}

/// A type's replay: a Fill's own field when its text is no secret, else
/// the type of its operand into `locator`.
pub(super) fn typed_action(
    locator: String,
    operand: TypeOperand,
    clear: bool,
    fill: Option<FieldSpec>,
) -> ReplayAction {
    match (fill, operand) {
        (Some(field), TypeOperand::Literal { .. }) => ReplayAction::Fill { locator, field },
        (_, operand) => ReplayAction::Type {
            locator,
            operand,
            clear,
        },
    }
}

impl BrowserSession {
    /// Where the act about to run begins: the page and the tab in front.
    pub(super) fn source(&self) -> Source {
        let url = self.driver.url().ok();
        let origin = url.as_deref().and_then(origin_of);
        Source {
            url,
            origin,
            tab: self.driver.front_target().to_owned(),
        }
    }

    /// The operand `entry`, typed into `row` on a page of `origin`, keeps
    /// (FIX 8028 custody): a secret's handle and kind, its text taken into
    /// custody where it came as text, or text the classifier calls none.
    pub(super) fn operand(&self, row: &Row, entry: Entry<'_>, origin: Option<&str>) -> TypeOperand {
        match entry {
            Entry::Secret(named) => {
                let handle = bare_handle(named).to_owned();
                match self.secrets.kind_of(&handle) {
                    Some(kind) => TypeOperand::Secret { kind, handle },
                    None => TypeOperand::Withheld {
                        kind: None,
                        cause: OperandGap::UnknownKind,
                    },
                }
            }
            Entry::Text(text) => match typed_secret(row, text) {
                None => TypeOperand::Literal {
                    text: text.to_owned(),
                },
                Some(kind) => match self.secrets.acquire(kind, text, origin.unwrap_or_default()) {
                    Ok(handle) => TypeOperand::Secret { kind, handle },
                    Err(note) => TypeOperand::Withheld {
                        kind: Some(kind),
                        cause: withheld(note),
                    },
                },
            },
        }
    }

    /// Keeps an effect's receipt in the history.
    pub(super) fn keep(&mut self, receipt: EffectReceipt) {
        self.trail.push(Event::Effect(Box::new(receipt)));
    }

    /// The newest effect's receipt, by its seq; 0 before any.
    pub(super) fn landed_seq(&self) -> u64 {
        self.trail
            .iter()
            .rev()
            .find_map(Event::receipt)
            .map_or(0, |receipt| receipt.seq)
    }

    /// Notes `stop` at the next seq of the session's sequence, with the
    /// page and tab in front now.
    fn mark(&mut self, stop: StepStop) -> u64 {
        self.receipt_seq += 1;
        let url = self.driver.url().ok();
        let origin = url.as_deref().and_then(origin_of);
        let tab = Some(self.driver.front_target().to_owned());
        self.trail.push(Event::Stop(Marker {
            seq: self.receipt_seq,
            stop,
            url,
            origin,
            tab,
        }));
        self.receipt_seq
    }

    /// Runs effect verb `verb`, noting its failure: before its effect, or
    /// after it, with the receipt it landed marked failed. The note waits
    /// for a batch's stop of the same step to complete it.
    pub(super) fn acting<T>(
        &mut self,
        verb: &str,
        act: impl FnOnce(&mut Self) -> Result<T, BrowserError>,
    ) -> Result<T, BrowserError> {
        let from = self.receipt_seq;
        self.press_refused = None;
        let acted = act(self);
        if let Err(error) = &acted {
            let receipt = Some(self.landed_seq()).filter(|seq| *seq > from);
            let stop = StepStop {
                step: verb.to_owned(),
                cause: BatchStopCause::of(error),
                error: error.code().to_owned(),
                receipt,
                effect_class: self.press_refused.take(),
            };
            self.stop_pending = Some(self.mark(stop));
        }
        acted
    }

    /// Notes a batch's or a library run's stop: it completes the note its
    /// failing verb just made, where one did, else stands as its own.
    pub(super) fn noted(&mut self, stop: StepStop) {
        if let Some(seq) = self.stop_pending.take() {
            let pending = self.trail.iter_mut().rev().find_map(|event| match event {
                Event::Stop(marker) if marker.seq == seq => Some(marker),
                _ => None,
            });
            if let Some(marker) = pending {
                let receipt = marker.stop.receipt.or(stop.receipt);
                let effect_class = marker.stop.effect_class.take().or(stop.effect_class);
                marker.stop = StepStop {
                    receipt,
                    effect_class,
                    ..stop
                };
                return;
            }
        }
        self.mark(stop);
    }
}
