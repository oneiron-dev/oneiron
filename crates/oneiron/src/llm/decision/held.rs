//! What a component that outlives one call holds to ask typed questions (a worker thread, a
//! provider a host keeps): the ladder's slots owned, and the call's bounded state.

use std::sync::Arc;

use serde_json::Value;

use super::types::invalid;
use super::{
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue,
    HumanDecisionRequest, MAX_DECISION_STATE_BYTES, ProviderPin, StateCut,
};
use crate::Result;

/// [`DecisionLadder`]'s slots, owned.
#[derive(Clone)]
pub struct HeldLadder {
    pub rule: Option<Arc<dyn DecisionProvider>>,
    pub local: Option<Arc<dyn DecisionProvider>>,
    pub system_one: Option<Arc<dyn DecisionProvider>>,
    pub escalation: Option<Arc<dyn DecisionProvider>>,
    pub big: Option<Arc<dyn DecisionProvider>>,
    pub human: Arc<dyn HumanDecisionQueue>,
    pub human_pin: ProviderPin,
    /// The host's paired question; see [`DecisionLadder::paired`].
    pub paired: Option<DecisionQuestion>,
    pub person: Option<DecisionQuestion>,
    /// The host's presence question; see [`DecisionLadder::presence`].
    pub presence: Option<DecisionQuestion>,
}

impl HeldLadder {
    /// A ladder with no provider in any slot and no person to ask: a caller's own read
    /// ([`super::GeneratedRung`]) is its one rung. A dial that reaches the person fails.
    #[must_use]
    pub fn unstaffed() -> Self {
        Self {
            rule: None,
            local: None,
            system_one: None,
            escalation: None,
            big: None,
            human: Arc::new(NoPerson),
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "no-person".into(),
                version: "1".into(),
            },
            paired: None,
            person: None,
            presence: None,
        }
    }

    /// The ladder for one call, borrowing these slots.
    #[must_use]
    pub fn ladder(&self) -> DecisionLadder<'_> {
        DecisionLadder {
            rule: self.rule.as_deref(),
            local: self.local.as_deref(),
            system_one: self.system_one.as_deref(),
            escalation: self.escalation.as_deref(),
            big: self.big.as_deref(),
            human: self.human.as_ref(),
            human_pin: self.human_pin.clone(),
            ask_to: None,
            paired: self.paired.as_ref(),
            person: self.person.as_ref(),
            presence: self.presence.as_ref(),
            correlation: None,
        }
    }
}

/// The person queue of a host with no person to ask.
struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        Err(invalid("no person to ask"))
    }
}

/// The call's bounded state, as `state` builds it with every long text cut to the bytes it
/// is given. The cut starts at half the `longest` text and halves until the whole fits
/// [`MAX_DECISION_STATE_BYTES`]; `state` says where (`cut_at_bytes`), so a provider knows
/// it reads a cut text. With nothing left to cut, the ladder refuses the state.
pub fn fit_state(longest: usize, state: impl Fn(Option<usize>) -> Value) -> Value {
    let mut cut = None;
    loop {
        let value = state(cut);
        let fits =
            serde_json::to_vec(&value).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES);
        cut = match cut {
            _ if fits => return value,
            None if longest > 0 => Some(longest / 2),
            Some(bytes) if bytes > 0 => Some(bytes / 2),
            _ => return value,
        };
    }
}

/// The one cut order for a state that holds a reserve sample of `items` and a long text of
/// `text` bytes (FIX 1326): whole when it fits [`MAX_DECISION_STATE_BYTES`]; else the longest
/// first part of the sample that fits, at whole items and at least one, with the text whole;
/// else that one item with the text cut, halving from its length, on a character boundary.
/// `state` builds the state from the items kept and the text's cut (`None` whole). Answers
/// the state and what was cut. With nothing left to cut it answers the smallest state, which
/// the ladder may still refuse.
pub fn fit_reserve_state(
    items: usize,
    text: usize,
    mut state: impl FnMut(usize, Option<usize>) -> Result<Value>,
) -> Result<(Value, Option<StateCut>)> {
    let fits = |value: &Value| {
        serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES)
    };
    let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let cut = |kept: usize, at: Option<usize>| StateCut {
        kept: count(kept),
        of: count(items),
        text_cut_at_bytes: at.map(count),
    };
    let whole = state(items, None)?;
    if fits(&whole) {
        return Ok((whole, None));
    }
    // The longest first part that fits: fewer items never make a longer state.
    let floor = items.min(1);
    let (mut low, mut high) = (floor, items.saturating_sub(1));
    let mut best = None;
    while low <= high {
        let mid = low + (high - low) / 2;
        let value = state(mid, None)?;
        if fits(&value) {
            best = Some((mid, value));
            low = mid + 1;
        } else if mid == 0 {
            break;
        } else {
            high = mid - 1;
        }
    }
    if let Some((kept, value)) = best {
        return Ok((value, Some(cut(kept, None))));
    }
    if text == 0 {
        return Ok((state(floor, None)?, Some(cut(floor, None))));
    }
    let mut at = text / 2;
    loop {
        let value = state(floor, Some(at))?;
        if fits(&value) || at == 0 {
            return Ok((value, Some(cut(floor, Some(at)))));
        }
        at /= 2;
    }
}

/// `text` cut to at most `cut` bytes, on a character boundary.
pub fn cut_text(text: &str, cut: Option<usize>) -> &str {
    let Some(cut) = cut else {
        return text;
    };
    let mut end = text.len().min(cut);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
