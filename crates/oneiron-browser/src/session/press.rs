//! The press each effect class's sends run under (FIX 4613, 4615, 8009).
//!
//! The vault's grants are read again at each classified send, where the
//! host gives a live read of them ([`PressGrants`]): a grant revoked during
//! the run covers no later send. The sends a reviewed batch's budget paid
//! stay on the session, which every door of the run shares: a door that
//! binds it again, or a grant read again, never refills the budget.
//!
//! A control a send's words name, on a page whose URL path names a payment
//! step (`payment_page_policy`, CALLS row), is a payment: it takes the pay
//! class's own path, a person's press, never a send grant.

use super::BrowserSession;
use crate::{EFFECT_PAY, EFFECT_SEND, PressMode, SendPolicy};
use std::collections::BTreeMap;

/// The host's live read of the vault's grants, as the press policy they
/// set now (FIX 4613).
pub trait PressGrants: Send {
    /// The press each effect class runs under as the grants stand now; the
    /// floor (a press per send) where they cannot be read.
    fn current(&self) -> SendPolicy;

    /// The press each effect class runs under for a send that reports
    /// `audience` as its counterparty (FIX 11907): the origin of the page
    /// the send acted on, or none where the send names none. The host's
    /// read may then count only the grants whose audience names it; a read
    /// that checks no audience answers as [`Self::current`].
    fn current_for(&self, audience: Option<&str>) -> SendPolicy {
        let _ = audience;
        self.current()
    }
}

/// The session's book of presses: the grants' policy as last read, the
/// sends a person's press over a reviewed batch covers, and the sends a
/// batch press already paid, per class. A desktop session keeps the same
/// book (FIX 12133).
#[derive(Default)]
pub(crate) struct PressBook {
    granted: SendPolicy,
    approved: BTreeMap<String, u32>,
    spent: BTreeMap<String, u32>,
    live: Option<Box<dyn PressGrants>>,
}

impl PressBook {
    pub(crate) fn new(granted: SendPolicy) -> Self {
        Self {
            granted,
            ..Self::default()
        }
    }

    /// Gives the book the host's live read of the vault's grants.
    pub(crate) fn set_live(&mut self, grants: Box<dyn PressGrants>) {
        self.live = Some(grants);
    }

    /// Sets the grants' policy as they stand now. The sends a batch press
    /// already paid stay paid (FIX 4615).
    pub(crate) fn set_granted(&mut self, granted: SendPolicy) {
        self.granted = granted;
    }

    /// The policy a classified send runs under now: the grants read again
    /// where the host reads them live, for the counterparty `audience`
    /// the send reports (FIX 11907), less the sends already paid.
    pub(crate) fn refresh(&mut self, audience: Option<&str>) -> SendPolicy {
        if let Some(live) = &self.live {
            self.granted = live.current_for(audience);
        }
        self.policy()
    }

    /// Counts a send a batch press paid.
    pub(crate) fn paid(&mut self, class: &str) {
        *self.spent.entry(class.to_owned()).or_default() += 1;
    }

    /// The policy the sends run under now: the grants' modes, each batch's
    /// budget with a person's approved sends, less the sends it paid.
    pub(crate) fn policy(&self) -> SendPolicy {
        let mut policy = self.granted.clone();
        for (class, count) in &self.approved {
            let mode = policy.modes.entry(class.clone()).or_default();
            if *mode == PressMode::PerSend {
                *mode = PressMode::PerBatch;
            }
            let left = policy.batch.entry(class.clone()).or_default();
            *left = left.saturating_add(*count);
        }
        for (class, left) in &mut policy.batch {
            *left = left.saturating_sub(self.spent.get(class).copied().unwrap_or_default());
        }
        policy
    }
}

impl BrowserSession {
    /// Gives the session the host's live read of the vault's grants: each
    /// classified send reads them again (FIX 4613).
    pub fn set_press_grants(&mut self, grants: Box<dyn PressGrants>) {
        self.presses.set_live(grants);
    }

    /// Sets the grants' policy as they stand now. The sends a batch press
    /// already paid stay paid: a door that binds the session again never
    /// refills them (FIX 4615).
    pub fn set_policy(&mut self, policy: SendPolicy) {
        self.presses.set_granted(policy);
        self.policy = self.presses.policy();
    }

    /// Records a person's press over a reviewed batch of `count` sends of
    /// `class`. Its sends then run without a press each until spent.
    pub fn approve_batch(&mut self, class: &str, count: u32) {
        let approved = self.presses.approved.entry(class.to_owned()).or_default();
        *approved = approved.saturating_add(count);
        self.policy = self.presses.policy();
    }

    /// The policy a classified send runs under now: the grants read again
    /// where the host reads them live, for the counterparty `audience`
    /// the send reports (FIX 11907), less the sends already paid.
    pub(super) fn press_policy(&mut self, audience: Option<&str>) -> &mut SendPolicy {
        self.policy = self.presses.refresh(audience);
        &mut self.policy
    }

    /// Counts a send a batch press paid.
    pub(super) fn press_paid(&mut self, class: &str) {
        self.presses.paid(class);
    }
}

/// Words of a URL's path that mark a payment step (`payment_page_policy`,
/// CALLS row), matched as whole words.
const PAYMENT_PAGE_WORDS: &[&str] = &["checkout", "payment", "pay", "billing", "purchase"];

/// Whether the page at `url` is a payment step (`payment_page_policy`,
/// CALLS row): a whole word of its path, split at every character that is
/// no letter or digit, is one of [`PAYMENT_PAGE_WORDS`]. `/pay/confirm`
/// and `/checkout-step` are; `/paypal-docs` and `/repayment-faq` are not.
pub(crate) fn payment_page_policy(url: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    url.path()
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| {
            PAYMENT_PAGE_WORDS
                .iter()
                .any(|pay| word.eq_ignore_ascii_case(pay))
        })
}

/// The class a control named `name` marks on the page at `url` (FIX
/// 8009): a send on a payment step is a payment, which only a person's
/// press runs; any other class as its name marks it.
pub(crate) fn effect_class_on(name: &str, url: Option<&str>) -> Option<&'static str> {
    let class = super::effect_class(name)?;
    let paying = class == EFFECT_SEND && url.is_some_and(payment_page_policy);
    Some(if paying { EFFECT_PAY } else { class })
}
