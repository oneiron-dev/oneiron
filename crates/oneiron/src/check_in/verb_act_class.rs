//! The act class each verb row states (`act_class` in
//! `scripts/sdk/verbs/<verb>.json`; ARCH-0082 #act-table, VS-CHECKIN-NAMES = A).
//!
//! `scripts/sdk/verb_table.py` refuses a row with no class, an unknown one, or
//! `read` on a Write row: no default fills a missing class (ARCH-0082:212).
//! The generator writes every row's class into
//! [`crate::verb_names::VERB_ACT_CLASSES`] as one of these values, so a token
//! with no value here fails the build.

use super::act_class::ActClass;

/// The value of a verb row's `act_class`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum VerbActClass {
    /// A read. Check-in is never asked for one: the grant's read power is the
    /// whole check (ARCH-0082:169 "READ and DRAFT are powers", :45). Only a
    /// Read row states it.
    Read,
    /// The act the verb makes.
    Act(ActClass),
    /// No undo class is proven for the verb's effect, so it holds on silence
    /// (ARCH-0082:212).
    Unstated,
}

impl VerbActClass {
    /// The token of [`Self::Read`].
    pub const READ_TOKEN: &'static str = "read";
    /// The token of [`Self::Unstated`].
    pub const UNSTATED_TOKEN: &'static str = "unstated";

    /// The value `token` names; `None` for any other text.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            Self::READ_TOKEN => Some(Self::Read),
            Self::UNSTATED_TOKEN => Some(Self::Unstated),
            _ => ActClass::from_token(token).map(Self::Act),
        }
    }

    /// The token the verb row states.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => Self::READ_TOKEN,
            Self::Act(act) => act.as_str(),
            Self::Unstated => Self::UNSTATED_TOKEN,
        }
    }
}

/// The act class verb `verb`'s own row states; `None` for a name that is no
/// verb row.
#[must_use]
pub fn verb_act_class(verb: &str) -> Option<VerbActClass> {
    let rows = &crate::verb_names::VERB_ACT_CLASSES;
    rows.binary_search_by(|(name, _)| (*name).cmp(verb))
        .ok()
        .map(|at| rows[at].1)
}

/// Whether verb `verb`'s own row takes the owner-checked preview and confirm
/// (DEC-0006 #undo-class): its row states an act that takes the owner
/// confirm. `false` for a name that is no verb row.
#[must_use]
pub fn verb_needs_owner_confirm(verb: &str) -> bool {
    matches!(
        verb_act_class(verb),
        Some(VerbActClass::Act(act)) if act.owner_confirms()
    )
}
