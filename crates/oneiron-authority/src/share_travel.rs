//! The values of what travels with a body when it leaves the vault (OF-491):
//! the text fields born with a body and the sharer's choice of them. They live
//! here so a signed authority action can carry a choice (FIX 2998, a grant's
//! travel choice); `oneiron::share_travel` re-exports each at its old path and
//! keeps every vault and export helper.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// One text field born with a body.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BornWithField {
    /// The prompt the body was made from, read from its birth's prompt rows.
    Prompt,
    /// The body's `why`.
    Why,
    /// The keep memo: the body's `keep`, the editing wants its people left.
    Keep,
    /// A lens pack's intent prompt, the recipe a recipient cooks against
    /// their own vault.
    IntentPrompt,
}

impl BornWithField {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Why => "why",
            Self::Keep => "keep",
            Self::IntentPrompt => "intent_prompt",
        }
    }

    /// The field [`Self::as_str`] names; `None` for any other name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "prompt" => Some(Self::Prompt),
            "why" => Some(Self::Why),
            "keep" => Some(Self::Keep),
            "intent_prompt" => Some(Self::IntentPrompt),
            _ => None,
        }
    }
}

/// Born-with text by field: prose only, never a ref.
pub type BornWith = BTreeMap<BornWithField, String>;

/// The kind of body leaving, which sets what travels when the sharer names nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TravelKind {
    Summary,
    LensPack,
    Brief,
    Artifact,
    Document,
    AgentPack,
}

/// The sharer's choice of born-with text to send. Refs are never a choice.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TravelChoice {
    #[serde(default)]
    pub born_with: BTreeSet<BornWithField>,
}

impl TravelChoice {
    /// What travels unless the sharer says otherwise: a lens pack's intent
    /// prompt, because it is the recipe. A summary's prompt and keep memo, and
    /// every other kind's born-with text, stay home. An agent pack's
    /// instructions and skill bodies are the pack, not born-with text, so they
    /// travel whatever this says.
    #[must_use]
    pub fn default_for(kind: TravelKind) -> Self {
        let born_with = match kind {
            TravelKind::LensPack => BTreeSet::from([BornWithField::IntentPrompt]),
            TravelKind::Summary
            | TravelKind::Brief
            | TravelKind::Artifact
            | TravelKind::Document
            | TravelKind::AgentPack => BTreeSet::new(),
        };
        Self { born_with }
    }

    /// The sharer's choice, or the kind's default when they named none.
    #[must_use]
    pub fn or_default(choice: Option<&Self>, kind: TravelKind) -> Self {
        choice.cloned().unwrap_or_else(|| Self::default_for(kind))
    }

    /// The chosen fields of `born_with`; the rest stays home.
    #[must_use]
    pub fn project(&self, born_with: BornWith) -> BornWith {
        born_with
            .into_iter()
            .filter(|(field, _)| self.born_with.contains(field))
            .collect()
    }

    /// What both choices let travel: the fields both name. Concurrent
    /// choices meet so (DEC-0005: concurrent stricter wins).
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            born_with: self
                .born_with
                .intersection(&other.born_with)
                .copied()
                .collect(),
        }
    }
}
