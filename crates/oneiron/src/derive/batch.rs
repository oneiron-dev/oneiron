//! What a derivation batch holds, and who commits it.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::write_envelope::{SourceLineage, WriteActor};
use crate::EntityId;

/// Who commits a derivation batch, as the engine stamps it: the actor of the
/// caller's credential, the run the batch belongs to, and that run's
/// recorded lineage. The verbs (6.7d) build it from the live-run attachment
/// and an engine job from its attempt; a caller never supplies it.
#[derive(Debug, Clone)]
pub(crate) struct DerivationStamp {
    /// The committing actor.
    pub(crate) actor: WriteActor,
    /// The run the batch belongs to, as recorded; `None` for an engine job
    /// with no run.
    pub(crate) run: Option<String>,
    /// The source classes the run's inputs carried. Every derived claim is
    /// `Generated`; this adds what it was derived from.
    pub(crate) lineage: SourceLineage,
}

/// A row a derivation item names: one already stored, or one an earlier item
/// of the same batch lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ItemRef {
    /// A stored row, by id.
    Stored(EntityId),
    /// The row an earlier item of the batch lands, by that item's local name.
    Local(String),
}

/// A claim an agent derived.
#[derive(Debug, Clone)]
pub(crate) struct DerivedClaim {
    /// The item's name inside its batch: unique there, and what later items
    /// name it by.
    pub(crate) local: String,
    /// The claim's predicate.
    pub(crate) predicate: String,
    /// What the claim is about.
    pub(crate) subject: ItemRef,
    /// The claim's value.
    pub(crate) value: serde_json::Value,
    /// Its confidence, in `[0, 1]`.
    pub(crate) confidence: f32,
    /// The rows it was derived from. The derivation floor (GATE-12) needs at
    /// least one of them to be live evidence.
    pub(crate) evidence: Vec<ItemRef>,
}

/// A supersession an agent derived: the claim `new` replaces the claim
/// `old`, which the agent's grant reaches.
#[derive(Debug, Clone)]
pub(crate) struct DerivedSupersede {
    /// The item's name inside its batch.
    pub(crate) local: String,
    /// The claim that stands.
    pub(crate) new: ItemRef,
    /// The claim it replaces.
    pub(crate) old: ItemRef,
}

/// One derived item. Each kind is one arm with a stager of its own.
#[derive(Debug, Clone)]
pub(crate) enum DerivationItem {
    /// A `Generated` claim (kind 1).
    Claim(DerivedClaim),
    /// A supersession (kind 3).
    Supersede(DerivedSupersede),
}

impl DerivationItem {
    /// The item's name inside its batch.
    pub(crate) fn local(&self) -> &str {
        match self {
            Self::Claim(claim) => &claim.local,
            Self::Supersede(supersede) => &supersede.local,
        }
    }

    /// The kind's name, as the batch record and the receipts name it.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Claim(_) => "claim",
            Self::Supersede(_) => "supersede",
        }
    }

    /// Every row the item names.
    pub(super) fn refs(&self) -> Vec<&ItemRef> {
        match self {
            Self::Claim(claim) => std::iter::once(&claim.subject)
                .chain(claim.evidence.iter())
                .collect(),
            Self::Supersede(supersede) => vec![&supersede.new, &supersede.old],
        }
    }
}

/// The items one commit lands, in order: an item names only rows stored
/// before the batch or landed by an item before it.
#[derive(Debug, Clone)]
pub(crate) struct DerivationBatch {
    /// The items, in the order they stage.
    pub(crate) items: Vec<DerivationItem>,
}

/// The most items one batch holds.
pub(crate) const MAX_BATCH_ITEMS: usize = 256;

impl DerivationBatch {
    /// Checks the batch's shape: at least one item and no more than
    /// [`MAX_BATCH_ITEMS`], every local name non-empty and unique, and every
    /// local reference naming an earlier item.
    ///
    /// # Errors
    ///
    /// A malformed batch, which aborts the whole commit.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.items.is_empty() {
            return Err(malformed("a derivation batch holds at least one item"));
        }
        if self.items.len() > MAX_BATCH_ITEMS {
            return Err(malformed("a derivation batch holds at most 256 items"));
        }
        let mut earlier: BTreeSet<&str> = BTreeSet::new();
        for item in &self.items {
            let local = item.local();
            if local.trim().is_empty() {
                return Err(malformed("every derivation item has a local name"));
            }
            for named in item.refs() {
                if let ItemRef::Local(name) = named
                    && !earlier.contains(name.as_str())
                {
                    return Err(malformed(
                        "a derivation item names only rows of items before it",
                    ));
                }
            }
            if !earlier.insert(local) {
                return Err(malformed("each derivation item's local name is unique in its batch"));
            }
        }
        Ok(())
    }
}

fn malformed(why: &'static str) -> Error {
    Error::InvalidClaimBody(why)
}
