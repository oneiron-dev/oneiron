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
pub struct DerivationStamp {
    /// The committing actor.
    pub actor: WriteActor,
    /// The run the batch belongs to, as recorded; `None` for an engine job
    /// with no run.
    pub run: Option<String>,
    /// The source classes the run's inputs carried. Every derived claim is
    /// `Generated`; this adds what it was derived from.
    pub lineage: SourceLineage,
}

/// A row a derivation item names: one already stored, or one an earlier item
/// of the same batch lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemRef {
    /// A stored row, by id.
    Stored(EntityId),
    /// The row an earlier item of the batch lands, by that item's local name.
    Local(String),
}

/// A claim an agent derived.
#[derive(Debug, Clone)]
pub struct DerivedClaim {
    /// The item's name inside its batch: unique there, and what later items
    /// name it by.
    pub local: String,
    /// The claim's predicate.
    pub predicate: String,
    /// What the claim is about.
    pub subject: ItemRef,
    /// The claim's value.
    pub value: serde_json::Value,
    /// Its confidence, in `[0, 1]`.
    pub confidence: f32,
    /// The rows it was derived from. The derivation floor (GATE-12) needs at
    /// least one of them to be live evidence.
    pub evidence: Vec<ItemRef>,
}

/// A supersession an agent derived: the claim `new` replaces the claim
/// `old`, which the agent's grant reaches.
#[derive(Debug, Clone)]
pub struct DerivedSupersede {
    /// The item's name inside its batch.
    pub local: String,
    /// The claim that stands.
    pub new: ItemRef,
    /// The claim it replaces.
    pub old: ItemRef,
}

/// An agent's answer to one open conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedSettlement {
    /// This member stands; each other live member is superseded by it.
    Keep(ItemRef),
    /// Every member stays active: the pair is held and its gap is known.
    HoldBoth,
    /// The marker named no real contradiction.
    Dismiss,
}

/// A settlement an agent derived for the open conflict `marker`.
#[derive(Debug, Clone)]
pub struct DerivedSettle {
    /// The item's name inside its batch.
    pub local: String,
    /// The open conflict's marker.
    pub marker: ItemRef,
    /// The answer.
    pub settlement: DerivedSettlement,
}

/// One derived item. Each kind is one arm with a stager of its own.
#[derive(Debug, Clone)]
pub enum DerivationItem {
    /// A `Generated` claim (kind 1).
    Claim(DerivedClaim),
    /// A supersession (kind 3).
    Supersede(DerivedSupersede),
    /// A conflict settlement (kind 3).
    Settle(DerivedSettle),
}

impl DerivationItem {
    /// The item's name inside its batch.
    pub fn local(&self) -> &str {
        match self {
            Self::Claim(claim) => &claim.local,
            Self::Supersede(supersede) => &supersede.local,
            Self::Settle(settle) => &settle.local,
        }
    }

    /// The kind's name, as the batch record and the receipts name it.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Claim(_) => "claim",
            Self::Supersede(_) => "supersede",
            Self::Settle(_) => "settle",
        }
    }

    /// Every row the item names.
    pub(super) fn refs(&self) -> Vec<&ItemRef> {
        match self {
            Self::Claim(claim) => std::iter::once(&claim.subject)
                .chain(claim.evidence.iter())
                .collect(),
            Self::Supersede(supersede) => vec![&supersede.new, &supersede.old],
            Self::Settle(settle) => match &settle.settlement {
                DerivedSettlement::Keep(kept) => vec![&settle.marker, kept],
                DerivedSettlement::HoldBoth | DerivedSettlement::Dismiss => vec![&settle.marker],
            },
        }
    }
}

/// The items one commit lands, in order: an item names only rows stored
/// before the batch or landed by an item before it.
#[derive(Debug, Clone)]
pub struct DerivationBatch {
    /// The items, in the order they stage.
    pub items: Vec<DerivationItem>,
}

/// The most items one batch holds.
pub const MAX_BATCH_ITEMS: usize = 256;

impl DerivationBatch {
    /// Checks the batch's shape: at least one item and no more than
    /// [`MAX_BATCH_ITEMS`], every local name non-empty and unique, and every
    /// local reference naming an earlier item.
    ///
    /// # Errors
    ///
    /// A malformed batch, which aborts the whole commit.
    pub(super) fn validate(&self) -> Result<()> {
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
