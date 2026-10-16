//! What travels with a body when it leaves the vault (OF-491). Refs into the
//! vault (frontiers, input hashes, made_by rows, actors and triggers) never
//! travel. Text born with the body (the prompt, the why, the keep memo, a lens
//! pack's intent prompt) travels only when the sharer says so, and the share
//! receipt lists what travelled.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::provenance::made_by::{MadeBy, MadeByInputRole};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::side_table::{self, Named, SideTable};
use crate::{Result, Vault};

/// The share receipt field listing the born-with fields that travelled.
pub const FIELD_TRAVELLED: &str = "travelled";

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
    /// every other kind's born-with text, stay home.
    #[must_use]
    pub fn default_for(kind: TravelKind) -> Self {
        let born_with = match kind {
            TravelKind::LensPack => BTreeSet::from([BornWithField::IntentPrompt]),
            TravelKind::Summary | TravelKind::Brief | TravelKind::Artifact | TravelKind::Document => {
                BTreeSet::new()
            }
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
}

/// A receipt's `travelled` value: the field names in order, comma-joined.
#[must_use]
pub fn travelled_value(fields: impl IntoIterator<Item = BornWithField>) -> String {
    fields
        .into_iter()
        .map(BornWithField::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// One artifact export's travel record: the copy, its digest, who sent it and
/// the born-with fields that left with it; never the exported bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportTravel {
    /// Vault clock seconds.
    pub at: u64,
    pub artifact_ref: String,
    pub version: u64,
    /// BLAKE3 of the exported file, lowercase hex.
    pub content_hash: String,
    /// The exporting actor as hex.
    pub by: String,
    pub travelled: Vec<BornWithField>,
}

const EXPORT_TRAVEL: SideTable<u64, ExportTravel, Named> =
    SideTable::new(&side_table::SHARE_EXPORT_TRAVEL);

const BRIEF_TRAVEL: SideTable<EntityId, TravelChoice, Named> =
    SideTable::new(&side_table::SHARE_BRIEF_TRAVEL);

/// Fix a brief share's choice in the transaction that admits the share.
pub(crate) fn put_brief_travel_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    share_id: &EntityId,
    choice: &TravelChoice,
) -> Result<()> {
    BRIEF_TRAVEL.put(&vault.store, txn, share_id, choice)
}

/// A brief share's choice; a share admitted without one sends the brief default.
pub(crate) fn brief_travel_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    share_id: &EntityId,
) -> Result<TravelChoice> {
    brief_travel_for_store_in_txn(&vault.store, txn, share_id)
}

/// [`brief_travel_in_txn`] over a bare store, for the share admission check.
pub(crate) fn brief_travel_for_store_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    share_id: &EntityId,
) -> Result<TravelChoice> {
    Ok(BRIEF_TRAVEL
        .get(store, txn, share_id)?
        .unwrap_or_else(|| TravelChoice::default_for(TravelKind::Brief)))
}

/// Every artifact export's share receipt, listing what travelled.
pub(crate) fn export_travel_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for row in EXPORT_TRAVEL.iter_from(&vault.store, txn, &[])? {
        let (sequence, travel) = row?;
        let receipt = ReceiptRecord {
            receipt_id: format!("share:export:{sequence}"),
            receipt_kind: ReceiptKind::Share,
            occurred_at: travel.at,
            actor: Some(travel.by.clone()),
            on_behalf_of: None,
            outcome: "exported".to_owned(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields: BTreeMap::from([
                ("artifact".to_owned(), travel.artifact_ref.clone()),
                ("version".to_owned(), travel.version.to_string()),
                ("content_hash".to_owned(), travel.content_hash.clone()),
                (
                    FIELD_TRAVELLED.to_owned(),
                    travelled_value(travel.travelled.iter().copied()),
                ),
            ]),
        };
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

impl Vault {
    /// The text born with `entity`, read here: its birth's prompt rows (or
    /// `made_by`'s, for one version of a body), its `why` and `keep`, and a
    /// lens's intent prompt. Only the prose is read; the refs that point at it
    /// stay home. A part with no text document reads as absent, so a failed
    /// read sends less, never more.
    pub fn born_with_text(&self, entity: &EntityId, made_by: Option<&MadeBy>) -> Result<BornWith> {
        let mut text = BornWith::new();
        let birth = match made_by {
            Some(_) => None,
            None => self.row_birth(entity)?,
        };
        if let Some(made_by) = made_by.or(birth.as_ref().map(|birth| &birth.made_by)) {
            let prompt = made_by
                .inputs
                .iter()
                .filter(|input| input.role == MadeByInputRole::Prompt)
                .filter_map(|input| self.entity_text(&input.row).ok())
                .filter(|prompt| !prompt.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n\n");
            if !prompt.is_empty() {
                text.insert(BornWithField::Prompt, prompt);
            }
        }
        if let Ok(document) =
            self.entity_document(entity, crate::vault::entity_revision::ReadMode::Live)
        {
            for (field, key) in [(BornWithField::Why, "why"), (BornWithField::Keep, "keep")] {
                if let Some(value) = document
                    .metadata
                    .get(key)
                    .and_then(rmpv::Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                {
                    text.insert(field, value.to_owned());
                }
            }
        }
        if let Some(intent) = self.get_lens_intent(entity)? {
            if !intent.prompt().trim().is_empty() {
                text.insert(BornWithField::IntentPrompt, intent.prompt().to_owned());
            }
        }
        Ok(text)
    }

    /// The born-with text a brief share lets travel, fixed when it was admitted.
    pub fn share_travel(&self, share_id: &EntityId) -> Result<TravelChoice> {
        let txn = self.store.env.read_txn()?;
        brief_travel_in_txn(self, &txn, share_id)
    }

    /// Record one artifact export's travel receipt. Export is never gated on
    /// it, except that born-with text does not leave unreceipted.
    pub(crate) fn record_export_travel(
        &self,
        artifact_ref: String,
        version: u64,
        content_hash: String,
        by: &EntityId,
        born_with: &BornWith,
    ) -> Result<()> {
        let travel = ExportTravel {
            at: self.store.clock.now_recorded_at(),
            artifact_ref,
            version,
            content_hash,
            by: by.to_hex(),
            travelled: born_with.keys().copied().collect(),
        };
        let written = self.with_write_txn_grouped(|txn| {
            let sequence = match EXPORT_TRAVEL.iter_rev_from(&self.store, txn, &[])?.next() {
                None => 0,
                Some(row) => row?
                    .0
                    .checked_add(1)
                    .ok_or(crate::Error::IndexOverflow("export travel sequence"))?,
            };
            EXPORT_TRAVEL.put(&self.store, txn, &sequence, &travel)
        });
        match written {
            Err(error) if travel.travelled.is_empty() => {
                tracing::warn!(%error, "artifact export served without its travel receipt");
                Ok(())
            }
            other => other,
        }
    }
}
