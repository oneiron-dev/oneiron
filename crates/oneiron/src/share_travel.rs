//! What travels with a body when it leaves the vault (OF-491). Refs into the
//! vault (frontiers, input hashes, made_by rows, actors and triggers) never
//! travel. Text born with the body (the prompt, the why, the keep memo, a lens
//! pack's intent prompt) travels only when the sharer says so, and the share
//! receipt lists what travelled. An AgentPack travels as the reference-free
//! projection in [`agent_pack`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::provenance::made_by::{MadeBy, MadeByInputRole};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::side_table::{self, Named, SideTable};
use crate::{Result, Vault};

pub mod agent_pack;
mod agent_pack_export;
mod pack_notice;

pub use self::agent_pack::{
    AGENT_PACK_TRAVEL_SCHEMA, AgentPackKnowledge, AgentPackPolicy, AgentPackSkill,
    AgentPackTravelProjection,
};
pub use self::agent_pack_export::{AgentPackExport, AgentPackExportFile, AgentPackExportRequest};
pub use self::pack_notice::{
    AGENT_PACK_IMPORT_DOUBLE_CHECK, OWNER_PACK_EXPORT_RECIPIENT_NOTICE, PACK_NOTICE_AUDIENCE,
    PACK_NOTICE_CHANNEL, PACK_NOTICE_VOICE, PACK_NOTICE_WORDING, PackNoticeWording,
    WorldRecipientNotice,
};
pub(crate) use self::pack_notice::{screen_owner_notice_fields, world_label_in_txn};

/// The share receipt field listing the born-with fields that travelled.
pub const FIELD_TRAVELLED: &str = "travelled";

// The born-with values are defined in `oneiron-authority`, where a signed grant
// travel choice carries one (FIX 2998); every `share_travel::` path is unchanged.
pub use oneiron_authority::share_travel::{BornWith, BornWithField, TravelChoice, TravelKind};

/// The born-with text one federation grant's windows carry to another vault,
/// with when the owner set it: the effective choice the grant travel door
/// reads (`Vault::federation_grant_travel`, FIX 2998).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTravel {
    pub travel: TravelChoice,
    pub set_at: u64,
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

/// What one export sent, by its local ref and revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportTarget {
    /// One version of an artifact.
    Artifact { artifact_ref: String, version: u64 },
    /// An agent definition, sent as its travelling AgentPack, with the
    /// knowledge claims it kept home.
    AgentPack {
        agent_ref: String,
        version: String,
        omitted: Vec<OmittedKnowledge>,
    },
}

/// A knowledge claim an AgentPack export kept home, and why: `ref_value`
/// (its value names an entity or an edge) or `typed_value` (not text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedKnowledge {
    /// The claim, as hex.
    pub claim: String,
    pub reason: String,
}

impl OmittedKnowledge {
    pub(crate) fn new(claim: EntityId, reason: crate::agent_def::OmittedClaimReason) -> Self {
        let reason = match reason {
            crate::agent_def::OmittedClaimReason::RefValue => "ref_value",
            crate::agent_def::OmittedClaimReason::TypedValue => "typed_value",
        };
        Self {
            claim: claim.to_hex(),
            reason: reason.to_owned(),
        }
    }
}

impl ExportTarget {
    /// The share receipt's fields naming the target. An AgentPack's
    /// `omitted` lists each claim kept home as `<claim>:<reason>`,
    /// comma-joined.
    fn receipt_fields(&self) -> Vec<(String, String)> {
        match self {
            Self::Artifact {
                artifact_ref,
                version,
            } => vec![
                ("artifact".to_owned(), artifact_ref.clone()),
                ("version".to_owned(), version.to_string()),
            ],
            Self::AgentPack {
                agent_ref,
                version,
                omitted,
            } => {
                let mut fields = vec![
                    ("agent".to_owned(), agent_ref.clone()),
                    ("version".to_owned(), version.clone()),
                ];
                if !omitted.is_empty() {
                    let omitted = omitted
                        .iter()
                        .map(|row| format!("{}:{}", row.claim, row.reason))
                        .collect::<Vec<_>>()
                        .join(",");
                    fields.push(("omitted".to_owned(), omitted));
                }
                fields
            }
        }
    }
}

/// One export's travel record: the copy, its digest, who sent it and the
/// born-with fields that left with it; never the exported bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportTravel {
    /// Vault clock seconds.
    pub at: u64,
    pub target: ExportTarget,
    /// The exported copy's digest, lowercase hex: BLAKE3 of an artifact
    /// file, the canonical tree hash of an agent pack's folder.
    pub content_hash: String,
    /// The exporting actor as hex.
    pub by: String,
    pub travelled: Vec<BornWithField>,
    /// Each world the owner's own export carried that his recipient choice
    /// would keep from where it went, and why (FIX 5493). Empty for every
    /// other export.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<WorldRecipientNotice>,
}

const EXPORT_TRAVEL: SideTable<u64, ExportTravel, Named> =
    SideTable::new(&side_table::SHARE_EXPORT_TRAVEL);

/// How many more writes the owner's own agent-pack share receipt gets when
/// its first fails (FIX 5523, CALLS "FIX 5523 receipt retry"): on this open
/// vault's next travel receipt, after which it is dropped with a warning.
const OWNER_EXPORT_RECEIPT_RETRY_COUNT: usize = 1;

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

/// Every export's share receipt, listing what travelled.
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
            fields: travel
                .target
                .receipt_fields()
                .into_iter()
                .chain([
                    ("content_hash".to_owned(), travel.content_hash.clone()),
                    (
                        FIELD_TRAVELLED.to_owned(),
                        travelled_value(travel.travelled.iter().copied()),
                    ),
                ])
                .chain(pack_notice::receipt_fields(&travel.notices))
                .collect(),
        };
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

/// The born-with text `choice` lets travel with `entity`, read in the door's
/// one `txn` through the sharer's `lane` (FIX 3307): the target and each of
/// its birth's prompt rows only as that lane admits them, nothing a world in
/// `kept` holds, and only the fields `choice` names. Opting in lets admitted
/// text travel; it never admits a prompt row the sharer cannot read. Text
/// a copy carried from another vault fills a chosen field nothing here holds.
pub(crate) fn born_with_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lane: &crate::claim::ScopedRead<'_>,
    entity: &EntityId,
    made_by: Option<&MadeBy>,
    choice: &TravelChoice,
    kept: &BTreeSet<EntityId>,
) -> Result<BornWith> {
    let mut text = BornWith::new();
    let admitted = |row: &EntityId| -> Result<bool> {
        Ok(lane.entity_raw_live_in(txn, row)?.is_some()
            && (kept.is_empty()
                || !crate::settings::device_local_keeps_among(&vault.store, txn, kept, row)?))
    };
    if choice.born_with.is_empty() || !admitted(entity)? {
        return Ok(text);
    }
    let chosen = |field: BornWithField| choice.born_with.contains(&field);
    if chosen(BornWithField::Prompt) {
        let birth = match made_by {
            Some(_) => None,
            None => crate::provenance::birth::row_birth_in_txn(&vault.store, txn, entity)?,
        };
        let mut prompts = Vec::new();
        if let Some(made_by) = made_by.or(birth.as_ref().map(|birth| &birth.made_by)) {
            for input in &made_by.inputs {
                if input.role == MadeByInputRole::Prompt && admitted(&input.row)? {
                    prompts.push(input.row);
                }
            }
        }
        let prompt = prompts
            .iter()
            .filter_map(|row| vault.entity_live_text_in_txn(txn, row).ok())
            .map(|(prompt, _)| prompt)
            .filter(|prompt| !prompt.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        if !prompt.is_empty() {
            text.insert(BornWithField::Prompt, prompt);
        }
    }
    if (chosen(BornWithField::Why) || chosen(BornWithField::Keep))
        && let Ok((_, metadata)) = vault.entity_live_text_in_txn(txn, entity)
    {
        for (field, key) in [(BornWithField::Why, "why"), (BornWithField::Keep, "keep")] {
            if let Some(value) = metadata
                .get(key)
                .and_then(rmpv::Value::as_str)
                .filter(|value| chosen(field) && !value.trim().is_empty())
            {
                text.insert(field, value.to_owned());
            }
        }
    }
    if chosen(BornWithField::IntentPrompt)
        && let Some(intent) = vault.lens_intent_in_txn(txn, entity)?
        && !intent.prompt().trim().is_empty()
    {
        text.insert(BornWithField::IntentPrompt, intent.prompt().to_owned());
    }
    #[cfg(feature = "sync")]
    for (field, value) in crate::sync::selector::carried_born_with_in_txn(vault, txn, entity)? {
        if chosen(field) {
            text.entry(field).or_insert(value);
        }
    }
    Ok(text)
}

impl Vault {
    /// The text born with `entity`, read here: its birth's prompt rows (or
    /// `made_by`'s, for one version of a body), its `why` and `keep`, and a
    /// lens's intent prompt, and on a copy from another vault the text that
    /// travelled with it. Only the prose is read; the refs that point at it
    /// stay home. A part with no text document reads as absent, so a failed
    /// read sends less, never more. This is the owner's own read; text that
    /// goes to another party reads through [`Self::born_with_text_kept_off`].
    pub fn born_with_text(&self, entity: &EntityId, made_by: Option<&MadeBy>) -> Result<BornWith> {
        self.born_with_text_kept_off(entity, made_by, &BTreeSet::new())
    }

    /// [`Self::born_with_text`] for another party that reads nothing of a
    /// world kept off an unknown machine: a brief share's recipient, an
    /// artifact export's.
    pub(crate) fn born_with_text_for_another(
        &self,
        entity: &EntityId,
        made_by: Option<&MadeBy>,
    ) -> Result<BornWith> {
        let kept = {
            let txn = self.store.env.read_txn()?;
            crate::settings::device_local_worlds_at(
                self,
                &txn,
                crate::claim::CallerLocality::OffDevice,
            )?
        };
        self.born_with_text_kept_off(entity, made_by, &kept)
    }

    /// [`Self::born_with_text`] for a party the worlds in `kept` are kept off
    /// (DEC-0005): a row one of them holds, the body or a prompt row, gives
    /// that party no text.
    pub(crate) fn born_with_text_kept_off(
        &self,
        entity: &EntityId,
        made_by: Option<&MadeBy>,
        kept: &BTreeSet<EntityId>,
    ) -> Result<BornWith> {
        let mut text = BornWith::new();
        let birth = match made_by {
            Some(_) => None,
            None => self.row_birth(entity)?,
        };
        let mut prompts = Vec::new();
        if let Some(made_by) = made_by.or(birth.as_ref().map(|birth| &birth.made_by)) {
            prompts.extend(
                made_by
                    .inputs
                    .iter()
                    .filter(|input| input.role == MadeByInputRole::Prompt)
                    .map(|input| input.row),
            );
        }
        if !kept.is_empty() {
            let txn = self.store.env.read_txn()?;
            let keeps = |row: &EntityId| {
                crate::settings::device_local_keeps_among(&self.store, &txn, kept, row)
            };
            if keeps(entity)? {
                return Ok(text);
            }
            let mut sent = Vec::with_capacity(prompts.len());
            for row in prompts {
                if !keeps(&row)? {
                    sent.push(row);
                }
            }
            prompts = sent;
        }
        let prompt = prompts
            .iter()
            .filter_map(|row| self.entity_text(row).ok())
            .filter(|prompt| !prompt.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        if !prompt.is_empty() {
            text.insert(BornWithField::Prompt, prompt);
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
        // A copy from another vault reads the text its sharer let travel with
        // it, where nothing here holds that field.
        #[cfg(feature = "sync")]
        for (field, value) in crate::sync::selector::carried_born_with(self, entity)? {
            text.entry(field).or_insert(value);
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
        self.record_travel(
            ExportTarget::Artifact {
                artifact_ref,
                version,
            },
            content_hash,
            by,
            born_with,
            Vec::new(),
            false,
        )
    }

    /// Record one travelling AgentPack's share receipt, with the knowledge
    /// it kept home and the owner's notices for his own export (FIX 5493),
    /// on the same terms as [`Self::record_export_travel`]; for the owner's
    /// own export (`owner_export`) a failed write never fails his share
    /// (FIX 5523).
    #[expect(
        clippy::too_many_arguments,
        reason = "one receipt row's fields, each the export door's own"
    )]
    pub(crate) fn record_agent_pack_travel(
        &self,
        agent: &EntityId,
        version: String,
        content_hash: String,
        by: &EntityId,
        born_with: &BornWith,
        omitted: Vec<OmittedKnowledge>,
        notices: Vec<WorldRecipientNotice>,
        owner_export: bool,
    ) -> Result<()> {
        self.record_travel(
            ExportTarget::AgentPack {
                agent_ref: agent.to_hex(),
                version,
                omitted,
            },
            content_hash,
            by,
            born_with,
            notices,
            owner_export,
        )
    }

    /// Writes one travel receipt, after the owner share receipts an earlier
    /// failed write queued here (FIX 5523). The owner's own agent-pack share
    /// never fails on its receipt: a failed write warns and queues it for
    /// this vault's next travel receipt. Any other export is served without
    /// its receipt only when no born-with text left with it.
    fn record_travel(
        &self,
        target: ExportTarget,
        content_hash: String,
        by: &EntityId,
        born_with: &BornWith,
        notices: Vec<WorldRecipientNotice>,
        owner_export: bool,
    ) -> Result<()> {
        let owner_export = owner_export && matches!(target, ExportTarget::AgentPack { .. });
        let travel = ExportTravel {
            at: self.store.clock.now_recorded_at(),
            target,
            content_hash,
            by: by.to_hex(),
            travelled: born_with.keys().copied().collect(),
            notices,
        };
        self.retry_owner_export_receipts();
        match self.append_export_travel(&travel) {
            Err(error) if owner_export => {
                tracing::warn!(
                    %error,
                    "owner export served without its travel receipt; queued for one retry"
                );
                self.owner_export_receipts().push(travel);
                Ok(())
            }
            Err(error) if travel.travelled.is_empty() => {
                tracing::warn!(%error, "export served without its travel receipt");
                Ok(())
            }
            other => other,
        }
    }

    /// Appends `travel` as the next export travel receipt in its own write,
    /// its sequence assigned as it is written.
    fn append_export_travel(&self, travel: &ExportTravel) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let sequence = match EXPORT_TRAVEL.iter_rev_from(&self.store, txn, &[])?.next() {
                None => 0,
                Some(row) => row?
                    .0
                    .checked_add(1)
                    .ok_or(crate::Error::IndexOverflow("export travel sequence"))?,
            };
            EXPORT_TRAVEL.put(&self.store, txn, &sequence, travel)
        })
    }

    /// Writes each owner share receipt a failed write queued (FIX 5523), up
    /// to [`OWNER_EXPORT_RECEIPT_RETRY_COUNT`] times, each in its own write,
    /// and drops it either way: a failure warns and never reaches the
    /// travel that retried it. The queue is taken whole and released before
    /// any write.
    fn retry_owner_export_receipts(&self) {
        let pending = std::mem::take(&mut *self.owner_export_receipts());
        for travel in pending {
            let mut written = Ok(());
            for _ in 0..OWNER_EXPORT_RECEIPT_RETRY_COUNT {
                written = self.append_export_travel(&travel);
                if written.is_ok() {
                    break;
                }
            }
            if let Err(error) = written {
                tracing::warn!(
                    %error,
                    "owner export travel receipt failed its retry and was dropped"
                );
            }
        }
    }

    /// This open vault's queued owner share receipts (FIX 5523); a poisoned
    /// lock still holds its queue.
    fn owner_export_receipts(&self) -> std::sync::MutexGuard<'_, Vec<ExportTravel>> {
        self.pending_owner_export_receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
