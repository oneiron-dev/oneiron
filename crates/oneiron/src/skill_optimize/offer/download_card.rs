//! Exact managed-worker download cards in the existing owner inbox.
//! A recorded card is not a read receipt. Only the inbox's own Seen/Acked
//! mark for a current Owner counts as having shown these files and terms.

use serde::{Deserialize, Serialize};

use super::{OfferCandidate, pending_training_offer_in_txn};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::skill_optimize::offer_pilot::{model_offer_licence, model_offer_pin};
use crate::{EntityId, Error, Result, Vault};
use oneiron_model::llm::ModelId;

const PRODUCER: &str = "coach.stock_download_card";

/// One actual file from the managed worker's validated artifact manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StockDownloadFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Native file and licence facts, not a caller's download-needed flag.
/// The repository and full revision locate the licence file's exact text;
/// its hash is in `files`, beside every file the worker would load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StockDownloadCard {
    pub model: String,
    pub manifest_sha256: String,
    pub repository: String,
    pub revision: String,
    pub licence: String,
    pub licence_file: String,
    pub files: Vec<StockDownloadFile>,
}

impl StockDownloadCard {
    fn source(&self, owner: EntityId) -> Result<NotificationSource> {
        let detail = serde_json::to_string_pretty(self)
            .map_err(|_| Error::InvariantViolation("stock download card encoding"))?;
        let digest = blake3::hash(detail.as_bytes()).to_hex();
        Ok(NotificationSource {
            producer: PRODUCER.to_owned(),
            event: format!("{digest}:{}", owner.to_hex()),
            result: Some(self.manifest_sha256.clone()),
            detail: Some(detail),
            ..NotificationSource::default()
        })
    }
}

/// Publish the actual captured worker's file/licence card for a pending
/// stock offer. Repeated offers of the same files reuse the same inbox row
/// and its marks. A changed file, licence, revision or model gets a new row.
/// No download, approval, switch or read mark is performed here.
///
/// # Errors
/// Storage errors or a card that does not encode. A stale or mismatched
/// offer simply publishes nothing; its ordinary manual path stays intact.
pub fn record_stock_download_card(
    vault: &Vault,
    offer: &EntityId,
    card: &StockDownloadCard,
    at: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let Some(offer) = pending_training_offer_in_txn(vault, txn, offer)? else {
            return Ok(());
        };
        let OfferCandidate::Stock {
            model,
            licence,
            source,
        } = &offer.candidate
        else {
            return Ok(());
        };
        if card.model != model.model || card.licence != *licence {
            return Ok(());
        }
        let id = ModelId::new(model.model.clone())
            .map_err(|_| Error::InvalidConfig("the stock model id does not parse".into()))?;
        let Some(row) = vault.model_registry_row_in_txn(txn, &id)? else {
            return Ok(());
        };
        if row.is_stale()
            || model_offer_pin(&row)
                .is_none_or(|(pin, backend)| pin != *model || backend != *source)
            || model_offer_licence(&row).as_deref() != Some(licence.as_str())
        {
            return Ok(());
        }
        for owner in crate::policy_model::owners_in_txn(vault, txn)? {
            vault.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Finding,
                    source: card.source(owner)?,
                    subject_refs: vec![offer.id],
                    recipient: Some(owner),
                    created_at: at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    })
}

/// Whether a current Owner has marked this exact native card Seen/Acked.
/// Merely listing or publishing the row never satisfies this reader. The
/// caller must construct `card` from the current worker manifest again;
/// this historical mark grants no model, policy or download authority.
///
/// # Errors
/// Storage errors or a card that does not encode.
pub fn stock_download_card_seen(vault: &Vault, card: &StockDownloadCard) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    stock_download_card_seen_in_txn(vault, &txn, card)
}

pub(in crate::skill_optimize) fn stock_download_card_seen_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &StockDownloadCard,
) -> Result<bool> {
    for owner in crate::policy_model::owners_in_txn(vault, txn)? {
        if vault.notification_seen_in_txn(txn, &card.source(owner)?, &owner)? == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Vault {
    /// The native card receipt in a trusted host's already-open decision
    /// snapshot. Only the inbox's own current-Owner Seen/Acked mark counts.
    pub fn stock_download_card_seen_in_snapshot(
        &self,
        txn: &heed::RoTxn<'_>,
        card: &StockDownloadCard,
    ) -> Result<bool> {
        stock_download_card_seen_in_txn(self, txn, card)
    }
}
