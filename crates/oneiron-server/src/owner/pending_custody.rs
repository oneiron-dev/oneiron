//! A restore's credentials pending on their source's evidence, and the
//! owner's one typed confirm that keeps a whole batch without it (FIX-LIST
//! 10671 (b), 11158): shared by `/v1/owner/secrets/custody/pending` and
//! `oneiron secrets pending`. Each batch carries a generic owner card a
//! surface may show in its own words: what waits, that the custody passes
//! recheck it on their own, and the one action that keeps it. Nothing here
//! reads a value, and the confirm is an ask, never a block.

use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    PendingCredentialBatch, PendingCredentialConfirmation, PendingCredentialReleaseReceipt,
};
use serde::Serialize;

use super::{OwnerError, OwnerResult, entity_id};

/// The owner route that takes the confirm.
const KEEP_ROUTE: &str = "POST /v1/owner/secrets/custody/pending";

/// Every batch, and what the owner may confirm.
#[derive(Debug, Serialize)]
pub(crate) struct PendingPage {
    batches: Vec<BatchView>,
}

/// One restore's batch: what waits on its source, and the receipt of the
/// confirm that kept it, if one did.
#[derive(Debug, Serialize)]
struct BatchView {
    /// The batch, as 32 hex.
    batch: String,
    pending: Vec<CardView>,
    released: Option<ReceiptView>,
    /// The one typed confirm `POST` takes for this batch while any waits.
    confirm: Option<&'static str>,
    /// What a surface shows the owner for this batch.
    card: OwnerCard,
}

/// One pending credential, by handle.
#[derive(Debug, Serialize)]
struct CardView {
    handle: String,
    generation: u32,
}

/// A released batch's receipt.
#[derive(Debug, Serialize)]
pub(crate) struct ReceiptView {
    batch: String,
    /// The owner who confirmed, as 32 hex; absent once his identity is erased.
    by: Option<String>,
    at: u64,
    confirmation: &'static str,
    /// The owner's election, never a check of the source.
    note: &'static str,
    outcomes: Vec<OutcomeView>,
}

/// What one credential came to: `readable`, `still_unavailable`, `erased`,
/// `superseded` or `pending`.
#[derive(Debug, Serialize)]
struct OutcomeView {
    handle: String,
    generation: u32,
    result: &'static str,
}

/// A generic owner card: a headline, a body in plain words, and the one
/// action it offers, if any. A surface may word it its own way.
#[derive(Debug, Serialize)]
struct OwnerCard {
    /// `pending_custody`.
    kind: &'static str,
    headline: String,
    body: &'static str,
    action: Option<CardAction>,
}

/// The card's one action: the typed confirm, the route that takes it and
/// the command that takes it on a stopped vault.
#[derive(Debug, Serialize)]
struct CardAction {
    label: &'static str,
    confirm: &'static str,
    route: &'static str,
    command: String,
}

/// What a batch's card says while credentials wait on their source.
const WAITING_BODY: &str = "This restore saved these credentials pending their source's \
     evidence. The custody passes recheck each one on their own, on upkeep, on the served tick \
     and when the vault opens: a credential lands once its source reads clear and its value \
     opens under its key, waits while the source does not read, and stays withheld when the \
     source names an erase. If the source is gone for good, you may keep the batch as the backup \
     carried it. That is your election, not a check of the source; a value that never opens \
     must be re-entered or reissued.";

/// What a batch's card says once the owner kept it and nothing waits.
const KEPT_BODY: &str = "You kept this batch without its source's evidence. Each outcome says \
     what a credential came to; one still unavailable must be re-entered or reissued.";

/// What a batch's card says when nothing waits and the owner kept nothing.
const SETTLED_BODY: &str = "The custody passes settled every credential of this batch against \
     its source; nothing waits.";

impl From<PendingCredentialReleaseReceipt> for ReceiptView {
    fn from(receipt: PendingCredentialReleaseReceipt) -> Self {
        Self {
            batch: receipt.batch.to_hex(),
            by: receipt.by.map(|by| by.to_hex()),
            at: receipt.at,
            confirmation: receipt.confirmation.as_str(),
            note: receipt.note(),
            outcomes: receipt
                .outcomes
                .into_iter()
                .map(|outcome| OutcomeView {
                    handle: outcome.handle,
                    generation: outcome.generation,
                    result: outcome.result.as_str(),
                })
                .collect(),
        }
    }
}

impl From<PendingCredentialBatch> for BatchView {
    fn from(batch: PendingCredentialBatch) -> Self {
        let id = batch.batch.to_hex();
        let waiting = batch.pending.len();
        let confirm = PendingCredentialConfirmation::KeepWithoutSource.as_str();
        Self {
            confirm: (waiting > 0).then_some(confirm),
            card: OwnerCard::of(&id, waiting, batch.released.is_some()),
            pending: batch
                .pending
                .into_iter()
                .map(|card| CardView {
                    handle: card.handle,
                    generation: card.generation,
                })
                .collect(),
            released: batch.released.map(ReceiptView::from),
            batch: id,
        }
    }
}

impl OwnerCard {
    /// The card of batch `id`, with `waiting` credentials pending on their
    /// source and, when `kept`, the owner's confirm on record.
    fn of(id: &str, waiting: usize, kept: bool) -> Self {
        let confirm = PendingCredentialConfirmation::KeepWithoutSource.as_str();
        let (headline, body) = match (waiting, kept) {
            (0, true) => (
                "Restored credentials kept without their source".to_owned(),
                KEPT_BODY,
            ),
            (0, false) => ("Restored credentials settled".to_owned(), SETTLED_BODY),
            (waiting, _) => (
                format!("{waiting} restored credential(s) wait on their source"),
                WAITING_BODY,
            ),
        };
        Self {
            kind: "pending_custody",
            headline,
            body,
            action: (waiting > 0).then(|| CardAction {
                label: "Keep without the source",
                confirm,
                route: KEEP_ROUTE,
                command: format!("oneiron secrets pending --keep {id} --confirm {confirm}"),
            }),
        }
    }
}

/// Each restore batch whose credentials wait on their source's evidence, by
/// handle, and each batch an owner kept, with its receipt and its card.
pub(crate) fn page(vault: &oneiron::Vault, owner: &AuthenticatedOwner) -> OwnerResult<PendingPage> {
    let batches = vault.pending_credential_batches_as_owner(owner)?;
    Ok(PendingPage {
        batches: batches.into_iter().map(BatchView::from).collect(),
    })
}

/// Keeps every credential `batch` (32 hex) holds pending on its source's
/// evidence as the image carried it, on the typed `confirm`, and returns the
/// batch's receipt; a repeat returns it.
pub(crate) fn keep(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    batch: &str,
    confirm: &str,
) -> OwnerResult<ReceiptView> {
    let batch = entity_id("batch", batch)?;
    let confirmation = PendingCredentialConfirmation::parse(confirm)
        .ok_or_else(|| OwnerError::Invalid("confirm must be keep_without_source".into()))?;
    Ok(vault
        .release_pending_credential_batch_as_owner(
            owner,
            &batch,
            confirmation,
            vault.now_recorded_at(),
        )?
        .into())
}
