//! The inputs and answers of the owner's root-request rows: the cancel
//! (FIX 5586), `vault.roots.requests.cancel`, a host door over the one
//! engine door `POST /v1/owner/roots/requests/cancel` already reaches,
//! [`Vault::cancel_root_request`] (#3261, FIX 4739); and its siblings (FIX
//! 5598): `vault.roots.requests.create` over [`Vault::request_root_change`]
//! (`POST /v1/owner/roots/requests`), `vault.roots.requests.list` over
//! [`Vault::pending_root_requests`] (`GET /v1/owner/roots/requests`) and
//! `vault.owner_work.get` over [`Vault::owner_work_receipt`]
//! (`GET /v1/owner/owner-work/{request}`). A server hands each the owner's
//! in-request proof, as `/v1/owner` takes it, and where his say-so reached
//! this install, for the act's audit record only; an embedded handle
//! answers as its own owner, on this install. Ids only: no seed, piece,
//! passphrase, enrolment code or carry list is asked for; the material a
//! change needs stays on the target's own route
//! (`POST /v1/owner/roots/requests/run`). They add no state, no gate and no
//! rule of their own, and the routes are unchanged.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{ActSurface, RecoveryRootId, RootChange, authority_log_entity_id_from_hash};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};
use crate::secret_custody::CustodyManifestCheck;
use crate::world_keys::OwnerWorkReceipt;

/// One owner work receipt with the holder's manifest judgment as a surface
/// shows it (FIX 5446): the receipt (ids only) and, for a custody register
/// whose result carries one, the words for what its holder checked.
/// Reporting only: an unchecked registration stays accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerWorkReceiptView {
    #[serde(flatten)]
    pub receipt: OwnerWorkReceipt,
    /// `CustodyManifestCheck::Judged(check).text()`, when the receipt's
    /// `manifest_check` names one; `None` before the result, and for any
    /// other work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_text: Option<String>,
}

impl From<OwnerWorkReceipt> for OwnerWorkReceiptView {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        let manifest_text = receipt
            .manifest_check
            .clone()
            .map(|check| CustodyManifestCheck::Judged(check).text());
        Self {
            receipt,
            manifest_text,
        }
    }
}

/// One owner work receipt as a surface shows it: the receipt (ids only),
/// the engine's words for where it stands, and, when no install could be
/// named, the engine's words for why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OwnerWorkView {
    #[serde(flatten)]
    pub receipt: OwnerWorkReceipt,
    /// The words for the holder's manifest judgment, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_text: Option<String>,
    /// `OwnerWorkStatus::text`: "recorded, awaiting a holder", "enacted by
    /// its holder", "refused by its holder", "cancelled by the owner" or
    /// "superseded by a newer request on its target".
    pub status_text: String,
    /// `OwnerWorkUnassigned::text`, when nothing was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unassigned_text: Option<String>,
    /// `OwnerWorkStatus::advice`, when a refusal names what the owner may do
    /// next: a root request whose target may not have synced (FIX 4738).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advice_text: Option<String>,
    /// `BundleHomeWarning::text`, when a publication's home may keep no
    /// sealed copy (FIX 4786).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_warning_text: Option<String>,
    /// `OwnerWorkCancelState::text`, when the owner cancelled a root request:
    /// "cancelled", or that its target answered it first, "already enacted"
    /// (FIX 4739).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_text: Option<String>,
    /// The check-in decision a root request `vault.roots.requests.create`
    /// recorded ran on (2k3): the Owner on their own proof, and the approved
    /// check-in of another asker it applied, with its requester. `None` for
    /// every other answer, and when nothing was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}

impl From<OwnerWorkReceipt> for OwnerWorkView {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        let OwnerWorkReceiptView {
            receipt,
            manifest_text,
        } = OwnerWorkReceiptView::from(receipt);
        let status_text = receipt.status.text().to_owned();
        let unassigned_text = receipt.unassigned.map(|why| why.text().to_owned());
        let advice_text = receipt.status.advice().map(str::to_owned);
        let home_warning_text = receipt
            .home_warning
            .as_ref()
            .map(|warning| warning.text().to_owned());
        let cancel_text = receipt
            .cancel
            .as_ref()
            .map(|cancel| cancel.state.text().to_owned());
        Self {
            receipt,
            manifest_text,
            status_text,
            unassigned_text,
            advice_text,
            home_warning_text,
            cancel_text,
            check_in: None,
        }
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::root_requests::{
    OwnerWorkGetRequest, RootChangeView, RootRequestCancelRequest, RootRequestCreateRequest,
};

/// `vault.roots.requests.cancel`: records the owner's cancel of one root
/// request through [`Vault::cancel_root_request`], from any surface he is
/// authenticated on; `surface` is audit only. It takes effect on the target
/// whenever the target syncs it, offline or not. The answer is the request's
/// receipt: cancelled, or the answer its target gave first, which stands,
/// with the cancel marked so. A cancel the fold already holds records
/// nothing again.
///
/// # Errors
///
/// `BAD_REQUEST` for a `request` that is not 64 lower-case hex; the engine's
/// refusal for a request this install folds as no root request (nothing is
/// written); a stale owner proof; an install that cannot carry the act;
/// storage errors.
pub fn cancel_root_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: RootRequestCancelRequest,
) -> MemoryResult<OwnerWorkReceipt> {
    let request = request_entry(&input.request)?;
    Ok(vault.cancel_root_request(owner, surface, request)?)
}

impl From<RootChange> for RootChangeView {
    fn from(change: RootChange) -> Self {
        let machine = match change {
            RootChange::Anchor { machine, .. } => Some(machine.to_hex()),
            RootChange::Pin { .. } | RootChange::Activate | RootChange::Restore { .. } => None,
        };
        Self {
            change: change.as_str().to_owned(),
            root: change
                .root()
                .map(|root| crate::entity_id::bytes_to_hex_lower(&root.0)),
            machine,
        }
    }
}

/// One root request naming this install with no result yet, as
/// `vault.roots.requests.list` answers it: its change and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingRootRequestView {
    pub change: RootChangeView,
    pub receipt: OwnerWorkView,
}

/// `vault.roots.requests.create` (FIX 5598): records the owner's root change
/// for the target install through [`Vault::request_root_change`], from any
/// surface he is authenticated on; `surface` is audit only. The answer is
/// the request's receipt: "recorded, awaiting a holder" until the target
/// makes the change, or, for a target this install cannot name (itself, or
/// one not linked), why nothing was written. A recorded request answers the
/// check-in decision it ran on; with `check_in_ref` the Owner applies an
/// asker's approved check-in for this change (2k3; P25-SHAPE Q1 = A).
///
/// # Errors
///
/// `BAD_REQUEST` for a malformed target, root, machine or `check_in_ref`,
/// or a change that is not pin, restore (each with root), anchor (with root
/// and machine) or activate (with neither); a stale owner proof; a check-in
/// that does not apply to a recorded request (a target this install cannot
/// name records nothing, so it answers no decision and spends no check-in);
/// storage errors.
pub fn create_root_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: RootRequestCreateRequest,
) -> MemoryResult<OwnerWorkView> {
    let target = EntityId::from_hex(&input.target)
        .map_err(|_| MemoryError::bad_request("target must be 32 hex"))?;
    let change = root_change(&input)?;
    let check_in_ref = super::shared::check_in_ref(input.check_in_ref.as_deref())?;
    let (receipt, check_in) =
        vault.request_root_change_with_check_in(owner, surface, target, change, check_in_ref)?;
    Ok(OwnerWorkView {
        check_in,
        ..OwnerWorkView::from(receipt)
    })
}

/// `vault.roots.requests.list` (FIX 5598): the root requests naming this
/// install with no result yet, ascending by entry, but those the owner
/// cancelled or a newer request superseded, through
/// [`Vault::pending_root_requests`]. Ids only.
///
/// # Errors
///
/// A stale owner proof; storage errors.
pub fn list_root_requests_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<PendingRootRequestView>> {
    Ok(vault
        .pending_root_requests(owner)?
        .into_iter()
        .map(|(_, change, receipt)| PendingRootRequestView {
            change: change.into(),
            receipt: receipt.into(),
        })
        .collect())
}

/// `vault.owner_work.get` (FIX 5598): the receipt of the owner work request
/// signed as entry `request`, as this install's fold stands, through
/// [`Vault::owner_work_receipt`].
///
/// # Errors
///
/// `BAD_REQUEST` for a `request` that is not 64 lower-case hex; `NOT_FOUND`
/// when this install folds no such request; a stale owner proof; storage
/// errors.
pub fn owner_work_receipt_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &OwnerWorkGetRequest,
) -> MemoryResult<OwnerWorkView> {
    let request = request_entry(&input.request)?;
    vault
        .owner_work_receipt(owner, request)?
        .map(OwnerWorkView::from)
        .ok_or_else(|| {
            MemoryError::not_found(format!(
                "this install folds no owner work request {}",
                input.request
            ))
        })
}

/// The rows every pending root request's receipt names, ascending.
#[must_use]
pub fn pending_root_request_rows(pending: &[PendingRootRequestView]) -> Vec<EntityId> {
    let mut rows: Vec<EntityId> = pending
        .iter()
        .flat_map(|view| root_request_receipt_rows(&view.receipt.receipt))
        .collect();
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// The change `input` names, each field present exactly when the change
/// states it, as the route reads it.
fn root_change(input: &RootRequestCreateRequest) -> MemoryResult<RootChange> {
    let root = input
        .root
        .as_deref()
        .map(|root| {
            entry_hash(root)
                .map(RecoveryRootId)
                .ok_or_else(|| MemoryError::bad_request("root must be 64 lower-case hex"))
        })
        .transpose()?;
    let machine = input
        .machine
        .as_deref()
        .map(|machine| {
            EntityId::from_hex(machine)
                .map_err(|_| MemoryError::bad_request("machine must be 32 hex"))
        })
        .transpose()?;
    Ok(match (input.change.as_str(), root, machine) {
        ("pin", Some(root), None) => RootChange::Pin { root },
        ("activate", None, None) => RootChange::Activate,
        ("restore", Some(root), None) => RootChange::Restore { root },
        ("anchor", Some(root), Some(machine)) => RootChange::Anchor { root, machine },
        _ => {
            return Err(MemoryError::bad_request(
                "a root change is pin, restore (each with root), anchor (with root and \
                 machine) or activate (with neither)",
            ));
        }
    })
}

/// The AUTHORITY_LOG rows a cancel's receipt names, which its listing
/// names: the request's own entry and each cancel's, ascending.
#[must_use]
pub fn root_request_receipt_rows(receipt: &OwnerWorkReceipt) -> Vec<EntityId> {
    let cancels = receipt.cancel.iter().flat_map(|note| note.entries.iter());
    let mut rows: Vec<EntityId> = receipt
        .request
        .iter()
        .chain(cancels)
        .filter_map(|hex| entry_hash(hex))
        .filter_map(|hash| authority_log_entity_id_from_hash(&hash).ok())
        .collect();
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// A request's entry as the route takes it: 64 lower-case hex.
fn request_entry(text: &str) -> MemoryResult<[u8; 32]> {
    entry_hash(text).ok_or_else(|| MemoryError::bad_request("request must be 64 lower-case hex"))
}

/// 32 bytes from 64 lower-case ASCII hex digits.
fn entry_hash(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
