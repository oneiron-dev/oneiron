//! Paged plugin reads: the pending-proposal list and the page shapes the
//! durable block reads answer with. Every page reports truthful counts for
//! its read snapshot and an explicit end; a positive requested size is served
//! in full through internal work pages, never clamped.
use super::super::paging::{BoardPageCursor, decode_page_cursor, encode_page_cursor, page_binding};
use super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::errors::{PluginResult, PluginSectionError};
use super::render::{PluginProposalRow, PluginSectionSnapshot};
use super::state::BoardBlockRecord;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// Rows one emitted proposal page holds when the caller names no size. A page
/// size, not a cap: a larger positive request is served in full.
pub const PLUGIN_PROPOSAL_PAGE_DEFAULT: usize = 256;

/// Pending consents read per internal work page.
const CONSENT_WORK_PAGE: usize = 1_000;

/// One page of pending plugin-section proposals, oldest consent first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginProposalPage {
    pub rows: Vec<PluginProposalRow>,
    /// Every matching pending proposal in this read snapshot, across pages.
    pub matching_total: u64,
    /// Matching proposals after this page's last row.
    pub remaining: u64,
    /// The cursor for the next page; `None` exactly when `end`.
    pub next_cursor: Option<String>,
    pub end: bool,
}

/// One page of this actor's durable blocks under one section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardBlockPage {
    pub rows: Vec<BoardBlockRecord>,
    /// Every block of this actor under the section in this read snapshot.
    pub total: u64,
    /// Blocks after this page's last row.
    pub remaining: u64,
    /// The cursor for the next page; `None` exactly when `end`.
    pub next_cursor: Option<String>,
    pub end: bool,
}

/// A block page projected for the renderer, with the same counts and end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginSectionSnapshotPage {
    pub snapshot: PluginSectionSnapshot,
    pub total: u64,
    pub remaining: u64,
    pub next_cursor: Option<String>,
    pub end: bool,
}

/// One page of every STILL-PENDING plugin-section install, in consent
/// sequence order.
///
/// The first page fences the pending-consent sequence at its high-water; the
/// cursor carries that fence, the last emitted sequence and a binding to
/// `caller`. Each page walks the whole fenced consent set in 1,000-row work
/// pages, filters to live proposals BEFORE choosing its rows, and counts the
/// complete matching set, so unrelated pending work never hides a proposal.
/// `limit` defaults to [`PLUGIN_PROPOSAL_PAGE_DEFAULT`]; zero reads as one.
///
/// A projection only: it mints nothing, stores nothing, and is not install
/// authority. A pending row whose payload or manifest does not strictly
/// decode is skipped and never counted, so one corrupt claim cannot blank
/// the list.
///
/// # Errors
///
/// [`PluginSectionError::MalformedCursor`] for a cursor this caller's list did
/// not mint, and storage errors.
pub fn pending_plugin_proposal_page(
    vault: &Vault,
    caller: EntityId,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> PluginResult<PluginProposalPage> {
    let binding = page_binding(PREDICATE_PLUGIN_SECTION_INSTALL, &[caller.as_bytes()]);
    proposal_page(
        vault,
        &binding,
        cursor,
        limit.unwrap_or(PLUGIN_PROPOSAL_PAGE_DEFAULT).max(1),
    )
}

/// The first `limit` pending proposals, in consent sequence order, through
/// the same paged walk as [`pending_plugin_proposal_page`].
///
/// # Errors
///
/// Storage errors.
pub fn pending_plugin_proposal_rows(
    vault: &Vault,
    limit: usize,
) -> PluginResult<Vec<PluginProposalRow>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let binding = page_binding(PREDICATE_PLUGIN_SECTION_INSTALL, &[]);
    Ok(proposal_page(vault, &binding, None, limit)?.rows)
}

fn proposal_page(
    vault: &Vault,
    binding: &[u8; 32],
    cursor: Option<&str>,
    limit: usize,
) -> PluginResult<PluginProposalPage> {
    let resume = cursor
        .map(|token| {
            decode_page_cursor(binding, token)
                .and_then(|cursor| {
                    let after = <[u8; 8]>::try_from(cursor.after.as_slice()).ok()?;
                    Some((cursor.fence?, u64::from_be_bytes(after)))
                })
                .ok_or(PluginSectionError::MalformedCursor)
        })
        .transpose()?;
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(crate::error::Error::from)?;
    let mut page = PluginProposalPage {
        rows: Vec::new(),
        matching_total: 0,
        remaining: 0,
        next_cursor: None,
        end: true,
    };
    let fence = match resume {
        Some((fence, _)) => fence,
        None => match vault.store.pending_gate_consents_high_water_in_txn(&rtxn)? {
            Some(fence) => fence,
            None => return Ok(page),
        },
    };
    let emitted_after = resume.map(|(_, after)| after);
    let mut last_emitted = None;
    let mut input_after = None;
    loop {
        let input = vault.store.pending_gate_consents_page_in_txn(
            &rtxn,
            input_after,
            Some(fence),
            CONSENT_WORK_PAGE,
        )?;
        let Some(&(last_read, _)) = input.last() else {
            break;
        };
        let full = input.len() == CONSENT_WORK_PAGE;
        for (sequence, pending) in input {
            let Some(row) = live_proposal_row(vault, &rtxn, pending.claim_id)? else {
                continue;
            };
            page.matching_total += 1;
            if emitted_after.is_some_and(|after| sequence <= after) {
                continue;
            }
            if page.rows.len() < limit {
                page.rows.push(row);
                last_emitted = Some(sequence);
            } else {
                page.remaining += 1;
            }
        }
        if !full {
            break;
        }
        input_after = Some(last_read);
    }
    if page.remaining > 0
        && let Some(last) = last_emitted
    {
        page.next_cursor = Some(encode_page_cursor(
            binding,
            &BoardPageCursor {
                fence: Some(fence),
                after: last.to_be_bytes().to_vec(),
            },
        ));
        page.end = false;
    }
    Ok(page)
}

/// The proposal row for one pending consent, when its claim is a live,
/// still-proposed plugin-section install whose payload strictly decodes.
fn live_proposal_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    claim_id: [u8; 16],
) -> PluginResult<Option<PluginProposalRow>> {
    let Ok(claim_id) = EntityId::from_bytes(claim_id) else {
        return Ok(None);
    };
    let Some(body) = vault.get_claim_in_txn(rtxn, &claim_id)? else {
        return Ok(None);
    };
    // A pending row survives only while the claim is genuinely awaiting an
    // owner: an approved, retracted, or superseded body has already been
    // decided and must not keep asking.
    if body.predicate != PREDICATE_PLUGIN_SECTION_INSTALL
        || body.approval != ClaimApprovalStatus::Proposed
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
    {
        return Ok(None);
    }
    let Ok(payload) = PluginInstallClaimPayload::from_value(&body.value) else {
        return Ok(None);
    };
    let Ok(envelope) = payload.manifest() else {
        return Ok(None);
    };
    Ok(Some(PluginProposalRow {
        install_claim_id: claim_id,
        origin: payload.origin,
        pack_id: envelope.manifest.provenance.pack_id,
        section_id: payload.section_id,
        label: envelope.manifest.name,
        awaiting_owner_consent: true,
    }))
}
