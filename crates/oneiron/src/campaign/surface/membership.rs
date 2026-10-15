//! Read-only membership projection over CA-01 heads and CA-02 event history.

use crate::campaign::claims::{PREDICATE_CAMPAIGN_MEMBER, decode_campaign_member_value};
use crate::claim::{ClaimLifecycleStatus, ClaimSubject};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::saved_query::{MembershipEvent, MembershipTransition, membership_events};
use crate::{EntityId, Vault};

/// Page size used when a caller passes `limit = 0`.
pub const MEMBERSHIP_PAGE_DEFAULT_LIMIT: u32 = 50;

/// Hard ceiling on one membership page.
pub const MEMBERSHIP_PAGE_MAX_LIMIT: u32 = 200;

/// One page request against a campaign's or a query's membership.
///
/// `owner_ref` is the CAMPAIGN for [`read_campaign_members`] and the
/// SAVED_QUERY for [`read_saved_query_members`]. `at_epoch`, when present,
/// reads the cohort as of that membership epoch — the bitemporal read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipReadRequest {
    /// The campaign or saved query whose membership is being paged.
    pub owner_ref: EntityId,
    /// Opaque cursor from a prior page's `next_cursor`.
    pub cursor: Option<String>,
    /// Requested page size; `0` means [`MEMBERSHIP_PAGE_DEFAULT_LIMIT`] and
    /// anything above [`MEMBERSHIP_PAGE_MAX_LIMIT`] is clamped to it.
    pub limit: u32,
    /// Optional epoch ceiling; events after it are not folded into the row.
    pub at_epoch: Option<u64>,
}

/// One entity's membership, folded from its entered/exited history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRow {
    /// The member.
    pub entity_ref: EntityId,
    /// `entered` or `exited` — the direction of the newest folded event.
    pub state: String,
    /// Valid time of the newest `entered` event.
    pub entered_valid: u64,
    /// Detection time of the newest `entered` event.
    pub entered_detected: u64,
    /// Valid time of the newest `exited` event, when the row is currently out.
    pub exited_valid: Option<u64>,
    /// Detection time of the newest `exited` event, when the row is currently
    /// out.
    pub exited_detected: Option<u64>,
    /// `data_change`, `scope_change`, or `definition_change`, exactly as CA-02
    /// produced it for the newest folded event.
    pub cause: Option<String>,
}

/// One page of membership rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipPage {
    /// Rows in stable cursor order: the order of their head claims' ids.
    pub rows: Vec<MembershipRow>,
    /// Cursor for the next page; `None` when the page is the last one. A
    /// page reads a bounded run of claims, so it may hold fewer rows than
    /// asked for, or none, and still carry a cursor.
    pub next_cursor: Option<String>,
}

/// Pages a campaign's cohort.
///
/// Read-only by construction: it opens no write transaction, mints no claim, and
/// enqueues no attempt. The cohort is CA-01's live `campaign.member` heads, and
/// each row's bitemporal fields come from CA-02's entered/exited event history
/// for the `(source query, entity)` pair the head names — so the projection
/// reports exactly what the enrollment writer recorded and nothing it inferred.
///
/// # Errors
///
/// Storage and decode errors propagate; a malformed cursor is
/// [`Error::InvalidKey`].
pub fn read_campaign_members(vault: &Vault, req: &MembershipReadRequest) -> Result<MembershipPage> {
    membership_page(vault, req, MembershipOwner::Campaign)
}

/// Pages the membership one saved query derived.
///
/// The query-side twin of [`read_campaign_members`], with the same read-only
/// guarantee and the same event source; only the filter axis differs.
///
/// # Errors
///
/// Storage and decode errors propagate; a malformed cursor is
/// [`Error::InvalidKey`].
pub fn read_saved_query_members(
    vault: &Vault,
    req: &MembershipReadRequest,
) -> Result<MembershipPage> {
    membership_page(vault, req, MembershipOwner::SavedQuery)
}

/// Which axis of a `campaign.member` head `owner_ref` selects on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipOwner {
    /// `owner_ref` is the CAMPAIGN the head is scoped to.
    Campaign,
    /// `owner_ref` is the SAVED_QUERY the head was derived from.
    SavedQuery,
}

/// One `(entity, query, campaign)` membership head.
struct MembershipHead {
    entity_ref: EntityId,
    query_ref: EntityId,
    campaign_ref: EntityId,
}

/// CLAIM rows one membership page reads at most, heads or not: a page's work
/// is bounded by the claims it reads, never by the rows it returns (F13).
const MEMBERSHIP_PAGE_SCAN_ROWS: usize = 4_096;

fn membership_page(
    vault: &Vault,
    req: &MembershipReadRequest,
    owner: MembershipOwner,
) -> Result<MembershipPage> {
    let limit = effective_limit(req.limit) as usize;
    let after = req.cursor.as_deref().map(parse_cursor).transpose()?;
    let claim_ids = vault.entities_by_type_page(
        ENTITY_TYPE_CLAIM,
        after.as_ref(),
        MEMBERSHIP_PAGE_SCAN_ROWS,
    )?;
    let mut rows = Vec::new();
    let mut last_read = None;
    let mut filled = false;
    for claim_id in &claim_ids {
        if rows.len() >= limit {
            filled = true;
            break;
        }
        if let Some(head) = membership_head(vault, claim_id, req.owner_ref, owner)? {
            let events = membership_events(vault, head.query_ref, head.entity_ref)?;
            if let Some(row) = fold_membership_events(&head, &events, req.at_epoch) {
                rows.push(row);
            }
        }
        // Advanced for every claim the page READ, not only for the heads that
        // produced a row: a claim that is no head, or a head whose history
        // folds to nothing, is still done, and re-offering it would stall a
        // caller that pages through a run of them.
        last_read = Some(*claim_id);
    }
    // A cursor is emitted while unread claims may remain: the page filled, or
    // it read its whole run of claims. A page that ran out of claims reports
    // `None`, so "keep paging while next_cursor is Some" terminates; a page
    // may return no row and still carry a cursor.
    let more = filled || claim_ids.len() >= MEMBERSHIP_PAGE_SCAN_ROWS;
    Ok(MembershipPage {
        rows,
        next_cursor: more.then(|| last_read.map(|id| id.to_hex())).flatten(),
    })
}

const fn effective_limit(requested: u32) -> u32 {
    if requested == 0 {
        MEMBERSHIP_PAGE_DEFAULT_LIMIT
    } else if requested > MEMBERSHIP_PAGE_MAX_LIMIT {
        MEMBERSHIP_PAGE_MAX_LIMIT
    } else {
        requested
    }
}

/// A cursor is exactly one hex claim id, the last claim a page read.
/// Rejecting a malformed one is the difference between "you asked for a page
/// that does not exist" and silently returning page one under a caller that
/// believes it is paging.
fn parse_cursor(cursor: &str) -> Result<EntityId> {
    EntityId::from_hex(cursor).map_err(|_| Error::InvalidKey)
}

/// The live `campaign.member` head `claim_id` holds, when it matches
/// `owner_ref` on the chosen axis.
///
/// CA-01 owns the head, and its value carries both the campaign it is scoped to
/// and the query that derived it, so one claim read answers both directions.
/// The CRM pack registers no membership index of its own — `registry.rs` is a
/// hard non-claim for this lane — so pages walk the CLAIM type index in id
/// order, a bounded run of claims at a time.
fn membership_head(
    vault: &Vault,
    claim_id: &EntityId,
    owner_ref: EntityId,
    owner: MembershipOwner,
) -> Result<Option<MembershipHead>> {
    let Some(body) = vault.get_claim(claim_id)? else {
        return Ok(None);
    };
    if body.predicate != PREDICATE_CAMPAIGN_MEMBER || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Ok(None);
    }
    let ClaimSubject::Entity(entity_ref) = body.subject else {
        return Ok(None);
    };
    let value = decode_campaign_member_value(&body.value)?;
    // A head with no derivation was not written by CA-03's consequence
    // writer, so there is no `(query, entity)` history to fold and no
    // honest bitemporal row to emit.
    let Some(derivation) = value.derivation else {
        return Ok(None);
    };
    let matches = match owner {
        MembershipOwner::Campaign => value.campaign == owner_ref,
        MembershipOwner::SavedQuery => derivation.source_query == owner_ref,
    };
    Ok(matches.then_some(MembershipHead {
        entity_ref,
        query_ref: derivation.source_query,
        campaign_ref: value.campaign,
    }))
}

/// Folds one head's history into a single row.
///
/// The event log is keyed `(query, entity)` and one such pair can hold heads in
/// SEVERAL campaigns, so the history handed in is the union across them and only
/// the events carrying this head's `campaign_ref` are this head's. Folding the
/// union would let one campaign's exit end a membership in another.
///
/// `entered_*` always report the newest ENTRY, even when the entity has since
/// exited, so a caller can tell "left after a long membership" from "left
/// immediately". `exited_*` are populated only when the newest event is an exit:
/// a re-entry supersedes the prior exit rather than leaving a stale end date on
/// a live member.
fn fold_membership_events(
    head: &MembershipHead,
    events: &[MembershipEvent],
    at_epoch: Option<u64>,
) -> Option<MembershipRow> {
    let mut entered: Option<&MembershipEvent> = None;
    let mut latest: Option<&MembershipEvent> = None;
    for event in events {
        if event.campaign_ref != head.campaign_ref {
            continue;
        }
        if at_epoch.is_some_and(|ceiling| event.epoch > ceiling) {
            continue;
        }
        if event.transition == MembershipTransition::Entered {
            entered = Some(event);
        }
        latest = Some(event);
    }
    let latest = latest?;
    let entered = entered?;
    let exited = (latest.transition == MembershipTransition::Exited).then_some(latest);
    Some(MembershipRow {
        entity_ref: head.entity_ref,
        state: latest.transition.as_str().to_owned(),
        entered_valid: entered.valid_at,
        entered_detected: entered.detected_at,
        exited_valid: exited.map(|event| event.valid_at),
        exited_detected: exited.map(|event| event.detected_at),
        cause: Some(latest.cause.as_str().to_owned()),
    })
}
