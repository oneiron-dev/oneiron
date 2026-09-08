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
    /// Rows in stable cursor order.
    pub rows: Vec<MembershipRow>,
    /// Cursor for the next page; `None` when the page is the last one.
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

/// One `(entity, query, campaign)` membership head, in cursor order.
struct MembershipHead {
    entity_ref: EntityId,
    query_ref: EntityId,
    campaign_ref: EntityId,
}

impl MembershipHead {
    /// The opaque cursor token for this head.
    ///
    /// The full triple, not just `entity_ref`: one entity can hold heads in
    /// several campaigns derived from one query, so an entity-only cursor could
    /// skip or repeat a row at a page boundary.
    fn cursor(&self) -> String {
        format!(
            "{}{}{}",
            self.entity_ref.to_hex(),
            self.query_ref.to_hex(),
            self.campaign_ref.to_hex()
        )
    }
}

fn membership_page(
    vault: &Vault,
    req: &MembershipReadRequest,
    owner: MembershipOwner,
) -> Result<MembershipPage> {
    let limit = effective_limit(req.limit);
    if let Some(cursor) = req.cursor.as_deref() {
        validate_cursor(cursor)?;
    }
    let mut heads = membership_heads(vault, req.owner_ref, owner)?;
    // Sorted on the same triple the cursor encodes, so "everything after the
    // cursor" is a total order and a page boundary is stable across calls.
    heads.sort_unstable_by_key(|head| {
        (
            *head.entity_ref.as_bytes(),
            *head.query_ref.as_bytes(),
            *head.campaign_ref.as_bytes(),
        )
    });

    let mut rows = Vec::new();
    let mut last_token = None;
    let mut has_more = false;
    for head in heads {
        let token = head.cursor();
        if req
            .cursor
            .as_deref()
            .is_some_and(|cursor| token.as_str() <= cursor)
        {
            continue;
        }
        if rows.len() as u32 >= limit {
            has_more = true;
            break;
        }
        let events = membership_events(vault, head.query_ref, head.entity_ref)?;
        if let Some(row) = fold_membership_events(&head, &events, req.at_epoch) {
            rows.push(row);
        }
        // Advanced for every head the loop CONSUMED, not only for the ones that
        // produced a row: a head whose history folds to nothing is still done,
        // and re-offering it on the next page would stall a caller that pages
        // through a cohort of them.
        last_token = Some(token);
    }
    // A cursor is emitted only when an unvisited head remains. A page that
    // exhausted the scan reports `None`, so "keep paging while next_cursor is
    // Some" terminates instead of looping on an empty tail.
    Ok(MembershipPage {
        rows,
        next_cursor: has_more.then_some(last_token).flatten(),
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

/// A cursor is exactly three hex entity ids. Rejecting a malformed one is the
/// difference between "you asked for a page that does not exist" and silently
/// returning page one under a caller that believes it is paging.
fn validate_cursor(cursor: &str) -> Result<()> {
    const CURSOR_LEN: usize = 96;
    if cursor.len() != CURSOR_LEN || !cursor.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Every live `campaign.member` head matching `owner_ref` on the chosen axis.
///
/// CA-01 owns the head, and its value carries both the campaign it is scoped to
/// and the query that derived it, so one predicate scan answers both directions.
/// The CRM pack registers no membership index of its own — `registry.rs` is a
/// hard non-claim for this lane — so this walks the CLAIM type index the way
/// `/api/core/discover` walks it. Output is bounded by the page limit; the scan
/// is not, and an index is the honest follow-up if cohorts get large.
fn membership_heads(
    vault: &Vault,
    owner_ref: EntityId,
    owner: MembershipOwner,
) -> Result<Vec<MembershipHead>> {
    let mut heads = Vec::new();
    for claim_id in vault.entities_by_type(ENTITY_TYPE_CLAIM)? {
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let ClaimSubject::Entity(entity_ref) = body.subject else {
            continue;
        };
        let value = decode_campaign_member_value(&body.value)?;
        // A head with no derivation was not written by CA-03's consequence
        // writer, so there is no `(query, entity)` history to fold and no
        // honest bitemporal row to emit.
        let Some(derivation) = value.derivation else {
            continue;
        };
        let matches = match owner {
            MembershipOwner::Campaign => value.campaign == owner_ref,
            MembershipOwner::SavedQuery => derivation.source_query == owner_ref,
        };
        if matches {
            heads.push(MembershipHead {
                entity_ref,
                query_ref: derivation.source_query,
                campaign_ref: value.campaign,
            });
        }
    }
    Ok(heads)
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
