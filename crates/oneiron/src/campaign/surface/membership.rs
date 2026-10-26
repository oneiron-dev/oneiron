//! Read-only membership projection over CA-01 heads and CA-02 event history.

use serde::{Deserialize, Serialize};

use crate::campaign::claims::{
    CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value,
};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedRead, decode_claim_body};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::saved_query::{MembershipEvent, MembershipTransition, membership_events_in_txn};
use crate::{EntityId, Vault};

use self::manual::manual_membership_row;

mod manual;

/// Page size used when a caller passes `limit = 0`.
pub const MEMBERSHIP_PAGE_DEFAULT_LIMIT: u32 = 50;

/// Hard ceiling on one membership page.
pub const MEMBERSHIP_PAGE_MAX_LIMIT: u32 = 200;

/// One page request against a campaign's or a query's membership.
///
/// `owner_ref` is the CAMPAIGN for [`read_campaign_members`] and the
/// SAVED_QUERY for [`read_saved_query_members`]. `at_epoch`, when present,
/// reads saved-query history as of that membership epoch — the bitemporal
/// read. It is a saved-query epoch, not a clock: a manual enrollment carries
/// none, and [`MANUAL_MEMBERSHIP_EPOCH_POLICY`] says how its row is treated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipReadRequest {
    /// The campaign or saved query whose membership is being paged.
    pub owner_ref: EntityId,
    /// Opaque cursor from a prior page's `next_cursor`.
    pub cursor: Option<String>,
    /// Requested page size; `0` means [`MEMBERSHIP_PAGE_DEFAULT_LIMIT`] and
    /// anything above [`MEMBERSHIP_PAGE_MAX_LIMIT`] is clamped to it.
    pub limit: u32,
    /// Optional saved-query epoch ceiling; query events after it are not
    /// folded into the row.
    pub at_epoch: Option<u64>,
}

/// Where a membership row's clocks, state and cause come from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipRowSource {
    /// A saved query derived the membership: the row folds CA-02's
    /// entered/exited history for the query, the entity and the campaign.
    SavedQuery {
        /// The query that derived the membership.
        query_ref: EntityId,
        /// The live `campaign.member` head.
        membership_claim_ref: EntityId,
        /// Epoch of the newest folded event.
        epoch: u64,
    },
    /// A manual enrollment wrote the membership (FIX 9669): the row reports
    /// the live head claim itself, its state and its own clocks. No
    /// saved-query event exists for it, and none is implied.
    ManualClaim {
        /// The live `campaign.member` head.
        membership_claim_ref: EntityId,
    },
}

/// How a page under an `at_epoch` ceiling treats a manual enrollment, which
/// carries no saved-query epoch to compare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualEpochPolicy {
    /// The row is on the page: the ceiling filters saved-query history only,
    /// and the row's `manual_claim` source says it is not versioned by one.
    IncludeUnversionedClaim,
    /// The row is left off any page that names a ceiling.
    OmitUnderEpochCeiling,
}

/// The manual-enrollment epoch policy campaign pages run (canon-silent; FIX
/// 9669). Including the row withholds nothing and invents no history: its
/// clocks are the claim's own, never compared to the query epoch.
pub const MANUAL_MEMBERSHIP_EPOCH_POLICY: ManualEpochPolicy =
    ManualEpochPolicy::IncludeUnversionedClaim;

/// One membership row.
///
/// A saved-query row folds its entered/exited history; a manual row reports
/// its head claim. [`Self::source`] says which, and so what every clock means.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRow {
    /// The member.
    pub entity_ref: EntityId,
    /// A saved-query row: `entered` or `exited`, the direction of the newest
    /// folded event. A manual row: the head's own member state, `enrolled`,
    /// `paused`, `exited` or `suppressed`.
    pub state: String,
    /// A saved-query row: valid time of the newest `entered` event. A manual
    /// row: the head claim's valid time.
    pub entered_valid: u64,
    /// A saved-query row: detection time of the newest `entered` event. A
    /// manual row: when the head claim was recorded.
    pub entered_detected: u64,
    /// Valid time of the newest `exited` event, when a saved-query row is
    /// currently out; `None` on a manual row.
    pub exited_valid: Option<u64>,
    /// Detection time of the newest `exited` event, when a saved-query row is
    /// currently out; `None` on a manual row.
    pub exited_detected: Option<u64>,
    /// `data_change`, `scope_change`, or `definition_change`, exactly as CA-02
    /// produced it for the newest folded event; `None` on a manual row.
    pub cause: Option<String>,
    /// Where the row comes from.
    pub source: MembershipRowSource,
}

/// One page of membership rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipPage {
    /// Rows in stable cursor order.
    pub rows: Vec<MembershipRow>,
    /// Cursor for the next page; `None` when the page is the last one.
    pub next_cursor: Option<String>,
}

/// Pages a campaign's cohort under the caller's read.
///
/// Read-only by construction: it opens no write transaction, mints no claim, and
/// enqueues no attempt. The cohort is CA-01's live `campaign.member` heads: a
/// head a saved query derived reports CA-02's entered/exited history for its
/// `(source query, entity)` pair, and a manually enrolled head reports itself
/// (FIX 9669). Nothing is inferred.
///
/// Every head, and the PERSON it names, is admitted under `read` in the one
/// serving snapshot BEFORE any sorting, cursor or lookahead (FIX 9668), so a
/// row, a clock or a cursor never reveals a membership the caller cannot read.
///
/// # Errors
///
/// Storage and decode errors propagate; a malformed cursor is
/// [`Error::InvalidKey`].
pub fn read_campaign_members(
    read: &ScopedRead<'_>,
    req: &MembershipReadRequest,
) -> Result<MembershipPage> {
    membership_page(read, req, MembershipOwner::Campaign)
}

/// Pages the membership one saved query derived, under the caller's read.
///
/// The query-side twin of [`read_campaign_members`], with the same read-only
/// guarantee, the same admission and the same event source; only the filter
/// axis differs, and a manual head is never on a query's page.
///
/// # Errors
///
/// Storage and decode errors propagate; a malformed cursor is
/// [`Error::InvalidKey`].
pub fn read_saved_query_members(
    read: &ScopedRead<'_>,
    req: &MembershipReadRequest,
) -> Result<MembershipPage> {
    membership_page(read, req, MembershipOwner::SavedQuery)
}

/// Which axis of a `campaign.member` head `owner_ref` selects on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipOwner {
    /// `owner_ref` is the CAMPAIGN the head is scoped to.
    Campaign,
    /// `owner_ref` is the SAVED_QUERY the head was derived from.
    SavedQuery,
}

/// One admitted live `campaign.member` head, in cursor order.
struct MembershipHead {
    entity_ref: EntityId,
    campaign_ref: EntityId,
    claim_ref: EntityId,
    source: MembershipHeadSource,
}

/// What wrote a head, and what a row for it reads.
enum MembershipHeadSource {
    /// A saved query derived it; its history is CA-02's event log.
    SavedQuery { query_ref: EntityId },
    /// A manual enrollment wrote it; the claim is its own record.
    ManualClaim {
        state: CampaignMemberState,
        valid_at: u64,
        recorded_at: u64,
    },
}

impl MembershipHead {
    /// The query that derived the head, or the head claim itself for a
    /// manual one: the middle of the cursor.
    const fn source_ref(&self) -> EntityId {
        match self.source {
            MembershipHeadSource::SavedQuery { query_ref } => query_ref,
            MembershipHeadSource::ManualClaim { .. } => self.claim_ref,
        }
    }

    fn order_key(&self) -> ([u8; 16], [u8; 16], [u8; 16]) {
        (
            *self.entity_ref.as_bytes(),
            *self.source_ref().as_bytes(),
            *self.campaign_ref.as_bytes(),
        )
    }

    /// The opaque cursor token for this head: `(entity, source, campaign)`.
    ///
    /// The full triple, not just `entity_ref`: one entity can hold heads in
    /// several campaigns, from one query or from manual enrollment, so an
    /// entity-only cursor could skip or repeat a row at a page boundary.
    fn cursor(&self) -> String {
        format!(
            "{}{}{}",
            self.entity_ref.to_hex(),
            self.source_ref().to_hex(),
            self.campaign_ref.to_hex()
        )
    }
}

fn membership_page(
    read: &ScopedRead<'_>,
    req: &MembershipReadRequest,
    owner: MembershipOwner,
) -> Result<MembershipPage> {
    let limit = effective_limit(req.limit) as usize;
    if let Some(cursor) = req.cursor.as_deref() {
        validate_cursor(cursor)?;
    }
    let vault = read.vault();
    let candidates = vault.entities_by_type(ENTITY_TYPE_CLAIM)?;
    let txn = vault.store.env.read_txn()?;
    let mut heads = membership_heads_in_txn(read, &txn, &candidates, req.owner_ref, owner)?;
    // Sorted on the same triple the cursor encodes, so "everything after the
    // cursor" is a total order and a page boundary is stable across calls.
    heads.sort_unstable_by_key(MembershipHead::order_key);

    let mut rows = Vec::new();
    let mut last_token = None;
    let mut remaining = heads.iter().filter(|head| {
        req.cursor
            .as_deref()
            .is_none_or(|cursor| head.cursor().as_str() > cursor)
    });
    for head in remaining.by_ref() {
        if let Some(row) = membership_row_in_txn(vault, &txn, head, req.at_epoch)? {
            rows.push(row);
        }
        // Advanced for every head the loop CONSUMED, not only for the ones that
        // produced a row: a head whose history folds to nothing is still done,
        // and re-offering it on the next page would stall a caller that pages
        // through a cohort of them.
        last_token = Some(head.cursor());
        if rows.len() >= limit {
            break;
        }
    }
    // A cursor is emitted only when an admitted head past this page still
    // yields a row, so a page that exhausted the scan, or whose tail folds to
    // nothing, reports `None`: "keep paging while next_cursor is Some"
    // terminates instead of fetching an empty tail.
    let mut has_more = false;
    for head in remaining {
        if membership_row_in_txn(vault, &txn, head, req.at_epoch)?.is_some() {
            has_more = true;
            break;
        }
    }
    Ok(MembershipPage {
        rows,
        next_cursor: has_more.then_some(last_token).flatten(),
    })
}

/// The row one admitted head yields under `at_epoch`, from its own source.
fn membership_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    head: &MembershipHead,
    at_epoch: Option<u64>,
) -> Result<Option<MembershipRow>> {
    Ok(match head.source {
        MembershipHeadSource::SavedQuery { query_ref } => {
            let events = membership_events_in_txn(vault, txn, query_ref, head.entity_ref)?;
            fold_membership_events(head, query_ref, &events, at_epoch)
        }
        MembershipHeadSource::ManualClaim {
            state,
            valid_at,
            recorded_at,
        } => manual_membership_row(head, state, valid_at, recorded_at, at_epoch),
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

/// Every live `campaign.member` head matching `owner_ref` on the chosen axis
/// that `read` admits, together with the PERSON it names, in `txn`.
///
/// CA-01 owns the head, and its value carries both the campaign it is scoped to
/// and the query that derived it, so one predicate scan answers both directions.
/// The CRM pack registers no membership index of its own — `registry.rs` is a
/// hard non-claim for this lane — so this walks the CLAIM type index the way
/// `/api/core/discover` walks it. Output is bounded by the page limit; the scan
/// is not, and an index is the honest follow-up if cohorts get large.
///
/// The scan only nominates heads. Each is then read again through `read` in
/// this same snapshot, and only the admitted body is trusted; a head whose
/// claim or PERSON `read` withholds is not a head here at all (FIX 9668).
fn membership_heads_in_txn(
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    candidates: &[EntityId],
    owner_ref: EntityId,
    owner: MembershipOwner,
) -> Result<Vec<MembershipHead>> {
    let vault = read.vault();
    let mut nominated = Vec::new();
    for claim_id in candidates {
        let Some(body) = vault.get_claim_in_txn(txn, claim_id)? else {
            continue;
        };
        if head_matches(&body, owner_ref, owner)?.is_some() {
            nominated.push(*claim_id);
        }
    }
    let admitted = read.get_entities_parts_in_txn(txn, &nominated)?;
    let mut heads = Vec::new();
    for (claim_ref, parts) in nominated.into_iter().zip(admitted) {
        let Some((kind, recorded_at, raw)) = parts else {
            continue;
        };
        if kind != ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = decode_claim_body(&raw, true)?;
        let Some((entity_ref, value)) = head_matches(&body, owner_ref, owner)? else {
            continue;
        };
        let source = match value.derivation {
            Some(derivation) => MembershipHeadSource::SavedQuery {
                query_ref: derivation.source_query,
            },
            None => MembershipHeadSource::ManualClaim {
                state: value.state,
                valid_at: body.valid_from.unwrap_or(recorded_at),
                recorded_at,
            },
        };
        heads.push(MembershipHead {
            entity_ref,
            campaign_ref: value.campaign,
            claim_ref,
            source,
        });
    }
    let subjects: Vec<_> = heads.iter().map(|head| head.entity_ref).collect();
    let readable = read.entities_readable_in_txn(txn, &subjects)?;
    Ok(heads
        .into_iter()
        .zip(readable)
        .filter_map(|(head, admitted)| admitted.then_some(head))
        .collect())
}

/// The member and the decoded value when `body` is a live `campaign.member`
/// head on the chosen axis. A campaign page takes every head of the campaign,
/// derived or manual; a query page takes only the heads that query derived.
fn head_matches(
    body: &ClaimBody,
    owner_ref: EntityId,
    owner: MembershipOwner,
) -> Result<Option<(EntityId, CampaignMemberValue)>> {
    if body.predicate != PREDICATE_CAMPAIGN_MEMBER || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Ok(None);
    }
    let ClaimSubject::Entity(entity_ref) = body.subject else {
        return Ok(None);
    };
    let value = decode_campaign_member_value(&body.value)?;
    let matches = match owner {
        MembershipOwner::Campaign => value.campaign == owner_ref,
        MembershipOwner::SavedQuery => value
            .derivation
            .as_ref()
            .is_some_and(|derivation| derivation.source_query == owner_ref),
    };
    Ok(matches.then_some((entity_ref, value)))
}

/// Folds one derived head's history into a single row.
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
    query_ref: EntityId,
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
        source: MembershipRowSource::SavedQuery {
            query_ref,
            membership_claim_ref: head.claim_ref,
            epoch: latest.epoch,
        },
    })
}
