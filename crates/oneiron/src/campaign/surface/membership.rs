//! Read-only membership projection over CA-01 heads and CA-02 event history.

use crate::campaign::claims::{
    CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value,
};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedRead, decode_claim_body};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::saved_query::{MembershipEvent, MembershipTransition, membership_events_in_txn};
use crate::{EntityId, Vault};

use self::manual::manual_membership_row;

mod manual;

pub use crate::memory::campaign_records::MANUAL_MEMBERSHIP_EPOCH_POLICY;
pub use crate::memory::campaign_records::MEMBERSHIP_PAGE_DEFAULT_LIMIT;
pub use crate::memory::campaign_records::MEMBERSHIP_PAGE_MAX_LIMIT;
pub use crate::memory::campaign_records::ManualEpochPolicy;
pub use crate::memory::campaign_records::MembershipPage;
pub use crate::memory::campaign_records::MembershipReadRequest;
pub use crate::memory::campaign_records::MembershipRow;
pub use crate::memory::campaign_records::MembershipRowSource;

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
/// axis differs, and a manual head is on a query's page only when it replaced
/// a head that query derived.
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
        if head_matches(vault, txn, claim_id, &body, owner_ref, owner)?.is_some() {
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
        let Some((entity_ref, value)) =
            head_matches(vault, txn, &claim_ref, &body, owner_ref, owner)?
        else {
            continue;
        };
        // A query's page folds the member from that query's own history,
        // whichever source the reconciled head names now (FIX 9664).
        let source = match (owner, value.derivation) {
            (MembershipOwner::SavedQuery, _) => MembershipHeadSource::SavedQuery {
                query_ref: owner_ref,
            },
            (MembershipOwner::Campaign, Some(derivation)) => MembershipHeadSource::SavedQuery {
                query_ref: derivation.source_query,
            },
            (MembershipOwner::Campaign, None) => MembershipHeadSource::ManualClaim {
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

/// Whether a `campaign.member` claim `head` replaced, directly or through
/// earlier replacements, was derived from `query_ref`, read in the caller's
/// `txn`.
fn lineage_names_query_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    head: &EntityId,
    query_ref: EntityId,
) -> Result<bool> {
    let mut seen = std::collections::BTreeSet::new();
    let mut next = vec![*head];
    while let Some(id) = next.pop() {
        for edge in vault.store.port_edges(
            txn,
            &id,
            EdgeDirection::Out,
            Some(EdgeKind::Supersedes),
            None,
        )? {
            let older = edge?.target;
            if !seen.insert(older) {
                continue;
            }
            let Some(body) = vault.get_claim_in_txn(txn, &older)? else {
                continue;
            };
            if body.predicate != PREDICATE_CAMPAIGN_MEMBER {
                continue;
            }
            if decode_campaign_member_value(&body.value)?
                .derivation
                .is_some_and(|derivation| derivation.source_query == query_ref)
            {
                return Ok(true);
            }
            next.push(older);
        }
    }
    Ok(false)
}

/// The member and the decoded value when `body` is a live `campaign.member`
/// head on the chosen axis. A campaign page takes every head of the campaign,
/// derived or manual; a query page takes the heads that query derived, and a
/// reconciled head that names another source but replaced, directly or
/// through earlier replacements, a head that query derived (FIX 9664).
fn head_matches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_ref: &EntityId,
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
        MembershipOwner::SavedQuery => {
            value
                .derivation
                .as_ref()
                .is_some_and(|derivation| derivation.source_query == owner_ref)
                || lineage_names_query_in_txn(vault, txn, claim_ref, owner_ref)?
        }
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
