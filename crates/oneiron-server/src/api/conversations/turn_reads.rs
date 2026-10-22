//! The TURN read and list doors' rows (FIX 5652, 5938), each one judged and
//! its words read in one snapshot (FIX 5870): no row is served from a later
//! read than the one that admitted it.

use crate::api::CORE_MAX_LIST_LIMIT;
use crate::api::CoreListQuery;
use crate::api::SearchResponse;
use crate::api::core_engine_error;
use crate::api::core_list_limit;
use crate::api::parse_entity_id_param;
use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use crate::projection;
use crate::projection::View;
use crate::protocol::CountMode;
use crate::protocol::PaginatedResponse;
use crate::protocol::ResponseMeta;
use axum::response::Json;
use oneiron::EdgeKind;
use oneiron::registry::ENTITY_TYPE_TURN;

/// A served row: its kind, time and body.
type TurnParts = (u8, u64, Vec<u8>);

/// The turn `id` as the TURN routes serve it to `read`'s caller: for the
/// owner's own read (`Vault::turn_doors_owner`), the stored row once the
/// turn's private threads admit it (FIX 5652), judged and read in one
/// snapshot (FIX 5870); for any other caller, the row its lane reads, in its
/// read's own snapshot (FIX 5938). A turn neither reads answers as missing.
pub(super) fn core_turn_for_read(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    id: &oneiron::EntityId,
) -> Result<TurnParts, EnvelopedApiError> {
    let failed = |error: oneiron::Error| {
        tracing::error!(kind = ?error.kind(), id = %id.to_hex(), "core TURN read failed");
        core_engine_error("core TURN read failed", error)
    };
    let (owner, owner_row) = vault
        .with_read_snapshot(|txn| -> oneiron::Result<(bool, Option<TurnParts>)> {
            if !vault.turn_doors_owner_in_txn(read, txn)? {
                return Ok((false, None));
            }
            let row = vault
                .turn_door_parts_in_txn(read, txn, true, std::slice::from_ref(id))?
                .pop()
                .flatten();
            Ok((true, row))
        })
        .map_err(failed)?;
    let row = if owner {
        owner_row.filter(|(entity_type, _, _)| *entity_type == ENTITY_TYPE_TURN)
    } else {
        read
            .get_entity_parts_with_receipt(id, None)
            .map_err(failed)?
            .value
    };
    Ok(row.ok_or_else(|| ApiError::not_found("turn", Some(&id.to_hex())))?)
}

/// What one TURN list read admitted, in its one snapshot.
struct ListedTurns {
    ids: Vec<oneiron::EntityId>,
    rows: Vec<Option<TurnParts>>,
    next_cursor: Option<String>,
    total: Option<u64>,
}

/// The conversation's turns `read`'s caller reads (FIX 5652): a turn of a
/// private thread it does not read, the opener included, is no row here.
/// Below the owner (`Vault::turn_doors_owner`), the conversation and each
/// turn are read through the caller's own lane, and so is the body served;
/// a conversation it does not read is not here (FIX 5938). A turn withheld
/// is not projected, takes no place on a page, is never a cursor and is not
/// counted. The page, each row's admission and words, and an exact count
/// are read in one snapshot (FIX 5870).
pub(super) fn core_list_conversation_turns(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    conversation: &oneiron::EntityId,
    params: CoreListQuery,
    body_bytes: usize,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    let view = params.view.unwrap_or(View::Summary);
    let limit = core_list_limit(params.limit);
    let after = params
        .after
        .as_deref()
        .map(|after| parse_entity_id_param(after, "after"))
        .transpose()?;
    let exact = matches!(params.count_mode, CountMode::Exact);
    let listed = vault
        .with_read_snapshot(|txn| -> oneiron::Result<Option<ListedTurns>> {
            let owner = vault.turn_doors_owner_in_txn(read, txn)?;
            if !owner && !vault.turn_door_admits_in_txn(read, txn, false, conversation)? {
                return Ok(None);
            }
            let (ids, next_cursor) =
                live_turn_page(vault, read, txn, owner, conversation, after, limit)?;
            let rows = vault.turn_door_parts_in_txn(read, txn, owner, &ids)?;
            let total = exact
                .then(|| count_live_turns_in(vault, read, txn, owner, conversation))
                .transpose()?;
            Ok(Some(ListedTurns {
                ids,
                rows,
                next_cursor,
                total,
            }))
        })
        .map_err(|error| {
            tracing::error!(error = %error, conversation = %conversation.to_hex(), "core conversation turns failed");
            core_engine_error("core conversation turns failed", error)
        })?;
    let Some(listed) = listed else {
        return Err(ApiError::not_found("conversation", Some(&conversation.to_hex())).into());
    };
    let mut bodies = projection::BodyBudget::new(vault, body_bytes);
    let items: Vec<_> = listed
        .ids
        .iter()
        .zip(listed.rows)
        .filter_map(|(id, row)| {
            let (entity_type, learned_at, body) = row?;
            Some(bodies.project(id, entity_type, learned_at, &body, view))
        })
        .collect();
    let meta = match params.count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(items.len() as u64),
        CountMode::Exact => ResponseMeta::new(listed.total.unwrap_or_default(), CountMode::Exact),
    };
    Ok(Json(PaginatedResponse::new(items, listed.next_cursor, meta)))
}

/// One page of `conversation`'s live turns the TURN doors serve, read in
/// `txn`, paged as `collect_live_entity_page` pages a list: a deleted shell
/// or a withheld turn takes no place, a page its run of edges left short
/// resumes where the run stopped, and a cursor never names a withheld turn.
fn live_turn_page(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    owner: bool,
    conversation: &oneiron::EntityId,
    after: Option<oneiron::EntityId>,
    limit: usize,
) -> oneiron::Result<(Vec<oneiron::EntityId>, Option<String>)> {
    if limit == 0 {
        return Ok((Vec::new(), None));
    }
    let admits = |id: &oneiron::EntityId| vault.turn_door_admits_in_txn(read, txn, owner, id);
    let mut ids = Vec::with_capacity(limit);
    let mut resume = after;
    loop {
        let fetched = vault.sources_page_in_txn(
            txn,
            conversation,
            EdgeKind::ChildOf,
            Some(ENTITY_TYPE_TURN),
            resume.as_ref(),
            limit.saturating_add(1),
        )?;
        for id in fetched.ids {
            if vault.is_deleted_shell_in_txn(txn, &id)? || !admits(&id)? {
                continue;
            }
            if ids.len() == limit {
                let next_cursor = ids.last().map(oneiron::EntityId::to_hex);
                return Ok((ids, next_cursor));
            }
            ids.push(id);
        }
        let Some(resume_after) = fetched.resume_after else {
            return Ok((ids, None));
        };
        // A full page resumes after its last item, as the list always has; a
        // page the run left short resumes where the run stopped, unless that
        // place is withheld, which is read on from and never handed out.
        if admits(&resume_after)? {
            let last_served = ids.last().filter(|_| ids.len() == limit);
            let next_cursor = last_served.unwrap_or(&resume_after).to_hex();
            return Ok((ids, Some(next_cursor)));
        }
        resume = Some(resume_after);
    }
}

/// The live turns of `conversation` `read`'s caller reads (FIX 5652), each
/// judged in `txn` as a page's are (FIX 5938). An exact count reads every
/// page: a short page is not the end.
fn count_live_turns_in(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    owner: bool,
    conversation: &oneiron::EntityId,
) -> oneiron::Result<u64> {
    let mut after = None;
    let mut total = 0_u64;
    loop {
        let page = vault.sources_page_in_txn(
            txn,
            conversation,
            EdgeKind::ChildOf,
            Some(ENTITY_TYPE_TURN),
            after.as_ref(),
            CORE_MAX_LIST_LIMIT,
        )?;
        for id in &page.ids {
            if !vault.is_deleted_shell_in_txn(txn, id)?
                && vault.turn_door_admits_in_txn(read, txn, owner, id)?
            {
                total = total.saturating_add(1);
            }
        }
        let Some(resume_after) = page.resume_after else {
            break;
        };
        after = Some(resume_after);
    }
    Ok(total)
}
