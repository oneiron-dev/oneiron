use super::*;

use super::claim::reconcile_replicated_critical_confirm;

/// What the rewrite plans for the write: the dominance eviction it orphaned,
/// the short-id update, the authority first-seen key, and the body buffers
/// that shadow `data` from here on.
pub(super) struct Rewrite {
    pub(super) evicted_shell_sources: BTreeSet<EntityId>,
    pub(super) short_id_plan: Option<crate::batch::short_id::ShortIdPlan>,
    pub(super) authority_first_seen_key: Option<String>,
    pub(super) escalated_skill_body: Option<Vec<u8>>,
    pub(super) reconciled_critical_claim_body: Option<Vec<u8>>,
}

/// P3: reject the envelope, evict a dominated squatter, then rewrite the body
/// (SKILL escalation, TASK streak strip, pad reference, critical-confirm
/// reconcile) and plan the short-id update over the rewritten bytes.
pub(super) fn rewrite_put_body(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    data: &[u8],
    fixed: &super::admission::FixedPut<'_>,
    dispatch: &mut super::admission::Dispatch,
    revision: &super::admission::RevisionSlot,
    task_body_without_streaks: &Option<Vec<u8>>,
    pad_stored_body: &Option<Vec<u8>>,
) -> Result<Rewrite> {
    if fixed.occurred.start > fixed.occurred.end {
        return Err(Error::InvalidTimeRange {
            start: fixed.occurred.start,
            end: fixed.occurred.end,
        });
    }
    // ONE-1604-D1 dominance MUTATION (fix-leg 2, P2): every side-effect-free
    // check that can reject this row REMOTELY has now run — including the
    // envelope's time-range validation directly above. That ordering is the
    // whole point: `InvalidTimeRange` is a `remote_rejection_reason`, so
    // Observer B quarantines it and COMMITS the transaction (sync/bridge.rs
    // quarantine-and-continue). An eviction performed before that check would
    // therefore survive the rejection as a durable side effect — a rejected
    // authority row would empty the key it failed to claim. A rejected input
    // must be a pure no-op, so the squatter is deindexed only here, past the
    // last remotely-rejectable gate.
    //
    // Placed BEFORE short-id planning and the old-record arm below (rather
    // than at the `store.entities.put` line) because both read the row this
    // eviction removes: the old-record arm would otherwise reject the
    // dominant row with `EntityTypeImmutable`, and a short-id plan built from
    // the squatter's rows would outlive them. Everything still fallible
    // between here and the write is LOCAL-class (storage/overflow), which
    // aborts the whole batch instead of committing — so it cannot strand this
    // mutation either.
    // Delete wins over a peer: no replicated put brings back a row this vault
    // deleted, whatever the window's tombstone map now says. Checked once the
    // body has passed its own validation, so a refused body still reports its
    // own error. The refusal is local-class: the batch aborts, and nothing
    // staged above survives it. A delete-protected record is never deleted, so
    // a fence planted at its id before it arrived refuses nothing.
    if fixed.replicated
        && !crate::registry::is_delete_protected_engine_record(fixed.entity_type)
        && revision.put.is_none()
        && !crate::dreamer_runner::authority::is_base_agent_actor(&fixed.id)?
        && store.port_deletion_marked(wtxn, DeletionMarker::RowFence, &fixed.id)?
    {
        return Err(Error::InvariantViolation(
            "a fixed.replicated put cannot restore an entity deleted here",
        ));
    }
    let evicted_shell_sources = if dispatch.authority_dominates_key_squatter || revision.squatter {
        evict_authority_log_store_key_squatter(store, wtxn, &fixed.id)?
    } else {
        BTreeSet::new()
    };
    // ONE-1892: the SKILL activation scan consult, at the one arm every road
    // to a SKILL body converges on. The typed update door is not the
    // chokepoint — `put_entity` and a raw `batch().put` land an already-
    // `active` body here without passing it — so the escalation from `auto`
    // to `proposed` (a dial, never a refusal) is computed here instead.
    //
    // LOCAL writes only: a replicated row carries a peer's already-settled
    // consent and re-deciding it would diverge the replicas, and the hub-sync
    // door copies the local approval stamp verbatim, so it never presents a
    // transition to escalate.
    //
    // Placed BEFORE short-id planning because the plan hashes the body bytes
    // into the ARCH-0019 row-n3 disambiguator: an escalation applied after it
    // would stage a body the short-id row no longer describes.
    // The match returns the escalated bytes it owns (rather than shadowing
    // `data` off a deferred local) so the owner can travel to the parent.
    let escalated_skill_body: Option<Vec<u8>> = match dispatch.new_skill_record.as_mut() {
        Some(updated) if !fixed.replicated && !fixed.hub_sync_imported => {
            if crate::skill_hub::scan_skill_admission(
                store,
                &*wtxn,
                &fixed.id,
                updated,
                fixed.hub_admission,
            )? {
                Some(crate::skill::encode_skill_record(updated)?)
            } else {
                None
            }
        }
        _ => None,
    };
    let data = escalated_skill_body.as_deref().unwrap_or(data);
    // STO-03: the sanitized TASK body replaces the inbound one from here on —
    // before short-id planning hashes it and before the old-record comparison
    // decides whether the body changed, so nothing downstream ever sees the
    // discarded counters.
    let data = task_body_without_streaks.as_deref().unwrap_or(data);
    let data = pad_stored_body.as_deref().unwrap_or(data);
    let reconciled_critical_claim_body =
        if fixed.replicated && fixed.entity_type == ENTITY_TYPE_CLAIM {
            reconcile_replicated_critical_confirm(
                store,
                wtxn,
                &fixed.id,
                data,
                &mut dispatch.decoded_claim_body,
            )?
        } else {
            None
        };
    let data = reconciled_critical_claim_body.as_deref().unwrap_or(data);
    // The AUTHORITY_LOG arm above already decoded the body and hashed it for
    // the store-key bind; reuse that hash instead of decoding a second time.
    let authority_first_seen_key = dispatch
        .authority_entry_hash_pin
        .as_ref()
        .map(crate::authority::authority_first_seen_sidecar_key);
    // Most maintenance-classified kinds (REDACTION_AUDIT) carry no short ID (static
    // registry `short_id_prefix: None`), matching the engine's direct receipt writer.
    // SECRET_CUSTODY is the exception: its `sc` handle names a secret without
    // holding it. Only engine doors and the internal sync path reach here with a
    // maintenance kind (public puts are rejected in `apply_ops`); skip short-id
    // planning for a kind with no prefix, which would otherwise fail with
    // `InvalidEntityType` on the missing prefix.
    let short_id_prefix = if dispatch.is_lexical_query_hint_claim {
        None
    } else if crate::registry::zone_of(fixed.entity_type)
        == crate::registry::TypeByteZone::PackHandle
    {
        Some(store.pack_short_id_prefix_in_txn(wtxn, fixed.entity_type, data)?)
    } else {
        store.short_id_prefix(fixed.entity_type).ok()
    };
    // A short reference hashes the logical body: a file-plane ASSET's facts,
    // never the manifest its row keeps (FIX 3677).
    let short_id_plan = if let Some(short_id_prefix) = short_id_prefix {
        Some(plan_short_id_update_hashed(
            store,
            &*wtxn,
            &fixed.id,
            fixed.entity_type,
            &short_id_prefix,
            fixed.options.storage.asset_file.map_or_else(
                || crate::batch::short_id_content_hash(data),
                |file| file.short_hash(),
            ),
        )?)
    } else {
        None
    };
    Ok(Rewrite {
        evicted_shell_sources,
        short_id_plan,
        authority_first_seen_key,
        escalated_skill_body,
        reconciled_critical_claim_body,
    })
}
