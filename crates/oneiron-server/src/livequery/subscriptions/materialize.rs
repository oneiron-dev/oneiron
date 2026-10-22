//! What a subscription's retained ring buffers and how a change materializes into its views.
//! `LiveQueries::buffered` is its call surface; `materialized` serves the root's refresh.
//! The subscriptions root defines `LiveQueries`, `Subscription` and `State`, the records used here.

use super::*;

impl LiveQueries {
    pub(crate) fn buffered(&self) -> Result<Vec<Push>, AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        let owner_ids: Vec<_> = state
            .subs
            .iter()
            .filter_map(|(id, sub)| {
                (sub.channel == Channel::OwnerFeed && !sub.needs_resync).then_some(*id)
            })
            .collect();
        for id in owner_ids {
            let sub = &state.subs[&id];
            let derived = self.source.derive(&sub.view, sub.channel)?;
            let fingerprint = fingerprint(&derived.value)?;
            // Even a queued snapshot from before a policy change is unsafe.
            // Compare EVERY retained result with a fresh scoped projection,
            // not merely the last fingerprint, before socket delivery.
            if fingerprint != sub.current
                || sub.ring.iter().any(|push| {
                    push.result
                        .as_ref()
                        .is_some_and(|result| result != &derived.value)
                })
            {
                let cursor = state.cursor(derived.cursor)?;
                let push = Push {
                    subscription_id: id,
                    cursor: cursor.clone(),
                    kind: "data",
                    rows: derived_rows(&derived.dependencies),
                    result: Some(derived.value),
                };
                let bytes = push_bytes(std::slice::from_ref(&push))?;
                let sub = state.subs.get_mut(&id).ok_or_else(state_error)?;
                sub.current = fingerprint;
                sub.dependencies = derived.dependencies;
                // Owner feeds are a coalesced latest-state projection. This
                // drops old bodies after either a local edit OR a policy
                // narrowing, then emits only the newly authorized value.
                // Neither transition requires the client to resubscribe.
                let retained = sub.coalesce_owner_ring()?;
                if retained
                    && bytes.saturating_add(sub.coalesced_bytes) <= MAX_RING_BYTES
                    && sub
                        .budget
                        .resize(sub.metadata_bytes + (bytes + sub.coalesced_bytes).max(4096))
                        .is_ok()
                {
                    sub.ring.push_back(push);
                    sub.bytes = bytes;
                } else {
                    // Only a true payload/cursor/budget overflow needs a gap.
                    sub.ring.clear();
                    sub.coalesced.clear();
                    sub.coalesced_bytes = 0;
                    sub.ring.push_back(Push {
                        subscription_id: id,
                        cursor,
                        kind: "gap",
                        result: None,
                        rows: Vec::new(),
                    });
                    sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                    sub.budget
                        .resize(sub.metadata_bytes + sub.bytes.max(4096))?;
                    sub.needs_resync = true;
                }
            }
        }
        // Owner feeds were re-derived above. Any other ring is re-judged
        // right before it is sent: one that names a row a device-local world
        // keeps since its derivation is retired for a gap.
        for (id, sub) in &mut state.subs {
            if sub.channel != Channel::OwnerFeed
                && !sub.needs_resync
                && self.source.withholds(sub.ring.make_contiguous())?
            {
                sub.resync(*id);
            }
        }
        Ok(state
            .subs
            .values()
            .flat_map(|sub| sub.ring.iter().cloned())
            .collect())
    }

    pub(super) fn materialized(
        &self,
        changes: &[(String, MaterializedDiffSummary, Vec<OriginMark>, bool)],
    ) -> Result<(), AppError> {
        let mut state = self.state.lock().map_err(|_| state_error())?;
        // Coarse re-derive sees CURRENT state, not intermediate event
        // states. Suppress only when EVERY affecting invalidation is our
        // own; an earlier own write must not swallow a later foreign one.
        let mut affected = BTreeMap::<u64, bool>::new();
        for (path, diff, contributors, live_only) in changes {
            for (dependency, ids) in &state.index {
                let relevant = dependency == path
                    || path
                        .strip_prefix(dependency.as_str())
                        .is_some_and(|tail| tail.starts_with('/'))
                    || dependency
                        .strip_prefix(path.as_str())
                        .is_some_and(|tail| tail.starts_with('/'))
                    || diff.containers.iter().any(|changed| changed == dependency);
                let membership = dependency.starts_with("membership:");
                if !relevant && !membership {
                    continue;
                }
                for id in ids {
                    if *live_only && state.subs[id].channel == Channel::View {
                        continue;
                    }
                    // The synthetic local-LMDB poll is not a Loro change.
                    // It must never re-derive unrelated recall/receipt subs.
                    if path == "owner-feed" && state.subs[id].channel != Channel::OwnerFeed {
                        continue;
                    }
                    // Likewise the local notification poll re-derives only
                    // notification views.
                    if path == NOTIFICATIONS_PATH
                        && state.subs[id].channel != Channel::Notifications
                    {
                        continue;
                    }
                    if !relevant
                        && !self.source.membership_changed(
                            &state.subs[id].view,
                            state.subs[id].channel,
                            diff,
                        )?
                    {
                        continue;
                    }
                    let own = !contributors.is_empty()
                        && contributors.iter().all(|by| {
                            by.conn_id == Some(state.conn_id)
                                || (by.origin.is_some() && by.origin == state.subs[id].origin)
                        });
                    affected
                        .entry(*id)
                        .and_modify(|echo| *echo &= own)
                        .or_insert(own);
                }
            }
        }
        for (id, echo) in affected {
            let sub = &state.subs[&id];
            if sub.needs_resync {
                continue;
            }
            let derived = self.source.derive(&sub.view, sub.channel)?;
            let current = fingerprint(&derived.value)?;
            let changed = sub.current != current;
            let cursor = state.cursor(derived.cursor)?;
            let rows = derived_rows(&derived.dependencies);
            let sub = state.subs.get_mut(&id).ok_or_else(state_error)?;
            sub.dependencies = derived.dependencies;
            sub.current = current;
            if echo || !changed {
                continue;
            }
            let push = Push {
                subscription_id: id,
                cursor: cursor.clone(),
                kind: "data",
                result: Some(derived.value),
                rows,
            };
            self.source
                .record(&sub.view, sub.channel, std::slice::from_ref(&push))?;
            let bytes = push_bytes(std::slice::from_ref(&push))?;
            let retained = if sub.channel == Channel::OwnerFeed {
                // Retire the old body, not its issued cursor. A delayed ACK
                // remains valid until an explicit bounded-retention gap.
                sub.coalesce_owner_ring()?
            } else {
                true
            };
            if !retained
                || sub.ring.len() >= LIVEQUERY_RING_CAPACITY
                || sub
                    .bytes
                    .saturating_add(bytes)
                    .saturating_add(sub.coalesced_bytes)
                    > MAX_RING_BYTES
                || sub
                    .budget
                    .resize(
                        sub.metadata_bytes + (sub.bytes + bytes + sub.coalesced_bytes).max(4096),
                    )
                    .is_err()
            {
                sub.ring.clear();
                sub.coalesced.clear();
                sub.coalesced_bytes = 0;
                let gap = Push {
                    subscription_id: id,
                    cursor,
                    kind: "gap",
                    result: None,
                    rows: Vec::new(),
                };
                sub.bytes = push_bytes(std::slice::from_ref(&gap))?;
                sub.budget
                    .resize(sub.metadata_bytes + sub.bytes.max(4096))?;
                sub.ring.push_back(gap);
                sub.needs_resync = true;
            } else {
                sub.bytes += bytes;
                sub.ring.push_back(push);
            }
        }
        state.reindex();
        Ok(())
    }
}
