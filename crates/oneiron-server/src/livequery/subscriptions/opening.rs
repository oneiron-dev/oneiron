//! How a live query subscription opens: admitted, derived, budgeted and registered in one turn.
//! `LiveQueries::open_in_turn` is its call surface.
//! The subscriptions root defines `LiveQueries`, `Subscription` and `State`, the records used here.

use super::*;

impl LiveQueries {
    /// Opens subscription `id` holding `turn`, its turn under
    /// `limits.live_subscriptions`; a reopen keeps the turn it held.
    pub(crate) fn open_in_turn(
        &self,
        id: u64,
        view: ScopedView,
        channel: Channel,
        cursor: Option<&Cursor>,
        origin: Option<String>,
        turn: Option<Permit>,
    ) -> Result<Vec<Push>, AppError> {
        if matches!(channel, Channel::MemoryBoard | Channel::Gap) {
            return Err(AppError::not_implemented("reserved subscription channel"));
        }
        if let Some(world) = &view.world_ref {
            oneiron::EntityId::from_hex(world)
                .map_err(|_| AppError::bad_request("invalid worldRef", Some("scopedView")))?;
        }
        let mut state = self.state.lock().map_err(|_| state_error())?;
        let new_subscription = !state.subs.contains_key(&id);
        let mut latest = None;
        // A reopened subscription keeps the turn it held.
        let mut turn = turn;
        // Owner-feed snapshots contain claim bodies. Never replay a retained
        // body after a reconnect: policy may have narrowed while this slip
        // remained live. A gap + newly scoped snapshot is the safe resume.
        if channel == Channel::OwnerFeed
            && let Some(sub) = state.subs.get(&id)
        {
            if sub.view != view || sub.channel != channel {
                return Err(AppError::bad_request(
                    "subscription id is already open",
                    Some("subscriptionId"),
                ));
            }
            if cursor.is_none() {
                return Err(AppError::bad_request(
                    "subscription is already open",
                    Some("subscriptionId"),
                ));
            }
            if let Some(old) = state.subs.remove(&id) {
                turn = old.turn.or(turn);
            }
            state.reindex();
        }
        if let Some(sub) = state.subs.get_mut(&id) {
            if sub.view != view || sub.channel != channel {
                return Err(AppError::bad_request(
                    "subscription id is already open",
                    Some("subscriptionId"),
                ));
            }
            if let Some(cursor) = cursor {
                // A retained ring may predate an indexed publication. Re-read
                // the authorized view before returning it, even for an acked
                // cursor: the hub may not have drained the notice yet.
                if self.source.can_resume(cursor)? && !sub.needs_resync {
                    let derived = self.source.derive(&view, channel)?;
                    let tail = if sub.acked.as_ref() == Some(cursor) {
                        Some(0)
                    } else {
                        sub.ring
                            .iter()
                            .rposition(|p| &p.cursor == cursor)
                            .map(|position| position + 1)
                    };
                    // A retained push that names a row a device-local world
                    // keeps since, or one its caller no longer reads (FIX
                    // 9493), is not sent again: the resume falls to a gap and
                    // a fresh snapshot.
                    if fingerprint(&derived.value)? == sub.current
                        && let Some(tail) = tail
                        && !self.source.withholds(&sub.ring.make_contiguous()[tail..])?
                        && self.source.readmits(&sub.ring.make_contiguous()[tail..])?
                    {
                        sub.origin = origin;
                        if tail > 0 {
                            sub.ring.drain(..tail);
                            sub.bytes = push_bytes(sub.ring.make_contiguous())?;
                            sub.budget
                                .resize(sub.bytes.max(4096) + sub.metadata_bytes)?;
                            sub.acked = Some(cursor.clone());
                        }
                        return Ok(sub.ring.iter().cloned().collect());
                    }
                    latest = Some(derived);
                }
            } else {
                return Err(AppError::bad_request(
                    "subscription is already open",
                    Some("subscriptionId"),
                ));
            }
        }
        // The old ring must release its budget before replay plus the fresh
        // indexed tail reserve theirs. A failed replay leaves no stale owner.
        if let Some(old) = state.subs.remove(&id) {
            turn = old.turn.or(turn);
            state.reindex();
        }
        let derived = if let Some(derived) = latest {
            derived
        } else {
            self.source.derive(&view, channel)?
        };
        if new_subscription && channel == Channel::View {
            let served: BTreeSet<String> = derived
                .dependencies
                .difference(&derived.followed)
                .cloned()
                .collect();
            let missing = self.source.pending_at_open(&served)?;
            self.tracker.mark_unavailable_at_open(&missing);
        }
        if channel != Channel::OwnerFeed
            && let Some(cursor) = cursor
            && self.source.can_resume(cursor)?
            && let Some(mut replay) = self.source.replay(&view, channel, cursor)?
            && !self.source.withholds(&replay)?
            && self.source.readmits(&replay)?
        {
            for push in &mut replay {
                push.subscription_id = id;
            }
            if let Some(last) = replay.last() {
                state.batch = state.batch.max(last.cursor.batch);
            }
            let previous = replay
                .iter()
                .rev()
                .find_map(|push| push.result.clone())
                .or(self.source.retained_value(&view, channel, cursor)?);
            if previous.as_ref().is_some_and(|last| last != &derived.value) {
                let catch_up = Push {
                    subscription_id: id,
                    cursor: state.cursor(derived.cursor.clone())?,
                    kind: "data",
                    result: Some(derived.value.clone()),
                    rows: derived_rows(&derived.dependencies),
                };
                self.source
                    .record(&view, channel, std::slice::from_ref(&catch_up))?;
                replay.push(catch_up);
            }
            let bytes = push_bytes(&replay)?;
            if bytes <= MAX_RING_BYTES && replay.len() <= LIVEQUERY_RING_CAPACITY {
                let metadata_bytes = serde_json::to_vec(&(&view, &origin))
                    .map_err(|_| state_error())?
                    .len()
                    .saturating_mul(8)
                    + 4096;
                let budget =
                    Reservation::new(self.budget.clone(), bytes.max(4096) + metadata_bytes)?;
                state.subs.insert(
                    id,
                    Subscription {
                        view,
                        channel,
                        origin,
                        dependencies: derived.dependencies,
                        current: fingerprint(&derived.value)?,
                        metadata_bytes,
                        budget,
                        ring: replay.iter().cloned().collect(),
                        bytes,
                        coalesced: VecDeque::new(),
                        coalesced_bytes: 0,
                        acked: Some(cursor.clone()),
                        needs_resync: false,
                        turn,
                    },
                );
                state.reindex();
                return Ok(replay);
            }
        }
        let next_cursor = state.cursor(derived.cursor)?;
        let mut pushes = Vec::new();
        if cursor.is_some() {
            pushes.push(Push {
                subscription_id: id,
                cursor: next_cursor.clone(),
                kind: "gap",
                result: None,
                rows: Vec::new(),
            });
        }
        pushes.push(Push {
            subscription_id: id,
            cursor: next_cursor.clone(),
            kind: "snapshot",
            result: Some(derived.value.clone()),
            rows: derived_rows(&derived.dependencies),
        });
        pushes.push(Push {
            subscription_id: id,
            cursor: next_cursor,
            kind: "eose",
            result: None,
            rows: Vec::new(),
        });
        let bytes = push_bytes(&pushes)?;
        if bytes > MAX_RING_BYTES {
            return Err(AppError::bad_request(
                "view snapshot too large",
                Some("scopedView"),
            ));
        }
        let metadata_bytes = serde_json::to_vec(&(&view, &origin))
            .map_err(|_| state_error())?
            .len()
            .saturating_mul(8)
            + 4096;
        let budget = Reservation::new(self.budget.clone(), bytes.max(4096) + metadata_bytes)?;
        let current = fingerprint(&derived.value)?;
        self.source.record(&view, channel, &pushes)?;
        state.subs.insert(
            id,
            Subscription {
                view,
                channel,
                origin,
                dependencies: derived.dependencies,
                current,
                metadata_bytes,
                budget,
                ring: pushes.iter().cloned().collect(),
                bytes,
                coalesced: VecDeque::new(),
                coalesced_bytes: 0,
                acked: None,
                needs_resync: false,
                turn,
            },
        );
        state.reindex();
        Ok(pushes)
    }
}
