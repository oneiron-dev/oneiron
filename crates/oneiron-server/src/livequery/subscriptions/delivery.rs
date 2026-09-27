use super::*;

impl LiveQueries {
    /// Drive from the server's subscription loop, OUTSIDE Observer B.
    /// Facade reads such as recall may persist retrieval telemetry; doing
    /// that inside the materializer callback would re-enter Loro.
    pub(crate) fn refresh(&self) -> Result<(), AppError> {
        let changes = {
            let mut pending = self.invalidations.lock().map_err(|_| state_error())?;
            std::mem::take(&mut *pending)
        };
        if self.invalidation_gap.swap(false, Ordering::AcqRel) {
            self.require_resync();
            return Ok(());
        }
        let mut ready = Vec::new();
        for (path, diff, by) in changes {
            match self.source.ready(&diff, &by) {
                Ok(true) => ready.push((path, diff, by)),
                Ok(false) => self.on_materialized(&path, &diff, &by),
                Err(error) => {
                    self.require_resync();
                    return Err(error);
                }
            }
        }
        if let Err(error) = self.materialized(&ready) {
            self.require_resync();
            return Err(error);
        }
        // Local LMDB claim/SAVED_QUERY commits do not pass through the Loro
        // materialization tee. Re-derive the owner-only feed on a bounded
        // cadence, through the same retained sub and cursor machinery. A
        // durable watch therefore works after restart and on local writes too.
        let poll = {
            let mut last = self
                .last_owner_feed_poll
                .lock()
                .map_err(|_| state_error())?;
            if last.elapsed() >= Duration::from_secs(1) {
                *last = Instant::now();
                true
            } else {
                false
            }
        };
        if poll
            && let Err(error) = self.materialized(&[(
                "owner-feed".to_owned(),
                MaterializedDiffSummary {
                    containers: Vec::new(),
                    bytes: 0,
                },
                OriginMark::default(),
            )])
        {
            self.require_resync();
            return Err(error);
        }
        Ok(())
    }

    fn require_resync(&self) {
        if let Ok(mut state) = self.state.lock() {
            for (id, sub) in &mut state.subs {
                if let Some(cursor) = sub
                    .ring
                    .back()
                    .map(|p| p.cursor.clone())
                    .or_else(|| sub.acked.clone())
                {
                    sub.ring.clear();
                    sub.coalesced.clear();
                    sub.coalesced_bytes = 0;
                    sub.ring.push_back(Push {
                        subscription_id: *id,
                        cursor,
                        kind: "gap",
                        result: None,
                    });
                    sub.bytes = push_bytes(sub.ring.make_contiguous()).unwrap_or(4096);
                    let _ = sub.budget.resize(sub.metadata_bytes + sub.bytes.max(4096));
                }
                sub.needs_resync = true;
            }
        }
    }
}

impl LiveQueryTee for LiveQueries {
    fn on_materialized(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        let Ok(mut pending) = self.invalidations.lock() else {
            self.invalidation_gap.store(true, Ordering::Release);
            return;
        };
        // Bound invalidation metadata independently of every subscription
        // ring. An overflow loses history explicitly, never silently.
        let bytes: usize = pending
            .iter()
            .map(|(path, diff, by)| {
                path.len()
                    + by.origin.as_ref().map_or(0, String::len)
                    + 128
                    + diff
                        .containers
                        .iter()
                        .map(|path| path.len() + 32)
                        .sum::<usize>()
            })
            .sum();
        let changed_paths = diff.containers.as_slice();
        let incoming = path.len()
            + by.origin.as_ref().map_or(0, String::len)
            + 128
            + changed_paths
                .iter()
                .map(|path| path.len() + 32 + 66)
                .sum::<usize>();
        if pending.len() >= LIVEQUERY_RING_CAPACITY || bytes.saturating_add(incoming) > 64 * 1024 {
            pending.clear();
            self.invalidation_gap.store(true, Ordering::Release);
            return;
        }
        // Entity-indexed subscriptions need the key delta even on an ordinary
        // commit. Bound it before cloning, and normalize deletion publications
        // that still originate from the window transport.
        let mut containers: BTreeSet<String> = changed_paths.iter().cloned().collect();
        for changed in changed_paths {
            if (changed.contains("/entities/") || changed.contains("/tombstones/"))
                && let Some(id) = changed.rsplit('/').next()
                && let Ok(id) = oneiron::EntityId::from_hex(id)
            {
                containers.insert(format!("e:{}", id.to_hex()));
            }
        }
        pending.push_back((
            path.to_owned(),
            MaterializedDiffSummary {
                containers: containers.into_iter().collect(),
                bytes: diff.bytes,
            },
            by.clone(),
        ));
    }
}
