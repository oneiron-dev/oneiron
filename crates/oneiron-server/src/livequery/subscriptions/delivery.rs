//! How live query subscriptions are delivered: a refresh, and resyncs on published changes.
//! `LiveQueries::refresh` is its call surface, driven by the server's subscription loop.
//! The subscriptions root defines `LiveQueries` and its state, the records used here.
use super::*;

impl LiveQueries {
    /// Drive from the server's subscription loop, OUTSIDE Observer B.
    /// Facade reads such as recall may persist retrieval telemetry; doing
    /// that inside the materializer callback would re-enter Loro.
    pub(crate) fn refresh(&self) -> Result<(), AppError> {
        let (changes, lost) = self.tracker.take();
        if !lost.is_empty() {
            self.require_resync_scoped(&lost);
        }
        let mut ready = Vec::new();
        for row in changes {
            let by = row.contributors.first().cloned().unwrap_or_default();
            match self.source.ready(&row.diff, &by) {
                Ok(true) => ready.push((row.path, row.diff, row.contributors, row.live_only)),
                Ok(false) => self.tracker.record(&row.path, &row.diff, &by),
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
        // Local LMDB claim/SAVED_QUERY and notification (type-42 put and
        // mark) commits bypass Observer B. The owner feed re-derives on a
        // bounded cadence through its normal cursor owner. The notification
        // views re-derive as soon as a committed put or mark signals (FIX
        // 3084), and on the same cadence for a writer that commits one in a
        // raw transaction of its own and sends no signal.
        let notified = self.notifications_signalled();
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
        let local = |path: &str| {
            (
                path.to_owned(),
                MaterializedDiffSummary {
                    containers: Vec::new(),
                    bytes: 0,
                    revision_events: Vec::new(),
                },
                vec![OriginMark::default()],
                false,
            )
        };
        let mut local_paths = Vec::new();
        if poll {
            local_paths.push(local("owner-feed"));
        }
        if poll || notified {
            local_paths.push(local(NOTIFICATIONS_PATH));
        }
        if !local_paths.is_empty()
            && let Err(error) = self.materialized(&local_paths)
        {
            self.require_resync();
            return Err(error);
        }
        Ok(())
    }

    /// Whether the vault's committed-notification signal changed since this
    /// session last looked. The look marks it seen before the views
    /// re-derive, so a commit during the derive signals the next refresh: a
    /// burst coalesces into re-reads that end on the committed rows.
    fn notifications_signalled(&self) -> bool {
        let mut wake = self
            .notification_wake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        wake.as_mut().is_some_and(|wake| {
            let changed = wake.has_changed().unwrap_or(false);
            if changed {
                wake.mark_unchanged();
            }
            changed
        })
    }

    fn require_resync_scoped(&self, paths: &BTreeSet<String>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        for (id, sub) in &mut state.subs {
            let affected = paths.contains("*")
                || paths.iter().any(|path| {
                    sub.dependencies.contains(path)
                        || (sub
                            .dependencies
                            .iter()
                            .any(|dep| dep.starts_with("membership:"))
                            && self
                                .source
                                .membership_changed(
                                    &sub.view,
                                    sub.channel,
                                    &MaterializedDiffSummary {
                                        containers: vec![path.clone()],
                                        bytes: 0,
                                        revision_events: Vec::new(),
                                    },
                                )
                                .unwrap_or(true))
                });
            if !affected {
                continue;
            }
            sub.resync(*id);
        }
    }

    pub(in crate::livequery) fn on_indexed_published(
        &self,
        publication: oneiron::memory::IndexedPublication,
    ) {
        self.tracker.publish(publication);
    }

    fn require_resync(&self) {
        if let Ok(mut state) = self.state.lock() {
            for (id, sub) in &mut state.subs {
                sub.resync(*id);
            }
        }
    }
}

impl LiveQueryTee for LiveQueries {
    fn on_materialized(&self, path: &str, diff: &MaterializedDiffSummary, by: &OriginMark) {
        self.tracker.record(path, diff, by);
    }
}
