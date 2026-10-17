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
        // mark) commits bypass Observer B. Poll only the owner feed and the
        // notification views on a bounded cadence through their normal
        // cursor owner.
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
        if poll
            && let Err(error) =
                self.materialized(&[local("owner-feed"), local(NOTIFICATIONS_PATH)])
        {
            self.require_resync();
            return Err(error);
        }
        Ok(())
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
