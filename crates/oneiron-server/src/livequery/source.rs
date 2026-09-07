//! Authority-bound coarse projection. The cursor document contains ONLY
//! derived app data, never a full sync window or an authority identifier.
use super::subscriptions::{DerivedView, LiveQuerySource, export_since};
use super::*;
use crate::server::SyncServer;
use loro::{CommitOptions, LoroDoc};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, Weak};

pub(super) struct BoundSource {
    server: Weak<SyncServer>,
    auth: CoreAuth,
    document: String,
    doc: Mutex<CursorDocument>,
}

struct CursorDocument {
    doc: LoroDoc,
    commits: usize,
    current: BTreeMap<String, String>,
    history: super::history::History,
}

impl BoundSource {
    #[cfg(test)]
    pub(super) fn new(server: Weak<SyncServer>, auth: CoreAuth, document: String) -> Self {
        Self::with_budgets(
            server,
            auth,
            document,
            budget::Budget::new(budget::SESSION_BYTES),
            budget::Budget::new(budget::HUB_BYTES),
        )
    }

    pub(super) fn with_budgets(
        server: Weak<SyncServer>,
        auth: CoreAuth,
        document: String,
        session: std::sync::Arc<budget::Budget>,
        hub: std::sync::Arc<budget::Budget>,
    ) -> Self {
        Self {
            server,
            auth,
            document,
            doc: Mutex::new(CursorDocument {
                doc: LoroDoc::new(),
                commits: 0,
                current: BTreeMap::new(),
                history: super::history::History::new(session, hub),
            }),
        }
    }

    fn server(&self) -> Result<std::sync::Arc<SyncServer>, AppError> {
        let server = self.server.upgrade().ok_or_else(AppError::unauthorized)?;
        self.auth.require(CoreScope::Read)?;
        if self
            .auth
            .jti()
            .is_some_and(|jti| crate::auth::is_revoked_or_unreadable(jti, server.vault().as_ref()))
        {
            return Err(AppError::unauthorized());
        }
        Ok(server)
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewFilter {
    limit: Option<usize>,
    kind: Option<String>,
    predicate: Option<String>,
}

impl LiveQuerySource for BoundSource {
    fn derive(&self, view: &ScopedView, channel: Channel) -> Result<DerivedView, AppError> {
        let server = self.server()?;
        let filter: ViewFilter =
            serde_json::from_value(view.filter.clone().unwrap_or_else(|| json!({})))
                .map_err(|_| AppError::bad_request("invalid scoped view filter", Some("filter")))?;
        let limit = reads::facade_limit(filter.limit, 100)?;
        if channel != Channel::View
            && (view.facet.is_some()
                || view.query.is_some()
                || filter.kind.is_some()
                || filter.predicate.is_some())
        {
            return Err(AppError::bad_request(
                "channel does not support query, facet, kind or predicate",
                Some("scopedView"),
            ));
        }
        // The same verified principal/class pair binds RPC and subscription reads.
        let memory = bound_memory(server.vault(), &self.auth)?;
        let value = match channel {
            Channel::View => {
                let scope = RecallScope {
                    world_ref: view.world_ref.clone(),
                    facet: view.facet.clone(),
                };
                let pack = memory
                    .recall_view(
                        view.query.as_deref().unwrap_or(""),
                        &scope,
                        filter.kind.as_deref(),
                        filter.predicate.as_deref(),
                        limit,
                    )
                    .map_err(AppError::from)?;
                // Do not publish out-of-scope-world accounting: a world-B
                // mutation must not produce a world-A push through metadata.
                serde_json::to_value(pack.items)
            }
            Channel::Receipts => serde_json::to_value(
                oneiron::sync::bridge::scoped_subscription_receipts(
                    server.vault(),
                    self.auth
                        .principal_ref()
                        .ok_or_else(AppError::unauthorized)?,
                    view.world_ref.as_deref(),
                    limit,
                )
                .map_err(|_| AppError::internal_server_error("scoped receipts read failed"))?,
            ),
            Channel::PendingConsent => serde_json::to_value(
                oneiron::sync::bridge::scoped_subscription_pending(
                    server.vault(),
                    self.auth
                        .principal_ref()
                        .ok_or_else(AppError::unauthorized)?,
                    view.world_ref.as_deref(),
                    limit,
                )
                .map_err(|_| AppError::internal_server_error("scoped consent read failed"))?,
            ),
            Channel::MemoryBoard | Channel::Gap => {
                return Err(AppError::not_implemented("reserved subscription channel"));
            }
        }
        .map_err(|_| AppError::internal_server_error("view serialization failed"))?;
        let mut state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        let encoded = serde_json::to_string(&(view, channel, &value))
            .map_err(|_| AppError::internal_server_error("view encoding failed"))?;
        if encoded.len() > 8 * 1024 * 1024 {
            return Err(AppError::bad_request(
                "view snapshot too large",
                Some("scopedView"),
            ));
        }
        let projection = serde_json::to_vec(&(view, channel))
            .map_err(|_| AppError::internal_server_error("view encoding failed"))?;
        let key = blake3::hash(&projection).to_hex().to_string();
        let fingerprint = blake3::hash(encoded.as_bytes()).to_hex().to_string();
        if state.current.get(&key) != Some(&fingerprint) {
            if !state.current.contains_key(&key)
                && state.current.len() >= subscriptions::MAX_SUBSCRIPTIONS
            {
                // Closed/replaced views cannot grow cursor metadata forever.
                // A new document has no retention for the old VVs.
                state.doc = LoroDoc::new();
                state.current.clear();
                state.history.clear();
                state.commits = 0;
            }
            state
                .doc
                .get_map("views")
                .insert(&key, fingerprint.clone())
                .map_err(|_| AppError::internal_server_error("cursor commit failed"))?;
            state
                .doc
                .commit_with(CommitOptions::new().origin("livequery"));
            state.current.insert(key, fingerprint);
            state.commits += 1;
            if state.commits >= super::subscriptions::LIVEQUERY_RING_CAPACITY {
                let snapshot = state
                    .doc
                    .export(loro::ExportMode::shallow_snapshot(
                        &state.doc.oplog_frontiers(),
                    ))
                    .map_err(|_| {
                        AppError::internal_server_error("cursor retention export failed")
                    })?;
                let retained = LoroDoc::new();
                retained.import(&snapshot).map_err(|_| {
                    AppError::internal_server_error("cursor retention import failed")
                })?;
                state.doc = retained;
                state.commits = 0;
            }
        }
        Ok(DerivedView {
            value,
            cursor: Cursor {
                document: self.document.clone(),
                version_vector: state.doc.oplog_vv().encode(),
                batch: 0,
            },
            // Coarse membership invalidation also covers inserts into empty
            // results and cross-window world/facet edges. Output comparison
            // suppresses changes outside the authorized scoped projection.
            dependencies: BTreeSet::from(["w:".to_owned()]),
        })
    }

    fn ready(
        &self,
        diff: &oneiron::sync::bridge::MaterializedDiffSummary,
        by: &oneiron::sync::bridge::OriginMark,
    ) -> Result<bool, AppError> {
        if by.origin.as_deref() != Some("deletion_tombstone") {
            return Ok(true);
        }
        let server = self.server()?;
        for path in &diff.containers {
            let id = path
                .rsplit('/')
                .next()
                .and_then(|id| oneiron::EntityId::from_hex(id).ok())
                .ok_or_else(|| AppError::internal_server_error("invalid purge dependency"))?;
            if !oneiron::sync::bridge::local_deletion_is_materialized(server.vault(), &id)
                .map_err(|_| AppError::internal_server_error("purge visibility read failed"))?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn record(
        &self,
        view: &ScopedView,
        channel: Channel,
        pushes: &[subscriptions::Push],
    ) -> Result<(), AppError> {
        let _server = self.server()?;
        let mut state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        let CursorDocument { doc, history, .. } = &mut *state;
        if !history.record(doc, view, channel, pushes)? {
            // Expire Loro and payload retention together, so a missing journal
            // is never presented as a retained cursor with a silent gap.
            state.doc = LoroDoc::new();
            state.current.clear();
            state.history.clear();
            state.commits = 0;
        }
        Ok(())
    }

    fn retained_value(
        &self,
        view: &ScopedView,
        channel: Channel,
        cursor: &Cursor,
    ) -> Result<Option<Value>, AppError> {
        let _server = self.server()?;
        let state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        super::history::History::value_at(&state.doc, view, channel, cursor)
    }

    fn replay(
        &self,
        view: &ScopedView,
        channel: Channel,
        cursor: &Cursor,
    ) -> Result<Option<Vec<subscriptions::Push>>, AppError> {
        if !self.can_resume(cursor)? {
            return Ok(None);
        }
        let state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        super::history::History::replay(&state.doc, view, channel, cursor)
    }

    fn can_resume(&self, cursor: &Cursor) -> Result<bool, AppError> {
        let _server = self.server()?;
        if cursor.document != self.document {
            loro::VersionVector::decode(&cursor.version_vector)
                .map_err(|_| AppError::bad_request("invalid cursor VV", Some("cursor")))?;
            return Ok(false);
        }
        let doc = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        let vv = loro::VersionVector::decode(&cursor.version_vector)
            .map_err(|_| AppError::bad_request("invalid cursor VV", Some("cursor")))?;
        if doc.current.is_empty() || doc.doc.oplog_vv().partial_cmp(&vv).is_none() {
            // A budget-expired document is empty until the next derivation.
            // Its old cursor is past retention, not a malformed future cursor.
            return Ok(false);
        }
        export_since(&doc.doc, cursor)
    }
}

#[cfg(test)]
mod remediation_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[tokio::test]
    async fn retained_loro_payloads_replay_after_delivery_ring_is_removed() {
        let (_dir, server) = super::super::production_tests::server();
        let auth = CoreAuth::from_bind_token(
            &super::super::production_tests::token("human"),
            &server.config,
            server.vault().as_ref(),
        )
        .unwrap();
        let source = std::sync::Arc::new(BoundSource::new(
            std::sync::Arc::downgrade(&server),
            auth,
            "retained".into(),
        ));
        let tier = subscriptions::LiveQueries::new(1, source.clone());
        let view = ScopedView::default();
        let opened = tier
            .open(7, view.clone(), Channel::Receipts, None, None)
            .unwrap();
        let anchor = opened[0].cursor.clone();
        // These are retained committed app projections; neither an RPC result
        // nor a raw sync-window update enters the journal.
        let mut next = source.derive(&view, Channel::Receipts).unwrap().cursor;
        next.batch = anchor.batch + 1;
        let push = subscriptions::Push {
            subscription_id: 7,
            cursor: next.clone(),
            kind: "data",
            result: Some(json!([1])),
        };
        source.record(&view, Channel::Receipts, &[push]).unwrap();
        assert!(source.can_resume(&anchor).unwrap());
        tier.close(7).unwrap();
        let replay = source
            .replay(&view, Channel::Receipts, &anchor)
            .unwrap()
            .unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].cursor, next);
        assert_eq!(replay[0].result, Some(json!([1])));
        assert!(
            source
                .replay(&view, Channel::PendingConsent, &anchor)
                .unwrap()
                .is_none()
        );
        // The subscription owner uses the source journal, not gap+snapshot,
        // even though its delivery ring no longer exists.
        let reopened = tier
            .open(7, view, Channel::Receipts, Some(&anchor), None)
            .unwrap();
        assert!(
            !reopened
                .iter()
                .any(|push| push.kind == "gap" || push.kind == "snapshot")
        );
        assert_eq!(reopened[0].result, Some(json!([1])));
    }

    #[tokio::test]
    async fn journal_budget_expiry_expires_the_cursor_without_allocating_unbounded_history() {
        let (_dir, server) = super::super::production_tests::server();
        let auth = CoreAuth::from_bind_token(
            &super::super::production_tests::token("human"),
            &server.config,
            server.vault().as_ref(),
        )
        .unwrap();
        let source = BoundSource::with_budgets(
            std::sync::Arc::downgrade(&server),
            auth,
            "bounded".into(),
            budget::Budget::new(1),
            budget::Budget::new(1),
        );
        let view = ScopedView::default();
        let cursor = source.derive(&view, Channel::Receipts).unwrap().cursor;
        source
            .record(
                &view,
                Channel::Receipts,
                &[subscriptions::Push {
                    subscription_id: 7,
                    cursor: cursor.clone(),
                    kind: "snapshot",
                    result: Some(json!([])),
                }],
            )
            .unwrap();
        assert!(!source.can_resume(&cursor).unwrap());
    }

    #[tokio::test]
    async fn alternating_unchanged_views_do_not_consume_retention() {
        let (_dir, server) = super::super::production_tests::server();
        let auth = CoreAuth::from_bind_token(
            &super::super::production_tests::token("human"),
            &server.config,
            server.vault().as_ref(),
        )
        .unwrap();
        let source = BoundSource::new(std::sync::Arc::downgrade(&server), auth, "fixture".into());
        let a = ScopedView::default();
        let b = ScopedView {
            world_ref: Some("22222222222222222222222222222222".into()),
            ..Default::default()
        };
        let first = source.derive(&a, Channel::Receipts).unwrap();
        let second = source.derive(&b, Channel::Receipts).unwrap();
        for _ in 0..subscriptions::LIVEQUERY_RING_CAPACITY {
            source.derive(&a, Channel::Receipts).unwrap();
            let latest = source.derive(&b, Channel::Receipts).unwrap();
            assert_eq!(latest.cursor.version_vector, second.cursor.version_vector);
        }
        assert_eq!(source.doc.lock().unwrap().commits, 2);
        assert!(source.can_resume(&first.cursor).unwrap());
    }
}
