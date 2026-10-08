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
    journal: LoroDoc,
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
                journal: LoroDoc::new(),
                commits: 0,
                current: BTreeMap::new(),
                history: super::history::History::new(session, hub),
            }),
        }
    }

    fn server(&self) -> Result<std::sync::Arc<SyncServer>, AppError> {
        let server = self.server.upgrade().ok_or_else(AppError::unauthorized)?;
        self.auth.require(CoreScope::Read)?;
        if !self.auth.credential_is_live(server.vault().as_ref()) {
            return Err(AppError::unauthorized());
        }
        Ok(server)
    }
}

fn owner_feed_principal(
    auth: &CoreAuth,
    vault: &oneiron::Vault,
) -> Result<oneiron::EntityId, AppError> {
    if !auth.is_owner_grade() || auth.actor_class() != Some("human") {
        return Err(AppError::forbidden(
            "owner feed requires a human owner",
            ["Use an owner-grade human credential."],
        ));
    }
    let principal = auth.principal_ref().ok_or_else(AppError::unauthorized)?;
    let owner = oneiron::EntityId::from_hex(principal)
        .map_err(|_| AppError::bad_request("invalid owner principal", Some("principal_ref")))?;
    vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .verify_owner()
        .map_err(AppError::from)?;
    Ok(owner)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewFilter {
    limit: Option<usize>,
    kind: Option<String>,
    predicate: Option<String>,
}

impl LiveQuerySource for BoundSource {
    fn pending_at_open(
        &self,
        dependencies: &BTreeSet<String>,
    ) -> Result<Vec<oneiron::EntityId>, AppError> {
        let server = self.server()?;
        let mut missing = Vec::new();
        for path in dependencies {
            let Some(entity) = path
                .strip_prefix("e:")
                .and_then(|id| oneiron::EntityId::from_hex(id).ok())
            else {
                continue;
            };
            let live = server
                .vault()
                .get_raw(&entity)
                .map_err(|_| AppError::internal_server_error("live revision read failed"))?;
            let indexed = server
                .vault()
                .get_raw_with_mode(&entity, oneiron::memory::ReadMode::Indexed)
                .map_err(|_| AppError::internal_server_error("indexed revision read failed"))?;
            if live != indexed {
                missing.push(entity);
            }
        }
        Ok(missing)
    }

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
        // An owner feed is never a route to an agent's board. Reject its
        // subscription even before deriving or retaining any view state.
        if channel == Channel::OwnerFeed {
            owner_feed_principal(&self.auth, server.vault())?;
            if view.world_ref.is_some() || filter.limit.is_some() {
                return Err(AppError::bad_request(
                    "owner feed is vault-wide and unpaged",
                    Some("scopedView"),
                ));
            }
        }
        // The same verified principal/class pair binds RPC and subscription reads.
        let memory = bound_memory(server.vault(), &self.auth)?;
        let mut dependencies = BTreeSet::new();
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
                for item in &pack.items {
                    for id in &item.provenance.source_revision_ids {
                        if let Ok(id) = oneiron::EntityId::from_hex(id) {
                            dependencies.insert(format!("e:{}", id.to_hex()));
                        }
                    }
                }
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
            Channel::OwnerFeed => {
                dependencies.insert("owner-feed".to_owned());
                let owner = owner_feed_principal(&self.auth, server.vault())?;
                let mut updates = Vec::new();
                for watch in oneiron::saved_query::memory_watches(server.vault(), owner)
                    .map_err(|_| AppError::internal_server_error("memory watches read failed"))?
                {
                    // A query definition changing from inactive to active must
                    // invalidate an already-open feed, not only the watched row.
                    dependencies.insert(format!("e:{}", watch.query_ref.to_hex()));
                    let read = crate::api::scoped_read_for_core_auth(server.vault(), &self.auth)
                        .map_err(AppError::from)?;
                    let timeline = read.memory_timeline(&watch.anchor).map_err(|_| {
                        AppError::internal_server_error("watched timeline read failed")
                    })?;
                    for record in &timeline.value.records {
                        dependencies.insert(format!("e:{}", record.id.to_hex()));
                    }
                    let response = crate::api::core_memory_timeline_response(
                        &read,
                        timeline,
                        crate::projection::View::Full,
                    )
                    .map_err(AppError::from)?;
                    let response = serde_json::to_value(response).map_err(|_| {
                        AppError::internal_server_error("watched timeline encoding failed")
                    })?;
                    if response["records"]
                        .as_array()
                        .is_some_and(|rows| !rows.is_empty())
                    {
                        updates.push(
                            json!({"query_ref":watch.query_ref.to_hex(),"timeline":response}),
                        );
                    }
                }
                serde_json::to_value(updates)
            }
            Channel::MemoryBoard | Channel::Gap => {
                return Err(AppError::not_implemented("reserved subscription channel"));
            }
        }
        .map_err(|_| AppError::internal_server_error("view serialization failed"))?;
        let mut state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        // A view is pinned to the index publication of every served entity.
        // A live edit cannot move this cursor while its index is still behind.
        let indexed = dependencies
            .iter()
            .filter(|path| path.starts_with("e:"))
            .map(|path| {
                let id = oneiron::EntityId::from_hex(path.strip_prefix("e:").ok_or_else(|| {
                    AppError::internal_server_error("invalid indexed dependency")
                })?)
                .map_err(|_| AppError::internal_server_error("invalid indexed dependency"))?;
                Ok((
                    id.to_hex(),
                    server.vault().indexed_revision(&id).map_err(|_| {
                        AppError::internal_server_error("indexed position read failed")
                    })?,
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let encoded = serde_json::to_string(&(view, channel, &value, &indexed))
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
                state.journal = LoroDoc::new();
                state.commits = 0;
            }
            let indexed_bytes = rmp_serde::to_vec(&indexed)
                .map_err(|_| AppError::internal_server_error("indexed position encoding failed"))?;
            state
                .doc
                .get_map("indexed")
                .insert(&key, indexed_bytes.as_slice())
                .map_err(|_| AppError::internal_server_error("indexed position commit failed"))?;
            state
                .doc
                .get_map("views")
                .insert(&key, fingerprint.clone())
                .map_err(|_| AppError::internal_server_error("cursor commit failed"))?;
            state
                .doc
                .commit_with(CommitOptions::new().origin("livequery"));
            state.current.insert(key.clone(), fingerprint);
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
            // Membership is a separate probe, never a wildcard window read.
            // Current result rows use the entity-document index above.
            dependencies: {
                dependencies.insert(format!("membership:{key}"));
                dependencies
            },
        })
    }

    fn membership_changed(
        &self,
        view: &ScopedView,
        channel: Channel,
        diff: &oneiron::sync::bridge::MaterializedDiffSummary,
    ) -> Result<bool, AppError> {
        let server = self.server()?;
        super::membership::changed(server.vault(), &self.auth, view, channel, diff)
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
                .strip_prefix("e:")
                .or_else(|| path.rsplit('/').next())
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
        if channel == Channel::OwnerFeed {
            // Owner body history cannot be replayed safely after a later
            // policy change. Keep only the live subscription ring, which is
            // re-authorized before each delivery, not a retained payload log.
            return Ok(());
        }
        let mut state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        let CursorDocument {
            journal, history, ..
        } = &mut *state;
        if !history.record(journal, view, channel, pushes)? {
            // Expire Loro and payload retention together, so a missing journal
            // is never presented as a retained cursor with a silent gap.
            state.doc = LoroDoc::new();
            state.current.clear();
            state.history.clear();
            state.journal = LoroDoc::new();
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
        if channel == Channel::OwnerFeed {
            return Ok(None);
        }
        let state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        super::history::History::value_at(&state.journal, view, channel, cursor)
    }

    fn replay(
        &self,
        view: &ScopedView,
        channel: Channel,
        cursor: &Cursor,
    ) -> Result<Option<Vec<subscriptions::Push>>, AppError> {
        if channel == Channel::OwnerFeed {
            return Ok(None);
        }
        if !self.can_resume(cursor)? {
            return Ok(None);
        }
        let state = self
            .doc
            .lock()
            .map_err(|_| AppError::internal_server_error("cursor document unavailable"))?;
        super::history::History::replay(&state.journal, view, channel, cursor)
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
