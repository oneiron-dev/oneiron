//! Authority-bound coarse projection. The cursor document contains ONLY
//! derived app data, never a full sync window or an authority identifier.
use super::subscriptions::{DerivedView, LiveQuerySource, export_since};
use super::*;
use crate::server::SyncServer;
use loro::{CommitOptions, LoroDoc};
use std::collections::BTreeSet;
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
    current: Option<String>,
}

impl BoundSource {
    pub(super) fn new(server: Weak<SyncServer>, auth: CoreAuth, document: String) -> Self {
        Self {
            server,
            auth,
            document,
            doc: Mutex::new(CursorDocument {
                doc: LoroDoc::new(),
                commits: 0,
                current: None,
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
                let mut pack = memory
                    .recall(
                        view.query.as_deref().unwrap_or(""),
                        Effort::Minimal,
                        &scope,
                        limit,
                        None,
                        None,
                    )
                    .map_err(AppError::from)?;
                pack.items.retain(|item| {
                    // Per-world subscription is stricter than recall's world+base scope.
                    item.world.as_ref() == view.world_ref.as_ref()
                        && view
                            .facet
                            .as_ref()
                            .is_none_or(|facet| item.facet.as_ref() == Some(facet))
                        && filter.kind.as_ref().is_none_or(|kind| &item.kind == kind)
                        && filter
                            .predicate
                            .as_ref()
                            .is_none_or(|predicate| item.predicate.as_ref() == Some(predicate))
                });
                // Do not publish out-of-scope-world accounting: a world-B
                // mutation must not produce a world-A push through metadata.
                serde_json::to_value(pack.items)
            }
            Channel::Receipts => {
                let mut rows = memory.receipts(limit).map_err(AppError::from)?;
                rows.retain(|row| row.actor_ref == self.auth.principal_ref().map(str::to_owned));
                let mut scoped = Vec::new();
                for row in rows {
                    if claim_in_world(
                        server.vault(),
                        row.claim_ref.as_deref(),
                        view.world_ref.as_deref(),
                    )? {
                        scoped.push(row);
                    }
                }
                serde_json::to_value(scoped)
            }
            Channel::PendingConsent => {
                let rows = memory.pending_writes(limit).map_err(AppError::from)?;
                let mut scoped = Vec::new();
                for row in rows {
                    if claim_in_world(
                        server.vault(),
                        Some(&row.claim_ref),
                        view.world_ref.as_deref(),
                    )? {
                        scoped.push(row);
                    }
                }
                serde_json::to_value(scoped)
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
        let encoded = serde_json::to_string(&(view, channel, &value))
            .map_err(|_| AppError::internal_server_error("view encoding failed"))?;
        if encoded.len() > 8 * 1024 * 1024 {
            return Err(AppError::bad_request(
                "view snapshot too large",
                Some("scopedView"),
            ));
        }
        // One key bounds current state even after arbitrarily many closes and
        // reopens. This document's delta is used only for server-side resume
        // validation; it is NEVER a subscription payload.
        let fingerprint = blake3::hash(encoded.as_bytes()).to_hex().to_string();
        if state.current.as_ref() != Some(&fingerprint) {
            state
                .doc
                .get_map("views")
                .insert("snapshot", fingerprint.clone())
                .map_err(|_| AppError::internal_server_error("cursor commit failed"))?;
            state
                .doc
                .commit_with(CommitOptions::new().origin("livequery"));
            state.current = Some(fingerprint);
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
        export_since(&doc.doc, cursor)
    }
}

fn claim_in_world(
    vault: &oneiron::Vault,
    claim: Option<&str>,
    world: Option<&str>,
) -> Result<bool, AppError> {
    let Some(claim) = claim else {
        return Ok(world.is_none());
    };
    let id = oneiron::EntityId::from_hex(claim)
        .map_err(|_| AppError::internal_server_error("invalid claim reference"))?;
    let claim = vault
        .get_claim(&id)
        .map_err(|_| AppError::internal_server_error("claim scope read failed"))?;
    Ok(claim.is_some_and(|claim| claim.world.map(|id| id.to_hex()).as_deref() == world))
}
