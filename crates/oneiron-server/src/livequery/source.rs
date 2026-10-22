//! Authority-bound coarse projection. The cursor document contains ONLY
//! derived app data, never a full sync window or an authority identifier.
use super::subscriptions::{DerivedView, LiveQuerySource, export_since};
use super::*;
use crate::server::SyncServer;
use loro::{CommitOptions, LoroDoc};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, Weak};

mod projection;

pub(super) struct BoundSource {
    server: Weak<SyncServer>,
    auth: CoreAuth,
    document: String,
    doc: Mutex<CursorDocument>,
}

/// Views one cursor document keeps positions for before it starts afresh:
/// a resume past it falls to a gap and a fresh snapshot, never a refusal.
const RETAINED_VIEWS: usize = 4_096;

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
        Self::with_budget(server, auth, document, budget::Budget::of(64 * 1024 * 1024))
    }

    pub(super) fn with_budget(
        server: Weak<SyncServer>,
        auth: CoreAuth,
        document: String,
        budget: std::sync::Arc<budget::Budget>,
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
                history: super::history::History::new(budget),
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

#[cfg(test)]
mod remediation_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[tokio::test]
    async fn retained_loro_payloads_replay_after_delivery_ring_is_removed() {
        let (_dir, server) = super::super::production_tests::server();
        let auth = crate::test_credentials::authenticate(
            &server,
            &super::super::production_tests::token("human"),
        );
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
            rows: Vec::new(),
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
        let auth = crate::test_credentials::authenticate(
            &server,
            &super::super::production_tests::token("human"),
        );
        // Retention past a full line expires; it is never refused.
        let line = budget::Budget::of(1);
        let _full = budget::Reservation::new(line.clone(), 1).unwrap();
        let source = BoundSource::with_budget(
            std::sync::Arc::downgrade(&server),
            auth,
            "bounded".into(),
            line,
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
                    rows: Vec::new(),
                }],
            )
            .unwrap();
        assert!(!source.can_resume(&cursor).unwrap());
    }

    #[tokio::test]
    async fn alternating_unchanged_views_do_not_consume_retention() {
        let (_dir, server) = super::super::production_tests::server();
        let auth = crate::test_credentials::authenticate(
            &server,
            &super::super::production_tests::token("human"),
        );
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
