//! The diary-review producer: a pending diary-read review wakes the reviewed
//! agent's STREAM connections (FIX 2879).
//!
//! A pending review already waits as a row of its agent's INBOX, and an
//! engine-native resident is dispatched for it. A foreign harness hears of it
//! here. After each commit, and when a connection attaches, the host reads
//! every pending review again with [`PendingDiaryReview::read_all`], outside
//! any lock, and hands the set to
//! [`BoardStreamRegistry::publish_diary_reviews`]. That queues one WAKE per
//! review on each connection of the reviewed agent (the review row's
//! `(agent, request)` key, never the reader) that has not had it yet.
//!
//! The wake names the review and nothing else: no reader, no reason, no
//! diary entry, and it grants no read. The agent opens the review through its
//! own doors and answers it with `self.memory.diary.review`. The adapter that
//! delivers the wake asks [`PendingDiaryReview::is_pending`] again and drops a
//! wake whose review was answered meanwhile. Nothing here runs inside the
//! write that opened the review, so a wake that does not go out never fails it.

use std::collections::{BTreeMap, BTreeSet};

use super::events::{BoardEvent, RouteObservation, SubscriptionScope};
use super::frames::StreamConnectionId;
use super::provenance::VerifiedDiaryReviewEvent;
use super::registry::BoardStreamRegistry;
use crate::{EntityId, Result, Vault};

/// The one line every review wake carries. It names no reader, reason or
/// entry: the review row holds those, behind the agent's own doors.
const REVIEW_WAKE_LINE: &str =
    "a read of your diary waits on your review; answer it with self.memory.diary.review";

/// One pending diary-read review, as the board STREAM sees it: the reviewed
/// agent and the request, read from the committed Pending row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDiaryReview {
    agent: EntityId,
    request: EntityId,
}

impl PendingDiaryReview {
    /// Every review that waits on its agent's answer now.
    pub fn read_all(vault: &Vault) -> Result<Vec<Self>> {
        Ok(vault
            .diary_read_inbox_items()?
            .into_iter()
            .filter_map(|item| {
                let review = item.diary_review?;
                Some(Self {
                    agent: item.actor_ref,
                    request: review.request,
                })
            })
            .collect())
    }

    /// Whether `agent`'s own review `request` still waits on its answer. The
    /// answer is the row's state and nothing of the row, so it grants no read
    /// of the diary or of the review.
    pub fn is_pending(vault: &Vault, agent: EntityId, request: EntityId) -> Result<bool> {
        Ok(Self::read_all(vault)?
            .into_iter()
            .any(|review| review.agent == agent && review.request == request))
    }

    /// The wake id of `agent`'s review `request`: the review's INBOX handle,
    /// `diary-read:<agent>:<request>`. A request is minted pending once and
    /// never returns to pending, so the id names one occurrence.
    #[must_use]
    pub fn wake_ref(agent: EntityId, request: EntityId) -> String {
        format!("diary-read:{}:{}", agent.to_hex(), request.to_hex())
    }
}

/// The connections each pending review was queued for.
#[derive(Debug, Default)]
pub(super) struct PublishedReviews {
    offered: BTreeMap<String, BTreeSet<StreamConnectionId>>,
}

impl PublishedReviews {
    /// Forgets what was queued for `connection` once its queue is gone, so
    /// a connection attached again under the same id hears each review anew.
    pub(super) fn forget(&mut self, connection: &StreamConnectionId) {
        self.offered.retain(|_, offered| {
            offered.remove(connection);
            !offered.is_empty()
        });
    }
}

impl BoardStreamRegistry {
    /// Queues a WAKE for each pending review on every connection of its
    /// reviewed agent that subscribes to [`SubscriptionScope::DiaryReviews`]
    /// and has not had that review yet, so a harness that attaches later
    /// still hears a review that waits.
    ///
    /// `pending` is the whole pending set, read after a commit. A review it
    /// no longer holds was answered and is forgotten here, since a request
    /// never returns to pending.
    pub fn publish_diary_reviews(&mut self, pending: Vec<PendingDiaryReview>) -> RouteObservation {
        let mut observed = RouteObservation::default();
        let live: BTreeSet<String> = pending
            .iter()
            .map(|review| PendingDiaryReview::wake_ref(review.agent, review.request))
            .collect();
        self.published_reviews
            .offered
            .retain(|event_ref, _| live.contains(event_ref));
        for review in pending {
            let event_ref = PendingDiaryReview::wake_ref(review.agent, review.request);
            let agent_ref = review.agent.to_hex();
            let fresh: BTreeSet<StreamConnectionId> = {
                let offered = self.published_reviews.offered.get(&event_ref);
                self.connections
                    .iter()
                    .filter(|(connection, state)| {
                        state.actor_ref == agent_ref
                            && state.subscribed.contains(&SubscriptionScope::DiaryReviews)
                            && !offered.is_some_and(|offered| offered.contains(*connection))
                    })
                    .map(|(connection, _)| connection.clone())
                    .collect()
            };
            if fresh.is_empty() {
                continue;
            }
            let routed = self.route_event_where(
                BoardEvent::DiaryReviewPending {
                    event: VerifiedDiaryReviewEvent {
                        agent_ref,
                        request_ref: review.request.to_hex(),
                        event_ref: event_ref.clone(),
                    },
                    line: REVIEW_WAKE_LINE.to_owned(),
                },
                |connection, _| fresh.contains(connection),
            );
            observed.wake_enqueued += routed.wake_enqueued;
            self.published_reviews
                .offered
                .entry(event_ref)
                .or_default()
                .extend(fresh);
        }
        observed
    }
}
