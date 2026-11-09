//! The change feed verbs on the actor's surface (untangle slice 6.8d): each
//! opens this actor's read lane and calls the feeds door with it, so a
//! subscription is the lane's actor's own and every entry is judged by the
//! caller's grant when it is read.

use crate::claim::ClaimReadStatus;
use crate::entity_id::EntityId;
use crate::feeds::{
    FeedAckRequest, FeedPage, FeedReadRequest, FeedSubscribeRequest, FeedSubscription,
};
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// Subscribes this actor to a change feed (`vault.feeds.subscribe`).
    ///
    /// # Errors
    ///
    /// The read lane's actor checks; a selector that names no source or one
    /// source twice; storage errors.
    pub fn feed_subscribe(&self, input: &FeedSubscribeRequest) -> MemoryResult<FeedSubscription> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(self.vault.feed_subscribe(&lane, input)?)
    }

    /// This actor's subscriptions with their cursors (`vault.feeds.list`).
    ///
    /// # Errors
    ///
    /// The read lane's actor checks; storage errors.
    pub fn feed_subscriptions(&self) -> MemoryResult<Vec<FeedSubscription>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(self.vault.feed_subscriptions(&lane)?)
    }

    /// The next page of one of this actor's subscriptions, judged by the
    /// caller's read lane now; it moves no cursor (`vault.feeds.read`).
    ///
    /// # Errors
    ///
    /// The read lane's actor checks; a subscription that is not this actor's;
    /// storage errors.
    pub fn feed_read(&self, input: &FeedReadRequest) -> MemoryResult<FeedPage> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(self.vault.feed_read(&lane, input)?)
    }

    /// Moves one of this actor's subscriptions' cursors forward
    /// (`vault.feeds.ack`).
    ///
    /// # Errors
    ///
    /// The read lane's actor checks; a subscription that is not this actor's;
    /// a position in a source it does not follow, two in one source, or one
    /// past that source's head; storage errors.
    pub fn feed_ack(&self, input: &FeedAckRequest) -> MemoryResult<FeedSubscription> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(self.vault.feed_ack(&lane, input)?)
    }

    /// Ends one of this actor's subscriptions; `true` when it stood
    /// (`vault.feeds.unsubscribe`).
    ///
    /// # Errors
    ///
    /// The read lane's actor checks; storage errors.
    pub fn feed_unsubscribe(&self, subscription: EntityId) -> MemoryResult<bool> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        Ok(self.vault.feed_unsubscribe(&lane, subscription)?)
    }
}
