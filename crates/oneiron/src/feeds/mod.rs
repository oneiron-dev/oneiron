//! Change feeds (untangle slice 6.8, primitive B; ARCH-0080 §4 Sources and cursors).
//!
//! Any actor subscribes to what changed in the vault and reads it from a durable cursor of its
//! own. Four sources: edits and withdrawals of every entity kind from the store's change log;
//! settled proposals from the settlement feed the fact hooks follow; edges added and removed; and
//! redirty notices, a TURN whose words changed with no new version of its own. A subscription is
//! a cursor per source, not a copy of the rows: a read pages the sources after the cursor, an ack
//! moves it.
//!
//! - **The grant is checked at delivery.** Each entry is shown only when the subscriber's own read
//!   lane, at read time, shows its entity: an edit at the revision it left (or as it stands, once
//!   that revision is gone), a settlement at its pinned revision, an edge when both its ends are
//!   shown, a redirty notice when its TURN is, and a withdrawal only where the lane may learn the
//!   row is gone ([`ScopedRead::withdrawals_revealed_in`], the rule a short reference to an
//!   erased row follows). A narrowed grant hides entries written before it narrowed. Nothing is
//!   frozen at subscribe.
//! - **Positions are commit order, never a timestamp.** The change log's ids and each feed's
//!   sequence are drawn inside the writer that commits the row, so a reader that resumes after its
//!   last position misses nothing that commits later.
//! - **A reader sees no sign of what it is not shown** (lead call K, 10 Nov). A page counts no
//!   withheld entry. Every position a reader is given is a token its subscription seals
//!   (AES-256-GCM, a fresh nonce each time, the subscription's own key), so it names no sequence
//!   and no time, and two tokens for one position differ. A page gives one token per source
//!   whether or not anything was scanned, and `more` says only that the page is full.
//! - **A cursor idle past retention gets a gap, never a skip** (lead call K). A cursor in a pruned
//!   source not acknowledged for [`FEED_RETENTION_SECS`] no longer holds the prune floor, and its
//!   subscription's reads answer [`FeedRead::Gap`] until [`Vault::feed_resync`]: the reader takes
//!   a snapshot and resyncs. The rule reads the cursor's age alone, never which rows went.
//! - **One cursor mechanism.** The change log positions and the settlement feed are the fact
//!   hooks' own. A subscription following settlements counts as that feed's reader, so it records
//!   settlements while hooks are off, and its prune keeps every row a subscription has not
//!   acknowledged. The edge and redirty feeds are written only while a subscription follows them,
//!   in the change's own commit, and the same housekeeping prune takes the rows every follower
//!   acknowledged. An erase scrubs every feed row that names an erased id.
//! - **The cursor commits with what the subscriber made of it.** [`ack_feed_in_txn`] moves a
//!   cursor inside a caller's write, so a derivation and the ack of what it read land together
//!   (slice 6.7's `feed_ack`).
//!
//! The verbs `vault.feeds.subscribe`, `.read`, `.ack` and `.unsubscribe` land in slice 6.8d, after
//! the per-verb sources (slice 4.2); until then these are the engine's doors.

mod edges;
pub(crate) mod tables;

use std::collections::BTreeSet;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::claim::{PointRead, ScopedRead};
use crate::error::ClaimError;
use crate::ports::{ChangeLogStoreRead, ChangeOp, EntityStoreRead};
use crate::runtime_hooks::{ClaimChangelogPosition, FactPosition, FactSource, SettlementPosition};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EntityId, Error, Result, Vault};

pub(crate) use edges::{record_edge_change_in_txn, record_redirty_in_txn};

/// One subscription row per actor and subscription.
const SUBSCRIPTIONS: SideTable<(EntityId, EntityId), SubscriptionRow, Named> =
    SideTable::new(&side_table::FEED_SUBSCRIPTION);

/// One cursor row per subscription and source.
const CURSORS: SideTable<(EntityId, [u8; 1]), CursorRow, Named> =
    SideTable::new(&side_table::FEED_CURSOR);

/// One row per source and subscription following it.
const FOLLOWING: SideTable<([u8; 1], EntityId), (), Named> =
    SideTable::new(&side_table::FEED_FOLLOWING);

/// The type of each entity a physical delete removed while the change log was followed.
const WITHDRAWN_TYPES: SideTable<EntityId, WithdrawnType, Named> =
    SideTable::new(&side_table::FEED_WITHDRAWN_TYPE);

/// Entries one read returns from each source when the request names no limit.
pub const FEED_READ_DEFAULT_LIMIT: usize = 64;
/// The most entries one read returns from each source.
pub const FEED_READ_MAX_LIMIT: usize = 256;
/// Change log rows a read may scan for each entry it returns, so a run of rows the selector
/// passes over cannot make one read unbounded. The page's `through` still moves past them.
const SCAN_PER_ENTRY: usize = 16;

/// How long a cursor in a pruned source stays held without an acknowledgement, in seconds on
/// the vault's recording clock (lead call K, 10 Nov). Past it the prune no longer keeps the rows
/// it has not acknowledged, and its subscription's reads answer [`FeedRead::Gap`]. An ack
/// refreshes a cursor even when it moves nothing, so a reader that acks each page never lapses.
pub const FEED_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// A sealed position's text prefix: the token format's version.
const TOKEN_PREFIX: &str = "fp1.";
/// A sealed position's nonce: AES-GCM's 96 bits, fresh for each token.
const TOKEN_NONCE_BYTES: usize = 12;
/// What a sealed position is bound to beside its subscription.
const TOKEN_CONTEXT: &[u8] = b"oneiron.feeds.position.v1";
/// Every sealed position's plain text is padded to this length (the longest, a change log
/// position), so a token's length tells neither its source nor whether it stands at the start.
const TOKEN_PLAIN_BYTES: usize = 40;

/// Where a feed's entries come from. Each source has its own cursor.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FeedSource {
    /// The store's change log: every entity write, in commit order.
    Changes,
    /// Settled proposals, in settlement order: the fact hooks' settlement feed.
    Settlements,
    /// Edges added and removed, in commit order.
    Edges,
    /// TURNs whose words changed with no new version of their own, in commit order.
    Redirty,
}

impl FeedSource {
    pub const ALL: [Self; 4] = [Self::Changes, Self::Settlements, Self::Edges, Self::Redirty];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changes => "changes",
            Self::Settlements => "settlements",
            Self::Edges => "edges",
            Self::Redirty => "redirty",
        }
    }

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|source| source.as_str() == name)
    }

    /// Whether a prune takes this source's rows: the change log keeps every row, so its cursors
    /// never lapse.
    const fn pruned(self) -> bool {
        !matches!(self, Self::Changes)
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Changes => 0,
            Self::Settlements => 1,
            Self::Edges => 2,
            Self::Redirty => 3,
        }
    }

    const fn of_fact_source(source: FactSource) -> Option<Self> {
        match source {
            FactSource::ClaimChangelog => Some(Self::Changes),
            FactSource::Settlement => Some(Self::Settlements),
            FactSource::Schedule | FactSource::SurfaceInbound => None,
        }
    }

    /// The newest position in this source, or `None` while it holds nothing, in `txn`.
    fn head_in_txn(self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<Position>> {
        Ok(match self {
            Self::Changes => crate::runtime_hooks::fact_source_head_in_txn(
                vault,
                txn,
                FactSource::ClaimChangelog,
            )?
            .map(Position::Fact),
            Self::Settlements => {
                crate::runtime_hooks::fact_source_head_in_txn(vault, txn, FactSource::Settlement)?
                    .map(Position::Fact)
            }
            Self::Edges => edges::edge_head_in_txn(&vault.store, txn)?.map(Position::Edges),
            Self::Redirty => edges::redirty_head_in_txn(&vault.store, txn)?.map(Position::Redirty),
        })
    }
}

/// A position in one source. Two positions compare only within one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Position {
    /// A change log or settlement feed position: the hooks' own.
    Fact(FactPosition),
    /// An edge feed sequence.
    Edges(u64),
    /// A redirty feed sequence.
    Redirty(u64),
}

/// What an entry says happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedEntryKind {
    /// An entity was created or written again: a create, an update, a supersession, a merge or
    /// a tier move.
    Edit,
    /// An entity was deleted, redacted or forgotten: a source anything derived from it stands on
    /// is withdrawn.
    Withdrawal,
    /// A proposal was settled.
    Settlement,
    /// An edge was added or removed.
    Edge,
    /// A TURN's words changed with no new version of its own: what was derived from them is
    /// due again.
    Redirty,
}

/// The write behind an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedOp {
    Create,
    Update,
    Supersede,
    Merge,
    TierTransition,
    Delete,
    Redact,
    Forget,
    Settle,
    EdgeAdded,
    EdgeRemoved,
    Redirty,
}

impl FeedOp {
    const fn of_change(op: ChangeOp) -> Self {
        match op {
            ChangeOp::Create => Self::Create,
            ChangeOp::Update => Self::Update,
            ChangeOp::Supersede => Self::Supersede,
            ChangeOp::Merge => Self::Merge,
            ChangeOp::TierTransition => Self::TierTransition,
            ChangeOp::Delete => Self::Delete,
            ChangeOp::Redact => Self::Redact,
            ChangeOp::Forget => Self::Forget,
        }
    }

    const fn kind(self) -> FeedEntryKind {
        match self {
            Self::Create | Self::Update | Self::Supersede | Self::Merge | Self::TierTransition => {
                FeedEntryKind::Edit
            }
            Self::Delete | Self::Redact | Self::Forget => FeedEntryKind::Withdrawal,
            Self::Settle => FeedEntryKind::Settlement,
            Self::EdgeAdded | Self::EdgeRemoved => FeedEntryKind::Edge,
            Self::Redirty => FeedEntryKind::Redirty,
        }
    }
}

/// A position in one source. A reader is given only opaque tokens its subscription sealed
/// (`fp1.` and base64): they name no sequence and no time. Inside the engine a cursor keeps the
/// plain text `changes:<32 hex>`, `settlements:<16 hex>`, `edges:<16 hex>` or `redirty:<16 hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct FeedPosition(pub String);

impl FeedPosition {
    fn of(position: Position) -> Result<Self> {
        let (source, bytes) = match position {
            Position::Fact(position) => (
                FeedSource::of_fact_source(position.source()).ok_or(Error::InvariantViolation(
                    "a feed position names a hook-only source",
                ))?,
                position.bytes(),
            ),
            Position::Edges(sequence) => (FeedSource::Edges, sequence.to_be_bytes().to_vec()),
            Position::Redirty(sequence) => (FeedSource::Redirty, sequence.to_be_bytes().to_vec()),
        };
        Ok(Self(format!(
            "{}:{}",
            source.as_str(),
            crate::receipt::hex_lower(&bytes)
        )))
    }

    /// The source and the typed position this text names.
    fn parse(&self) -> Result<(FeedSource, Position)> {
        let (source, hex) = self
            .0
            .split_once(':')
            .ok_or_else(|| invalid("a feed position is <source>:<hex>"))?;
        let sequence = || {
            crate::deletion::parse_hex::<8>(hex)
                .map(u64::from_be_bytes)
                .ok_or_else(|| invalid("a feed sequence position is 16 hex"))
        };
        match source {
            "changes" => Ok((
                FeedSource::Changes,
                Position::Fact(FactPosition::ClaimChangelog(ClaimChangelogPosition(
                    crate::deletion::parse_hex::<16>(hex)
                        .ok_or_else(|| invalid("a changes position is 32 hex"))?,
                ))),
            )),
            "settlements" => Ok((
                FeedSource::Settlements,
                Position::Fact(FactPosition::Settlement(SettlementPosition(sequence()?))),
            )),
            "edges" => Ok((FeedSource::Edges, Position::Edges(sequence()?))),
            "redirty" => Ok((FeedSource::Redirty, Position::Redirty(sequence()?))),
            _ => Err(invalid("unknown feed source")),
        }
    }
}

/// What a subscription follows. Every list but `sources` is a narrowing; an empty one takes all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedSelector {
    /// The sources it follows; at least one.
    pub sources: Vec<FeedSource>,
    /// The entry kinds it takes.
    #[serde(default)]
    pub kinds: Vec<FeedEntryKind>,
    /// The entity type bytes it takes: an edge's by its source end.
    #[serde(default)]
    pub entity_types: Vec<u8>,
    /// Predicate globs (`*` matches any run) a claim's edit or settlement must match; with any
    /// glob, no other entity's edit or settlement passes. A withdrawn claim's predicate went with
    /// its body, so withdrawals, edges and redirty notices pass this list.
    #[serde(default)]
    pub predicates: Vec<String>,
}

/// Where a new subscription starts.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FeedStart {
    /// After everything committed so far.
    #[default]
    Head,
    /// Before the oldest row each source still holds.
    Beginning,
}

/// A request to subscribe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedSubscribeRequest {
    pub selector: FeedSelector,
    #[serde(default)]
    pub start: FeedStart,
}

/// One subscription as its actor reads it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedSubscription {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub subscription: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub actor: EntityId,
    pub selector: FeedSelector,
    /// When it was made, on the vault's recording clock.
    pub created_at: u64,
    /// Each source's cursor, one sealed token per source in selector order.
    pub cursors: Vec<FeedPosition>,
}

/// A request to read a subscription's next page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedReadRequest {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub subscription: EntityId,
    /// Entries to return from each source, at most [`FEED_READ_MAX_LIMIT`];
    /// [`FEED_READ_DEFAULT_LIMIT`] when absent.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// An edge an entry names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedEdge {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub source: EntityId,
    /// The edge kind's snake_case name.
    pub kind: String,
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub target: EntityId,
}

/// One change a subscriber may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedEntry {
    pub position: FeedPosition,
    pub kind: FeedEntryKind,
    pub op: FeedOp,
    /// The entity the change is to: an edge's source end.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub entity: EntityId,
    pub entity_type: u8,
    /// Who made the write, where the source records it: the change log and the settlement feed
    /// do; the edge and redirty feeds do not.
    #[serde(with = "crate::serialize::entity_ref::optional")]
    #[schemars(with = "Option<String>")]
    pub actor: Option<EntityId>,
    /// When it committed, on the vault's recording clock.
    pub recorded_at: u64,
    /// The retained revision the write left, when it still stands.
    pub revision: Option<RevisionRef>,
    /// The edge, for an edge entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<FeedEdge>,
}

/// One page of a subscription. It moves no cursor: [`Vault::feed_ack`] does, with `through`.
/// It carries no sign of entries the subscriber's lane did not show: no count, no marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedPage {
    pub entries: Vec<FeedEntry>,
    /// One sealed token per source, in selector order: where the page ends, the positions to ack.
    pub through: Vec<FeedPosition>,
    /// The page is full: read again now. A page that is not full may still be followed by
    /// entries on the next read.
    pub more: bool,
}

/// What a read of a subscription answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FeedRead {
    /// The next page.
    Page(FeedPage),
    /// A cursor lay idle past [`FEED_RETENTION_SECS`], so rows it had not acknowledged may be
    /// gone. No page is read until the reader takes a snapshot and calls [`Vault::feed_resync`].
    Gap(FeedGap),
}

/// The typed gap answer: resync from a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedGap {
    pub resync_from: FeedResyncFrom,
}

/// Where a reader past a gap rebuilds what it follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedResyncFrom {
    /// A snapshot read of the vault as it stands.
    Snapshot,
}

/// A request to move a subscription's cursors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedAckRequest {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub subscription: EntityId,
    /// One sealed token per source to move to, from this subscription's pages. A position at or
    /// before the cursor moves nothing, and still refreshes it.
    pub through: Vec<FeedPosition>,
}

/// The stored subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SubscriptionRow {
    selector: FeedSelector,
    created_at: u64,
    /// The key this subscription seals the positions it gives with; never shown.
    seal: [u8; 32],
}

/// The type a physical delete's row had, kept for the withdrawal's judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WithdrawnType {
    entity_type: u8,
}

/// The stored cursor: the last position acknowledged, `None` at the source's start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CursorRow {
    position: Option<FeedPosition>,
    updated_at: u64,
}

impl CursorRow {
    /// Whether this cursor in `source` lay idle past retention at `now`.
    fn lapsed(&self, source: FeedSource, now: u64) -> bool {
        source.pruned() && now.saturating_sub(self.updated_at) > FEED_RETENTION_SECS
    }

    fn position(&self) -> Result<Option<Position>> {
        self.position
            .as_ref()
            .map(|position| position.parse().map(|(_, position)| position))
            .transpose()
    }
}

/// The lowest cursor of every subscription following one source, as the fact hooks' feed prune
/// reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedFloor {
    /// No subscription follows the source.
    Unfollowed,
    /// A subscription stands at the source's start: nothing may go.
    AtStart,
    /// Every subscription stands at or past this position.
    At(FactPosition),
}

impl Vault {
    /// Subscribes `reader`'s actor to `request.selector`, its cursors placed at
    /// `request.start`. Nothing is read: the grant is judged at each read.
    ///
    /// # Errors
    ///
    /// A selector with no source, a repeated source or an empty predicate glob, or the write.
    pub fn feed_subscribe(
        &self,
        reader: &ScopedRead<'_>,
        request: &FeedSubscribeRequest,
    ) -> Result<FeedSubscription> {
        validate_selector(&request.selector)?;
        let subscription = EntityId::now();
        self.with_write_txn(|txn| {
            let actor = live_reader_actor_in(reader, txn)?;
            let at = self.store.clock.now_recorded_at();
            let mut seal = [0_u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seal);
            let row = SubscriptionRow {
                selector: request.selector.clone(),
                created_at: at,
                seal,
            };
            SUBSCRIPTIONS.put(&self.store, txn, &(actor, subscription), &row)?;
            for source in &request.selector.sources {
                let position = match request.start {
                    FeedStart::Head => source.head_in_txn(self, txn)?,
                    FeedStart::Beginning => None,
                };
                let cursor = CursorRow {
                    position: position.map(FeedPosition::of).transpose()?,
                    updated_at: at,
                };
                CURSORS.put(&self.store, txn, &(subscription, [source.tag()]), &cursor)?;
                FOLLOWING.put(&self.store, txn, &([source.tag()], subscription), &())?;
            }
            subscription_view_in_txn(self, txn, actor, subscription, row)
        })
    }

    /// `reader`'s actor's subscriptions, oldest first.
    ///
    /// # Errors
    ///
    /// The read, or a stored row that does not decode.
    pub fn feed_subscriptions(&self, reader: &ScopedRead<'_>) -> Result<Vec<FeedSubscription>> {
        let txn = self.store.env.read_txn()?;
        let actor = live_reader_actor_in(reader, &txn)?;
        let mut rows = Vec::new();
        for row in SUBSCRIPTIONS.iter_from(&self.store, &txn, actor.as_bytes())? {
            let ((_, subscription), row) = row?;
            rows.push(subscription_view_in_txn(
                self,
                &txn,
                actor,
                subscription,
                row,
            )?);
        }
        rows.sort_by_key(|row| (row.created_at, row.subscription));
        Ok(rows)
    }

    /// The next page of `reader`'s subscription: each source's entries after its cursor that
    /// the selector takes, each shown only where `reader`'s lane shows it now, with no sign of
    /// any it did not show. It moves no cursor. A subscription with a cursor idle past
    /// [`FEED_RETENTION_SECS`] answers [`FeedRead::Gap`] until [`Vault::feed_resync`].
    ///
    /// # Errors
    ///
    /// `EntityNotFound` when the subscription is not this actor's, a limit of zero, or the read.
    pub fn feed_read(
        &self,
        reader: &ScopedRead<'_>,
        request: &FeedReadRequest,
    ) -> Result<FeedRead> {
        let limit = request.limit.unwrap_or(FEED_READ_DEFAULT_LIMIT);
        if limit == 0 {
            return Err(invalid("a feed read's limit is at least 1"));
        }
        let limit = limit.min(FEED_READ_MAX_LIMIT);
        let _bodies = reader.prepare_point_read::<Error>()?;
        let txn = self.store.env.read_txn()?;
        let actor = live_reader_actor_in(reader, &txn)?;
        let row = SUBSCRIPTIONS
            .get(&self.store, &txn, &(actor, request.subscription))?
            .ok_or(Error::EntityNotFound)?;
        let now = self.store.clock.now_recorded_at();
        let mut cursors = Vec::with_capacity(row.selector.sources.len());
        for source in &row.selector.sources {
            let cursor = CURSORS
                .get(&self.store, &txn, &(request.subscription, [source.tag()]))?
                .ok_or(Error::CorruptedIndex(
                    "feed subscription without its cursor",
                ))?;
            if cursor.lapsed(*source, now) {
                return Ok(FeedRead::Gap(FeedGap {
                    resync_from: FeedResyncFrom::Snapshot,
                }));
            }
            cursors.push((*source, cursor));
        }
        let mut page = FeedPage {
            entries: Vec::new(),
            through: Vec::with_capacity(cursors.len()),
            more: false,
        };
        for (source, cursor) in cursors {
            let after = cursor.position()?;
            let scanned = match source {
                FeedSource::Changes => changes_after_in_txn(self, &txn, after, limit)?,
                FeedSource::Settlements => settlements_after_in_txn(self, &txn, after, limit)?,
                FeedSource::Edges => edges::edges_after_in_txn(self, &txn, after, limit)?,
                FeedSource::Redirty => edges::redirty_after_in_txn(self, &txn, after, limit)?,
            };
            // One token per source, scanned or not, so a page gives no sign of what it passed.
            let through = match scanned.through {
                Some(position) => Some(FeedPosition::of(position)?),
                None => cursor.position,
            };
            page.through.push(seal_position(
                &row,
                request.subscription,
                source,
                through.as_ref(),
            )?);
            let shown = shown_in_txn(reader, &txn, &row.selector, scanned.entries)?;
            page.more |= shown.len() >= limit;
            for mut entry in shown {
                entry.position =
                    seal_position(&row, request.subscription, source, Some(&entry.position))?;
                page.entries.push(entry);
            }
        }
        Ok(FeedRead::Page(page))
    }

    /// Moves `reader`'s subscription's cursors to `request.through`, in one write.
    ///
    /// # Errors
    ///
    /// `EntityNotFound` when the subscription is not this actor's; a position in a source it does
    /// not follow, two positions in one source, or one past that source's head; or the write.
    pub fn feed_ack(
        &self,
        reader: &ScopedRead<'_>,
        request: &FeedAckRequest,
    ) -> Result<FeedSubscription> {
        self.with_write_txn(|txn| {
            let actor = live_reader_actor_in(reader, txn)?;
            ack_feed_in_txn(self, txn, actor, request)?;
            let row = SUBSCRIPTIONS
                .get(&self.store, txn, &(actor, request.subscription))?
                .ok_or(Error::EntityNotFound)?;
            subscription_view_in_txn(self, txn, actor, request.subscription, row)
        })
    }

    /// Moves every cursor of `reader`'s subscription to its source's head and refreshes it, in
    /// one write: the way back past a [`FeedRead::Gap`]. The reader takes its snapshot first, so
    /// a change that lands between the two is in the snapshot or in the next page.
    ///
    /// # Errors
    ///
    /// `EntityNotFound` when the subscription is not this actor's, or the write.
    pub fn feed_resync(
        &self,
        reader: &ScopedRead<'_>,
        subscription: EntityId,
    ) -> Result<FeedSubscription> {
        self.with_write_txn(|txn| {
            let actor = live_reader_actor_in(reader, txn)?;
            let row = SUBSCRIPTIONS
                .get(&self.store, txn, &(actor, subscription))?
                .ok_or(Error::EntityNotFound)?;
            let at = self.store.clock.now_recorded_at();
            for source in &row.selector.sources {
                let cursor = CursorRow {
                    position: source
                        .head_in_txn(self, txn)?
                        .map(FeedPosition::of)
                        .transpose()?,
                    updated_at: at,
                };
                CURSORS.put(&self.store, txn, &(subscription, [source.tag()]), &cursor)?;
            }
            subscription_view_in_txn(self, txn, actor, subscription, row)
        })
    }

    /// Ends `reader`'s subscription: its row, its cursors and its following rows go in one write,
    /// so no feed keeps rows for it. `false` when it was not this actor's or is gone.
    ///
    /// # Errors
    ///
    /// The write.
    pub fn feed_unsubscribe(
        &self,
        reader: &ScopedRead<'_>,
        subscription: EntityId,
    ) -> Result<bool> {
        self.with_write_txn(|txn| {
            let actor = live_reader_actor_in(reader, txn)?;
            if !SUBSCRIPTIONS.delete(&self.store, txn, &(actor, subscription))? {
                return Ok(false);
            }
            forget_subscription_in_txn(&self.store, txn, subscription)?;
            forget_withdrawn_types_unless_followed_in_txn(&self.store, txn)?;
            Ok(true)
        })
    }
}

/// Moves `actor`'s subscription's cursors to `request.through` inside the caller's write, so a
/// derivation commits with the ack of what it read (slice 6.7). A position at or before a cursor
/// moves nothing and refreshes it, as every named cursor is refreshed.
///
/// # Errors
///
/// `EntityNotFound` when the subscription is not `actor`'s; a token this subscription did not
/// seal, one in a source it does not follow, two in one source, or one past that source's head;
/// a cursor idle past [`FEED_RETENTION_SECS`] (resync first); or the write.
pub(crate) fn ack_feed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    request: &FeedAckRequest,
) -> Result<()> {
    let row = SUBSCRIPTIONS
        .get(&vault.store, txn, &(actor, request.subscription))?
        .ok_or(Error::EntityNotFound)?;
    let mut seen = Vec::with_capacity(request.through.len());
    let at = vault.store.clock.now_recorded_at();
    for token in &request.through {
        let (source, position) = open_position(&row, request.subscription, token)?;
        if !row.selector.sources.contains(&source) {
            return Err(invalid(
                "a feed ack names a source its subscription does not follow",
            ));
        }
        if seen.contains(&source) {
            return Err(invalid("a feed ack names one source twice"));
        }
        seen.push(source);
        let key = (request.subscription, [source.tag()]);
        let current = CURSORS
            .get(&vault.store, txn, &key)?
            .ok_or(Error::CorruptedIndex(
                "feed subscription without its cursor",
            ))?;
        if current.lapsed(source, at) {
            return Err(invalid(
                "a feed cursor lay idle past retention: resync from a snapshot first",
            ));
        }
        let moved = match position {
            Some(position) => {
                let head = source.head_in_txn(vault, txn)?;
                if head.is_none_or(|head| position > head) {
                    return Err(invalid("a feed ack moves past its source's head"));
                }
                current
                    .position()?
                    .is_none_or(|current| current < position)
                    .then_some(position)
            }
            None => None,
        };
        let cursor = CursorRow {
            position: match moved {
                Some(position) => Some(FeedPosition::of(position)?),
                None => current.position,
            },
            updated_at: at,
        };
        CURSORS.put(&vault.store, txn, &key, &cursor)?;
    }
    Ok(())
}

/// Seals `raw`, a position in `source` or its start, for the reader of `subscription`: a fresh
/// nonce each time, so the token names no sequence and no time, and two tokens for one position
/// differ.
fn seal_position(
    row: &SubscriptionRow,
    subscription: EntityId,
    source: FeedSource,
    raw: Option<&FeedPosition>,
) -> Result<FeedPosition> {
    let plain = match raw {
        Some(raw) => raw.0.clone(),
        None => format!("{}:", source.as_str()),
    };
    if plain.len() > TOKEN_PLAIN_BYTES {
        return Err(Error::InvariantViolation(
            "a feed position too long to seal",
        ));
    }
    let plain = format!("{plain:<width$}", width = TOKEN_PLAIN_BYTES);
    let mut nonce = [0_u8; TOKEN_NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let sealed = token_cipher(row)?
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plain.as_bytes(),
                aad: &token_aad(subscription),
            },
        )
        .map_err(|_| Error::InvariantViolation("feed position seal"))?;
    let mut bytes = Vec::with_capacity(TOKEN_NONCE_BYTES + sealed.len());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&sealed);
    Ok(FeedPosition(format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )))
}

/// Opens a token `subscription` sealed: its source, and its position, `None` at the source's
/// start.
fn open_position(
    row: &SubscriptionRow,
    subscription: EntityId,
    token: &FeedPosition,
) -> Result<(FeedSource, Option<Position>)> {
    let foreign = || invalid("a feed position this subscription did not give");
    let bytes = token
        .0
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|body| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .ok()
        })
        .filter(|bytes| bytes.len() > TOKEN_NONCE_BYTES)
        .ok_or_else(foreign)?;
    let (nonce, sealed) = bytes.split_at(TOKEN_NONCE_BYTES);
    let plain = token_cipher(row)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: &token_aad(subscription),
            },
        )
        .map_err(|_| foreign())?;
    let text = String::from_utf8(plain).map_err(|_| foreign())?;
    let text = text.trim_end();
    match text.strip_suffix(':').and_then(FeedSource::named) {
        Some(source) => Ok((source, None)),
        None => {
            let (source, position) = FeedPosition(text.to_owned()).parse()?;
            Ok((source, Some(position)))
        }
    }
}

fn token_cipher(row: &SubscriptionRow) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(&row.seal).map_err(|_| Error::InvariantViolation("feed position key"))
}

fn token_aad(subscription: EntityId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TOKEN_CONTEXT.len() + 16);
    aad.extend_from_slice(TOKEN_CONTEXT);
    aad.extend_from_slice(subscription.as_bytes());
    aad
}

/// Keeps, in a physical delete's own write, the type of entity `id` whose row it removes, while a
/// subscription follows the change log (review #6897 round 2): the change log's delete names no
/// type, and a withdrawal is judged by it. Without a follower it writes nothing.
///
/// # Errors
///
/// The follower read or the write.
pub(crate) fn remember_withdrawn_type_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if !changes_followed_in_txn(store, txn)? || erase_fenced_in_txn(store, txn, id)? {
        return Ok(());
    }
    WITHDRAWN_TYPES.put(store, txn, id, &WithdrawnType { entity_type })
}

/// Whether an erase fences `id` in this write: its permanent hard-delete marker, or a cleanup
/// archive's marker. The hook carriers keep such an id out by the same rule
/// (`runtime_hooks::store::source_erased_in_txn`). An erase scrubs the feed rows naming `id`
/// before its tear, so a feed write the tear makes after the scrub (a cascaded edge removal, a
/// withdrawn type) keeps the id out too, and the erase leaves no feed row naming it (review
/// #6942).
///
/// # Errors
///
/// The marker reads.
pub(crate) fn erase_fenced_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    use crate::ports::{DeletionMarker, TombstoneStoreRead};
    Ok(
        store.port_deletion_marked(txn, DeletionMarker::HardDelete, id)?
            || store.port_deletion_marked(txn, DeletionMarker::Archive, id)?,
    )
}

/// Whether any subscription follows the change log in `txn`: one seek.
fn changes_followed_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    source_followed_in_txn(store, txn, FeedSource::Changes)
}

/// Whether `subscription` is `actor`'s, read in `txn`: a feed-woken turn program names one of its
/// own actor's (slice 6.8c).
pub(crate) fn subscription_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    subscription: EntityId,
) -> Result<bool> {
    SUBSCRIPTIONS.contains(&vault.store, txn, &(actor, subscription))
}

/// Rows a feed-woken program's wake looks at, at most, in each source after its cursor (slice
/// 6.8c).
const WAKE_SCAN_ROWS: usize = 16 * FEED_READ_MAX_LIMIT;

/// What wakes a feed-woken program (slice 6.8c, lead call K), judged as `reader`'s reads would
/// be: `None` when nothing `reader` is shown waits after the cursors; otherwise a mark of the
/// last entry each source would show it, so the program wakes once per set of entries it can
/// see and never for a change its lane does not show. A cursor idle past retention marks the gap
/// its read would answer, which shows no row either. `None` too when the subscription is not
/// `reader`'s.
///
/// # Errors
///
/// The read.
pub(crate) fn feed_wake_mark(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    subscription: EntityId,
) -> Result<Option<String>> {
    let _bodies = reader.prepare_point_read::<Error>()?;
    let txn = vault.store.env.read_txn()?;
    let actor = live_reader_actor_in(reader, &txn)?;
    let Some(row) = SUBSCRIPTIONS.get(&vault.store, &txn, &(actor, subscription))? else {
        return Ok(None);
    };
    let now = vault.store.clock.now_recorded_at();
    let mut marks = Vec::new();
    for source in &row.selector.sources {
        let cursor = CURSORS
            .get(&vault.store, &txn, &(subscription, [source.tag()]))?
            .ok_or(Error::CorruptedIndex(
                "feed subscription without its cursor",
            ))?;
        if cursor.lapsed(*source, now) {
            return Ok(Some(format!("gap:{}", cursor.updated_at)));
        }
        let mut after = cursor.position()?;
        let mut looked = 0;
        let mut last = None;
        while looked < WAKE_SCAN_ROWS {
            let scanned = match source {
                FeedSource::Changes => {
                    changes_after_in_txn(vault, &txn, after, FEED_READ_MAX_LIMIT)?
                }
                FeedSource::Settlements => {
                    settlements_after_in_txn(vault, &txn, after, FEED_READ_MAX_LIMIT)?
                }
                FeedSource::Edges => {
                    edges::edges_after_in_txn(vault, &txn, after, FEED_READ_MAX_LIMIT)?
                }
                FeedSource::Redirty => {
                    edges::redirty_after_in_txn(vault, &txn, after, FEED_READ_MAX_LIMIT)?
                }
            };
            let Some(through) = scanned.through else {
                break;
            };
            looked += scanned.entries.len().max(1);
            if let Some(shown) = shown_in_txn(reader, &txn, &row.selector, scanned.entries)?.pop() {
                last = Some(shown.position.0);
            }
            after = Some(through);
        }
        marks.extend(last);
    }
    Ok((!marks.is_empty()).then(|| marks.join("\n")))
}

/// Whether any subscription follows `source` in `txn`: the fact hooks' feed then records each
/// fact of it, hooks on or off.
pub(crate) fn followed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
) -> Result<bool> {
    let Some(source) = FeedSource::of_fact_source(source) else {
        return Ok(false);
    };
    source_followed_in_txn(&vault.store, txn, source)
}

/// Whether any subscription follows `source` in `txn`: one seek.
fn source_followed_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: FeedSource,
) -> Result<bool> {
    Ok(FOLLOWING
        .iter_from(store, txn, &[source.tag()])?
        .next()
        .transpose()?
        .is_some())
}

/// The lowest cursor of every subscription following `source`, read in `txn`.
pub(crate) fn floor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: FactSource,
) -> Result<FeedFloor> {
    let Some(source) = FeedSource::of_fact_source(source) else {
        return Ok(FeedFloor::Unfollowed);
    };
    Ok(match source_floor_in_txn(&vault.store, txn, source)? {
        SourceFloor::Unfollowed => FeedFloor::Unfollowed,
        SourceFloor::AtStart => FeedFloor::AtStart,
        SourceFloor::At(Position::Fact(position)) => FeedFloor::At(position),
        SourceFloor::At(_) => {
            return Err(Error::CorruptedIndex(
                "a hook source's floor names a feed sequence",
            ));
        }
    })
}

/// The lowest cursor of every subscription following one source.
enum SourceFloor {
    Unfollowed,
    AtStart,
    At(Position),
}

fn source_floor_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: FeedSource,
) -> Result<SourceFloor> {
    let mut floor = SourceFloor::Unfollowed;
    let now = store.clock.now_recorded_at();
    for key in FOLLOWING.scan_keys(store, txn, &[source.tag()])? {
        let (_, subscription) = key;
        let cursor = CURSORS
            .get(store, txn, &(subscription, [source.tag()]))?
            .ok_or(Error::CorruptedIndex("feed follower without its cursor"))?;
        // A cursor idle past retention holds nothing: its subscription answers a gap.
        if cursor.lapsed(source, now) {
            continue;
        }
        let Some(position) = cursor.position()? else {
            return Ok(SourceFloor::AtStart);
        };
        floor = match floor {
            SourceFloor::At(held) if held <= position => SourceFloor::At(held),
            _ => SourceFloor::At(position),
        };
    }
    Ok(floor)
}

/// The housekeeping prune of the feeds this module owns, beside the hooks' own: each takes the
/// edge and redirty rows at or below the lowest cursor of every subscription following it, or
/// every row while none does, at most `max_rows` a feed, in one write only when there are any.
/// A subscription made after the plan starts at the feed head, past every planned row.
///
/// # Errors
///
/// The read or the write.
pub(crate) fn prune_feeds(vault: &Vault, max_rows: usize) -> Result<()> {
    let planned = {
        let rtxn = vault.store.env.read_txn()?;
        let mut planned = Vec::new();
        for source in [FeedSource::Edges, FeedSource::Redirty] {
            let floor = match source_floor_in_txn(&vault.store, &rtxn, source)? {
                SourceFloor::AtStart => continue,
                SourceFloor::Unfollowed => None,
                SourceFloor::At(position) => Some(position),
            };
            let rows = edges::passed_rows_in_txn(&vault.store, &rtxn, source, floor, max_rows)?;
            if !rows.is_empty() {
                planned.push((source, rows));
            }
        }
        planned
    };
    if planned.is_empty() {
        return Ok(());
    }
    // The plan above only says there is work. The rows go as this write's own snapshot plans
    // them (review #6897): a subscription made since the read above, one that starts at the
    // beginning above all, holds every row its cursor has not passed.
    vault.with_write_txn_grouped(|txn| {
        for (source, _) in &planned {
            let floor = match source_floor_in_txn(&vault.store, txn, *source)? {
                SourceFloor::AtStart => continue,
                SourceFloor::Unfollowed => None,
                SourceFloor::At(position) => Some(position),
            };
            let rows = edges::passed_rows_in_txn(&vault.store, txn, *source, floor, max_rows)?;
            edges::delete_rows_in_txn(&vault.store, txn, *source, &rows)?;
        }
        Ok(())
    })
}

/// An erase's scrub of the feeds this module owns: every edge row with an erased end and every
/// redirty row naming an erased TURN go, in the caller's erase write. The change log and the
/// settlement feed are scrubbed where they live.
///
/// # Errors
///
/// The scan or the deletes.
pub(crate) fn scrub_feeds_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &BTreeSet<EntityId>,
) -> Result<()> {
    edges::scrub_in_txn(&vault.store, txn, ids)
}

/// How many rows of the feeds this module owns name `id`: edge, redirty and withdrawn-type rows.
/// An erase leaves it at zero. Read for the test door `test_doors::feeds`.
///
/// # Errors
///
/// The read.
#[cfg(oneiron_test_support)]
pub(crate) fn rows_naming(vault: &Vault, id: &EntityId) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let kept = usize::from(WITHDRAWN_TYPES.get(&vault.store, &txn, id)?.is_some());
    Ok(edges::rows_naming_in_txn(&vault.store, &txn, id)? + kept)
}

/// An erased actor follows nothing: its subscriptions, their cursors and their following rows go
/// in the erase's own writer, by key, so a row that does not decode goes too, and no feed keeps a
/// row for it.
pub(crate) fn erase_feed_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (_, subscription) in SUBSCRIPTIONS.scan_keys(&vault.store, txn, actor.as_bytes())? {
        forget_subscription_in_txn(&vault.store, txn, subscription)?;
    }
    SUBSCRIPTIONS.delete_from(&vault.store, txn, actor.as_bytes())?;
    forget_withdrawn_types_unless_followed_in_txn(&vault.store, txn)
}

/// Drops every kept withdrawn type once no subscription follows the change log: nothing judges
/// a withdrawal any more.
fn forget_withdrawn_types_unless_followed_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    if changes_followed_in_txn(store, txn)? {
        return Ok(());
    }
    WITHDRAWN_TYPES.delete_from(store, txn, &[]).map(drop)
}

/// Erases `ids`' kept withdrawn types in the erase's own write, as the hook feeds scrub theirs.
pub(crate) fn scrub_withdrawn_types_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    ids: &std::collections::BTreeSet<EntityId>,
) -> Result<()> {
    for id in ids {
        WITHDRAWN_TYPES.delete(store, txn, id)?;
    }
    Ok(())
}

/// Drops `subscription`'s cursors and following rows, in the caller's write.
fn forget_subscription_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    subscription: EntityId,
) -> Result<()> {
    for source in FeedSource::ALL {
        FOLLOWING.delete(store, txn, &([source.tag()], subscription))?;
    }
    CURSORS.delete_from(store, txn, subscription.as_bytes())?;
    Ok(())
}

/// `reader`'s actor, once its credential and owner binding still hold in `txn` (review #6897):
/// every feed door checks it in the transaction that touches the subscription, so a key revoked
/// or lapsed since it was made neither reads, lists, moves nor ends one.
fn live_reader_actor_in(reader: &ScopedRead<'_>, txn: &heed::RoTxn<'_>) -> Result<EntityId> {
    let actor = EntityId::from_hex(reader.actor_key().actor_ref())
        .map_err(|_| invalid("a feed subscriber reads as an entity"))?;
    if !reader.credential_live_in(txn)? {
        return Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
            reason: "a feed subscriber's credential no longer holds",
        }));
    }
    Ok(actor)
}

fn validate_selector(selector: &FeedSelector) -> Result<()> {
    if selector.sources.is_empty() {
        return Err(invalid("a feed selector follows at least one source"));
    }
    for (index, source) in selector.sources.iter().enumerate() {
        if selector.sources[..index].contains(source) {
            return Err(invalid("a feed selector names one source twice"));
        }
    }
    if selector
        .predicates
        .iter()
        .any(|glob| glob.trim().is_empty())
    {
        return Err(invalid("a feed predicate glob is empty"));
    }
    Ok(())
}

fn subscription_view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    subscription: EntityId,
    row: SubscriptionRow,
) -> Result<FeedSubscription> {
    let mut cursors = Vec::with_capacity(row.selector.sources.len());
    for source in &row.selector.sources {
        let raw = CURSORS
            .get(&vault.store, txn, &(subscription, [source.tag()]))?
            .ok_or(Error::CorruptedIndex(
                "feed subscription without its cursor",
            ))?
            .position;
        cursors.push(seal_position(&row, subscription, *source, raw.as_ref())?);
    }
    Ok(FeedSubscription {
        subscription,
        actor,
        selector: row.selector,
        created_at: row.created_at,
        cursors,
    })
}

/// How the subscriber's lane judges one candidate.
#[derive(Debug, Clone, Copy)]
enum Judge {
    /// An edit, a settlement or a redirty notice: shown when this read of its entity is.
    Read(PointRead<'static>),
    /// An edge: shown when both its ends are.
    ReadBoth(PointRead<'static>, PointRead<'static>),
    /// A withdrawal: shown where the lane may learn the row is gone.
    Withdrawal,
    /// Its history is gone, so no lane can be shown it.
    Withheld,
}

/// One fact a source read found, before the subscriber's lane judges it.
struct Candidate {
    entry: FeedEntry,
    judge: Judge,
}

/// One bounded read of a source.
struct Scanned {
    entries: Vec<Candidate>,
    through: Option<Position>,
}

/// Up to `limit` change log rows after `after`, every entity kind: an edit names the revision it
/// left, a withdrawal the entity's type while its record stands.
fn changes_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<Position>,
    limit: usize,
) -> Result<Scanned> {
    let after = match after {
        None => None,
        Some(Position::Fact(FactPosition::ClaimChangelog(position))) => Some(position.0),
        Some(_) => {
            return Err(Error::CorruptedIndex(
                "a changes cursor names another source",
            ));
        }
    };
    let budget = limit.saturating_mul(SCAN_PER_ENTRY).max(1);
    let mut scanned = Scanned {
        entries: Vec::new(),
        through: None,
    };
    for (count, row) in vault.store.port_changelog_after(txn, after)?.enumerate() {
        if count >= budget || scanned.entries.len() >= limit {
            break;
        }
        let (id, change) = row?;
        if change.id != id {
            return Err(Error::CorruptedIndex("feed changelog identity"));
        }
        let position = Position::Fact(FactPosition::ClaimChangelog(ClaimChangelogPosition(id)));
        scanned.through = Some(position);
        let op = FeedOp::of_change(change.op);
        let entity_type = match vault.store.port_entity_record(txn, &change.entity)? {
            Some(record) => record.entity_type,
            // A physical delete removed the row and kept its type while the change log was
            // followed (review #6897 round 2): the withdrawal is judged by that type.
            None if op.kind() == FeedEntryKind::Withdrawal => {
                match WITHDRAWN_TYPES.get(&vault.store, txn, &change.entity)? {
                    Some(kept) => kept.entity_type,
                    None => continue,
                }
            }
            // No record names the entity's type any more: nothing a lane can judge.
            None => continue,
        };
        let (revision, judge) = if op.kind() == FeedEntryKind::Edit {
            let revision = crate::vault::entity_revision::revision_for_body_hash_in_txn(
                vault,
                txn,
                &change.entity,
                &change.input_hash,
            )?;
            let point = match revision {
                Some(revision) => PointRead::id(change.entity).at(ReadMode::Pinned(revision)),
                None => PointRead::id(change.entity),
            };
            (revision, Judge::Read(point))
        } else {
            (None, Judge::Withdrawal)
        };
        scanned.entries.push(Candidate {
            entry: FeedEntry {
                position: FeedPosition::of(position)?,
                kind: op.kind(),
                op,
                entity: change.entity,
                entity_type,
                actor: Some(change.actor_principal),
                recorded_at: change.recorded_at,
                revision,
                edge: None,
            },
            judge,
        });
    }
    Ok(scanned)
}

/// Up to `limit` settled proposals after `after`, from the fact hooks' settlement feed.
fn settlements_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<Position>,
    limit: usize,
) -> Result<Scanned> {
    let after = match after {
        None => None,
        Some(Position::Fact(FactPosition::Settlement(position))) => Some(position),
        Some(_) => {
            return Err(Error::CorruptedIndex(
                "a settlements cursor names another source",
            ));
        }
    };
    let settled = crate::runtime_hooks::settled_feed_facts_after_in_txn(vault, txn, after, limit)?;
    let mut scanned = Scanned {
        entries: Vec::with_capacity(settled.facts.len()),
        through: settled
            .through
            .map(|position| Position::Fact(FactPosition::Settlement(position))),
    };
    for fact in settled.facts {
        let Some(record) = vault.store.port_entity_record(txn, &fact.entity)? else {
            continue;
        };
        scanned.entries.push(Candidate {
            entry: FeedEntry {
                position: FeedPosition::of(Position::Fact(FactPosition::Settlement(
                    fact.position,
                )))?,
                kind: FeedEntryKind::Settlement,
                op: FeedOp::Settle,
                entity: fact.entity,
                entity_type: record.entity_type,
                actor: Some(fact.actor),
                recorded_at: fact.recorded_at,
                revision: fact.revision,
                edge: None,
            },
            judge: fact.point.map_or(Judge::Withheld, Judge::Read),
        });
    }
    Ok(scanned)
}

/// The candidates `selector` takes and `reader`'s lane shows now. Nothing is told of the rest.
fn shown_in_txn(
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    selector: &FeedSelector,
    candidates: Vec<Candidate>,
) -> Result<Vec<FeedEntry>> {
    let candidates: Vec<Candidate> = candidates
        .into_iter()
        .filter(|candidate| {
            (selector.kinds.is_empty() || selector.kinds.contains(&candidate.entry.kind))
                && (selector.entity_types.is_empty()
                    || selector.entity_types.contains(&candidate.entry.entity_type))
        })
        .collect();
    let mut points: Vec<PointRead<'static>> = Vec::new();
    for candidate in &candidates {
        match candidate.judge {
            Judge::Read(point) => points.push(point),
            Judge::ReadBoth(source, target) => {
                points.push(source);
                points.push(target);
            }
            Judge::Withdrawal | Judge::Withheld => {}
        }
    }
    let withdrawn: Vec<(EntityId, u8)> = candidates
        .iter()
        .filter(|candidate| matches!(candidate.judge, Judge::Withdrawal))
        .map(|candidate| (candidate.entry.entity, candidate.entry.entity_type))
        .collect();
    let rows = reader
        .read_projected_in_txn(txn, &points, None, |_, rows| Ok::<_, Error>(rows))?
        .value;
    let revealed = reader.withdrawals_revealed_in(txn, &withdrawn)?;
    let mut rows = rows.into_iter();
    let mut revealed = revealed.into_iter();
    let mut shown = Vec::new();
    for candidate in candidates {
        let (visible, taken) = match candidate.judge {
            Judge::Read(_) => match rows.next().flatten() {
                Some(row) => match row.body.as_deref() {
                    Some(body) => (true, takes_predicate(selector, &candidate.entry, body)),
                    None => (false, false),
                },
                None => (false, false),
            },
            Judge::ReadBoth(_, _) => {
                let source = rows.next().flatten().is_some_and(|row| row.body.is_some());
                let target = rows.next().flatten().is_some_and(|row| row.body.is_some());
                (source && target, true)
            }
            Judge::Withdrawal => (revealed.next().unwrap_or(false), true),
            Judge::Withheld => (false, false),
        };
        // A row the lane does not show leaves no trace on the page: no count, no marker.
        if visible && taken {
            shown.push(candidate.entry);
        }
    }
    Ok(shown)
}

/// Whether a shown row's body passes the selector's predicate globs: every row when there are
/// none, and a redirty notice always; otherwise only a claim whose predicate one glob matches.
fn takes_predicate(selector: &FeedSelector, entry: &FeedEntry, body: &[u8]) -> bool {
    if selector.predicates.is_empty() || entry.kind == FeedEntryKind::Redirty {
        return true;
    }
    if entry.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return false;
    }
    crate::claim::decode_claim_body(body, true).is_ok_and(|claim| {
        selector
            .predicates
            .iter()
            .any(|glob| crate::runtime_hooks::glob_match(glob, &claim.predicate))
    })
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
