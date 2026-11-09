//! Change feeds (untangle slice 6.8, primitive B; ARCH-0080 §4 Sources and cursors).
//!
//! Any actor subscribes to what changed in the vault and reads it from a durable cursor of its
//! own: edits and withdrawals of every entity kind from the store's change log, and settled
//! proposals from the settlement feed the fact hooks follow. A subscription is a cursor per
//! source, not a copy of the rows: a read pages the sources after the cursor, an ack moves it.
//!
//! - **The grant is checked at delivery.** Each entry is shown only when the subscriber's own read
//!   lane, at read time, shows its entity: an edit at the revision it left (or as it stands, once
//!   that revision is gone), a settlement at its pinned revision, and a withdrawal only where the
//!   lane may learn the row is gone ([`ScopedRead::withdrawals_revealed_in`], the rule a short
//!   reference to an erased row follows). A narrowed grant hides entries written before it
//!   narrowed. Nothing is frozen at subscribe.
//! - **Positions are commit order, never a timestamp.** The change log's ids are drawn inside the
//!   writer that commits each row, and the settlement feed's sequence likewise, so a reader that
//!   resumes after its last position misses nothing that commits later.
//! - **One cursor mechanism.** The positions, the sources and the settlement feed are the fact
//!   hooks' own. A subscription following the settlement feed counts as its reader, so the feed
//!   records settlements while hooks are off, and its prune keeps every row a subscription has not
//!   acknowledged.
//! - **The cursor commits with what the subscriber made of it.** [`ack_feed_in_txn`] moves a
//!   cursor inside a caller's write, so a derivation and the ack of what it read land together
//!   (slice 6.7's `feed_ack`).
//!
//! The verbs `vault.feeds.subscribe`, `.read`, `.ack` and `.unsubscribe` land in slice 6.8d, after
//! the per-verb sources (slice 4.2); until then these are the engine's doors.

pub(crate) mod tables;

use serde::{Deserialize, Serialize};

use crate::claim::{PointRead, ScopedRead};
use crate::error::ClaimError;
use crate::ports::{ChangeLogStoreRead, ChangeOp, EntityStoreRead};
use crate::runtime_hooks::{ClaimChangelogPosition, FactPosition, FactSource, SettlementPosition};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EntityId, Error, Result, Vault};

/// One subscription row per actor and subscription.
const SUBSCRIPTIONS: SideTable<(EntityId, EntityId), SubscriptionRow, Named> =
    SideTable::new(&side_table::FEED_SUBSCRIPTION);

/// One cursor row per subscription and source.
const CURSORS: SideTable<(EntityId, [u8; 1]), CursorRow, Named> =
    SideTable::new(&side_table::FEED_CURSOR);

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
}

impl FeedSource {
    pub const ALL: [Self; 2] = [Self::Changes, Self::Settlements];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changes => "changes",
            Self::Settlements => "settlements",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Changes => 0,
            Self::Settlements => 1,
        }
    }

    const fn fact_source(self) -> FactSource {
        match self {
            Self::Changes => FactSource::ClaimChangelog,
            Self::Settlements => FactSource::Settlement,
        }
    }

    const fn of_fact_source(source: FactSource) -> Option<Self> {
        match source {
            FactSource::ClaimChangelog => Some(Self::Changes),
            FactSource::Settlement => Some(Self::Settlements),
            FactSource::Schedule | FactSource::SurfaceInbound => None,
        }
    }
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
}

/// The write behind an entry, as the change log or the settlement feed names it.
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
        }
    }
}

/// A position in one source, as text: `changes:<32 hex>` or `settlements:<16 hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct FeedPosition(pub String);

impl FeedPosition {
    fn of(position: FactPosition) -> Result<Self> {
        let source = FeedSource::of_fact_source(position.source()).ok_or(
            Error::InvariantViolation("a feed position names a hook-only source"),
        )?;
        Ok(Self(format!(
            "{}:{}",
            source.as_str(),
            crate::receipt::hex_lower(&position.bytes())
        )))
    }

    /// The source and the typed position this text names.
    fn parse(&self) -> Result<(FeedSource, FactPosition)> {
        let (source, hex) = self
            .0
            .split_once(':')
            .ok_or_else(|| invalid("a feed position is <source>:<hex>"))?;
        match source {
            "changes" => Ok((
                FeedSource::Changes,
                FactPosition::ClaimChangelog(ClaimChangelogPosition(
                    crate::deletion::parse_hex::<16>(hex)
                        .ok_or_else(|| invalid("a changes position is 32 hex"))?,
                )),
            )),
            "settlements" => Ok((
                FeedSource::Settlements,
                FactPosition::Settlement(SettlementPosition(u64::from_be_bytes(
                    crate::deletion::parse_hex::<8>(hex)
                        .ok_or_else(|| invalid("a settlements position is 16 hex"))?,
                ))),
            )),
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
    /// The entity type bytes it takes.
    #[serde(default)]
    pub entity_types: Vec<u8>,
    /// Predicate globs (`*` matches any run) a claim's edit or settlement must match; with any
    /// glob, only claims pass. A withdrawn claim's predicate went with its body, so a withdrawal
    /// passes this list.
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
    /// Each source's cursor: the last position acknowledged, absent while it stands at the
    /// source's start.
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

/// One change a subscriber may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedEntry {
    pub position: FeedPosition,
    pub kind: FeedEntryKind,
    pub op: FeedOp,
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub entity: EntityId,
    pub entity_type: u8,
    /// Who made the write.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub actor: EntityId,
    /// When it committed, on the vault's recording clock.
    pub recorded_at: u64,
    /// The retained revision the write left, when it still stands.
    pub revision: Option<RevisionRef>,
}

/// One page of a subscription. It moves no cursor: [`Vault::feed_ack`] does, with `through`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedPage {
    pub entries: Vec<FeedEntry>,
    /// Entries the subscriber's lane did not show. Their ids are not named.
    pub withheld: u64,
    /// Each source's last position this page scanned, shown or not: the positions to ack.
    pub through: Vec<FeedPosition>,
    /// A source holds more after `through`.
    pub more: bool,
}

/// A request to move a subscription's cursors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedAckRequest {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub subscription: EntityId,
    /// One position per source to move to: a page's `through`, or any position up to the
    /// source's head. A position at or before the cursor moves nothing.
    pub through: Vec<FeedPosition>,
}

/// The stored subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SubscriptionRow {
    selector: FeedSelector,
    created_at: u64,
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
    fn position(&self) -> Result<Option<FactPosition>> {
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
            let row = SubscriptionRow {
                selector: request.selector.clone(),
                created_at: at,
            };
            SUBSCRIPTIONS.put(&self.store, txn, &(actor, subscription), &row)?;
            for source in &request.selector.sources {
                let position = match request.start {
                    FeedStart::Head => crate::runtime_hooks::fact_source_head_in_txn(
                        self,
                        txn,
                        source.fact_source(),
                    )?,
                    FeedStart::Beginning => None,
                };
                let cursor = CursorRow {
                    position: position.map(FeedPosition::of).transpose()?,
                    updated_at: at,
                };
                CURSORS.put(&self.store, txn, &(subscription, [source.tag()]), &cursor)?;
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
    /// the selector takes, each shown only where `reader`'s lane shows it now. It moves no
    /// cursor.
    ///
    /// # Errors
    ///
    /// `EntityNotFound` when the subscription is not this actor's, a limit of zero, or the read.
    pub fn feed_read(
        &self,
        reader: &ScopedRead<'_>,
        request: &FeedReadRequest,
    ) -> Result<FeedPage> {
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
        let mut page = FeedPage {
            entries: Vec::new(),
            withheld: 0,
            through: Vec::new(),
            more: false,
        };
        for source in &row.selector.sources {
            let cursor = CURSORS
                .get(&self.store, &txn, &(request.subscription, [source.tag()]))?
                .ok_or(Error::CorruptedIndex(
                    "feed subscription without its cursor",
                ))?
                .position()?;
            let scanned = match source {
                FeedSource::Changes => changes_after_in_txn(self, &txn, cursor, limit)?,
                FeedSource::Settlements => settlements_after_in_txn(self, &txn, cursor, limit)?,
            };
            if let Some(through) = scanned.through {
                page.through.push(FeedPosition::of(through)?);
            }
            page.more |= scanned.more;
            let (shown, withheld) = shown_in_txn(reader, &txn, &row.selector, scanned.entries)?;
            page.entries.extend(shown);
            page.withheld = page.withheld.saturating_add(withheld);
        }
        Ok(page)
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

    /// Ends `reader`'s subscription: its row and its cursors go in one write, so the settlement
    /// feed no longer keeps rows for it. `false` when it was not this actor's or is gone.
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
            CURSORS.delete_from(&self.store, txn, subscription.as_bytes())?;
            forget_withdrawn_types_unless_followed_in_txn(&self.store, txn)?;
            Ok(true)
        })
    }
}

/// Moves `actor`'s subscription's cursors to `request.through` inside the caller's write, so a
/// derivation commits with the ack of what it read (slice 6.7). A position at or before a cursor
/// moves nothing.
///
/// # Errors
///
/// `EntityNotFound` when the subscription is not `actor`'s; a position in a source it does not
/// follow, two positions in one source, or one past that source's head; or the write.
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
    for text in &request.through {
        let (source, position) = text.parse()?;
        if !row.selector.sources.contains(&source) {
            return Err(invalid(
                "a feed ack names a source its subscription does not follow",
            ));
        }
        if seen.contains(&source) {
            return Err(invalid("a feed ack names one source twice"));
        }
        seen.push(source);
        let head = crate::runtime_hooks::fact_source_head_in_txn(vault, txn, source.fact_source())?;
        if head.is_none_or(|head| position > head) {
            return Err(invalid("a feed ack moves past its source's head"));
        }
        let key = (request.subscription, [source.tag()]);
        let current = CURSORS
            .get(&vault.store, txn, &key)?
            .ok_or(Error::CorruptedIndex(
                "feed subscription without its cursor",
            ))?
            .position()?;
        if current.is_some_and(|current| current >= position) {
            continue;
        }
        let cursor = CursorRow {
            position: Some(text.clone()),
            updated_at: at,
        };
        CURSORS.put(&vault.store, txn, &key, &cursor)?;
    }
    Ok(())
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
    if !changes_followed_in_txn(store, txn)? {
        return Ok(());
    }
    WITHDRAWN_TYPES.put(store, txn, id, &WithdrawnType { entity_type })
}

/// Whether any subscription follows the change log in `txn`.
fn changes_followed_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(CURSORS
        .scan_keys(store, txn, &[])?
        .iter()
        .any(|(_, tag)| *tag == [FeedSource::Changes.tag()]))
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
    for key in CURSORS.scan_keys(&vault.store, txn, &[])? {
        if key.1 == [source.tag()] {
            return Ok(true);
        }
    }
    Ok(false)
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
    let mut floor = FeedFloor::Unfollowed;
    for row in CURSORS.iter_from(&vault.store, txn, &[])? {
        let ((_, tag), cursor) = row?;
        if tag != [source.tag()] {
            continue;
        }
        let Some(position) = cursor.position()? else {
            return Ok(FeedFloor::AtStart);
        };
        floor = match floor {
            FeedFloor::At(held) if held <= position => FeedFloor::At(held),
            _ => FeedFloor::At(position),
        };
    }
    Ok(floor)
}

/// An erased actor follows nothing: its subscriptions and their cursors go in the erase's own
/// writer, by key, so a row that does not decode goes too, and the settlement feed keeps no row
/// for it.
pub(crate) fn erase_feed_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (_, subscription) in SUBSCRIPTIONS.scan_keys(&vault.store, txn, actor.as_bytes())? {
        CURSORS.delete_from(&vault.store, txn, subscription.as_bytes())?;
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
    let mut cursors = Vec::new();
    for source in &row.selector.sources {
        if let Some(position) = CURSORS
            .get(&vault.store, txn, &(subscription, [source.tag()]))?
            .and_then(|cursor| cursor.position)
        {
            cursors.push(position);
        }
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
    /// An edit or a settlement: shown when this read of its entity is.
    Read(PointRead<'static>),
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
    through: Option<FactPosition>,
    more: bool,
}

/// Up to `limit` change log rows after `after`, every entity kind: an edit names the revision it
/// left, a withdrawal the entity's type while its record stands.
fn changes_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<FactPosition>,
    limit: usize,
) -> Result<Scanned> {
    let after = match after {
        None => None,
        Some(FactPosition::ClaimChangelog(position)) => Some(position.0),
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
        more: false,
    };
    for (count, row) in vault.store.port_changelog_after(txn, after)?.enumerate() {
        if count >= budget || scanned.entries.len() >= limit {
            scanned.more = true;
            break;
        }
        let (id, change) = row?;
        if change.id != id {
            return Err(Error::CorruptedIndex("feed changelog identity"));
        }
        let position = FactPosition::ClaimChangelog(ClaimChangelogPosition(id));
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
                actor: change.actor_principal,
                recorded_at: change.recorded_at,
                revision,
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
    after: Option<FactPosition>,
    limit: usize,
) -> Result<Scanned> {
    let after = match after {
        None => None,
        Some(FactPosition::Settlement(position)) => Some(position),
        Some(_) => {
            return Err(Error::CorruptedIndex(
                "a settlements cursor names another source",
            ));
        }
    };
    let settled = crate::runtime_hooks::settled_feed_facts_after_in_txn(vault, txn, after, limit)?;
    let mut scanned = Scanned {
        entries: Vec::with_capacity(settled.facts.len()),
        through: settled.through.map(FactPosition::Settlement),
        more: settled.more,
    };
    for fact in settled.facts {
        let Some(record) = vault.store.port_entity_record(txn, &fact.entity)? else {
            continue;
        };
        scanned.entries.push(Candidate {
            entry: FeedEntry {
                position: FeedPosition::of(FactPosition::Settlement(fact.position))?,
                kind: FeedEntryKind::Settlement,
                op: FeedOp::Settle,
                entity: fact.entity,
                entity_type: record.entity_type,
                actor: fact.actor,
                recorded_at: fact.recorded_at,
                revision: fact.revision,
            },
            judge: fact.point.map_or(Judge::Withheld, Judge::Read),
        });
    }
    Ok(scanned)
}

/// The candidates `selector` takes and `reader`'s lane shows now, and how many the lane
/// withheld. A row the lane shows but a predicate glob does not take is neither.
fn shown_in_txn(
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    selector: &FeedSelector,
    candidates: Vec<Candidate>,
) -> Result<(Vec<FeedEntry>, u64)> {
    let candidates: Vec<Candidate> = candidates
        .into_iter()
        .filter(|candidate| {
            (selector.kinds.is_empty() || selector.kinds.contains(&candidate.entry.kind))
                && (selector.entity_types.is_empty()
                    || selector.entity_types.contains(&candidate.entry.entity_type))
        })
        .collect();
    let points: Vec<PointRead<'static>> = candidates
        .iter()
        .filter_map(|candidate| match candidate.judge {
            Judge::Read(point) => Some(point),
            Judge::Withdrawal | Judge::Withheld => None,
        })
        .collect();
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
    let mut withheld = 0_u64;
    for candidate in candidates {
        let (visible, taken) = match candidate.judge {
            Judge::Read(_) => match rows.next().flatten() {
                Some(row) => match row.body.as_deref() {
                    Some(body) => (
                        true,
                        takes_predicate(selector, candidate.entry.entity_type, body),
                    ),
                    None => (false, false),
                },
                None => (false, false),
            },
            Judge::Withdrawal => (revealed.next().unwrap_or(false), true),
            Judge::Withheld => (false, false),
        };
        if !visible {
            withheld = withheld.saturating_add(1);
        } else if taken {
            shown.push(candidate.entry);
        }
    }
    Ok((shown, withheld))
}

/// Whether a shown row's body passes the selector's predicate globs: every row when there are
/// none, and only a claim whose predicate one glob matches when there are.
fn takes_predicate(selector: &FeedSelector, entity_type: u8, body: &[u8]) -> bool {
    if selector.predicates.is_empty() {
        return true;
    }
    if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
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
