//! Per-reader report schedules (OF-499). The host's deadline timer serves
//! them: each due person or agent digest renders under its own reader's
//! read and lands in that reader's inbox in the same write. An owner's due
//! digest renders as its schedule's recorded live Owner, with his due notice
//! (`scheduled_owner.rs`, FIX 1259); else he gets today's notice and it
//! renders when he opens it. No composition policy lives here. Each
//! published period with anything in it queues the lens's generate step
//! (`weave_lens.rs`), whose render lands on the row.
//! Glossary: `WeaveDigestSchedule` is one reader's digest cadence and due
//! time; it is not the commitment `Schedule` in `crate::commitment_schedule`.
use super::weave_lens::{
    KeptLiveLens, WeaveLensRefusal, WeaveLensRender, settle_live_weave_lens, settle_weave_lens_axes,
};
use super::{
    ScopedRead, ScopedReadResult, WeaveItem, WeaveReader, WeaveReport, WeaveSectionKind,
    WeaveSectionSpec,
};
use crate::claim::encode_claim_body;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::ports::TombstoneStoreRead;
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
// The test module reaches this through `use super::*`; the wire rows that
// named it outside tests moved to `wire.rs`, so tests resolve as before.
#[cfg(test)]
use crate::EdgeKind;

// An in-Grant agent's ack of an owner's due notice (FIX 5778).
mod acknowledgements;
// The weave Admin's digest key, saved reads, kept live render and erase
// binding (OF-499 A3).
mod admin;
// The owner's digest settings and the Coach's changes to them (FIX 5495).
mod changes;
mod coach;
// The rows a saved period's copies depend on, for its erase index (FIX 8672).
mod dependencies;
// A saved period's loop-decision rows: carrier, erase index, recheck (OF-499 A2).
mod loop_decisions;
// A hard delete inside a saved period: rows rewritten, not the period (FIX 7693).
mod rewrite;
// A due Owner schedule renders as its recorded live Owner (FIX 1259).
pub(super) mod scheduled_owner;
mod settings;
// A saved schedule's and period's stored rows and their conversions.
mod wire;
pub use admin::WeaveAdminKey;
pub use changes::WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER;
pub use coach::WeaveDigestSettingsDrafter;
use settings::SettingsEdit;
pub use settings::{
    WeaveDigestFeedback, WeaveDigestSettingAnswer, WeaveDigestSettingChange,
    WeaveDigestSettingChangeStatus, WeaveDigestSettingUndo, WeaveDigestSettings,
};
use wire::{WireDigest, WireSchedule, report_sources, source_key};

const SCHEDULE_PREFIX: &[u8] = b"weave:schedule:v1:";
const DIGEST_PREFIX: &[u8] = b"weave:digest:v1:";
const SOURCE_PREFIX: &[u8] = b"weave:digest_source:v1:";
/// Each reader's newest live lens render, as [`KeptLiveLens`] keeps it.
const LIVE_PREFIX: &[u8] = b"weave:live:v1:";
/// The producer of a weave digest's inbox NOTIFICATION; `source.result` is
/// the digest's period, its `scheduled_for` second.
pub const WEAVE_DIGEST_NOTIFICATION_PRODUCER: &str = "weave.digest";

fn invalid() -> Error {
    Error::InvalidConfig("invalid weave digest row".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeaveDigestReader {
    Person(EntityId),
    Owner(EntityId),
    Agent(EntityId),
    /// A weave Admin's namespace (OF-499 A3): keyed by its exact membership
    /// grant, its person carried beside it. Identity only, taken from a
    /// checked proof; it authenticates no one.
    Admin(WeaveAdminKey),
}

impl WeaveDigestReader {
    /// The reader's own id: an Admin's person, never its grant.
    #[must_use]
    pub fn id(self) -> EntityId {
        match self {
            Self::Person(id) | Self::Owner(id) | Self::Agent(id) => id,
            Self::Admin(key) => key.actor(),
        }
    }

    /// The reader's role tag, as its keys and inbox events spell it, with
    /// the id its namespace keys on: an Admin's membership grant.
    pub(super) fn tag(self) -> (&'static str, EntityId) {
        match self {
            Self::Person(id) => ("p", id),
            Self::Owner(id) => ("o", id),
            Self::Agent(id) => ("a", id),
            Self::Admin(key) => (admin::ADMIN_TAG, key.membership_grant()),
        }
    }

    /// An Admin's tag decodes to no reader: its person is not in its id,
    /// and no stored tag stands in for its proof.
    pub(super) fn from_tag(tag: &str, id: EntityId) -> Option<Self> {
        match tag {
            "p" => Some(Self::Person(id)),
            "o" => Some(Self::Owner(id)),
            "a" => Some(Self::Agent(id)),
            _ => None,
        }
    }

    fn key(self, prefix: &[u8]) -> Vec<u8> {
        [prefix, self.stem().as_slice()].concat()
    }

    /// The reader's tag byte and the id its namespace keys on, as every
    /// family of its keys starts.
    fn stem(self) -> Vec<u8> {
        let (kind, id) = self.tag();
        [kind.as_bytes(), id.as_bytes()].concat()
    }

    /// The reader a schedule key names; `None` for a key of another shape,
    /// an Admin's among them (no Admin schedule exists, OF-499 A3).
    fn from_schedule_key(key: &[u8]) -> Option<Self> {
        let (&kind, id) = key.strip_prefix(SCHEDULE_PREFIX)?.split_first()?;
        let id = EntityId::from_bytes(<[u8; 16]>::try_from(id).ok()?).ok()?;
        match kind {
            b'p' => Some(Self::Person(id)),
            b'o' => Some(Self::Owner(id)),
            b'a' => Some(Self::Agent(id)),
            _ => None,
        }
    }

    fn of(reader: &WeaveReader<'_>, id: EntityId) -> Self {
        match reader {
            WeaveReader::Person(_) => Self::Person(id),
            WeaveReader::Owner(_) => Self::Owner(id),
            WeaveReader::Agent(_) => Self::Agent(id),
            WeaveReader::Admin(admin) => Self::Admin(WeaveAdminKey::of(admin)),
        }
    }

    /// The reader's inbox event for one period's digest. With the producer
    /// it derives the NOTIFICATION id, so a replay lands the same row. An
    /// Admin's names its grant and goes to its person.
    pub(super) fn notification(self, scheduled_for: u64, now: u64) -> NotificationEvent {
        let (kind, id) = self.tag();
        NotificationEvent {
            kind: NotificationKind::Digest,
            source: NotificationSource {
                producer: WEAVE_DIGEST_NOTIFICATION_PRODUCER.to_owned(),
                event: format!("{kind}:{}:{scheduled_for}", id.to_hex()),
                result: Some(scheduled_for.to_string()),
                ..NotificationSource::default()
            },
            subject_refs: Vec::new(),
            recipient: Some(self.id()),
            created_at: now,
            origin_conversation: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeaveDigestCadence {
    Daily,
    Weekly,
}

impl WeaveDigestCadence {
    fn seconds(self) -> u64 {
        match self {
            Self::Daily => 86_400,
            Self::Weekly => 604_800,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WeaveDigestSchedule {
    pub reader: WeaveDigestReader,
    pub cadence: WeaveDigestCadence,
    /// The first due Unix second. A host drives the clock and queues renders.
    pub next_due_at: u64,
    /// Host/resident-authored composition, subject to the live lens role gate.
    pub recipe: Vec<WeaveSectionSpec>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredWeaveDigest {
    pub reader: WeaveDigestReader,
    pub scheduled_for: u64,
    pub rendered_at: u64,
    pub report: ScopedReadResult<WeaveReport>,
    /// The lens's generate step's render of this period, once it landed.
    pub lens: Option<WeaveLensRender>,
    /// Why the generate step left this period with no render.
    pub lens_refused: Option<WeaveLensRefusal>,
}

/// Why the timer left a schedule row: until when, and the refusal that held
/// it. An owner's due notice holds its row with no refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveScheduleHold {
    pub until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub because: Option<String>,
}

/// One saved period's row in `txn`, copied out.
fn digest_row_in(store: &Store, txn: &heed::RoTxn<'_>, key: &[u8]) -> Result<Option<Vec<u8>>> {
    Ok(store.vault_meta.get(txn, key)?.map(|raw| raw.to_vec()))
}

/// Writes one saved period's row.
fn put_digest_row_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    bytes: &[u8],
) -> Result<()> {
    store.vault_meta.put(txn, key, bytes)?;
    Ok(())
}

/// Sets (`indexed`) or clears `source`'s entry in one period's erase index.
fn index_source_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
    digest_key: &[u8],
    indexed: bool,
) -> Result<()> {
    let key = source_key(source, digest_key);
    if indexed {
        store.vault_meta.put(txn, &key, &[])?;
    } else {
        store.vault_meta.delete(txn, &key)?;
    }
    Ok(())
}

/// A hard delete cannot leave a copied report body in vault metadata. This
/// source-prefix index is populated in the same transaction as publication,
/// and invalidated by the common deletion door in its erasure transaction:
/// a period the source gates goes whole, any other only loses the rows'
/// copies of it (`rewrite.rs`, FIX 7693, 8672).
/// A deleted reader's own rows go too: its saved periods (a resident's carry
/// its dreaming counters, which index no source), its schedule and its kept
/// live render. So do the wrong labels that name it, as reader or target.
/// A deleted Admin membership grant takes its Admin namespace and labels,
/// and a deleted person each Admin namespace its binding names (OF-499 A3).
pub(crate) fn invalidate_weave_digest_source_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    let prefix = [SOURCE_PREFIX, source.as_bytes()].concat();
    let keys = store
        .vault_meta
        .prefix_iter(&*txn, &prefix)?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    for index_key in keys {
        let digest_key = index_key
            .strip_prefix(prefix.as_slice())
            .ok_or(Error::CorruptedIndex("weave digest source index"))?;
        if let Some(stem) = admin::bound_admin_stem(digest_key) {
            admin::erase_reader_rows_in_txn(store, txn, stem)?;
        } else {
            if !digest_key.starts_with(DIGEST_PREFIX)
                || digest_key.len() != DIGEST_PREFIX.len() + 1 + 16 + 8
            {
                return Err(Error::CorruptedIndex("weave digest source index"));
            }
            rewrite::erase_source_in_period_in_txn(store, txn, digest_key, source)?;
        }
        store.vault_meta.delete(txn, &index_key)?;
    }
    for reader in [
        WeaveDigestReader::Person(*source),
        WeaveDigestReader::Owner(*source),
        WeaveDigestReader::Agent(*source),
    ] {
        admin::erase_reader_rows_in_txn(store, txn, &reader.stem())?;
    }
    admin::erase_reader_rows_in_txn(store, txn, &admin::grant_stem(source))?;
    // A deleted owner reader's settings, behaviour and Coach changes.
    settings::erase_owner_weave_digest_settings_in_txn(store, txn, source)?;
    super::weave_correction::erase_weave_labels_in_txn(store, txn, source)
}

/// Deletes one saved period and the source-index keys its report wrote.
fn erase_weave_digest_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    digest_key: &[u8],
) -> Result<()> {
    if let Some(raw) = digest_row_in(store, txn, digest_key)? {
        // Even an undecodable saved row is deleted. If it cannot be
        // decoded, orphan index keys contain references but no body bytes.
        if let Ok(wire) = serde_json::from_slice::<WireDigest>(&raw)
            && let Ok(report) = wire.into_report()
            && let Ok(sources) = dependencies::indexed_sources(&report.value)
        {
            for other in sources {
                index_source_in_txn(store, txn, &other, digest_key, false)?;
            }
        }
        store.vault_meta.delete(txn, digest_key)?;
    }
    Ok(())
}

/// Refuse a stale saved body even if a metadata index row is lost or a
/// deletion tombstone has committed before its active-store purge.
fn sources_live_in_txn(store: &Store, txn: &heed::RoTxn<'_>, report: &WeaveReport) -> Result<bool> {
    for source in report_sources(report)? {
        let state = store.port_deletion_state(txn, &source)?;
        if state.deleted || state.stale {
            return Ok(false);
        }
    }
    for section in &report.sections {
        for item in &section.items {
            if let WeaveItem::Claim { id, .. } = item
                && crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, id, |raw| {
                    Ok(raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN)
                })?
                .unwrap_or(true)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl Vault {
    /// Owner-authorized local schedule. Hosts enqueue due rows; this door owns no timer.
    /// The owner's own schedule writes through the one writer his settings
    /// have (FIX 5495), which bumps their generation in this same write.
    pub fn set_weave_digest_schedule(
        &self,
        owner: &AuthenticatedOwner,
        row: &WeaveDigestSchedule,
    ) -> Result<()> {
        if row.recipe.is_empty() {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(&WireSchedule::from_row(row)).map_err(|_| invalid())?;
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let reader = match row.reader {
                WeaveDigestReader::Person(id) => WeaveReader::Person(id),
                WeaveDigestReader::Owner(id) if id == actor => WeaveReader::Owner(owner),
                WeaveDigestReader::Owner(_) => return Err(invalid()),
                WeaveDigestReader::Agent(id) => WeaveReader::Agent(id),
                // No Admin schedule: an Admin reads in the foreground only,
                // and an Owner proof never stands for an Admin's (OF-499 A3).
                WeaveDigestReader::Admin(_) => return Err(invalid()),
            };
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            super::weave_report::validate_weave_recipe(self, txn, &policy, &reader, &row.recipe)?;
            if let WeaveDigestReader::Owner(id) = row.reader {
                self.put_owner_weave_digest_schedule_in_txn(
                    txn,
                    id,
                    &bytes,
                    SettingsEdit::Owner,
                    now,
                )?;
                return Ok(());
            }
            self.store
                .vault_meta
                .put(txn, &row.reader.key(SCHEDULE_PREFIX), &bytes)?;
            Ok(())
        })?;
        // The deadline timer re-reads committed rows on this signal.
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// Owner-only: stop one reader's digests. Its saved digests stay, and
    /// its newest rendered period settles on the weave-report skill's axes
    /// now, since no next period will render to settle it (CALLS: OF-499
    /// stopped digest settles at stop).
    pub fn clear_weave_digest_schedule(
        &self,
        owner: &AuthenticatedOwner,
        reader: WeaveDigestReader,
    ) -> Result<bool> {
        let now = self.store.clock.now_recorded_at();
        let cleared = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let cleared = self
                .store
                .vault_meta
                .delete(txn, &reader.key(SCHEDULE_PREFIX))?;
            // Stopping an owner's digest is his own settings edit (FIX 5495).
            if cleared && let WeaveDigestReader::Owner(id) = reader {
                self.bump_weave_digest_settings_in_txn(txn, id, SettingsEdit::Owner, now)?;
            }
            Ok(cleared)
        })?;
        self.store.notify_proactivity_changes();
        if cleared && let Some((at, report, last)) = self.previous_weave_lens(reader, u64::MAX)? {
            // Evidence about the skill, never a gate on the stop.
            if let Err(error) = settle_weave_lens_axes(
                self,
                reader,
                at,
                &report,
                &last,
                self.store.clock.now_recorded_at(),
            ) {
                tracing::warn!(
                    ?error,
                    "the stopped weave digest's last period did not settle"
                );
            }
        }
        Ok(cleared)
    }

    /// Owner-only: every reader's schedule, in key order. An undecodable
    /// row is left out; it arms no deadline either.
    pub fn weave_digest_schedules(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<(WeaveDigestSchedule, Option<WeaveScheduleHold>)>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let mut rows = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&txn, SCHEDULE_PREFIX)? {
            let (key, bytes) = row?;
            let Some(reader) = WeaveDigestReader::from_schedule_key(&key) else {
                continue;
            };
            if let Ok(mut wire) = serde_json::from_slice::<WireSchedule>(&bytes) {
                let hold = wire.held_until.map(|until| WeaveScheduleHold {
                    until,
                    because: wire.held_because.take(),
                });
                if let Ok(row) = wire.into_row(reader) {
                    rows.push((row, hold));
                }
            }
        }
        Ok(rows)
    }

    /// The earliest instant the deadline timer has a schedule to serve. A
    /// held row counts from its hold. Host-only: no reader learns another's
    /// cadence from it.
    pub fn next_weave_digest_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        let mut next: Option<u64> = None;
        for row in self.store.vault_meta.prefix_iter(&txn, SCHEDULE_PREFIX)? {
            let (_, bytes) = row?;
            // An undecodable row must not arm an instantly repeating deadline.
            let Ok(wire) = serde_json::from_slice::<WireSchedule>(&bytes) else {
                continue;
            };
            let at = wire.serve_at();
            next = Some(next.map_or(at, |current| current.min(at)));
        }
        Ok(next)
    }

    /// The deadline timer's pass over due schedules, on the elected home
    /// node only. A person's or agent's digest renders under that reader's
    /// own read (its grants, never the host's) and lands in its inbox. An
    /// owner's renders as its recorded live Owner, else gets today's due
    /// notice (FIX 1259). A row that fails to render is held
    /// to its next boundary, so a broken row cannot spin the timer. Returns
    /// how many rows were served.
    pub fn serve_due_weave_digests(&self, now: u64, local_node_id: u64) -> Result<usize> {
        let store = crate::dreamer_runner::DreamerRunnerStore::new(self);
        if store
            .home_node_designation()?
            .is_none_or(|home| home.node_id != local_node_id)
            || store
                .local_home_node_candidate(false, false, false)?
                .node_id
                != local_node_id
        {
            return Ok(0);
        }
        let due = {
            let txn = self.store.env.read_txn()?;
            let mut due = Vec::new();
            for row in self.store.vault_meta.prefix_iter(&txn, SCHEDULE_PREFIX)? {
                let (key, bytes) = row?;
                if let Some(reader) = WeaveDigestReader::from_schedule_key(&key)
                    && let Ok(wire) = serde_json::from_slice::<WireSchedule>(&bytes)
                    && wire.serve_at() <= now
                {
                    due.push((reader, key.to_vec(), bytes.to_vec()));
                }
            }
            due
        };
        let mut served = 0;
        for (reader, key, saved) in due {
            let outcome = match reader {
                WeaveDigestReader::Owner(owner) => {
                    self.serve_due_owner_weave_digest(owner, &key, &saved, now)
                }
                WeaveDigestReader::Person(id) => self
                    .render_scheduled_weave_digest(id, EdgeActorClass::Human, now)
                    .map(|stored| stored.is_some()),
                WeaveDigestReader::Agent(id) => self
                    .render_scheduled_weave_digest(id, EdgeActorClass::Agent, now)
                    .map(|stored| stored.is_some()),
                // No Admin schedule key decodes (OF-499 A3): one would be
                // held to its boundary, never rendered without its proof.
                WeaveDigestReader::Admin(_) => Ok(false),
            };
            match outcome {
                Ok(true) => served += 1,
                Ok(false) => self.hold_weave_schedule(&key, &saved, now, None)?,
                Err(error) => {
                    tracing::warn!(?error, "scheduled weave digest refused; held a period");
                    self.hold_weave_schedule(&key, &saved, now, Some(error.to_string()))?;
                }
            }
        }
        // The Coach's pass over the owners' digest settings (FIX 5495): each
        // failure is logged and skipped inside it.
        self.coach_weave_digest_settings(now);
        Ok(served)
    }

    /// Render one person's or agent's due digest under its own read, as the
    /// timer and the resident's own dreaming do. `None`: nothing was due,
    /// or a concurrent write moved its row; one retry covers the race.
    pub(crate) fn render_scheduled_weave_digest(
        &self,
        id: EntityId,
        class: EdgeActorClass,
        now: u64,
    ) -> Result<Option<StoredWeaveDigest>> {
        let reader = match class {
            EdgeActorClass::Human => WeaveReader::Person(id),
            EdgeActorClass::Agent => WeaveReader::Agent(id),
            EdgeActorClass::System => return Err(invalid()),
        };
        let memory = self.memory(id, class);
        let read = memory
            .read_lane(super::ClaimReadStatus::Surfaceable)
            .map_err(|error| Error::InvalidConfig(format!("weave digest reader: {error}")))?;
        match read.render_due_weave_digest(reader, now)? {
            Some(stored) => Ok(Some(stored)),
            None => read.render_due_weave_digest(reader, now),
        }
    }

    /// Leave a row the timer could not serve until its next boundary, with
    /// the refusal that held it for the owner's schedule view.
    fn hold_weave_schedule(
        &self,
        key: &[u8],
        saved: &[u8],
        now: u64,
        because: Option<String>,
    ) -> Result<()> {
        let Ok(wire) = serde_json::from_slice::<WireSchedule>(saved) else {
            return Ok(());
        };
        let held = serde_json::to_vec(&WireSchedule {
            held_until: Some(wire.next_boundary_after(now)?),
            held_because: because,
            ..wire
        })
        .map_err(|_| invalid())?;
        self.with_write_txn_grouped(|txn| {
            if self.store.vault_meta.get(&*txn, key)?.as_deref() == Some(saved) {
                self.store.vault_meta.put(txn, key, &held)?;
            }
            Ok(())
        })
    }

    /// Owner-only schedule inspection; callers never infer another reader's cadence.
    pub fn weave_digest_schedule(
        &self,
        owner: &AuthenticatedOwner,
        reader: WeaveDigestReader,
    ) -> Result<Option<WeaveDigestSchedule>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        self.store
            .vault_meta
            .get(&txn, &reader.key(SCHEDULE_PREFIX))?
            .map(|bytes| {
                serde_json::from_slice::<WireSchedule>(&bytes)
                    .map_err(|_| invalid())?
                    .into_row(reader)
            })
            .transpose()
    }
}

impl Vault {
    /// One saved period as the lens's generate step reads it: a person's or
    /// an agent's under its own current read, an owner's under his own
    /// owner read, freshly resolved, with every check his own door applies
    /// (SCAN C026). The Dreamer holds no owner proof, and only the owner's
    /// own door ever serves what it renders; a period that is no longer that
    /// owner's to read, or whose saved bodies changed, is withheld.
    pub(crate) fn weave_digest_for_lens(
        &self,
        reader: WeaveDigestReader,
        scheduled_for: u64,
    ) -> Result<Option<StoredWeaveDigest>> {
        let (class, lens_reader) = match reader {
            WeaveDigestReader::Person(id) => (EdgeActorClass::Human, WeaveReader::Person(id)),
            WeaveDigestReader::Agent(id) => (EdgeActorClass::Agent, WeaveReader::Agent(id)),
            // An Admin's period reads only under its current proof, which
            // the Dreamer never holds (OF-499 A3): withheld before any model.
            WeaveDigestReader::Admin(_) => return Ok(None),
            WeaveDigestReader::Owner(owner) => {
                // A due Owner schedule's period reads under its schedule's
                // binding and the live-owner census (FIX 1259).
                if let Some(scheduled) = self.scheduled_owner_period_for_lens(owner, scheduled_for)
                {
                    return scheduled;
                }
                let key = self
                    .memory(owner, EdgeActorClass::Human)
                    .read_key()
                    .map_err(|error| {
                        Error::InvalidConfig(format!("weave digest reader: {error}"))
                    })?;
                // Still that owner's own read, never a human's narrower one.
                if key.vault_owner_ref() != Some(owner) {
                    return Ok(None);
                }
                let read = self.scoped_read(key);
                let txn = read.grant_read_txn()?;
                return read.saved_weave_digest_in_txn(&txn, reader, scheduled_for, None);
            }
        };
        let memory = self.memory(reader.id(), class);
        let read = memory
            .read_lane(super::ClaimReadStatus::Surfaceable)
            .map_err(|error| Error::InvalidConfig(format!("weave digest reader: {error}")))?;
        read.read_weave_digest(lens_reader, scheduled_for)
    }

    /// Save the generate step's render on its period, only while the row is
    /// still the one it rendered from and holds no render yet. Then settle
    /// the reader's previous rendered period on the skill's axes. `true`:
    /// the render landed.
    pub(crate) fn attach_weave_lens(
        &self,
        reader: WeaveDigestReader,
        scheduled_for: u64,
        rendered_at: u64,
        render: &WeaveLensRender,
    ) -> Result<bool> {
        let key = digest_key(reader, scheduled_for);
        let landed = self.with_write_txn_grouped(|txn| {
            let Some(bytes) = self.store.vault_meta.get(&*txn, &key)? else {
                return Ok(false);
            };
            let mut wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if wire.rendered_at != rendered_at || wire.lens.is_some() {
                return Ok(false);
            }
            wire.lens = Some(render.clone());
            let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
            self.store.vault_meta.put(txn, &key, &bytes)?;
            Ok(true)
        })?;
        if landed
            && let Some((at, report, previous)) = self.previous_weave_lens(reader, scheduled_for)?
        {
            // The axes are evidence about the skill, never a gate on the
            // render: a refusal here leaves the render landed.
            if let Err(error) =
                settle_weave_lens_axes(self, reader, at, &report, &previous, render.rendered_at)
            {
                tracing::warn!(?error, "weave lens axes did not settle");
            }
        }
        Ok(landed)
    }

    /// Save why the generate step left its period with no render, only while
    /// the row is still the one it rendered from and holds neither a render
    /// nor a refusal. `true`: the refusal landed.
    pub(crate) fn refuse_weave_lens(
        &self,
        reader: WeaveDigestReader,
        scheduled_for: u64,
        rendered_at: u64,
        refusal: &WeaveLensRefusal,
    ) -> Result<bool> {
        let key = digest_key(reader, scheduled_for);
        self.with_write_txn_grouped(|txn| {
            let Some(bytes) = self.store.vault_meta.get(&*txn, &key)? else {
                return Ok(false);
            };
            let mut wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if wire.rendered_at != rendered_at || wire.lens.is_some() || wire.lens_refused.is_some()
            {
                return Ok(false);
            }
            wire.lens_refused = Some(refusal.clone());
            let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
            self.store.vault_meta.put(txn, &key, &bytes)?;
            Ok(true)
        })
    }

    /// Keep a live lens's render as `reader`'s newest (OF-499), then settle
    /// the one it replaces on the skill's corrections axis. The axis is
    /// evidence about the skill, never a gate on the render.
    pub(super) fn keep_live_weave_lens(
        &self,
        reader: WeaveReader<'_>,
        report: &WeaveReport,
        render: &WeaveLensRender,
    ) -> Result<()> {
        // An Admin's render keeps under its grant, its proof current in the
        // writer that keeps it (OF-499 A3).
        if let WeaveReader::Admin(admin) = reader {
            return self.keep_weave_admin_live_lens(admin, report, render);
        }
        let id = {
            let txn = self.store.env.read_txn()?;
            reader.id(self, &txn)?
        };
        let reader = WeaveDigestReader::of(&reader, id);
        let key = reader.key(LIVE_PREFIX);
        let bytes = serde_json::to_vec(&KeptLiveLens::of(report, render)).map_err(|_| invalid())?;
        let previous = self.with_write_txn_grouped(|txn| {
            let previous = self
                .store
                .vault_meta
                .get(&*txn, &key)?
                .map(|bytes| serde_json::from_slice::<KeptLiveLens>(&bytes))
                .transpose()
                .map_err(|_| invalid())?;
            self.store.vault_meta.put(txn, &key, &bytes)?;
            Ok(previous)
        })?;
        if let Some(previous) = previous.filter(|kept| kept.rendered_at() < render.rendered_at)
            && let Err(error) = settle_live_weave_lens(self, reader, &previous, render.rendered_at)
        {
            tracing::warn!(?error, "live weave lens axis did not settle");
        }
        Ok(())
    }

    /// The reader's newest period before `scheduled_for` that holds a render.
    fn previous_weave_lens(
        &self,
        reader: WeaveDigestReader,
        scheduled_for: u64,
    ) -> Result<Option<(u64, WeaveReport, WeaveLensRender)>> {
        let txn = self.store.env.read_txn()?;
        let prefix = reader.key(DIGEST_PREFIX);
        let mut previous = None;
        for row in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (key, bytes) = row?;
            let Some(at) = key
                .strip_prefix(prefix.as_slice())
                .and_then(|at| <[u8; 8]>::try_from(at).ok())
                .map(u64::from_be_bytes)
            else {
                continue;
            };
            if at >= scheduled_for {
                break;
            }
            let mut wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if let Some(lens) = wire.lens.take() {
                previous = Some((at, wire.into_report()?.value, lens));
            }
        }
        Ok(previous)
    }
}

fn digest_key(reader: WeaveDigestReader, scheduled_for: u64) -> Vec<u8> {
    [
        reader.key(DIGEST_PREFIX),
        scheduled_for.to_be_bytes().to_vec(),
    ]
    .concat()
}

impl ScopedRead<'_> {
    /// Load historical digest content only for its bound reader, applying the
    /// CURRENT read policy to the SAVED bodies and each referenced endpoint.
    /// No owner inspection shortcut is a data-read grant.
    pub fn read_weave_digest(
        &self,
        reader: WeaveReader<'_>,
        scheduled_for: u64,
    ) -> Result<Option<StoredWeaveDigest>> {
        if self.session_view.is_some() {
            return Err(invalid());
        }
        // Its grants judge at the refreshed persisted clock (FIX 8671).
        let txn = self.grant_read_txn()?;
        let id = match reader {
            WeaveReader::Person(id) | WeaveReader::Agent(id) => {
                if self.actor_key.actor_ref() != id.to_hex() {
                    return Err(invalid());
                }
                id
            }
            WeaveReader::Owner(owner) => {
                let actor = owner.revalidate_in_txn(self.vault, &txn)?;
                if self.actor_key.actor_ref() != actor.to_hex()
                    && self.actor_key.actor_ref() != owner.principal_ref_for_read(self.vault)?
                {
                    return Err(invalid());
                }
                actor
            }
            // An Admin binds this lane to its proof in this snapshot (OF-499
            // A3); its own door builds the lane here too.
            WeaveReader::Admin(admin) => {
                self.bind_weave_admin_in(&txn, admin)?;
                admin.actor()
            }
        };
        let reader_key = match reader {
            WeaveReader::Person(_) => WeaveDigestReader::Person(id),
            WeaveReader::Owner(_) => WeaveDigestReader::Owner(id),
            WeaveReader::Agent(_) => WeaveDigestReader::Agent(id),
            WeaveReader::Admin(admin) => WeaveDigestReader::Admin(WeaveAdminKey::of(admin)),
        };
        self.saved_weave_digest_in_txn(&txn, reader_key, scheduled_for, Some(reader))
    }

    /// `reader_key`'s saved period at `scheduled_for` in `txn`, under this
    /// read's CURRENT policy: [`Self::read_weave_digest`]'s checks once its
    /// reader is bound, shared with the owner's background lens (SCAN C026).
    /// The saved sections must still be the reader's, each source live and
    /// retrievable, each claim's current body exactly its saved one and
    /// readable, each link still admitted and each card still the reader's;
    /// anything else is withheld (`None`). Each loop decision row is
    /// rechecked on its own under `opener`, the bound reader, or with none
    /// (the owner's proofless background lens) its recorded owner's hook; a
    /// row that no longer reads as saved is withheld alone (OF-499 A2).
    pub(super) fn saved_weave_digest_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader_key: WeaveDigestReader,
        scheduled_for: u64,
        opener: Option<WeaveReader<'_>>,
    ) -> Result<Option<StoredWeaveDigest>> {
        let id = reader_key.id();
        let role = match reader_key {
            WeaveDigestReader::Person(_) => "person",
            WeaveDigestReader::Owner(_) => "owner",
            WeaveDigestReader::Agent(_) => "agent",
            WeaveDigestReader::Admin(_) => crate::gate::weave_policy::ADMIN_ROLE,
        };
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        // Even an empty saved report must not reveal historical section names
        // or an old narrowing receipt to a caller with no current read door.
        if filter.deny_all {
            return Ok(None);
        }
        let Some(allowed) = crate::gate::weave_policy::effective_resolved(&policy, role, id) else {
            return Ok(None);
        };
        let Some(bytes) = self
            .vault
            .store
            .vault_meta
            .get(txn, &digest_key(reader_key, scheduled_for))?
        else {
            return Ok(None);
        };
        let mut wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let rendered_at = wire.rendered_at;
        let lens = wire.lens.take();
        let lens_refused = wire.lens_refused.take();
        let mut report = wire.into_report()?;
        // A saved digest is served whole, however many sections and items it
        // holds (rule 5).
        if report
            .value
            .sections
            .iter()
            .any(|section| !allowed.sections.contains(section.kind.policy_name()))
            || !sources_live_in_txn(&self.vault.store, txn, &report.value)?
        {
            return Ok(None);
        }
        for source in report_sources(&report.value)? {
            if !self.is_entity_retrievable_with_policy_in(txn, &policy, &filter, &source)? {
                return Ok(None);
            }
        }
        for section in &report.value.sections {
            for item in &section.items {
                match item {
                    WeaveItem::Claim { id, body } => {
                        let Some(current) = crate::ports::EntityStoreRead::port_entity_raw(
                            &self.vault.store,
                            txn,
                            id,
                        )?
                        else {
                            return Ok(None);
                        };
                        if current.len() < crate::batch::ENTITY_METADATA_HEADER_LEN
                            || current[0] != crate::registry::ENTITY_TYPE_CLAIM
                        {
                            return Ok(None);
                        }
                        let saved_body = encode_claim_body(body)?;
                        // A current public replacement cannot authorize a
                        // different old body or changed claim-facet graph.
                        if current[crate::batch::ENTITY_METADATA_HEADER_LEN..] != saved_body {
                            return Ok(None);
                        }
                        let mut historical =
                            current[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
                        historical.extend_from_slice(&saved_body);
                        if !self.is_entity_raw_readable_with_filter_in(
                            txn,
                            &policy,
                            id,
                            &historical,
                            &filter,
                        )? {
                            return Ok(None);
                        }
                        // Readable endpoints are not pair authority: an edge
                        // claim keeps the live lens's exact-relation admission.
                        if !self.weave_claim_edge_admitted_in(txn, &policy, &filter, body)? {
                            return Ok(None);
                        }
                    }
                    WeaveItem::Link {
                        source,
                        kind,
                        target,
                    } => {
                        let Some(edge) = self.live_weave_edge_in(txn, *source, *kind, *target)?
                        else {
                            return Ok(None);
                        };
                        if !self
                            .admit_stored_edge_in(txn, &policy, &filter, *source, edge)?
                            .visible()
                        {
                            return Ok(None);
                        }
                    }
                    // Dreaming progress is only ever its own resident's.
                    WeaveItem::DreamProgress { resident, .. }
                        if reader_key != WeaveDigestReader::Agent(*resident) =>
                    {
                        return Ok(None);
                    }
                    // A saved card stays its audience's: it must still exist,
                    // and the reader must still be one of its recipients or a
                    // live owner.
                    WeaveItem::AgentHealth { card, .. } => {
                        match crate::dreamer_runner::maintenance::agent_health::agent_health_card_in_txn(
                            self.vault,
                            txn,
                            &card.card_ref(),
                        )? {
                            Some(current)
                                if super::weave_report::weave_card_admitted(
                                    self.vault, txn, &current, id,
                                )? => {}
                            _ => return Ok(None),
                        }
                    }
                    // A saved audit serves while its own row reads exactly
                    // as saved: a newer sample moves no older period.
                    WeaveItem::SieveAudit { attempt, audit, .. }
                        if !super::weave_report::sieve_score::sieve_audit_unchanged_in(
                            &self.vault.store,
                            txn,
                            attempt,
                            audit,
                        ) =>
                    {
                        return Ok(None);
                    }
                    _ => {}
                }
            }
        }
        // Each loop row is rechecked on its own: one that no longer reads as
        // saved is withheld alone, never the period (OF-499 A2).
        self.recheck_saved_loop_decisions_in_txn(txn, reader_key, opener, &mut report.value);
        self.serve_saved_copy_in(txn, &mut report.value)?;
        Ok(Some(StoredWeaveDigest {
            reader: reader_key,
            scheduled_for,
            rendered_at,
            report,
            lens,
            lens_refused,
        }))
    }

    /// The bound reader's newest saved digest, under the same checks as
    /// [`Self::read_weave_digest`].
    pub fn read_latest_weave_digest(
        &self,
        reader: WeaveReader<'_>,
    ) -> Result<Option<StoredWeaveDigest>> {
        let latest = {
            let txn = self.vault.store.env.read_txn()?;
            let reader_key = WeaveDigestReader::of(&reader, reader.id(self.vault, &txn)?);
            admin::latest_period_in(&self.vault.store, &txn, reader_key)?
        };
        match latest {
            Some(scheduled_for) => self.read_weave_digest(reader, scheduled_for),
            None => Ok(None),
        }
    }

    /// Project a due row through exactly the live lens. A non-due row changes
    /// nothing. The schedule advance and saved report commit in one transaction.
    pub fn render_due_weave_digest(
        &self,
        reader: WeaveReader<'_>,
        now: u64,
    ) -> Result<Option<StoredWeaveDigest>> {
        self.render_due_weave_digest_with(reader, now, || Ok(()))
    }

    // The callback is used only by same-module tests to place a concurrent
    // mutation precisely between projection and the publication transaction.
    fn render_due_weave_digest_with(
        &self,
        reader: WeaveReader<'_>,
        now: u64,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<Option<StoredWeaveDigest>> {
        let owner = match &reader {
            WeaveReader::Owner(owner) => Some(*owner),
            _ => None,
        };
        let id = match &reader {
            WeaveReader::Person(id) => WeaveDigestReader::Person(*id),
            WeaveReader::Owner(owner) => WeaveDigestReader::Owner(owner.revalidate(self.vault)?),
            WeaveReader::Agent(id) => WeaveDigestReader::Agent(*id),
            // An Admin reads in the foreground only: no Admin schedule
            // exists to render, and none publishes (OF-499 A3).
            WeaveReader::Admin(_) => return Ok(None),
        };
        // Do not turn a non-due probe into a backdoor for inspecting the row:
        // even a skip must be actor-bound (and an owner must still be live).
        if match &reader {
            WeaveReader::Person(person) | WeaveReader::Agent(person) => {
                self.actor_key.actor_ref() != person.to_hex()
            }
            WeaveReader::Owner(owner) => {
                let txn = self.vault.store.env.read_txn()?;
                let actor = owner.revalidate_in_txn(self.vault, &txn)?;
                self.actor_key.actor_ref() != actor.to_hex()
                    && self.actor_key.actor_ref() != owner.principal_ref_in_txn(self.vault, &txn)?
            }
            // Returned above: an Admin renders nothing here.
            WeaveReader::Admin(_) => true,
        } {
            return Err(invalid());
        }
        let key = id.key(SCHEDULE_PREFIX);
        let saved = {
            let txn = self.vault.store.env.read_txn()?;
            self.vault
                .store
                .vault_meta
                .get(&txn, &key)?
                .map(|b| b.to_vec())
        };
        let Some(saved) = saved else {
            return Ok(None);
        };
        let row = serde_json::from_slice::<WireSchedule>(&saved)
            .map_err(|_| invalid())?
            .into_row(id)?;
        if now < row.next_due_at {
            return Ok(None);
        }
        let elapsed = now - row.next_due_at;
        let periods = elapsed / row.cadence.seconds() + 1;
        let next_due_at = row
            .next_due_at
            .checked_add(
                periods
                    .checked_mul(row.cadence.seconds())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        let report = self.weave_report_snapshot(reader, &row.recipe)?;
        let sources = dependencies::indexed_sources(&report.value)?;
        let wire = WireDigest::from_report(now, &report)?;
        let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
        let next = serde_json::to_vec(&WireSchedule {
            next_due_at,
            ..WireSchedule::from_row(&row)
        })
        .map_err(|_| invalid())?;
        let digest_key = [
            id.key(DIGEST_PREFIX),
            row.next_due_at.to_be_bytes().to_vec(),
        ]
        .concat();
        before_commit()?;
        let published = self.vault.with_write_txn_grouped(|txn| {
            if let Some(owner) = owner {
                owner.revalidate_in_txn(self.vault, txn)?;
            }
            // Re-run the identical scoped lens in this writer's snapshot.
            // Its claim, project, budget, link and edge-endpoint checks must
            // all still produce the report and receipt we intend to save.
            if self.vault.store.vault_meta.get(&*txn, &key)?.as_deref() != Some(saved.as_slice()) {
                return Ok(None);
            }
            if !sources_live_in_txn(&self.vault.store, txn, &report.value)? {
                return Ok(None);
            }
            // Each row it saves must still serve; a loop decision the
            // ledger gained since joins the next period (FIX 7694).
            let current = self.weave_report_in_txn(txn, reader, &row.recipe)?;
            if current.receipt != report.receipt
                || !super::weave_lens::snapshot_still_served(&report.value, &current.value)
            {
                return Ok(None);
            }
            if let Some(raw) = digest_row_in(&self.vault.store, txn, &digest_key)? {
                let previous: WireDigest = serde_json::from_slice(&raw).map_err(|_| invalid())?;
                for source in dependencies::indexed_sources(&previous.into_report()?.value)? {
                    index_source_in_txn(&self.vault.store, txn, &source, &digest_key, false)?;
                }
            }
            for source in &sources {
                index_source_in_txn(&self.vault.store, txn, source, &digest_key, true)?;
            }
            put_digest_row_in_txn(&self.vault.store, txn, &digest_key, &bytes)?;
            self.vault.store.vault_meta.put(txn, &key, &next)?;
            // Delivery is the reader's inbox, in this same write, for a
            // digest with anything in it. An owner's notice went out when
            // its digest fell due, and the owner is the one opening it now.
            let any = report
                .value
                .sections
                .iter()
                .any(|section| !section.items.is_empty());
            if owner.is_none() && any {
                self.vault
                    .record_notification_in_txn(txn, &id.notification(row.next_due_at, now))?;
            }
            // The lens's generate step renders the period on the Dreamer's
            // lent model, queued in this same write.
            if any {
                crate::dreamer_runner::DreamerRunnerStore::new(self.vault)
                    .enqueue_weave_lens_in_txn(txn, id, row.next_due_at, now)?;
            }
            // The copy handed back serves as a read of it would.
            let mut served = report;
            self.serve_saved_copy_in(txn, &mut served.value)?;
            Ok(Some(StoredWeaveDigest {
                reader: id,
                scheduled_for: row.next_due_at,
                rendered_at: now,
                report: served,
                lens: None,
                lens_refused: None,
            }))
        })?;
        // The period's inbox notice also goes to the reader's own channel
        // once it has committed (FIX 1262); a period with no notice sends
        // nothing.
        if owner.is_none()
            && let Some(digest) = &published
            && let Ok(notice) =
                crate::inbox::notification_id(&id.notification(digest.scheduled_for, now).source)
        {
            self.vault
                .send_weave_digest(id, digest.scheduled_for, notice);
        }
        Ok(published)
    }
}

#[cfg(test)]
mod tests;
