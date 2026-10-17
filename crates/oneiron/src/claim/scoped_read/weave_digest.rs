//! Per-reader report schedules (OF-499). The host's deadline timer serves
//! them: each due person or agent digest renders under its own reader's
//! read and lands in that reader's inbox in the same write. An owner's
//! digest needs the owner's live proof, so the timer sends the owner a due
//! notice and the digest renders when the owner opens it. No composition
//! policy lives here. Each published period with anything in it queues the
//! lens's generate step (`weave_lens.rs`), whose render lands on the row.
use super::weave_lens::{WeaveLensRender, settle_weave_lens_axes};
use super::{
    ScopedRead, ScopedReadReceipt, ScopedReadResult, WeaveItem, WeaveReader, WeaveReport,
    WeaveSection, WeaveSectionKind, WeaveSectionSpec,
};
use crate::claim::{ClaimSubject, decode_claim_body, encode_claim_body};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::ports::TombstoneStoreRead;
use crate::store::Store;
use crate::{EdgeKind, EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const SCHEDULE_PREFIX: &[u8] = b"weave:schedule:v1:";
const DIGEST_PREFIX: &[u8] = b"weave:digest:v1:";
const SOURCE_PREFIX: &[u8] = b"weave:digest_source:v1:";
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
}

impl WeaveDigestReader {
    /// The reader's own id.
    #[must_use]
    pub fn id(self) -> EntityId {
        match self {
            Self::Person(id) | Self::Owner(id) | Self::Agent(id) => id,
        }
    }

    /// The reader's role tag, as its keys and inbox events spell it.
    pub(super) fn tag(self) -> (&'static str, EntityId) {
        match self {
            Self::Person(id) => ("p", id),
            Self::Owner(id) => ("o", id),
            Self::Agent(id) => ("a", id),
        }
    }

    pub(super) fn from_tag(tag: &str, id: EntityId) -> Option<Self> {
        match tag {
            "p" => Some(Self::Person(id)),
            "o" => Some(Self::Owner(id)),
            "a" => Some(Self::Agent(id)),
            _ => None,
        }
    }

    fn key(self, prefix: &[u8]) -> Vec<u8> {
        let (kind, id) = match self {
            Self::Person(id) => (b'p', id),
            Self::Owner(id) => (b'o', id),
            Self::Agent(id) => (b'a', id),
        };
        [prefix, &[kind], id.as_bytes()].concat()
    }

    /// The reader a schedule key names; `None` for a key of another shape.
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
        }
    }

    /// The reader's inbox event for one period's digest. With the producer
    /// it derives the NOTIFICATION id, so a replay lands the same row.
    pub(super) fn notification(self, scheduled_for: u64, now: u64) -> NotificationEvent {
        let (kind, id) = match self {
            Self::Person(id) => ("p", id),
            Self::Owner(id) => ("o", id),
            Self::Agent(id) => ("a", id),
        };
        NotificationEvent {
            kind: NotificationKind::Digest,
            source: NotificationSource {
                producer: WEAVE_DIGEST_NOTIFICATION_PRODUCER.to_owned(),
                event: format!("{kind}:{}:{scheduled_for}", id.to_hex()),
                result: Some(scheduled_for.to_string()),
                ..NotificationSource::default()
            },
            subject_refs: Vec::new(),
            recipient: Some(id),
            created_at: now,
            origin_conversation: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSectionSpec {
    kind: WeaveSectionKind,
    predicates: Vec<String>,
    edge_kinds: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSchedule {
    cadence: WeaveDigestCadence,
    next_due_at: u64,
    recipe: Vec<WireSectionSpec>,
    /// The timer leaves this row until then: an owner's notice went out, or
    /// its render failed. The next render or schedule write clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_until: Option<u64>,
}

impl WireSchedule {
    /// When the timer next serves this row.
    fn serve_at(&self) -> u64 {
        self.held_until
            .map_or(self.next_due_at, |held| held.max(self.next_due_at))
    }

    /// The first cadence boundary after `now`, counted from `next_due_at`.
    fn next_boundary_after(&self, now: u64) -> Result<u64> {
        let periods = now.saturating_sub(self.next_due_at) / self.cadence.seconds() + 1;
        self.next_due_at
            .checked_add(
                periods
                    .checked_mul(self.cadence.seconds())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)
    }

    fn from_row(row: &WeaveDigestSchedule) -> Self {
        Self {
            cadence: row.cadence,
            next_due_at: row.next_due_at,
            held_until: None,
            recipe: row
                .recipe
                .iter()
                .map(|s| WireSectionSpec {
                    kind: s.kind,
                    predicates: s.predicates.clone(),
                    edge_kinds: s.edge_kinds.iter().map(|k| *k as u8).collect(),
                })
                .collect(),
        }
    }
    fn into_row(self, reader: WeaveDigestReader) -> Result<WeaveDigestSchedule> {
        Ok(WeaveDigestSchedule {
            reader,
            cadence: self.cadence,
            next_due_at: self.next_due_at,
            recipe: self
                .recipe
                .into_iter()
                .map(|s| {
                    Ok(WeaveSectionSpec {
                        kind: s.kind,
                        predicates: s.predicates,
                        edge_kinds: s
                            .edge_kinds
                            .into_iter()
                            .map(|k| EdgeKind::try_from_u8(k).ok_or_else(invalid))
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDigest {
    rendered_at: u64,
    receipt: ScopedReadReceipt,
    sections: Vec<WireSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lens: Option<WeaveLensRender>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSection {
    kind: WeaveSectionKind,
    items: Vec<WireItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum WireItem {
    Claim {
        id: String,
        body: Vec<u8>,
    },
    Project {
        id: String,
        goal: Option<String>,
    },
    Budget {
        project: String,
        budget_ref: String,
    },
    Link {
        source: String,
        kind: u8,
        target: String,
    },
    DreamProgress {
        resident: String,
        dreamed_at: u64,
        entries: u64,
    },
    AgentHealth {
        card: crate::dreamer_runner::maintenance::agent_health::AgentHealthCard,
    },
}

impl WireDigest {
    fn from_report(rendered_at: u64, report: &ScopedReadResult<WeaveReport>) -> Result<Self> {
        Ok(Self {
            rendered_at,
            receipt: report.receipt.clone(),
            sections: report
                .value
                .sections
                .iter()
                .map(|s| {
                    Ok(WireSection {
                        kind: s.kind,
                        items: s
                            .items
                            .iter()
                            .map(|i| {
                                Ok(match i {
                                    WeaveItem::Claim { id, body } => WireItem::Claim {
                                        id: id.to_hex(),
                                        body: encode_claim_body(body)?,
                                    },
                                    WeaveItem::Project { id, goal } => WireItem::Project {
                                        id: id.to_hex(),
                                        goal: goal.clone(),
                                    },
                                    WeaveItem::Budget {
                                        project,
                                        budget_ref,
                                    } => WireItem::Budget {
                                        project: project.to_hex(),
                                        budget_ref: budget_ref.to_hex(),
                                    },
                                    WeaveItem::Link {
                                        source,
                                        kind,
                                        target,
                                    } => WireItem::Link {
                                        source: source.to_hex(),
                                        kind: *kind as u8,
                                        target: target.to_hex(),
                                    },
                                    WeaveItem::DreamProgress {
                                        resident,
                                        dreamed_at,
                                        entries,
                                    } => WireItem::DreamProgress {
                                        resident: resident.to_hex(),
                                        dreamed_at: *dreamed_at,
                                        entries: *entries,
                                    },
                                    WeaveItem::AgentHealth { card } => {
                                        WireItem::AgentHealth { card: card.clone() }
                                    }
                                })
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            lens: None,
        })
    }
    fn into_report(self) -> Result<ScopedReadResult<WeaveReport>> {
        Ok(ScopedReadResult {
            receipt: self.receipt,
            value: WeaveReport {
                sections: self
                    .sections
                    .into_iter()
                    .map(|s| {
                        Ok(WeaveSection {
                            kind: s.kind,
                            items: s
                                .items
                                .into_iter()
                                .map(|i| {
                                    Ok(match i {
                                        WireItem::Claim { id, body } => WeaveItem::Claim {
                                            id: EntityId::from_hex(&id).map_err(|_| invalid())?,
                                            body: Box::new(
                                                decode_claim_body(&body, true)
                                                    .map_err(|_| invalid())?,
                                            ),
                                        },
                                        WireItem::Project { id, goal } => WeaveItem::Project {
                                            id: EntityId::from_hex(&id).map_err(|_| invalid())?,
                                            goal,
                                        },
                                        WireItem::Budget {
                                            project,
                                            budget_ref,
                                        } => WeaveItem::Budget {
                                            project: EntityId::from_hex(&project)
                                                .map_err(|_| invalid())?,
                                            budget_ref: EntityId::from_hex(&budget_ref)
                                                .map_err(|_| invalid())?,
                                        },
                                        WireItem::Link {
                                            source,
                                            kind,
                                            target,
                                        } => WeaveItem::Link {
                                            source: EntityId::from_hex(&source)
                                                .map_err(|_| invalid())?,
                                            kind: EdgeKind::try_from_u8(kind)
                                                .ok_or_else(invalid)?,
                                            target: EntityId::from_hex(&target)
                                                .map_err(|_| invalid())?,
                                        },
                                        WireItem::DreamProgress {
                                            resident,
                                            dreamed_at,
                                            entries,
                                        } => WeaveItem::DreamProgress {
                                            resident: EntityId::from_hex(&resident)
                                                .map_err(|_| invalid())?,
                                            dreamed_at,
                                            entries,
                                        },
                                        WireItem::AgentHealth { card } => {
                                            WeaveItem::AgentHealth { card }
                                        }
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            },
        })
    }
}

/// Include the copied claim and every typed reference carried by its saved
/// projection. This is an index over byte carriers, not a read authorization.
fn report_sources(report: &WeaveReport) -> Result<BTreeSet<EntityId>> {
    let mut sources = BTreeSet::new();
    for section in &report.sections {
        for item in &section.items {
            match item {
                WeaveItem::Claim { id, body } => {
                    sources.insert(*id);
                    match body.subject {
                        ClaimSubject::Entity(subject) => {
                            sources.insert(subject);
                        }
                        ClaimSubject::Edge { source, target, .. } => {
                            sources.insert(source);
                            sources.insert(target);
                        }
                    }
                }
                WeaveItem::Project { id, goal } => {
                    sources.insert(*id);
                    if let Some(goal) = goal {
                        sources.insert(EntityId::from_hex(goal).map_err(|_| invalid())?);
                    }
                }
                WeaveItem::Budget {
                    project,
                    budget_ref,
                } => {
                    sources.insert(*project);
                    sources.insert(*budget_ref);
                }
                WeaveItem::Link { source, target, .. } => {
                    sources.insert(*source);
                    sources.insert(*target);
                }
                // The reader's own dreaming time and entry count: no copied
                // body, and no diary entry's id or text.
                WeaveItem::DreamProgress { .. } => {}
                // A card is a side-table row, not a record: a saved period
                // reads the current card again before it serves one.
                WeaveItem::AgentHealth { .. } => {}
            }
        }
    }
    Ok(sources)
}

fn source_key(source: &EntityId, digest_key: &[u8]) -> Vec<u8> {
    [SOURCE_PREFIX, source.as_bytes(), digest_key].concat()
}

/// A hard delete cannot leave a copied report body in vault metadata. This
/// source-prefix index is populated in the same transaction as publication,
/// and invalidated by the common deletion door in its erasure transaction.
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
        if !digest_key.starts_with(DIGEST_PREFIX)
            || digest_key.len() != DIGEST_PREFIX.len() + 1 + 16 + 8
        {
            return Err(Error::CorruptedIndex("weave digest source index"));
        }
        if let Some(raw) = store.vault_meta.get(&*txn, digest_key)? {
            // Even an undecodable saved row is deleted. If it cannot be
            // decoded, orphan index keys contain references but no body bytes.
            if let Ok(wire) = serde_json::from_slice::<WireDigest>(&raw)
                && let Ok(report) = wire.into_report()
                && let Ok(sources) = report_sources(&report.value)
            {
                for other in sources {
                    store
                        .vault_meta
                        .delete(txn, &source_key(&other, digest_key))?;
                }
            }
            store.vault_meta.delete(txn, digest_key)?;
        }
        store.vault_meta.delete(txn, &index_key)?;
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
                && crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
                    .is_none_or(|raw| raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl Vault {
    /// Owner-authorized local schedule. Hosts enqueue due rows; this door owns no timer.
    pub fn set_weave_digest_schedule(
        &self,
        owner: &AuthenticatedOwner,
        row: &WeaveDigestSchedule,
    ) -> Result<()> {
        let reader = match row.reader {
            WeaveDigestReader::Person(id) => WeaveReader::Person(id),
            WeaveDigestReader::Owner(id) if id == owner.revalidate(self)? => {
                WeaveReader::Owner(owner)
            }
            WeaveDigestReader::Owner(_) => return Err(invalid()),
            WeaveDigestReader::Agent(id) => WeaveReader::Agent(id),
        };
        if row.recipe.is_empty() {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(&WireSchedule::from_row(row)).map_err(|_| invalid())?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            super::weave_report::validate_weave_recipe(self, txn, &policy, &reader, &row.recipe)?;
            self.store
                .vault_meta
                .put(txn, &row.reader.key(SCHEDULE_PREFIX), &bytes)?;
            Ok(())
        })?;
        // The deadline timer re-reads committed rows on this signal.
        self.store.notify_proactivity_changes();
        Ok(())
    }

    /// Owner-only: stop one reader's digests. Its saved digests stay.
    pub fn clear_weave_digest_schedule(
        &self,
        owner: &AuthenticatedOwner,
        reader: WeaveDigestReader,
    ) -> Result<bool> {
        let cleared = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            Ok(self
                .store
                .vault_meta
                .delete(txn, &reader.key(SCHEDULE_PREFIX))?)
        })?;
        self.store.notify_proactivity_changes();
        Ok(cleared)
    }

    /// Owner-only: every reader's schedule, in key order. An undecodable
    /// row is left out; it arms no deadline either.
    pub fn weave_digest_schedules(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<WeaveDigestSchedule>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let mut rows = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&txn, SCHEDULE_PREFIX)? {
            let (key, bytes) = row?;
            let Some(reader) = WeaveDigestReader::from_schedule_key(&key) else {
                continue;
            };
            if let Ok(wire) = serde_json::from_slice::<WireSchedule>(&bytes)
                && let Ok(row) = wire.into_row(reader)
            {
                rows.push(row);
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
    /// owner's gets a due notice instead. A row that fails to render is held
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
                    self.notify_owner_weave_digest_due(owner, &key, &saved, now)
                }
                WeaveDigestReader::Person(id) => self
                    .render_scheduled_weave_digest(id, EdgeActorClass::Human, now)
                    .map(|stored| stored.is_some()),
                WeaveDigestReader::Agent(id) => self
                    .render_scheduled_weave_digest(id, EdgeActorClass::Agent, now)
                    .map(|stored| stored.is_some()),
            };
            match outcome {
                Ok(true) => served += 1,
                Ok(false) => self.hold_weave_schedule(&key, &saved, now)?,
                Err(error) => {
                    tracing::warn!(?error, "scheduled weave digest refused; held a period");
                    self.hold_weave_schedule(&key, &saved, now)?;
                }
            }
        }
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

    /// An owner's digest renders only under its live proof, so a due row
    /// gets a notice naming its period, then waits for the owner to open it.
    fn notify_owner_weave_digest_due(
        &self,
        owner: EntityId,
        key: &[u8],
        saved: &[u8],
        now: u64,
    ) -> Result<bool> {
        let wire: WireSchedule = serde_json::from_slice(saved).map_err(|_| invalid())?;
        let scheduled_for = wire.next_due_at;
        let held = serde_json::to_vec(&WireSchedule {
            held_until: Some(wire.next_boundary_after(now)?),
            ..wire
        })
        .map_err(|_| invalid())?;
        self.with_write_txn_grouped(|txn| {
            if self.store.vault_meta.get(&*txn, key)?.as_deref() != Some(saved) {
                return Ok(false);
            }
            self.record_notification_in_txn(
                txn,
                &WeaveDigestReader::Owner(owner).notification(scheduled_for, now),
            )?;
            self.store.vault_meta.put(txn, key, &held)?;
            Ok(true)
        })
    }

    /// Leave a row the timer could not serve until its next boundary.
    fn hold_weave_schedule(&self, key: &[u8], saved: &[u8], now: u64) -> Result<()> {
        let Ok(wire) = serde_json::from_slice::<WireSchedule>(saved) else {
            return Ok(());
        };
        let held = serde_json::to_vec(&WireSchedule {
            held_until: Some(wire.next_boundary_after(now)?),
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
    /// an agent's under its own current read, an owner's from the row with
    /// its sources still live. The Dreamer holds no owner proof, and only the
    /// owner's own door ever serves what it renders.
    pub(crate) fn weave_digest_for_lens(
        &self,
        reader: WeaveDigestReader,
        scheduled_for: u64,
    ) -> Result<Option<StoredWeaveDigest>> {
        let (class, lens_reader) = match reader {
            WeaveDigestReader::Person(id) => (EdgeActorClass::Human, WeaveReader::Person(id)),
            WeaveDigestReader::Agent(id) => (EdgeActorClass::Agent, WeaveReader::Agent(id)),
            WeaveDigestReader::Owner(_) => {
                let txn = self.store.env.read_txn()?;
                let Some(bytes) = self
                    .store
                    .vault_meta
                    .get(&txn, &digest_key(reader, scheduled_for))?
                else {
                    return Ok(None);
                };
                let mut wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                let rendered_at = wire.rendered_at;
                let lens = wire.lens.take();
                let report = wire.into_report()?;
                if !sources_live_in_txn(&self.store, &txn, &report.value)? {
                    return Ok(None);
                }
                return Ok(Some(StoredWeaveDigest {
                    reader,
                    scheduled_for,
                    rendered_at,
                    report,
                    lens,
                }));
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
        let txn = self.vault.store.env.read_txn()?;
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
        };
        let reader_key = match reader {
            WeaveReader::Person(_) => WeaveDigestReader::Person(id),
            WeaveReader::Owner(_) => WeaveDigestReader::Owner(id),
            WeaveReader::Agent(_) => WeaveDigestReader::Agent(id),
        };
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        // Even an empty saved report must not reveal historical section names
        // or an old narrowing receipt to a caller with no current read door.
        if filter.deny_all {
            return Ok(None);
        }
        let Some(allowed) =
            crate::gate::weave_policy::effective_resolved(&policy, reader.role(), id)
        else {
            return Ok(None);
        };
        let key = [
            reader_key.key(DIGEST_PREFIX),
            scheduled_for.to_be_bytes().to_vec(),
        ]
        .concat();
        let Some(bytes) = self.vault.store.vault_meta.get(&txn, &key)? else {
            return Ok(None);
        };
        let mut wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let rendered_at = wire.rendered_at;
        let lens = wire.lens.take();
        let report = wire.into_report()?;
        if report.value.sections.len() > allowed.max_sections
            || report.value.sections.iter().any(|section| {
                !allowed.sections.contains(section.kind.policy_name())
                    || section.items.len() > allowed.max_rows
            })
            || !sources_live_in_txn(&self.vault.store, &txn, &report.value)?
        {
            return Ok(None);
        }
        for source in report_sources(&report.value)? {
            if !self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &source)? {
                return Ok(None);
            }
        }
        for section in &report.value.sections {
            for item in &section.items {
                match item {
                    WeaveItem::Claim { id, body } => {
                        let Some(current) = crate::ports::EntityStoreRead::port_entity_raw(
                            &self.vault.store,
                            &txn,
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
                            &txn,
                            &policy,
                            id,
                            &historical,
                            &filter,
                        )? {
                            return Ok(None);
                        }
                        // Readable endpoints are not pair authority: an edge
                        // claim keeps the live lens's exact-relation admission.
                        if !self.weave_claim_edge_admitted_in(&txn, &policy, &filter, body)? {
                            return Ok(None);
                        }
                    }
                    WeaveItem::Link {
                        source,
                        kind,
                        target,
                    } => {
                        let Some(edge) = self.live_weave_edge_in(&txn, *source, *kind, *target)?
                        else {
                            return Ok(None);
                        };
                        if !self
                            .admit_stored_edge_in(&txn, &policy, &filter, *source, edge)?
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
                    WeaveItem::AgentHealth { card } => {
                        match crate::dreamer_runner::maintenance::agent_health::agent_health_card_in_txn(
                            self.vault,
                            &txn,
                            &card.card_ref(),
                        )? {
                            Some(current)
                                if super::weave_report::weave_card_admitted(
                                    self.vault, &txn, &current, id,
                                )? => {}
                            _ => return Ok(None),
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(Some(StoredWeaveDigest {
            reader: reader_key,
            scheduled_for,
            rendered_at,
            report,
            lens,
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
            let prefix =
                WeaveDigestReader::of(&reader, reader.id(self.vault, &txn)?).key(DIGEST_PREFIX);
            let mut latest = None;
            for row in self.vault.store.vault_meta.prefix_iter(&txn, &prefix)? {
                let (key, _) = row?;
                if let Some(at) = key
                    .strip_prefix(prefix.as_slice())
                    .and_then(|at| <[u8; 8]>::try_from(at).ok())
                {
                    latest = Some(u64::from_be_bytes(at));
                }
            }
            latest
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
        let report = self.weave_report(reader, &row.recipe)?;
        let sources = report_sources(&report.value)?;
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
        self.vault.with_write_txn_grouped(|txn| {
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
            if self.weave_report_in_txn(txn, reader, &row.recipe)? != report {
                return Ok(None);
            }
            if let Some(raw) = self.vault.store.vault_meta.get(&*txn, &digest_key)? {
                let previous: WireDigest = serde_json::from_slice(&raw).map_err(|_| invalid())?;
                for source in report_sources(&previous.into_report()?.value)? {
                    self.vault
                        .store
                        .vault_meta
                        .delete(txn, &source_key(&source, &digest_key))?;
                }
            }
            for source in &sources {
                self.vault
                    .store
                    .vault_meta
                    .put(txn, &source_key(source, &digest_key), &[])?;
            }
            self.vault.store.vault_meta.put(txn, &digest_key, &bytes)?;
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
            Ok(Some(StoredWeaveDigest {
                reader: id,
                scheduled_for: row.next_due_at,
                rendered_at: now,
                report,
                lens: None,
            }))
        })
    }
}

#[cfg(test)]
mod tests;
