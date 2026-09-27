//! Host-triggered, per-reader report schedules. No timer or composition policy lives here.
use super::{
    ScopedRead, ScopedReadReceipt, ScopedReadResult, WeaveItem, WeaveReader, WeaveReport,
    WeaveSection, WeaveSectionKind, WeaveSectionSpec,
};
use crate::claim::{ClaimSubject, decode_claim_body, encode_claim_body};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::ports::TombstoneStoreRead;
use crate::store::Store;
use crate::{EdgeKind, EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const SCHEDULE_PREFIX: &[u8] = b"weave:schedule:v1:";
const DIGEST_PREFIX: &[u8] = b"weave:digest:v1:";
const SOURCE_PREFIX: &[u8] = b"weave:digest_source:v1:";

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
    fn key(self, prefix: &[u8]) -> Vec<u8> {
        let (kind, id) = match self {
            Self::Person(id) => (b'p', id),
            Self::Owner(id) => (b'o', id),
            Self::Agent(id) => (b'a', id),
        };
        [prefix, &[kind], id.as_bytes()].concat()
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
}

impl WireSchedule {
    fn from_row(row: &WeaveDigestSchedule) -> Self {
        Self {
            cadence: row.cadence,
            next_due_at: row.next_due_at,
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
                                })
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
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
                && store
                    .entities
                    .get(txn, id.as_bytes())?
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
            WeaveDigestReader::Owner(id) if id == owner.actor() => WeaveReader::Owner(owner),
            WeaveDigestReader::Owner(_) => return Err(invalid()),
            WeaveDigestReader::Agent(id) => WeaveReader::Agent(id),
        };
        if row.recipe.is_empty() {
            return Err(invalid());
        }
        let bytes = serde_json::to_vec(&WireSchedule::from_row(row)).map_err(|_| invalid())?;
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            super::weave_report::validate_weave_recipe(&policy, &reader, &row.recipe)?;
            self.store
                .vault_meta
                .put(txn, &row.reader.key(SCHEDULE_PREFIX), &bytes)?;
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

    /// Owner-only saved projection. A scheduled reader gets the fresh render result
    /// through the scoped door, not an unscoped historical-content lookup.
    pub fn read_weave_digest(
        &self,
        owner: &AuthenticatedOwner,
        reader: WeaveDigestReader,
        scheduled_for: u64,
    ) -> Result<Option<StoredWeaveDigest>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let key = [
            reader.key(DIGEST_PREFIX),
            scheduled_for.to_be_bytes().to_vec(),
        ]
        .concat();
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|bytes| {
                let wire: WireDigest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                let rendered_at = wire.rendered_at;
                let report = wire.into_report()?;
                if !sources_live_in_txn(&self.store, &txn, &report.value)? {
                    return Ok(None);
                }
                Ok(Some(StoredWeaveDigest {
                    reader,
                    scheduled_for,
                    rendered_at,
                    report,
                }))
            })
            .transpose()
            .map(Option::flatten)
    }
}

impl ScopedRead<'_> {
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
            WeaveReader::Owner(owner) => WeaveDigestReader::Owner(owner.actor()),
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
                owner.revalidate_in_txn(self.vault, &txn)?;
                self.actor_key.actor_ref() != owner.actor().to_hex()
                    && self.actor_key.actor_ref() != owner.principal_ref()
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
        self.vault.with_write_txn(|txn| {
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
            if self.weave_report_in(txn, reader, &row.recipe)? != report {
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
            Ok(Some(StoredWeaveDigest {
                reader: id,
                scheduled_for: row.next_due_at,
                rendered_at: now,
                report,
            }))
        })
    }
}

#[cfg(test)]
mod tests;
