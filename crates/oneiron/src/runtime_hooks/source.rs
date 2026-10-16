//! Fact sources and their typed positions (ARCH-0080 §4 Sources and cursors).
//! A position is never a timestamp or the notify counter: an imported claim
//! can carry an old time, and the notify counter is process-local.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::ports::{ChangeLogRecord, ChangeLogStore, ChangeOp, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The claim changelog: the mutation-audit rows, keyed by their record id.
///
/// The id is drawn from `StoreClock::ulid` inside the writer transaction that
/// commits the row, and LMDB runs one writer at a time, so a later commit
/// always holds a larger id. The id floor (`ports:id_floor:v1`) is persisted
/// with every mutation and observed when the vault opens, so ids keep rising
/// across restarts. Key order is therefore commit order: a reader that resumes
/// after its last id never misses a row that commits later.
const CHANGES: SideTable<[u8; 16], ChangeLogRecord, Named> =
    SideTable::new(&side_table::PORTS_CHANGE);
/// The settlement feed: one row per settled proposal, keyed by its sequence.
const SETTLED: SideTable<u64, SettledRow, Named> = SideTable::new(&side_table::HOOKS_SETTLED);
/// The last settlement sequence handed out.
const SETTLED_NEXT: SideTable<(), u64, Named> = SideTable::new(&side_table::HOOKS_SETTLED_NEXT);

/// Rows a batch may scan for each entry it keeps, so a run of other entity
/// kinds cannot make one pass unbounded.
const SCAN_PER_ENTRY: usize = 16;
/// The binding changes read to find where a binding was last written.
const BINDING_CHANGES: usize = 4_096;

/// Where a fact comes from. Each source has its own cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactSource {
    /// Claim writes, in commit order.
    ClaimChangelog,
    /// Settled proposals, in settlement order.
    Settlement,
}

impl FactSource {
    pub const ALL: [Self; 2] = [Self::ClaimChangelog, Self::Settlement];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimChangelog => "claim_changelog",
            Self::Settlement => "settlement",
        }
    }

    pub(super) const fn tag(self) -> u8 {
        match self {
            Self::ClaimChangelog => 0,
            Self::Settlement => 1,
        }
    }
}

/// A claim changelog position: the audit record id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimChangelogPosition(pub [u8; 16]);

/// A settlement position: the feed's committed sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettlementPosition(pub u64);

/// A position in one source. Two positions compare only within one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactPosition {
    ClaimChangelog(ClaimChangelogPosition),
    Settlement(SettlementPosition),
}

impl FactPosition {
    #[must_use]
    pub const fn source(self) -> FactSource {
        match self {
            Self::ClaimChangelog(_) => FactSource::ClaimChangelog,
            Self::Settlement(_) => FactSource::Settlement,
        }
    }

    /// The position's own bytes: the record id, or the sequence big-endian.
    #[must_use]
    pub fn bytes(self) -> Vec<u8> {
        match self {
            Self::ClaimChangelog(position) => position.0.to_vec(),
            Self::Settlement(position) => position.0.to_be_bytes().to_vec(),
        }
    }

    /// Lowercase hex of [`Self::bytes`], as a hook's input carries it.
    #[must_use]
    pub fn hex(self) -> String {
        crate::receipt::hex_lower(&self.bytes())
    }

    /// The source-tagged form replay takes.
    #[must_use]
    pub fn to_hex(self) -> FactPositionHex {
        FactPositionHex(format!("{}:{}", self.source().as_str(), self.hex()))
    }
}

/// A position as text: `claim_changelog:<hex32>` or `settlement:<hex16>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FactPositionHex(pub String);

impl FactPositionHex {
    /// The typed position this text names.
    pub fn parse(&self) -> Result<FactPosition> {
        let (source, hex) = self
            .0
            .split_once(':')
            .ok_or_else(|| invalid("a fact position is <source>:<hex>"))?;
        match source {
            "claim_changelog" => Ok(FactPosition::ClaimChangelog(ClaimChangelogPosition(
                decode_hex(hex)?,
            ))),
            "settlement" => Ok(FactPosition::Settlement(SettlementPosition(
                u64::from_be_bytes(decode_hex(hex)?),
            ))),
            _ => Err(invalid("unknown fact source")),
        }
    }
}

/// The kinds of fact slice 1 follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactKind {
    #[serde(rename = "claim.landed")]
    ClaimLanded,
    #[serde(rename = "claim.superseded")]
    ClaimSuperseded,
    #[serde(rename = "proposal.settled")]
    ProposalSettled,
}

impl FactKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimLanded => "claim.landed",
            Self::ClaimSuperseded => "claim.superseded",
            Self::ProposalSettled => "proposal.settled",
        }
    }
}

/// What the write that made a fact did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FactOp {
    Create,
    Update,
    Supersede,
    Settle,
}

impl FactOp {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Supersede => "supersede",
            Self::Settle => "settle",
        }
    }
}

/// One fact read from a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FactEntry {
    pub(super) position: FactPosition,
    pub(super) kind: FactKind,
    pub(super) entity: EntityId,
    pub(super) op: FactOp,
    pub(super) actor: EntityId,
    pub(super) recorded_at: u64,
    /// The fact's own input hash: the changelog's, or the settlement row's.
    pub(super) input_hash: [u8; 32],
    /// BLAKE3 of the entity's body as this fact left it, when known.
    pub(super) body_hash: Option<[u8; 32]>,
    /// The claim's predicate, for block expiry only. Filters read the claim
    /// under the hook's grant instead.
    pub(super) predicate: Option<String>,
}

/// One bounded read from a source.
#[derive(Debug, Default)]
pub(super) struct SourceBatch {
    pub(super) entries: Vec<FactEntry>,
    /// The last position scanned, kept or not.
    pub(super) through: Option<FactPosition>,
    /// The batch stopped at its bound before the source's end.
    pub(super) more: bool,
}

/// How a proposal settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettledOutcome {
    /// A bundle approved, or a critical confirm cleared.
    Approved,
    /// A bundle declined.
    Declined,
    /// A critical confirm retracted the write.
    Retracted,
    /// A critical confirm demoted the write to a proposal.
    Demoted,
}

/// Which settlement door settled a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    GateConsentBundle,
    CriticalWriteConfirm,
}

/// One settlement, as its door records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettledFact {
    pub proposal: EntityId,
    pub outcome: SettledOutcome,
    pub settled_by: EntityId,
    pub kind: SettlementKind,
}

/// The settlement feed's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SettledRow {
    #[serde(with = "crate::serialize::entity_ref")]
    proposal: EntityId,
    outcome: SettledOutcome,
    #[serde(with = "crate::serialize::entity_ref")]
    settled_by: EntityId,
    kind: SettlementKind,
    /// BLAKE3 of the proposal's body when it settled, when it had one.
    body_hash: Option<[u8; 32]>,
    recorded_at: u64,
}

impl SettledRow {
    fn input_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-settlement.v1");
        hasher.update(self.proposal.as_bytes());
        hasher.update(&[self.outcome as u8, self.kind as u8]);
        hasher.update(self.settled_by.as_bytes());
        hasher.update(&self.body_hash.unwrap_or_default());
        *hasher.finalize().as_bytes()
    }
}

/// Appends one settlement to the feed, in the settling door's transaction.
/// The sequence is allocated there, so feed order is commit order.
pub(crate) fn record_settlement_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fact: SettledFact,
) -> Result<SettlementPosition> {
    let last = SETTLED_NEXT.get(&vault.store, txn, &())?.unwrap_or(0);
    let sequence = last
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hook settlement sequence"))?;
    let body_hash = vault
        .store
        .port_entity_record(txn, &fact.proposal)?
        .map(|row| *blake3::hash(&row.body).as_bytes());
    let row = SettledRow {
        proposal: fact.proposal,
        outcome: fact.outcome,
        settled_by: fact.settled_by,
        kind: fact.kind,
        body_hash,
        recorded_at: vault.store.clock.now_recorded_at(),
    };
    SETTLED.put(&vault.store, txn, &sequence, &row)?;
    SETTLED_NEXT.put(&vault.store, txn, &(), &sequence)?;
    Ok(SettlementPosition(sequence))
}

/// Up to `max_entries` facts after `after` (exclusive) in `source`.
pub(super) fn read_after(
    vault: &Vault,
    source: FactSource,
    after: Option<FactPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    match (source, after) {
        (FactSource::ClaimChangelog, None) => claim_changes_after(vault, None, max_entries),
        (FactSource::ClaimChangelog, Some(FactPosition::ClaimChangelog(position))) => {
            claim_changes_after(vault, Some(position), max_entries)
        }
        (FactSource::Settlement, None) => settlements_after(vault, None, max_entries),
        (FactSource::Settlement, Some(FactPosition::Settlement(position))) => {
            settlements_after(vault, Some(position), max_entries)
        }
        _ => Err(Error::InvariantViolation(
            "hook cursor names another source",
        )),
    }
}

/// Claim writes after `after`: Create and Update land a claim, Supersede
/// closes one. Other entity kinds and other ops are scanned past.
fn claim_changes_after(
    vault: &Vault,
    after: Option<ClaimChangelogPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |position| Bound::Excluded(&position.0));
    let budget = max_entries.saturating_mul(SCAN_PER_ENTRY).max(1);
    let mut batch = SourceBatch::default();
    for (scanned, row) in CHANGES
        .iter_range(&vault.store, &rtxn, start, Bound::Unbounded)?
        .enumerate()
    {
        if scanned >= budget || batch.entries.len() >= max_entries {
            batch.more = true;
            break;
        }
        let (id, change) = row?;
        if change.id != id {
            return Err(Error::CorruptedIndex("hook changelog identity"));
        }
        let position = FactPosition::ClaimChangelog(ClaimChangelogPosition(id));
        batch.through = Some(position);
        let (kind, op) = match change.op {
            ChangeOp::Create => (FactKind::ClaimLanded, FactOp::Create),
            ChangeOp::Update => (FactKind::ClaimLanded, FactOp::Update),
            ChangeOp::Supersede => (FactKind::ClaimSuperseded, FactOp::Supersede),
            _ => continue,
        };
        let Some(record) = vault.store.port_entity_record(&rtxn, &change.entity)? else {
            continue;
        };
        if record.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let predicate = crate::claim::decode_claim_body(&record.body, true)
            .ok()
            .map(|body| body.predicate);
        batch.entries.push(FactEntry {
            position,
            kind,
            entity: change.entity,
            op,
            actor: change.actor_principal,
            recorded_at: change.recorded_at,
            input_hash: change.input_hash,
            body_hash: Some(change.input_hash),
            predicate,
        });
    }
    Ok(batch)
}

/// Settlements after `after`.
fn settlements_after(
    vault: &Vault,
    after: Option<SettlementPosition>,
    max_entries: usize,
) -> Result<SourceBatch> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after
        .as_ref()
        .map_or(Bound::Unbounded, |position| Bound::Excluded(&position.0));
    let mut batch = SourceBatch::default();
    for row in SETTLED.iter_range(&vault.store, &rtxn, start, Bound::Unbounded)? {
        if batch.entries.len() >= max_entries {
            batch.more = true;
            break;
        }
        let (sequence, settled) = row?;
        let position = FactPosition::Settlement(SettlementPosition(sequence));
        batch.through = Some(position);
        batch.entries.push(FactEntry {
            position,
            kind: FactKind::ProposalSettled,
            entity: settled.proposal,
            op: FactOp::Settle,
            actor: settled.settled_by,
            recorded_at: settled.recorded_at,
            input_hash: settled.input_hash(),
            body_hash: settled.body_hash,
            predicate: None,
        });
    }
    Ok(batch)
}

/// The newest position in `source`, or `None` while it is empty.
pub(super) fn head(vault: &Vault, source: FactSource) -> Result<Option<FactPosition>> {
    let rtxn = vault.store.env.read_txn()?;
    let head = match source {
        FactSource::ClaimChangelog => CHANGES
            .iter_rev_from(&vault.store, &rtxn, &[])?
            .next()
            .transpose()?
            .map(|(id, _)| FactPosition::ClaimChangelog(ClaimChangelogPosition(id))),
        FactSource::Settlement => SETTLED
            .iter_rev_from(&vault.store, &rtxn, &[])?
            .next()
            .transpose()?
            .map(|(sequence, _)| FactPosition::Settlement(SettlementPosition(sequence))),
    };
    Ok(head)
}

/// The changelog position of a binding claim's latest write: where a new or
/// re-enabled binding starts following the claim changelog.
pub(super) fn binding_written_at(
    vault: &Vault,
    binding: &EntityId,
) -> Result<Option<FactPosition>> {
    let rtxn = vault.store.env.read_txn()?;
    let changes = vault
        .store
        .port_changelog_list_by_entity(&rtxn, binding, BINDING_CHANGES)?;
    Ok(changes
        .iter()
        .map(|change| change.id)
        .max()
        .map(|id| FactPosition::ClaimChangelog(ClaimChangelogPosition(id))))
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(invalid("fact position has the wrong length"));
    }
    let mut out = [0_u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("fact position is not lowercase hex")),
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
