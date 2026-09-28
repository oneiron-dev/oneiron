//! Terminal-pact per-world stale stamping (FED-04).

use std::collections::BTreeMap;

use crate::authority::FederationPactStatus;
use crate::entity_id::{EntityId, ForeignWorldId, bytes_to_hex_lower, is_foreign_world_id_range};
use crate::error::{Error, Result, SideTableRowProblem, StoreError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::Store;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Terminal-pact stale stamping (FED-04, ONE-1411).
//
// A terminal pact stops REFRESH, not READ. The sweep is purely ADDITIVE: it
// writes `fedstale:` marker rows and nothing else. No world entity, claim body,
// edge, or index row is purged, tombstoned, or rewritten, so everything the
// pact ever delivered still reads back through `Vault::get_raw` afterwards.
// Deleting federated content stays a separate, opt-in flow.
//
// Keying is ONE STAMP PER WORLD (`fedstale:{world}`), not per pact. A world can
// arrive through several pacts, and the marker answers "is this content still
// refreshing?" — a question about the WORLD, not about any one relationship.
// The first terminal transition to reach a world therefore wins permanently:
// re-sweeping, replaying a later terminal transition, or a second pact going
// terminal never rewrites an existing stamp's reason, epoch, or timestamp.
// ---------------------------------------------------------------------------

/// Why a foreign world's federated content stopped refreshing.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationStaleReason {
    /// The pact was unilaterally severed.
    Disconnected = 1,
    /// The pact was unilaterally dissolved.
    Dissolved = 2,
    /// The pact was succeeded by a co-owned vault.
    ///
    /// Kept distinguishable from a severance — a promotion is a graduation, not
    /// a break — but it stops refresh THROUGH THIS PACT exactly as hard.
    Promoted = 3,
}

impl FederationStaleReason {
    /// Returns the pinned wire byte for this reason.
    #[must_use]
    pub const fn as_wire_byte(self) -> u8 {
        self as u8
    }

    /// Parses a pinned wire byte; unknown bytes fail closed as `None`.
    #[must_use]
    pub fn from_wire_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Disconnected),
            2 => Some(Self::Dissolved),
            3 => Some(Self::Promoted),
            _ => None,
        }
    }

    /// Returns the lowercase diagnostic word for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Dissolved => "dissolved",
            Self::Promoted => "promoted",
        }
    }

    /// The ONE mapping from fold-derived pact status to stale reason.
    ///
    /// Non-terminal statuses return `None`, which is what makes the sweep's
    /// filter and its reason lookup the same act — a pact can never be stamped
    /// with a reason its status does not carry.
    const fn from_pact_status(status: FederationPactStatus) -> Option<Self> {
        match status {
            FederationPactStatus::Disconnected => Some(Self::Disconnected),
            FederationPactStatus::Dissolved => Some(Self::Dissolved),
            FederationPactStatus::Promoted => Some(Self::Promoted),
            FederationPactStatus::Active | FederationPactStatus::Suspended => None,
        }
    }
}

/// Immutable marker recording that a world's federated content went stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorldStaleStamp {
    /// Which terminal transition stamped this world.
    pub reason: FederationStaleReason,
    /// Pact epoch at which the pact went terminal.
    pub disconnect_epoch: u64,
    /// Unix-seconds instant the stamp was written.
    pub stamped_at_secs: u64,
}

/// LMDB `sync_state` key prefix for per-world stale stamps.
pub const FEDERATION_STALE_KEY_PREFIX: &str = "fedstale:";

/// LMDB `sync_state` key prefix for pact-to-world registrations.
pub const FEDERATION_WORLD_KEY_PREFIX: &str = "fedworld:";

/// Encoded length of a [`WorldStaleStamp`].
pub const WORLD_STALE_STAMP_LEN: usize = 18;

/// Wire version of the stale-stamp layout.
const WORLD_STALE_STAMP_VERSION: u8 = 1;

/// The entire value of a `fedworld:` row: presence IS the registration.
const FEDERATION_WORLD_ROW_VALUE: &[u8] = &[0x01];

/// One stamp per world, never per pact. Key: [`ForeignWorldKey`].
const FEDERATION_STALE: SideTable<ForeignWorldKey, WorldStaleStamp, Raw> =
    SideTable::new(&side_table::FEDERATION_STALE);

/// Pact-to-world registrations. Key: `{pact_id_hex}:{world_id_hex}` (the bytes after the
/// `fedworld:` table prefix); the value is the presence-only [`WorldRegistrationMarker`].
const FEDERATION_WORLD: SideTable<String, WorldRegistrationMarker, Raw> =
    SideTable::new(&side_table::FEDERATION_WORLD_REGISTRATION);

/// A foreign-range world id in its canonical lowercase 32-hex spelling — every key `fedstale:`
/// rows are written under. A local-range id or a non-canonical hex spelling decodes as `None`
/// (corruption, never an alternative encoding to tolerate — see [`canonical_foreign_world_id`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForeignWorldKey(EntityId);

impl SideKey for ForeignWorldKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.0.to_hex().as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        canonical_foreign_world_id(std::str::from_utf8(bytes).ok()?).map(Self)
    }
}

impl RawValue for WorldStaleStamp {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_world_stale_stamp(*self).to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_world_stale_stamp(bytes)?)
    }
}

/// The entire value of a `fedworld:` row: presence IS the registration, so ANY other byte
/// content is corruption, never a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorldRegistrationMarker;

impl RawValue for WorldRegistrationMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(FEDERATION_WORLD_ROW_VALUE.to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes == FEDERATION_WORLD_ROW_VALUE {
            Ok(Self)
        } else {
            Err(corrupt_world_registration().into())
        }
    }
}

/// Encodes a stale stamp as `[version][reason][epoch LE][stamped_at LE]`.
#[must_use]
pub fn encode_world_stale_stamp(stamp: WorldStaleStamp) -> [u8; WORLD_STALE_STAMP_LEN] {
    let mut out = [0u8; WORLD_STALE_STAMP_LEN];
    out[0] = WORLD_STALE_STAMP_VERSION;
    out[1] = stamp.reason.as_wire_byte();
    out[2..10].copy_from_slice(&stamp.disconnect_epoch.to_le_bytes());
    out[10..18].copy_from_slice(&stamp.stamped_at_secs.to_le_bytes());
    out
}

/// Decodes a stale stamp, failing closed on length, version, or reason.
///
/// These bytes are only ever written by [`apply_federation_stale_stamps`], so a
/// decode failure is LOCAL CORRUPTION, not a bad peer body — and it propagates.
/// Skipping the row would silently un-stale a world whose pact is provably
/// terminal, which is exactly the state an attacker with write access wants.
pub fn decode_world_stale_stamp(bytes: &[u8]) -> Result<WorldStaleStamp> {
    let Ok(bytes) = <&[u8; WORLD_STALE_STAMP_LEN]>::try_from(bytes) else {
        return Err(corrupt_stale_stamp());
    };
    if bytes[0] != WORLD_STALE_STAMP_VERSION {
        return Err(corrupt_stale_stamp());
    }
    let reason = FederationStaleReason::from_wire_byte(bytes[1]).ok_or_else(corrupt_stale_stamp)?;
    // Length is proven by the guard above; only version and reason can fail.
    Ok(WorldStaleStamp {
        reason,
        disconnect_epoch: u64::from_le_bytes(bytes[2..10].try_into().expect("length checked")),
        stamped_at_secs: u64::from_le_bytes(bytes[10..].try_into().expect("length checked")),
    })
}

/// Renders the pinned engine diagnostic text for a stale world.
///
/// This is an ENGINE DIAGNOSTIC CONTRACT string, not product or persona copy:
/// readers match it verbatim, so the wording, the epoch it names, and the
/// lowercase reason are all part of the contract.
#[must_use]
pub fn world_stale_marker(stamp: WorldStaleStamp) -> String {
    format!(
        "⚠ stale federation content ({} at pact epoch {}) — may be outdated",
        stamp.reason.as_str(),
        stamp.disconnect_epoch
    )
}

/// Registers `world` as content delivered by `pact_id`.
///
/// Deliberately `pub(crate)` and NEVER re-exported from `lib.rs`. Registration
/// is immutable and it silently suppresses that world's rows from unscoped
/// retrieval the moment the pact goes terminal, so a public writer would let
/// any unauthenticated caller permanently bind a wrong or hostile world to a
/// pact. Until production admission remapping lands (explicitly out of
/// ONE-1411), only the crate's own sync/import path may call this.
///
/// Idempotent: the value is presence-only, so re-registering rewrites the same
/// byte.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn register_foreign_world_for_pact(
    vault: &Vault,
    pact_id: &[u8; 32],
    world: ForeignWorldId,
) -> Result<()> {
    let key = federation_world_key(pact_id, world.entity_id());
    vault.with_write_txn(|wtxn| {
        FEDERATION_WORLD.put(&vault.store, wtxn, &key, &WorldRegistrationMarker)?;
        Ok(())
    })
}

/// Stamps every world registered to a pact that the fold reports terminal.
///
/// ONE authority fold per sweep: the fold is the authority on which pacts went
/// terminal, so a stored-but-fold-REJECTED entry justifies no stamp of its own —
/// being written is not being applied. The sweep is GLOBAL, not entry-scoped:
/// whatever triggers it, it writes every stamp the current fold justifies,
/// including a world registered after its pact already went terminal. Returns
/// how many NEW stamps were written, so a second sweep over unchanged state
/// returns 0.
pub fn apply_federation_stale_stamps(vault: &Vault) -> Result<usize> {
    let fold = vault.authority_fold()?;
    let terminal: Vec<([u8; 32], FederationStaleReason, u64)> = fold
        .federation_pacts
        .iter()
        .filter_map(|(pact_id, state)| {
            let reason = FederationStaleReason::from_pact_status(state.status)?;
            // Disconnect/Dissolve keep the epoch, Promote bumps it; either way
            // `terminal_epoch` is the epoch the pact DIED at. The fallback is
            // structurally unreachable (every terminal transition sets it) and
            // resolves to the same epoch rather than to a panic.
            let epoch = state.terminal_epoch.unwrap_or(state.pact_epoch);
            Some((*pact_id, reason, epoch))
        })
        .collect();
    if terminal.is_empty() {
        return Ok(0);
    }

    // ONE timestamp for the whole sweep: two worlds stamped by one transition
    // are stale at one instant, not at two clock reads.
    let stamped_at_secs = vault.store.clock.now_recorded_at();
    vault.with_write_txn(|wtxn| {
        let mut stamped = 0usize;
        for (pact_id, reason, disconnect_epoch) in &terminal {
            let prefix = federation_world_prefix(pact_id);
            let worlds = FEDERATION_WORLD
                .scan_from(&vault.store, wtxn, prefix.as_bytes())?
                .into_iter()
                .map(|(key, _marker)| registered_world_from_key(&key, &prefix))
                .collect::<Result<Vec<_>>>()?;
            for world in worlds {
                let key = ForeignWorldKey(world);
                // FIRST STAMP WINS. An existing row is never compared or
                // overwritten — not even by a strictly later terminal epoch.
                // It must still DECODE: existence alone would let a malformed
                // row pose as the immutable winner forever, leaving a provably
                // dead world with no valid stamp, which is exactly the
                // un-staling a write-capable attacker wants.
                if FEDERATION_STALE.get(&vault.store, wtxn, &key)?.is_some() {
                    continue;
                }
                let stamp = WorldStaleStamp {
                    reason: *reason,
                    disconnect_epoch: *disconnect_epoch,
                    stamped_at_secs,
                };
                FEDERATION_STALE.put(&vault.store, wtxn, &key, &stamp)?;
                stamped += 1;
            }
        }
        Ok(stamped)
    })
}

/// Reads one world's stale stamp, if it carries one.
pub fn foreign_world_stale_stamp(
    vault: &Vault,
    world: EntityId,
) -> Result<Option<WorldStaleStamp>> {
    let rtxn = vault.store.env.read_txn()?;
    FEDERATION_STALE.get(&vault.store, &rtxn, &ForeignWorldKey(world))
}

/// Every stale-stamped world, for ONE read of the retrieval path.
///
/// Callers load this once per retrieval run and probe the map per candidate;
/// re-scanning per claim would turn a prefix scan into an inner loop.
pub(crate) fn stale_stamped_worlds(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, WorldStaleStamp>> {
    // `FEDERATION_STALE`'s generic key-shape refusal is remapped to this
    // family's own pinned corruption verdict, matching the bulk read's
    // pre-typed-table error (a malformed key is exactly as fatal as a
    // malformed value here: both are LOCAL writes, so both are corruption).
    let rows = FEDERATION_STALE.scan(store, rtxn).map_err(|err| {
        if matches!(
            &err,
            Error::Store(StoreError::SideTableRow {
                problem: SideTableRowProblem::KeyShape,
                ..
            })
        ) {
            corrupt_stale_stamp()
        } else {
            err
        }
    })?;
    Ok(rows
        .into_iter()
        .map(|(ForeignWorldKey(world), stamp)| (world, stamp))
        .collect())
}

/// `fedstale:{world_id_hex}` — one stamp per world, never per pact.
///
/// Crate-visible so every in-crate reader addresses the row through this one
/// spelling instead of re-deriving the key format at each site. Production
/// reads/writes now go through [`FEDERATION_STALE`]'s typed door; this raw
/// builder is reached only by test fixtures that plant or inspect rows
/// directly.
#[cfg(test)]
pub(crate) fn federation_stale_key(world: EntityId) -> String {
    let mut key = String::with_capacity(FEDERATION_STALE_KEY_PREFIX.len() + 32);
    key.push_str(FEDERATION_STALE_KEY_PREFIX);
    key.push_str(&world.to_hex());
    key
}

/// `{pact_id_hex}:` — [`FEDERATION_WORLD`]'s scan prefix for ONE pact's worlds (the bytes after
/// the `fedworld:` table prefix).
fn federation_world_prefix(pact_id: &[u8; 32]) -> String {
    let mut prefix = String::with_capacity(65);
    prefix.push_str(&bytes_to_hex_lower(pact_id));
    prefix.push(':');
    prefix
}

/// `{pact_id_hex}:{world_id_hex}` — [`FEDERATION_WORLD`]'s key for one registration.
fn federation_world_key(pact_id: &[u8; 32], world: EntityId) -> String {
    let mut key = federation_world_prefix(pact_id);
    key.push_str(&world.to_hex());
    key
}

/// The world named by one stored registration key, under its own scan prefix.
fn registered_world_from_key(key: &str, prefix: &str) -> Result<EntityId> {
    key.strip_prefix(prefix)
        .and_then(canonical_foreign_world_id)
        .ok_or_else(corrupt_world_registration)
}

/// A foreign-range world id in its canonical lowercase spelling, or `None`.
///
/// Both checks are fail-closed reads of OUR OWN writes: every key is written
/// from `EntityId::to_hex` (lowercase) through a [`ForeignWorldId`] door, so an
/// uppercase spelling or a local-range id on disk is corruption, not an
/// alternative encoding to be tolerated.
fn canonical_foreign_world_id(hex: &str) -> Option<EntityId> {
    let id = EntityId::from_hex(hex).ok()?;
    (id.to_hex() == hex && is_foreign_world_id_range(id)).then_some(id)
}

fn corrupt_stale_stamp() -> Error {
    Error::CorruptedIndex("federation world stale stamp")
}

fn corrupt_world_registration() -> Error {
    Error::CorruptedIndex("federation world registration")
}
