//! Terminal-pact per-world stale stamping (FED-04).

use std::collections::BTreeMap;

use crate::authority::FederationPactStatus;
use crate::entity_id::{EntityId, ForeignWorldId, bytes_to_hex_lower, is_foreign_world_id_range};
use crate::error::{Error, Result};
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
pub(crate) fn register_foreign_world_for_pact(
    vault: &Vault,
    pact_id: &[u8; 32],
    world: ForeignWorldId,
) -> Result<()> {
    let key = federation_world_key(pact_id, world.entity_id());
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, &key, FEDERATION_WORLD_ROW_VALUE)?;
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
    let stamped_at_secs = crate::unix_seconds_now();
    vault.with_write_txn(|wtxn| {
        let mut stamped = 0usize;
        for (pact_id, reason, disconnect_epoch) in &terminal {
            let prefix = federation_world_prefix(pact_id);
            let mut worlds = Vec::new();
            for row in vault.store.sync_state.prefix_iter(wtxn, &prefix)? {
                let (key, value) = row?;
                if value.as_ref() != FEDERATION_WORLD_ROW_VALUE {
                    return Err(corrupt_world_registration());
                }
                worlds.push(registered_world_from_key(&key, &prefix)?);
            }
            for world in worlds {
                let key = federation_stale_key(world);
                // FIRST STAMP WINS. An existing row is never compared or
                // overwritten — not even by a strictly later terminal epoch.
                // It must still DECODE: existence alone would let a malformed
                // row pose as the immutable winner forever, leaving a provably
                // dead world with no valid stamp, which is exactly the
                // un-staling a write-capable attacker wants.
                if let Some(existing) = vault.store.sync_state.get(wtxn, &key)? {
                    decode_world_stale_stamp(&existing)?;
                    continue;
                }
                let encoded = encode_world_stale_stamp(WorldStaleStamp {
                    reason: *reason,
                    disconnect_epoch: *disconnect_epoch,
                    stamped_at_secs,
                });
                vault.store.sync_state.put(wtxn, &key, &encoded)?;
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
    let Some(raw) = vault
        .store
        .sync_state
        .get(&rtxn, &federation_stale_key(world))?
    else {
        return Ok(None);
    };
    decode_world_stale_stamp(&raw).map(Some)
}

/// Every stale-stamped world, for ONE read of the retrieval path.
///
/// Callers load this once per retrieval run and probe the map per candidate;
/// re-scanning per claim would turn a prefix scan into an inner loop.
pub(crate) fn stale_stamped_worlds(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, WorldStaleStamp>> {
    let mut stamped = BTreeMap::new();
    for row in store
        .sync_state
        .prefix_iter(rtxn, FEDERATION_STALE_KEY_PREFIX)?
    {
        let (key, raw) = row?;
        let world = key
            .strip_prefix(FEDERATION_STALE_KEY_PREFIX)
            .and_then(canonical_foreign_world_id)
            .ok_or_else(corrupt_stale_stamp)?;
        stamped.insert(world, decode_world_stale_stamp(&raw)?);
    }
    Ok(stamped)
}

/// `fedstale:{world_id_hex}` — one stamp per world, never per pact.
///
/// Crate-visible so every in-crate reader addresses the row through this one
/// spelling instead of re-deriving the key format at each site.
pub(crate) fn federation_stale_key(world: EntityId) -> String {
    let mut key = String::with_capacity(FEDERATION_STALE_KEY_PREFIX.len() + 32);
    key.push_str(FEDERATION_STALE_KEY_PREFIX);
    key.push_str(&world.to_hex());
    key
}

/// `fedworld:{pact_id_hex}:` — the scan prefix for ONE pact's worlds.
fn federation_world_prefix(pact_id: &[u8; 32]) -> String {
    let mut prefix = String::with_capacity(FEDERATION_WORLD_KEY_PREFIX.len() + 65);
    prefix.push_str(FEDERATION_WORLD_KEY_PREFIX);
    prefix.push_str(&bytes_to_hex_lower(pact_id));
    prefix.push(':');
    prefix
}

/// `fedworld:{pact_id_hex}:{world_id_hex}`.
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
