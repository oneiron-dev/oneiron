//! Which version of a sealed window's mirror last landed here (FIX 5506).
//!
//! A take of a bundle generation merges each world section's window into its
//! mirror and materializes the mirror's rows here (FIX 4788). On a full
//! machine most windows are unchanged from the last take, so their forward
//! pass would land again exactly what it landed before. Each window keeps a
//! mark of the mirror version whose rows last landed in full, and of the
//! forward pass that landed them ([`FORWARD_PASS_VERSION`], FIX 6509): a take
//! whose merge gains nothing, of a mirror at that version, under that pass,
//! skips the pass. After an engine upgrade whose pass lands rows an older
//! one dropped, every window lands again once, though its mirror has not
//! moved; a mark this pass cannot read names nothing, and lands again too.
//!
//! A mark is written only after the forward pass, in the transaction that
//! stores the mirror, and only when the window has no rematerialization
//! repair pending (a pass can return while rows still wait on a retry). A
//! missing mark, another version, or a pending repair lands the mirror
//! again. A take that does not materialize never marks. A local removal of
//! the window's rows marks it removed, each time with a new count, so a pass
//! that began before the removal does not mark over it. An erased world's
//! marks go with its mirrors. A restore brings the image's marks back with
//! the image's rows (restore class Content), never trusting a mark the live
//! vault wrote over other rows.

use loro::{LoroDoc, VersionVector};

use super::content::LANDED;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::sync::types::WindowKey;
use crate::sync::window::FORWARD_PASS_VERSION;

/// A mark's first byte.
const LANDED_VERSION: u8 = 1;
const REMOVED: u8 = 0;

/// What one window's mark holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Landed {
    /// The forward pass that landed the mirror's rows in full (big-endian
    /// u64), then the encoded version vector of that mirror.
    Version(Vec<u8>),
    /// The window's rows here were removed, the count-th time since a
    /// version landed.
    Removed(u64),
}

impl Landed {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Version(version) => {
                let mut out = Vec::with_capacity(1 + version.len());
                out.push(LANDED_VERSION);
                out.extend_from_slice(version);
                out
            }
            Self::Removed(count) => {
                let mut out = vec![REMOVED];
                out.extend_from_slice(&count.to_be_bytes());
                out
            }
        }
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        let corrupt = || Error::CorruptedIndex("sealed mirror landed mark");
        match raw.split_first() {
            Some((&LANDED_VERSION, version)) => Ok(Self::Version(version.to_vec())),
            Some((&REMOVED, count)) => Ok(Self::Removed(u64::from_be_bytes(
                count.try_into().map_err(|_| corrupt())?,
            ))),
            _ => Err(corrupt()),
        }
    }

    /// The mark of `mirror`'s version landed by this engine's forward pass.
    fn of(mirror: &LoroDoc) -> Self {
        let mut mark = FORWARD_PASS_VERSION.to_be_bytes().to_vec();
        mark.extend_from_slice(&mirror.oplog_vv().encode());
        Self::Version(mark)
    }

    /// Whether this mark names `mirror`'s version, landed by this engine's
    /// forward pass. Another pass, or a mark that names none, does not.
    fn names(&self, mirror: &LoroDoc) -> bool {
        let Self::Version(mark) = self else {
            return false;
        };
        let Some((pass, version)) = mark.split_first_chunk::<8>() else {
            return false;
        };
        if u64::from_be_bytes(*pass) != FORWARD_PASS_VERSION {
            return false;
        }
        let Ok(landed) = VersionVector::decode(version) else {
            return false;
        };
        let held = mirror.oplog_vv();
        landed.includes_vv(&held) && held.includes_vv(&landed)
    }
}

fn landed_key(world: EntityId, window: &WindowKey) -> String {
    format!("{}:{}", world.to_hex(), window.as_str())
}

/// The mark of `window` of `world`, as the last commit left it.
pub(super) fn landed_mark(
    vault: &Vault,
    world: EntityId,
    window: &WindowKey,
) -> Result<Option<Landed>> {
    let txn = vault.store.env.read_txn()?;
    LANDED
        .get(&vault.store, &txn, &landed_key(world, window))?
        .as_deref()
        .map(Landed::decode)
        .transpose()
}

/// Whether `window` waits on a rematerialization repair here: a pass left a
/// marker for one of its rows. Read in its own snapshot, outside any writer.
pub(super) fn repair_pending(vault: &Vault, window: &WindowKey) -> Result<bool> {
    Ok(!crate::sync::quarantine::pending_remat_entities(vault, window.as_str())?.is_empty())
}

/// Whether a take of `mirror` may skip its forward pass: the merge gained
/// nothing, the window's mark names the mirror's version, and no repair
/// waits on the window.
pub(super) fn landed_already(
    vault: &Vault,
    window: &WindowKey,
    mark: Option<&Landed>,
    mirror: &LoroDoc,
    gained: bool,
) -> Result<bool> {
    if gained || !mark.is_some_and(|mark| mark.names(mirror)) {
        return Ok(false);
    }
    Ok(!repair_pending(vault, window)?)
}

/// Marks `window` of `world` landed at `mirror`'s version, by this engine's
/// forward pass, in `wtxn`, the transaction that stores the mirror, when its
/// mark is still `before`, the one read before the forward pass: a removal
/// since then keeps its own mark. The caller marks only a pass that left no
/// repair pending.
pub(super) fn mark_landed_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    (world, window): (EntityId, &WindowKey),
    before: Option<&Landed>,
    mirror: &LoroDoc,
) -> Result<()> {
    let key = landed_key(world, window);
    let now = LANDED
        .get(store, wtxn, &key)?
        .as_deref()
        .map(Landed::decode)
        .transpose()?;
    if now.as_ref() != before {
        return Ok(());
    }
    LANDED.put(store, wtxn, &key, &Landed::of(mirror).encode())
}

/// Marks `window`'s rows removed here, in the removal's write transaction:
/// the next take of the window's mirror lands it again (FIX 5506). A window
/// of no world keeps no mark.
pub(crate) fn unland_window_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    window: &WindowKey,
) -> Result<()> {
    let Some(world) = window.world() else {
        return Ok(());
    };
    let key = landed_key(world, window);
    let count = match LANDED
        .get(store, wtxn, &key)?
        .as_deref()
        .map(Landed::decode)
        .transpose()?
    {
        Some(Landed::Removed(count)) => count.saturating_add(1),
        Some(Landed::Version(_)) | None => 1,
    };
    LANDED.put(store, wtxn, &key, &Landed::Removed(count).encode())
}
