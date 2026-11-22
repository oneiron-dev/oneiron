//! One authority entry past one RPC frame (FIX 8087, 8246), such as a machine
//! profile revision that lists every act it acknowledged.
//!
//! A tail or range page carries each entry inline while the room
//! [`AUTHORITY_PAGE_INLINE_BYTES`] leaves holds it, and any other by
//! reference: its place in the page, its hash and its length. The machine
//! fetches that entry a part at a time ([`authority_entry_part_for`]), as it
//! reads a checkpoint image, and puts it back in its place. The other way, a
//! machine appends an entry past one request frame a part at a time
//! ([`authority_append_part_for`]); the home holds the parts for that socket
//! alone and imports the entry once it is whole, the room they take charged
//! as a countersign stage's is (FIX 5111). Either side joins the parts and
//! checks them against the entry's hash before the signed-history door reads
//! them. No entry is clipped or refused for its length.

use std::sync::{Mutex, PoisonError};

use super::authority_tail::{
    AuthorityAppendProgress, ITEM11_AUTHORITY_FILTER_SCOPE, authority_append_progress_for,
    owner_machine, require_owner_machine,
};
use crate::Vault;
use crate::authority::{
    AUTHORITY_OVERLAY_ROW_MAX, AuthorityEntryHash, AuthorityEntryRead, CarriedOverlays,
    CountersignStageCharge, PeerMachine, WorldPrivacyView, authority_entry_hash,
    authority_log_entity_id_from_hash, carried_overlays_in_txn, read_authority_log_entry_body,
    side_world,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;

/// The most bytes one part of an authority entry carries either way: inside
/// one request frame once base64 and the RPC envelope are added, under the
/// home's default inbound WebSocket frame bound (4 MiB) as well as the floor.
pub const AUTHORITY_ENTRY_PART_MAX: usize = 2 * 1024 * 1024;

/// The most entry bytes one tail or range page carries inline: inside the
/// RPC reply once base64 is added.
pub const AUTHORITY_PAGE_INLINE_BYTES: usize = 16 * 1024 * 1024;

// A sealed entry's overlay row rides its body's offset-0 part and leaves the
// body room there (census L5-22 1a-ii).
const _: () = assert!(AUTHORITY_OVERLAY_ROW_MAX < AUTHORITY_ENTRY_PART_MAX);

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("authority entry part refused: {reason}"))
}

/// An entry a page names by reference, fetched in parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityEntryRef {
    /// Its place in the page.
    pub place: usize,
    pub hash: AuthorityEntryHash,
    /// Its length in bytes.
    pub total: u64,
}

/// One page of entries as it goes over the RPC ([`split_authority_page`]).
#[derive(Debug, Default)]
pub struct AuthorityPartedPage {
    /// The entries carried inline, in page order.
    pub inline: Vec<Vec<u8>>,
    /// The entries named by reference, in page order.
    pub parted: Vec<AuthorityEntryRef>,
    /// The overlay rows of the sealed entries carried inline, keyed by entry
    /// hash; an entry named by reference brings its own on its offset-0 part
    /// ([`AuthorityEntryPart::overlay`]).
    pub overlays: CarriedOverlays,
}

/// `entries`, one page in order, as it goes over the RPC: each inline while
/// the room [`AUTHORITY_PAGE_INLINE_BYTES`] leaves holds it with its overlay
/// row from `overlays` (census L5-22 1a-ii), by reference otherwise. An
/// inline entry's row rides in the page's map; an entry named by reference
/// brings its row on its offset-0 part, so no row is split and the reply
/// stays inside the room.
///
/// # Errors
///
/// An entry that does not decode.
pub fn split_authority_page(
    entries: Vec<Vec<u8>>,
    overlays: &CarriedOverlays,
) -> Result<AuthorityPartedPage> {
    let mut page = AuthorityPartedPage::default();
    let mut inline = 0usize;
    for (place, entry) in entries.into_iter().enumerate() {
        let hash = match read_authority_log_entry_body(&entry)? {
            AuthorityEntryRead::Open(body) => authority_entry_hash(&body)?,
            AuthorityEntryRead::Sealed(scaffold) => scaffold.hash,
        };
        let row = overlays.get(&hash);
        let bytes = entry.len().saturating_add(row.map_or(0, Vec::len));
        if inline.saturating_add(bytes) <= AUTHORITY_PAGE_INLINE_BYTES {
            inline += bytes;
            page.inline.push(entry);
            if let Some(row) = row {
                page.overlays.insert(hash, row.clone());
            }
        } else {
            page.parted.push(AuthorityEntryRef {
                place,
                hash,
                total: entry.len() as u64,
            });
        }
    }
    Ok(page)
}

/// One part of a held authority entry ([`authority_entry_part_for`]).
#[derive(Debug)]
pub struct AuthorityEntryPart {
    /// The entry's whole length.
    pub total: u64,
    /// Its bytes from the part's offset.
    pub part: Vec<u8>,
    /// On the offset-0 part of a sealed entry: the opaque overlay row this
    /// home holds for it (census L5-22 1a-ii).
    pub overlay: Option<Vec<u8>>,
}

/// One part of the entry `hash` names, at most [`AUTHORITY_ENTRY_PART_MAX`]
/// bytes from `offset` with its overlay row, for a linked machine whose proof
/// stands here, as the tail serves it: the side branch of a world that may not
/// be readable on the machine is not served. A sealed entry's overlay row this
/// home holds rides the offset-0 part, read in the same read txn, and that
/// part's body bytes leave it room. `None` for an entry not held here and an
/// offset at or past its end. Refused for any other peer, as the tail is.
///
/// # Errors
///
/// A refused peer; a held row that does not decode; storage errors.
pub fn authority_entry_part_for(
    vault: &Vault,
    peer: PeerMachine,
    hash: &AuthorityEntryHash,
    offset: u64,
) -> Result<Option<AuthorityEntryPart>> {
    require_owner_machine(vault, peer)?;
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .port_entity_raw(&txn, &authority_log_entity_id_from_hash(hash)?)?
    else {
        return Ok(None);
    };
    let entry = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("authority row header"))?;
    let read = read_authority_log_entry_body(entry)?;
    let (held, side) = match &read {
        AuthorityEntryRead::Open(body) => (authority_entry_hash(body)?, side_world(&body.op)),
        // Sealed rows are never side-branch rows, so never withheld.
        AuthorityEntryRead::Sealed(scaffold) => (scaffold.hash, None),
    };
    if held != *hash {
        return Ok(None);
    }
    if let Some(world) = side
        && ITEM11_AUTHORITY_FILTER_SCOPE
        && WorldPrivacyView::load_in(vault, &txn)?
            .withheld_for_peer(peer)?
            .contains(&world)
    {
        return Ok(None);
    }
    let Some(rest) = usize::try_from(offset)
        .ok()
        .and_then(|offset| entry.get(offset..))
        .filter(|rest| !rest.is_empty())
    else {
        return Ok(None);
    };
    let overlay = if offset == 0 {
        carried_overlays_in_txn(&vault.store, &txn, [entry])?
            .into_values()
            .next()
    } else {
        None
    };
    let room = AUTHORITY_ENTRY_PART_MAX.saturating_sub(overlay.as_ref().map_or(0, Vec::len));
    Ok(Some(AuthorityEntryPart {
        total: entry.len() as u64,
        part: rest[..rest.len().min(room)].to_vec(),
        overlay,
    }))
}

/// The entry a machine appends a part at a time on one socket, held for that
/// socket alone until it is whole ([`authority_append_part_for`]), with the
/// host's charge for the room it takes. It goes with the socket, and its
/// charge with it. A sealed entry's opaque overlay row rides beside its body,
/// sent on the offset-0 part only and charged to the same retained bytes.
pub struct AuthorityAppendStage {
    hash: AuthorityEntryHash,
    total: u64,
    bytes: Vec<u8>,
    overlay: Option<Vec<u8>>,
    /// Only the socket's loop takes it, through `&mut`; the mutex keeps the
    /// stage `Sync`.
    charge: Mutex<Box<dyn CountersignStageCharge>>,
}

impl std::fmt::Debug for AuthorityAppendStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityAppendStage")
            .field("hash", &self.hash)
            .field("total", &self.total)
            .field("staged", &self.bytes.len())
            .field("overlay", &self.overlay.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// What one append part came to ([`authority_append_part_for`]).
#[derive(Debug)]
pub enum AuthorityAppendPart {
    /// The part is held; more are to come.
    Held,
    /// The entry was whole and went through the signed-history door.
    Whole(AuthorityAppendProgress),
    /// The host's line had no room for the part: the stage is dropped, and
    /// its machine starts the entry again on a later pass.
    NoRoom,
}

/// Charges room for `more` bytes past those `stage` holds, before they are
/// allocated, as a countersign stage charges its own: the room grows by
/// doubling, up to the entry's length. The staged overlay row, when one rides
/// beside the body, is charged to the same retained bytes. `false` when the
/// host's line has none.
fn reserve_charged(stage: &mut AuthorityAppendStage, more: usize) -> bool {
    let overlay = stage.overlay.as_ref().map_or(0, Vec::len);
    let want = stage.bytes.len().saturating_add(more);
    let room = stage.bytes.capacity();
    if want <= room {
        return true;
    }
    let total = usize::try_from(stage.total).unwrap_or(usize::MAX);
    let room = want.max(room.saturating_mul(2)).min(total.max(want));
    let charge = stage
        .charge
        .get_mut()
        .unwrap_or_else(PoisonError::into_inner);
    if !charge.resize(room.saturating_add(overlay)) {
        return false;
    }
    stage.bytes.reserve_exact(room - stage.bytes.len());
    true
}

/// Takes part `part` at `offset` of the entry `hash` names, `total` bytes
/// long, that a linked machine appends on the socket whose stage is `stage`.
/// A part at offset zero starts the entry again, under a new charge `charge`
/// makes; the joined bytes stay charged until the entry is imported. A sealed
/// entry's opaque overlay row rides on the offset-0 part only, beside the body
/// and charged to the same retained bytes. Once whole, the bytes are checked
/// against `hash` and imported as a one-entry append with the staged row
/// ([`authority_append_progress_for`]). `None` for a peer that is not
/// a proven linked machine.
///
/// # Errors
///
/// A part that is not the next one or runs past its entry's length; an overlay
/// on any part but offset zero; joined bytes that are not the entry `hash`
/// names; storage errors.
#[allow(clippy::too_many_arguments)]
pub fn authority_append_part_for(
    vault: &Vault,
    peer: PeerMachine,
    stage: &mut Option<AuthorityAppendStage>,
    hash: AuthorityEntryHash,
    total: u64,
    offset: u64,
    part: &[u8],
    charge: impl FnOnce() -> Box<dyn CountersignStageCharge>,
    overlay: Option<Vec<u8>>,
) -> Result<Option<AuthorityAppendPart>> {
    if !owner_machine(vault, peer)? {
        *stage = None;
        return Ok(None);
    }
    let end = offset.saturating_add(part.len() as u64);
    if part.is_empty() || part.len() > AUTHORITY_ENTRY_PART_MAX || end > total {
        *stage = None;
        return Err(refused("malformed"));
    }
    if overlay.is_some() && offset != 0 {
        *stage = None;
        return Err(refused("overlay rides the offset-0 part only"));
    }
    if overlay
        .as_ref()
        .is_some_and(|row| row.len() > AUTHORITY_OVERLAY_ROW_MAX)
    {
        *stage = None;
        return Err(refused("overlay row past its bound"));
    }
    if offset == 0 {
        let mut started = AuthorityAppendStage {
            hash,
            total,
            bytes: Vec::new(),
            overlay,
            charge: Mutex::new(charge()),
        };
        if let Some(row) = started.overlay.as_ref()
            && !row.is_empty()
        {
            let held = started
                .charge
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner);
            if !held.resize(row.len()) {
                *stage = None;
                return Ok(Some(AuthorityAppendPart::NoRoom));
            }
        }
        *stage = Some(started);
    }
    let mut held = match stage.take() {
        Some(held)
            if held.hash == hash && held.total == total && held.bytes.len() as u64 == offset =>
        {
            held
        }
        _ => return Err(refused("not the next part")),
    };
    if !reserve_charged(&mut held, part.len()) {
        return Ok(Some(AuthorityAppendPart::NoRoom));
    }
    held.bytes.extend_from_slice(part);
    if end < total {
        *stage = Some(held);
        return Ok(Some(AuthorityAppendPart::Held));
    }
    let AuthorityAppendStage {
        bytes: entry,
        overlay,
        charge: _charge,
        ..
    } = held;
    let joined = match read_authority_log_entry_body(&entry)? {
        AuthorityEntryRead::Open(body) => authority_entry_hash(&body)?,
        AuthorityEntryRead::Sealed(scaffold) => scaffold.hash,
    };
    if joined != hash {
        return Err(refused("the joined entry is not the one named"));
    }
    let mut overlays = CarriedOverlays::new();
    if let Some(row) = overlay {
        overlays.insert(hash, row);
    }
    Ok(
        authority_append_progress_for(vault, peer, &[entry], &overlays)?
            .map(AuthorityAppendPart::Whole),
    )
}
