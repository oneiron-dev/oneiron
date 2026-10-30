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
    AuthorityEntryHash, CountersignStageCharge, PeerMachine, WorldPrivacyView,
    authority_entry_hash, authority_log_entity_id_from_hash, decode_authority_log_entry_body,
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
}

/// `entries`, one page in order, as it goes over the RPC: each inline while
/// the room [`AUTHORITY_PAGE_INLINE_BYTES`] leaves holds it, by reference
/// otherwise.
///
/// # Errors
///
/// An entry named by reference that does not decode.
pub fn split_authority_page(entries: Vec<Vec<u8>>) -> Result<AuthorityPartedPage> {
    let mut page = AuthorityPartedPage::default();
    let mut inline = 0usize;
    for (place, entry) in entries.into_iter().enumerate() {
        if inline.saturating_add(entry.len()) <= AUTHORITY_PAGE_INLINE_BYTES {
            inline += entry.len();
            page.inline.push(entry);
        } else {
            page.parted.push(AuthorityEntryRef {
                place,
                hash: authority_entry_hash(&decode_authority_log_entry_body(&entry)?)?,
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
}

/// One part of the entry `hash` names, at most [`AUTHORITY_ENTRY_PART_MAX`]
/// bytes from `offset`, for a linked machine whose proof stands here, as the
/// tail serves it: the side branch of a world that may not be readable on
/// the machine is not served. `None` for an entry not held here and an offset
/// at or past its end. Refused for any other peer, as the tail is.
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
    let body = decode_authority_log_entry_body(entry)?;
    if authority_entry_hash(&body)? != *hash {
        return Ok(None);
    }
    if let Some(world) = side_world(&body.op)
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
    Ok(Some(AuthorityEntryPart {
        total: entry.len() as u64,
        part: rest[..rest.len().min(AUTHORITY_ENTRY_PART_MAX)].to_vec(),
    }))
}

/// The entry a machine appends a part at a time on one socket, held for that
/// socket alone until it is whole ([`authority_append_part_for`]), with the
/// host's charge for the room it takes. It goes with the socket, and its
/// charge with it.
pub struct AuthorityAppendStage {
    hash: AuthorityEntryHash,
    total: u64,
    bytes: Vec<u8>,
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
/// doubling, up to the entry's length. `false` when the host's line has none.
fn reserve_charged(stage: &mut AuthorityAppendStage, more: usize) -> bool {
    let want = stage.bytes.len().saturating_add(more);
    let room = stage.bytes.capacity();
    if want <= room {
        return true;
    }
    let total = usize::try_from(stage.total).unwrap_or(usize::MAX);
    let room = want.max(room.saturating_mul(2)).min(total.max(want));
    let charge = stage.charge.get_mut().unwrap_or_else(PoisonError::into_inner);
    if !charge.resize(room) {
        return false;
    }
    stage.bytes.reserve_exact(room - stage.bytes.len());
    true
}

/// Takes part `part` at `offset` of the entry `hash` names, `total` bytes
/// long, that a linked machine appends on the socket whose stage is `stage`.
/// A part at offset zero starts the entry again, under a new charge `charge`
/// makes; the joined bytes stay charged until the entry is imported. Once
/// whole, the bytes are checked against `hash` and imported as a one-entry
/// append ([`authority_append_progress_for`]). `None` for a peer that is not
/// a proven linked machine.
///
/// # Errors
///
/// A part that is not the next one or runs past its entry's length; joined
/// bytes that are not the entry `hash` names; storage errors.
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
    if offset == 0 {
        *stage = Some(AuthorityAppendStage {
            hash,
            total,
            bytes: Vec::new(),
            charge: Mutex::new(charge()),
        });
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
        charge: _charge,
        ..
    } = held;
    if authority_entry_hash(&decode_authority_log_entry_body(&entry)?)? != hash {
        return Err(refused("the joined entry is not the one named"));
    }
    Ok(authority_append_progress_for(vault, peer, &[entry])?.map(AuthorityAppendPart::Whole))
}
