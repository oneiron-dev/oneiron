//! The exterior holder debt of erasable keys (FIX 8875): which other
//! machines hold a copy of a key this custody sent or received, kept beside
//! the vault and outside its image like every custody entry, so a rollback
//! of the vault never forgets a copy.
//!
//! `<compartment>/.holders/` holds one empty file per debt,
//! `<ref hex>.<holder machine hex>`: written and synced before an export
//! releases the key, and removed only once that holder's retirement of it
//! is verified. A retired key whose debt stands reads
//! `custody_remote_retirement_pending(<holder>)`, never complete.
//!
//! Each debt recorded or cleared is journaled after its file is written or
//! removed (FIX 11206), again on a retry after a failed append (FIX 12191),
//! so every member's custody head is sealed again
//! carrying the debts that stand (`head::holder_debts`), and a disaster
//! recovery's landing keeps them.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::files::EntryState;
use crate::key_custody::files::custody_present;
use crate::key_custody::files::open_dir;
use crate::key_custody::files::write_once;
use crate::key_custody::identity::CustodySubject;
use crate::key_custody::identity::hex_decode;
use crate::key_custody::platform;

pub const HOLDERS: &str = ".holders";

/// One copy another machine holds: the key's ref and the holder.
pub type HolderDebt = ([u8; 32], EntityId);

pub fn debt_name(key_ref: &[u8; 32], holder: &EntityId) -> String {
    format!(
        "{}.{}",
        oneiron_contracts::entity_id::bytes_to_hex_lower(key_ref),
        holder.to_hex()
    )
}

/// The debt a file name names; `None` for a name custody would not write.
pub fn debt_of_name(name: &str) -> Option<HolderDebt> {
    let (key_ref, holder) = name.split_once('.')?;
    let key_ref = <[u8; 32]>::try_from(hex_decode(key_ref)?).ok()?;
    let holder = EntityId::from_bytes(<[u8; 16]>::try_from(hex_decode(holder)?).ok()?).ok()?;
    (debt_name(&key_ref, &holder) == name).then_some((key_ref, holder))
}

/// `standing (1) | ref (32) | holder (16)`: a log frame's body after its op
/// (FIX 11206); `standing` is 0 for a debt cleared.
pub fn encode_debt(debt: &HolderDebt, standing: bool) -> [u8; 49] {
    let mut out = [0u8; 49];
    out[0] = u8::from(standing);
    out[1..33].copy_from_slice(&debt.0);
    out[33..].copy_from_slice(debt.1.as_bytes());
    out
}

/// The debt and whether it stands a frame's body names; `None` for one
/// custody would not write.
pub fn decode_debt(bytes: &[u8]) -> Option<(HolderDebt, bool)> {
    let (&standing, rest) = bytes.split_first()?;
    let (key_ref, holder) = rest.split_first_chunk::<32>()?;
    let holder = EntityId::from_bytes(<[u8; 16]>::try_from(holder).ok()?).ok()?;
    let standing = match standing {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(((*key_ref, holder), standing))
}
