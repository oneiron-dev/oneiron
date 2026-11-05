//! The custody anchor (KS-4, FIX 5685): one lineage's current position, kept
//! where neither the vault's image nor its custody rolls it back, read with
//! authentication and advanced only by compare-and-swap.
//!
//! A record is `"OCAN" | u8 1 | position (96) | tag (32)`: the position in
//! the clear, so a keyless store checks that an advance extends it, and a
//! BLAKE3 keyed tag under the lineage's anchor key, so a reader holding the
//! head's control secret knows the record is the lineage's own. A signed
//! record carried with a backup proves no freshness; only the store's
//! current one does.
//!
//! The self-host store ([`FileAnchor`]) is one directory the owner selects,
//! outside the vault and its custody: `<namespace hex>.<vault hex>.anchor`
//! per lineage, replaced atomically and synced under an exclusive lock on
//! `<namespace hex>.<vault hex>.lock`. Its root is never made here: a
//! missing one (an unmounted disk) is a pending anchor, never a directory
//! quietly made on the local disk.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngCore;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::identity::CustodyNamespace;
use crate::key_custody::identity::CustodyVaultId;
use crate::key_custody::protocol::AnchorAdvance;
use crate::key_custody::protocol::AnchorStore;

pub const ANCHOR_MAGIC: &[u8; 4] = b"OCAN";
pub const ANCHOR_VERSION: u8 = 1;

pub fn anchor_corrupt() -> Error {
    Error::CorruptedIndex("key custody anchor")
}
