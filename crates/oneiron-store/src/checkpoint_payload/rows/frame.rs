//! The bundle framing of an owner's content and of an actor's parts: a
//! version byte, then fixed fields and length-prefixed bytes, every length a
//! u32be. Framing only: the seal and its commitments are KS7-2b's.

use crate::checkpoint_payload::OWNER_LEN;
use crate::checkpoint_payload::Subtype;
use crate::checkpoint_payload::corrupt;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub const VERSION: u8 = 1;

pub const EXACT: u8 = 0;
pub const NO_ACTOR: u8 = 1;
pub const ACTOR_KEYED: u8 = 2;

pub fn put_len(out: &mut Vec<u8>, len: usize) -> Result<()> {
    let len = u32::try_from(len).map_err(|_| corrupt())?;
    out.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// One row's key and value, as an actor-keyed row's actor part holds them.
pub fn frame_row(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(key.len() + value.len() + 8);
    put_bytes(&mut out, key)?;
    put_bytes(&mut out, value)?;
    Ok(out)
}
