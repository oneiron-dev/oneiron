//! One private world's window messages, sealed for a home that may not read
//! the world, which stores them and relays them between the owner's machines
//! (DEC-0005 "The thirteen fixes", row 8: "The cloud relays its sealed
//! updates between the owner's machines and cannot read them"; CLIP-SYNC = A,
//! FIX 12586).
//!
//! A message (an update, a window snapshot or a want) is sealed in parts of at
//! most [`SEALED_UPDATE_PART_BYTES`], so a message of any size crosses frames
//! of the relay's bound. The home holds one E0 envelope per part. Its clear
//! header names no world, no window and no key: its `key_id` is a fresh salt
//! and a hint, the keyed hash of that salt under a key only a holder of the
//! world key derives. So the home cannot link two parts of one world, and a
//! machine finds its own worlds' parts by recomputing the hint under each
//! world key it holds, opening only the one that matches. Each part's body is
//! padded to a size step and carries the key's id, the message's kind and
//! window, the whole message's digest, the part's index and count, and its
//! slice of the message.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use zeroize::Zeroizing;

use super::{WORLD_KEY_EPOCH, WorldKey, WorldKeyId, derive_guarded, os_fill, refused};
use crate::EntityId;
use crate::error::Result;

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const KEY_CONTEXT: &str = "oneiron/sealed-world-update-key/v1";
const HINT_CONTEXT: &str = "oneiron/sealed-world-update-hint/v1";
const ID_CONTEXT: &str = "oneiron/sealed-world-update-id/v1";
/// The E0 recipient: it names no reader and no world.
const RECIPIENT: &[u8] = b"oneiron/sealed-world-update";
const BODY_LABEL: &[u8] = b"oneiron/sealed-world-update/v2\0";
const SALT_LEN: usize = 16;
const HINT_LEN: usize = 16;
/// The id a relayed part goes by on its home: the same part of the same
/// message under the same key always takes the same id, and only a holder of
/// the key computes it.
pub(crate) const SEALED_UPDATE_ID_LEN: usize = 16;
/// The smallest padded part body. Bodies grow by doubling from here, so the
/// home learns a part's size only to within a factor of two (Engine call
/// CLIP-SYNC relay padding, CALLS.md).
pub(crate) const SEALED_UPDATE_PAD_FLOOR_BYTES: usize = 1024;
/// The largest padded part body: a message past it is sealed in several
/// parts, each padded to exactly this size but the last.
pub(crate) const SEALED_UPDATE_PART_BYTES: usize = 1024 * 1024;
/// label ‖ kind ‖ key id ‖ window length ‖ digest ‖ index ‖ count ‖ chunk
/// length, before the window key and the chunk.
const PART_HEADER_BYTES: usize = BODY_LABEL.len() + 1 + 40 + 1 + 32 + 4 + 4 + 4;

/// What one sealed message carries for its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SealedUpdateKind {
    /// One update of the window, as its writer made it.
    Update = 0,
    /// The window's history-free snapshot, as its sender holds it: what a
    /// reader that lacks the history an update stands on installs as a
    /// replacement instead.
    Snapshot = 1,
    /// A reader asks the world's other readers for the window's snapshot.
    Want = 2,
}

impl SealedUpdateKind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Update),
            1 => Some(Self::Snapshot),
            2 => Some(Self::Want),
            _ => None,
        }
    }
}

/// One sealed part, as the outbox keeps it.
pub(crate) struct SealedPart {
    pub id: [u8; SEALED_UPDATE_ID_LEN],
    pub sealed: Vec<u8>,
}

/// One opened part: the key that opened it, its message's kind, window and
/// digest, its place among the message's parts and its slice.
pub(crate) struct OpenedWorldUpdate {
    pub key: WorldKeyId,
    pub kind: SealedUpdateKind,
    pub window_key: String,
    pub digest: [u8; 32],
    pub index: u32,
    pub count: u32,
    pub chunk: Zeroizing<Vec<u8>>,
}

impl OpenedWorldUpdate {
    #[must_use]
    pub(crate) fn world(&self) -> EntityId {
        self.key.world
    }
}

fn key_parts<'a>(vault_id: &'a [u8; 32], key_id: &'a [u8; 40], key: &'a WorldKey) -> [&'a [u8]; 3] {
    [&vault_id[..], &key_id[..], &key.expose()[..]]
}

fn hint_for(vault_id: &[u8; 32], key: &WorldKey, salt: &[u8; SALT_LEN]) -> [u8; HINT_LEN] {
    let key_id = key.id().envelope_key_id();
    let hint_key = derive_guarded(HINT_CONTEXT, &key_parts(vault_id, &key_id, key));
    let mut out = [0u8; HINT_LEN];
    out.copy_from_slice(&blake3::keyed_hash(&hint_key, salt).as_bytes()[..HINT_LEN]);
    out
}

fn kek_for(vault_id: &[u8; 32], key: &WorldKey) -> Kek {
    let key_id = key.id().envelope_key_id();
    Kek::from_zeroizing(derive_guarded(
        KEY_CONTEXT,
        &key_parts(vault_id, &key_id, key),
    ))
}

/// The id the home keeps part `index` of a message under.
fn part_id(
    vault_id: &[u8; 32],
    key: &WorldKey,
    kind: SealedUpdateKind,
    window_key: &str,
    digest: &[u8; 32],
    index: u32,
) -> [u8; SEALED_UPDATE_ID_LEN] {
    let key_id = key.id().envelope_key_id();
    let window_len = (window_key.len() as u64).to_be_bytes();
    let derived = derive_guarded(
        ID_CONTEXT,
        &[
            &vault_id[..],
            &key_id[..],
            &key.expose()[..],
            &[kind as u8][..],
            &window_len[..],
            window_key.as_bytes(),
            &digest[..],
            &index.to_be_bytes()[..],
        ],
    );
    let mut out = [0u8; SEALED_UPDATE_ID_LEN];
    out.copy_from_slice(&derived[..SEALED_UPDATE_ID_LEN]);
    out
}

/// The padded body length for `len` content bytes: the next power of two at
/// or above both `len` and [`SEALED_UPDATE_PAD_FLOOR_BYTES`].
fn padded_len(len: usize) -> Option<usize> {
    len.max(SEALED_UPDATE_PAD_FLOOR_BYTES)
        .checked_next_power_of_two()
}

/// Seals `bytes`, one message of `kind` for `window_key`, under `key` for the
/// home to relay: one E0 envelope per part, each of at most
/// [`SEALED_UPDATE_PART_BYTES`] padded, in order.
///
/// # Errors
/// A refusal when the window key is longer than 255 bytes or the message
/// needs more than `u32::MAX` parts, or when sealing fails.
pub(crate) fn seal_world_message(
    vault_id: &[u8; 32],
    key: &WorldKey,
    kind: SealedUpdateKind,
    window_key: &str,
    bytes: &[u8],
) -> Result<Vec<SealedPart>> {
    let window_len =
        u8::try_from(window_key.len()).map_err(|_| refused("a window key past 255 bytes"))?;
    let room = SEALED_UPDATE_PART_BYTES - PART_HEADER_BYTES - window_key.len();
    let digest = *blake3::hash(bytes).as_bytes();
    let chunks: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(room).collect()
    };
    let count = u32::try_from(chunks.len()).map_err(|_| refused("too many sealed parts"))?;
    let kek = kek_for(vault_id, key);
    let mut parts = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| refused("too many sealed parts"))?;
        let content = PART_HEADER_BYTES + window_key.len() + chunk.len();
        let padded = padded_len(content).ok_or_else(|| refused("a part too large to pad"))?;
        let mut body = Zeroizing::new(Vec::with_capacity(padded));
        body.extend_from_slice(BODY_LABEL);
        body.push(kind as u8);
        body.extend_from_slice(&key.id().envelope_key_id());
        body.push(window_len);
        body.extend_from_slice(window_key.as_bytes());
        body.extend_from_slice(&digest);
        body.extend_from_slice(&index.to_be_bytes());
        body.extend_from_slice(&count.to_be_bytes());
        body.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        body.extend_from_slice(chunk);
        body.resize(padded, 0);
        let mut salt = [0u8; SALT_LEN];
        os_fill(&mut salt)?;
        let hint = hint_for(vault_id, key, &salt);
        let mut key_id = [0u8; SALT_LEN + HINT_LEN];
        key_id[..SALT_LEN].copy_from_slice(&salt);
        key_id[SALT_LEN..].copy_from_slice(&hint);
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SealedWorldUpdate,
            epoch: WORLD_KEY_EPOCH,
            key_id: &key_id,
            recipient: RECIPIENT,
            vault_id,
        };
        let envelope = seal(&params, SealKey::SymmetricKek(&kek), &body, &mut SysRng)
            .map_err(|_| refused("sealing the world update failed"))?;
        parts.push(SealedPart {
            id: part_id(vault_id, key, kind, window_key, &digest, index),
            sealed: envelope.to_bytes(),
        });
    }
    Ok(parts)
}

/// Opens `sealed` under whichever of `keys` its hint names: `None` when none
/// does, as for another world's part or one sealed under a key this machine
/// does not hold.
///
/// # Errors
/// A refusal when the bytes are no sealed part, or when the key the hint
/// names does not open them, or opens a body that disagrees with that key.
pub(crate) fn open_world_update(
    vault_id: &[u8; 32],
    keys: &[WorldKey],
    sealed: &[u8],
) -> Result<Option<OpenedWorldUpdate>> {
    let malformed = || refused("not a sealed world update");
    let envelope = Envelope::parse(sealed).map_err(|_| malformed())?;
    let header = envelope.header();
    if header.purpose != Purpose::SealedWorldUpdate
        || header.recipient != RECIPIENT
        || header.key_id.len() != SALT_LEN + HINT_LEN
    {
        return Err(malformed());
    }
    let salt: [u8; SALT_LEN] = header.key_id[..SALT_LEN]
        .try_into()
        .map_err(|_| malformed())?;
    let Some(key) = keys
        .iter()
        .find(|key| hint_for(vault_id, key, &salt)[..] == header.key_id[SALT_LEN..])
    else {
        return Ok(None);
    };
    let mut expected = [0u8; SALT_LEN + HINT_LEN];
    expected[..SALT_LEN].copy_from_slice(&salt);
    expected[SALT_LEN..].copy_from_slice(&hint_for(vault_id, key, &salt));
    let policy = OpenPolicy {
        purpose: Purpose::SealedWorldUpdate,
        vault_id,
        recipient: RECIPIENT,
        key_id: &expected,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let kek = kek_for(vault_id, key);
    let body = envelope
        .open(OpenKey::SymmetricKek(&kek), &policy)
        .map_err(|_| refused("a sealed world update does not open under the key its hint names"))?;
    let disagree = || refused("a sealed world update's body disagrees with its key");
    let rest = body.strip_prefix(BODY_LABEL).ok_or_else(disagree)?;
    let (&kind, rest) = rest.split_first().ok_or_else(disagree)?;
    let kind = SealedUpdateKind::from_byte(kind).ok_or_else(disagree)?;
    let (named, rest) = rest.split_at_checked(40).ok_or_else(disagree)?;
    if named != key.id().envelope_key_id() {
        return Err(disagree());
    }
    let (&window_len, rest) = rest.split_first().ok_or_else(disagree)?;
    let (window_key, rest) = rest
        .split_at_checked(usize::from(window_len))
        .ok_or_else(disagree)?;
    let window_key = std::str::from_utf8(window_key)
        .map_err(|_| disagree())?
        .to_owned();
    let (digest, rest) = rest.split_first_chunk::<32>().ok_or_else(disagree)?;
    let (index, rest) = rest.split_first_chunk::<4>().ok_or_else(disagree)?;
    let (count, rest) = rest.split_first_chunk::<4>().ok_or_else(disagree)?;
    let (chunk_len, rest) = rest.split_first_chunk::<4>().ok_or_else(disagree)?;
    let (index, count) = (u32::from_be_bytes(*index), u32::from_be_bytes(*count));
    if count == 0 || index >= count {
        return Err(disagree());
    }
    let (chunk, padding) = rest
        .split_at_checked(u32::from_be_bytes(*chunk_len) as usize)
        .ok_or_else(disagree)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(disagree());
    }
    Ok(Some(OpenedWorldUpdate {
        key: *key.id(),
        kind,
        window_key,
        digest: *digest,
        index,
        count,
        chunk: Zeroizing::new(chunk.to_vec()),
    }))
}

impl crate::Vault {
    /// The vault id sealed world updates bind: the authority genesis's.
    ///
    /// # Errors
    /// A refusal before the vault has an authority genesis; store errors.
    pub(crate) fn sealed_update_vault_id(&self) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        self.authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))
    }
}
