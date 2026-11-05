//! One private world's window update, sealed for a home that may not read the
//! world, which stores it and relays it between the owner's machines
//! (DEC-0005 "The thirteen fixes", row 8: "The cloud relays its sealed
//! updates between the owner's machines and cannot read them"; CLIP-SYNC = A,
//! FIX 12586).
//!
//! The home holds one E0 envelope per update. Its clear header names no world,
//! no window and no key: its `key_id` is a fresh salt and a hint, the keyed
//! hash of that salt under a key only a holder of the world key derives. So
//! the home cannot link two updates of one world, and a machine finds its own
//! worlds' updates by recomputing the hint under each world key it holds,
//! opening only the one that matches. The body is padded to a size step and
//! carries the key's id, the window key and the update bytes.

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
const BODY_LABEL: &[u8] = b"oneiron/sealed-world-update/v1\0";
const SALT_LEN: usize = 16;
const HINT_LEN: usize = 16;
/// The id a relayed update goes by on its home: the same update of the same
/// window under the same key always takes the same id, and only a holder of
/// the key computes it.
pub(crate) const SEALED_UPDATE_ID_LEN: usize = 16;
/// The smallest padded body. Bodies grow by doubling from here, so the home
/// learns an update's size only to within a factor of two (Engine call
/// CLIP-SYNC relay padding, CALLS.md).
pub(crate) const SEALED_UPDATE_PAD_FLOOR_BYTES: usize = 1024;

/// What one sealed message carries for its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealedUpdateKind {
    /// One update of the window, as its writer made it.
    Update = 0,
    /// The window's whole document, as its sender holds it: what a reader
    /// that lacks the history an update stands on imports instead.
    Snapshot = 1,
    /// A reader asks the world's other readers for the window's snapshot:
    /// no bytes.
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

/// One opened message: the key that opened it, what it carries, its window
/// and its bytes.
pub(crate) struct OpenedWorldUpdate {
    pub key: WorldKeyId,
    pub kind: SealedUpdateKind,
    pub window_key: String,
    pub update: Zeroizing<Vec<u8>>,
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

/// The id the home keeps `update` of `window_key` under, sealed under `key`.
#[must_use]
pub(crate) fn sealed_update_id(
    vault_id: &[u8; 32],
    key: &WorldKey,
    kind: SealedUpdateKind,
    window_key: &str,
    update: &[u8],
) -> [u8; SEALED_UPDATE_ID_LEN] {
    let key_id = key.id().envelope_key_id();
    let window_len = (window_key.len() as u64).to_be_bytes();
    let update_len = (update.len() as u64).to_be_bytes();
    let digest = derive_guarded(
        ID_CONTEXT,
        &[
            &vault_id[..],
            &key_id[..],
            &key.expose()[..],
            &[kind as u8][..],
            &window_len[..],
            window_key.as_bytes(),
            &update_len[..],
            update,
        ],
    );
    let mut out = [0u8; SEALED_UPDATE_ID_LEN];
    out.copy_from_slice(&digest[..SEALED_UPDATE_ID_LEN]);
    out
}

/// The padded body length for `len` content bytes: the next power of two at
/// or above both `len` and [`SEALED_UPDATE_PAD_FLOOR_BYTES`].
fn padded_len(len: usize) -> Option<usize> {
    len.max(SEALED_UPDATE_PAD_FLOOR_BYTES)
        .checked_next_power_of_two()
}

/// Seals `update` of `window_key` under `key` for the home to relay: one E0
/// envelope, as bytes, at most `max_bytes` long.
///
/// # Errors
/// A refusal when the window key is longer than 255 bytes, when the padded
/// envelope would pass `max_bytes`, or when sealing fails.
pub(crate) fn seal_world_update(
    vault_id: &[u8; 32],
    key: &WorldKey,
    kind: SealedUpdateKind,
    window_key: &str,
    update: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let window_len =
        u8::try_from(window_key.len()).map_err(|_| refused("a window key past 255 bytes"))?;
    let update_len = u32::try_from(update.len()).map_err(|_| refused("an update past 4 GiB"))?;
    let content = BODY_LABEL.len() + 1 + 40 + 1 + window_key.len() + 4 + update.len();
    let padded = padded_len(content).ok_or_else(|| refused("an update too large to pad"))?;
    if padded > max_bytes {
        return Err(refused(
            "the padded sealed update would pass the frame bound",
        ));
    }
    let mut body = Zeroizing::new(Vec::with_capacity(padded));
    body.extend_from_slice(BODY_LABEL);
    body.push(kind as u8);
    body.extend_from_slice(&key.id().envelope_key_id());
    body.push(window_len);
    body.extend_from_slice(window_key.as_bytes());
    body.extend_from_slice(&update_len.to_be_bytes());
    body.extend_from_slice(update);
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
    let kek = kek_for(vault_id, key);
    let envelope = seal(&params, SealKey::SymmetricKek(&kek), &body, &mut SysRng)
        .map_err(|_| refused("sealing the world update failed"))?;
    Ok(envelope.to_bytes())
}

/// Opens `sealed` under whichever of `keys` its hint names: `None` when none
/// does, as for another world's update or one sealed under a key this machine
/// does not hold.
///
/// # Errors
/// A refusal when the bytes are no sealed update, or when the key the hint
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
    let (update_len, rest) = rest.split_at_checked(4).ok_or_else(disagree)?;
    let update_len = u32::from_be_bytes(update_len.try_into().map_err(|_| disagree())?) as usize;
    let (update, padding) = rest.split_at_checked(update_len).ok_or_else(disagree)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(disagree());
    }
    Ok(Some(OpenedWorldUpdate {
        key: *key.id(),
        kind,
        window_key,
        update: Zeroizing::new(update.to_vec()),
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
