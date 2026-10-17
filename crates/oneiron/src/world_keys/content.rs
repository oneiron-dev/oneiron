//! Sealed world content (OF-570 (d), world privacy fix 8): one window of a private
//! world, sealed under a key only the world's readers hold, so a home node that may
//! not read the world can still keep a copy of it.
//!
//! - The content key is `BLAKE3-derive_key("oneiron/sealed-world-content-key/v1",
//!   vault ‖ key id ‖ world key)`. It is never the vault key, a host key or a recovery
//!   seed: recovery first restores the world key through its root wrap.
//! - A packet is a short frame around E0 envelopes (purpose `SealedWorldContent`,
//!   symmetric KEK, XChaCha20-Poly1305). Outside the ciphertext it names only its
//!   vault and a tag. The tag is `BLAKE3-derive_key("oneiron/sealed-world-content-tag/v1",
//!   key id ‖ pad)`: a replica that holds the key's pad row can file a packet under
//!   it and purge it with the world, and cannot open it. The host holds pads too, so
//!   it can tell which packets share a key; the cloud's one-bundle rule is the
//!   carrier's.
//! - The sealed body names the world key, the window, whether it is an update or a
//!   replacement, and the version vectors it spans, then the Loro bytes, then zeros up
//!   to a size step. Each envelope carries one slice of it with the body's digest, so
//!   slices of two packets never mix.
//! - The shelf keeps packets by tag and digest. A reader retires a packet another one
//!   replaces; a retired packet is purged 30 days later, and a second retire never
//!   resets that clock (fix 7). Deleting the world purges its packets at once, current
//!   and retired, on every replica that applies the delete; a packet for a key whose
//!   pad is not here is refused, so none lands after.

use std::sync::Arc;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::pads::{live_pad_tag_in_txn, require_pad_in_txn};
use super::{WORLD_KEY_EPOCH, WorldKey, WorldKeyId, base_world, refused};
use crate::Vault;
use crate::authority::{Destination, EffectiveRead, SealedCopies};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// How long a retired packet stays on the shelf (DEC-0005 fix 7).
pub const SEALED_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

const FRAME_MAGIC: &[u8; 4] = b"OSWC";
const FRAME_VERSION: u8 = 1;
const BODY_LABEL: &[u8] = b"oneiron/sealed-world-content/v1\0";
const PART_LABEL: &[u8] = b"oneiron/sealed-world-content-part/v1\0";
const KEY_CONTEXT: &str = "oneiron/sealed-world-content-key/v1";
/// The E0 recipient every sealed packet names: no machine and no world.
const RECIPIENT: &[u8] = b"oneiron/sealed-world-content";
const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// One envelope's slice of the body, under E0's 16 MiB plaintext bound.
const CHUNK: usize = 8 * 1024 * 1024;
/// The most envelopes one packet holds: a 1 GiB body.
const MAX_PARTS: usize = 128;
/// The smallest padded body.
const PAD_FLOOR: usize = 4096;
const MAX_WINDOW_LEN: usize = 255;
/// label ‖ digest (32) ‖ index (2) ‖ count (2).
const PART_HEADER_LEN: usize = PART_LABEL.len() + 32 + 2 + 2;

/// The shelf: one packet per row. Key: hex64 (tag) ":" hex64 (digest).
const SHELF: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::WORLD_KEY_SEALED);
/// When a shelved packet was retired, in vault seconds. Same key as the shelf.
const RETIRED: SideTable<String, u64, Raw> = SideTable::new(&side_table::WORLD_KEY_SEALED_RETIRED);
/// A reader's own Loro document per sealed window, the history its packets
/// continue. Key: hex32 (world) ":" window label.
pub(super) const MIRROR: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORLD_KEY_SEALED_MIRROR);
/// The newest shelved packet of one window, by shelf id hex. Key: window label.
const WINDOW_INDEX: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORLD_KEY_SEALED_WINDOW);

/// What a packet's Loro bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedContentKind {
    /// Updates the reader merges into the window it holds from `from`.
    Update,
    /// A whole snapshot the reader installs in place of its sealed window.
    Replacement,
}

impl SealedContentKind {
    const fn wire(self) -> u8 {
        match self {
            Self::Update => 1,
            Self::Replacement => 2,
        }
    }

    fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Update),
            2 => Some(Self::Replacement),
            _ => None,
        }
    }
}

/// What a packet is bound to, authenticated inside its ciphertext. Only a reader
/// learns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedContentBinding {
    /// The world key the packet is sealed under: the world and its generation.
    pub key: WorldKeyId,
    /// The window label, `YYYY-MM@<world hex>`.
    pub window: String,
    pub kind: SealedContentKind,
    /// The encoded Loro version vector the bytes start from; empty for a replacement.
    pub from: Vec<u8>,
    /// The encoded Loro version vector the bytes reach.
    pub to: Vec<u8>,
}

/// An opened packet: its binding and its Loro bytes, wiped on drop.
pub struct OpenedSealedContent {
    pub binding: SealedContentBinding,
    pub payload: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedSealedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedSealedContent")
            .field("binding", &self.binding)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Where a packet rests on a shelf: its tag and the digest of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedContentId {
    pub tag: [u8; 32],
    pub digest: [u8; 32],
}

impl SealedContentId {
    /// `hex(tag) ":" hex(digest)`, the shelf key.
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("{}:{}", hex32(&self.tag), hex32(&self.digest))
    }

    /// Parses [`Self::to_hex`].
    pub fn from_hex(text: &str) -> Result<Self> {
        let (tag, digest) = text
            .split_once(':')
            .ok_or_else(|| refused("a sealed content id is tag:digest"))?;
        Ok(Self {
            tag: unhex32(tag)?,
            digest: unhex32(digest)?,
        })
    }
}

/// One sealed packet: the frame bytes and the envelopes they hold, checked for
/// shape. Whether it opens is a reader's question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedResidenceContent {
    bytes: Vec<u8>,
    tag: [u8; 32],
    parts: Vec<Envelope>,
}

impl SealedResidenceContent {
    /// Strict parse: magic, version, tag, part count, each part one canonical E0
    /// envelope of purpose `SealedWorldContent` under a symmetric KEK named by the tag,
    /// for the sealed-content recipient, and nothing after the last part.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = || refused("malformed sealed world content");
        let mut cursor = Cursor { bytes, at: 0 };
        if cursor.take(4) != Some(&FRAME_MAGIC[..]) || cursor.take(1) != Some(&[FRAME_VERSION][..])
        {
            return Err(malformed());
        }
        let tag: [u8; 32] = cursor.array().ok_or_else(malformed)?;
        let count = usize::from(u16::from_be_bytes(cursor.array().ok_or_else(malformed)?));
        if count == 0 || count > MAX_PARTS {
            return Err(malformed());
        }
        let mut parts = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
            let part = cursor.take(len as usize).ok_or_else(malformed)?;
            let envelope = Envelope::parse(part).map_err(|_| malformed())?;
            let header = envelope.header();
            if header.purpose != Purpose::SealedWorldContent
                || header.wrap != WrapType::SymmetricKek
                || header.suite != AEAD
                || header.key_id != tag
                || header.recipient != RECIPIENT
            {
                return Err(malformed());
            }
            parts.push(envelope);
        }
        if cursor.at != bytes.len() {
            return Err(malformed());
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            tag,
            parts,
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub fn id(&self) -> SealedContentId {
        SealedContentId {
            tag: self.tag,
            digest: *blake3::hash(&self.bytes).as_bytes(),
        }
    }

    /// Whether every envelope names `vault_id`. Unauthenticated until a reader opens it.
    fn names_vault(&self, vault_id: &[u8; 32]) -> bool {
        self.parts
            .iter()
            .all(|part| part.header().vault_id == vault_id)
    }

    fn frame(tag: [u8; 32], parts: Vec<Envelope>) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FRAME_MAGIC);
        bytes.push(FRAME_VERSION);
        bytes.extend_from_slice(&tag);
        bytes.extend_from_slice(&(parts.len() as u16).to_be_bytes());
        for part in &parts {
            let encoded = part.to_bytes();
            bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Self { bytes, tag, parts }
    }
}

/// One world key ready to seal or open content: the key, the vault it belongs
/// to, and the tag its packets carry.
pub(crate) struct WorldContentSealer {
    key: Arc<WorldKey>,
    vault_id: [u8; 32],
    tag: [u8; 32],
}

impl WorldContentSealer {
    fn kek(&self) -> Kek {
        let mut hasher = blake3::Hasher::new_derive_key(KEY_CONTEXT);
        hasher.update(&self.vault_id);
        hasher.update(&self.key.id().envelope_key_id());
        hasher.update(self.key.expose());
        let kek = Kek::from_bytes(*hasher.finalize().as_bytes());
        // The hasher's block buffer still holds the key's bytes.
        zeroize::Zeroize::zeroize(&mut hasher);
        kek
    }

    /// Seals `payload`, the Loro bytes of `window` spanning `from` to `to`.
    pub(crate) fn seal(
        &self,
        window: &str,
        kind: SealedContentKind,
        from: &[u8],
        to: &[u8],
        payload: &[u8],
    ) -> Result<SealedResidenceContent> {
        check_window(self.key.id().world, window)?;
        let body = encode_body(self.key.id(), window, kind, from, to, payload)?;
        let digest = *blake3::hash(&body).as_bytes();
        let chunks: Vec<&[u8]> = body.chunks(CHUNK).collect();
        if chunks.len() > MAX_PARTS {
            return Err(refused("the window is too large for one sealed packet"));
        }
        let kek = self.kek();
        let params = SealParams {
            suite: AEAD,
            purpose: Purpose::SealedWorldContent,
            epoch: WORLD_KEY_EPOCH,
            key_id: &self.tag,
            recipient: RECIPIENT,
            vault_id: &self.vault_id,
        };
        let count = chunks.len() as u16;
        let mut parts = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.into_iter().enumerate() {
            let mut plaintext = Zeroizing::new(Vec::with_capacity(PART_HEADER_LEN + chunk.len()));
            plaintext.extend_from_slice(PART_LABEL);
            plaintext.extend_from_slice(&digest);
            plaintext.extend_from_slice(&(index as u16).to_be_bytes());
            plaintext.extend_from_slice(&count.to_be_bytes());
            plaintext.extend_from_slice(chunk);
            parts.push(
                seal(
                    &params,
                    SealKey::SymmetricKek(&kek),
                    &plaintext,
                    &mut SysRng,
                )
                .map_err(|_| refused("sealing failed"))?,
            );
        }
        Ok(SealedResidenceContent::frame(self.tag, parts))
    }

    /// Opens `packet`, refusing one not sealed under this key and vault, one whose
    /// slices disagree, and one whose body names another key or window.
    pub(crate) fn open(
        &self,
        window: &str,
        packet: &SealedResidenceContent,
    ) -> Result<OpenedSealedContent> {
        if packet.tag != self.tag {
            return Err(refused(
                "the packet is sealed under another key of the world",
            ));
        }
        let kek = self.kek();
        let policy = OpenPolicy {
            purpose: Purpose::SealedWorldContent,
            vault_id: &self.vault_id,
            recipient: RECIPIENT,
            key_id: &self.tag,
            wraps: &[WrapType::SymmetricKek],
            aead_suites: &[AEAD],
            kem_suites: &[],
            min_epoch: WORLD_KEY_EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let count = packet.parts.len();
        let mut body = Zeroizing::new(Vec::new());
        let mut expected: Option<[u8; 32]> = None;
        for (index, part) in packet.parts.iter().enumerate() {
            let plaintext = part
                .open(OpenKey::SymmetricKek(&kek), &policy)
                .map_err(|_| refused("the packet does not open under the world's key"))?;
            let slices_disagree = || refused("the packet's slices disagree");
            if plaintext.len() < PART_HEADER_LEN || !plaintext.starts_with(PART_LABEL) {
                return Err(slices_disagree());
            }
            let header = &plaintext[PART_LABEL.len()..PART_HEADER_LEN];
            let digest: [u8; 32] = header[..32].try_into().map_err(|_| slices_disagree())?;
            let at = u16::from_be_bytes([header[32], header[33]]);
            let of = u16::from_be_bytes([header[34], header[35]]);
            if usize::from(at) != index
                || usize::from(of) != count
                || expected.is_some_and(|first| first != digest)
            {
                return Err(slices_disagree());
            }
            expected = Some(digest);
            body.extend_from_slice(&plaintext[PART_HEADER_LEN..]);
        }
        if expected != Some(*blake3::hash(&body).as_bytes()) {
            return Err(refused("the packet's slices disagree"));
        }
        let opened = decode_body(&body)?;
        if opened.binding.key != *self.key.id() || opened.binding.window != window {
            return Err(refused("the packet names another key or window"));
        }
        Ok(opened)
    }
}

fn check_window(world: EntityId, window: &str) -> Result<()> {
    let names_world = window
        .rsplit_once('@')
        .is_some_and(|(_, hex)| hex == world.to_hex());
    if !names_world || window.len() > MAX_WINDOW_LEN {
        return Err(refused("the window is not one of the world's"));
    }
    Ok(())
}

/// The padded size of an `unpadded`-byte body: a power of two from 4 KiB, then
/// whole slices.
fn padded_len(unpadded: usize) -> usize {
    if unpadded <= CHUNK {
        unpadded.next_power_of_two().max(PAD_FLOOR)
    } else {
        unpadded.div_ceil(CHUNK) * CHUNK
    }
}

fn encode_body(
    key: &WorldKeyId,
    window: &str,
    kind: SealedContentKind,
    from: &[u8],
    to: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let too_large = || refused("the window is too large for one sealed packet");
    let from_len = u32::try_from(from.len()).map_err(|_| too_large())?;
    let to_len = u32::try_from(to.len()).map_err(|_| too_large())?;
    let unpadded = BODY_LABEL.len()
        + 40
        + 1
        + 1
        + window.len()
        + 4
        + from.len()
        + 4
        + to.len()
        + 8
        + payload.len();
    let mut body = Zeroizing::new(Vec::with_capacity(padded_len(unpadded)));
    body.extend_from_slice(BODY_LABEL);
    body.extend_from_slice(&key.envelope_key_id());
    body.push(kind.wire());
    body.push(u8::try_from(window.len()).map_err(|_| too_large())?);
    body.extend_from_slice(window.as_bytes());
    body.extend_from_slice(&from_len.to_be_bytes());
    body.extend_from_slice(from);
    body.extend_from_slice(&to_len.to_be_bytes());
    body.extend_from_slice(to);
    body.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    body.extend_from_slice(payload);
    body.resize(padded_len(unpadded), 0);
    Ok(body)
}

fn decode_body(body: &[u8]) -> Result<OpenedSealedContent> {
    let malformed = || refused("the packet's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(BODY_LABEL.len()) != Some(BODY_LABEL) {
        return Err(malformed());
    }
    let world =
        EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
    let generation = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mint: [u8; 16] = cursor.array().ok_or_else(malformed)?;
    let kind: [u8; 1] = cursor.array().ok_or_else(malformed)?;
    let kind = SealedContentKind::from_wire(kind[0]).ok_or_else(malformed)?;
    let window_len: [u8; 1] = cursor.array().ok_or_else(malformed)?;
    let window = cursor
        .take(usize::from(window_len[0]))
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or_else(malformed)?
        .to_owned();
    let from = cursor.counted().ok_or_else(malformed)?.to_vec();
    let to = cursor.counted().ok_or_else(malformed)?.to_vec();
    let payload_len = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let payload = usize::try_from(payload_len)
        .ok()
        .and_then(|len| cursor.take(len))
        .ok_or_else(malformed)?;
    let payload = Zeroizing::new(payload.to_vec());
    let end = cursor.at;
    if body[end..].iter().any(|byte| *byte != 0) || body.len() != padded_len(end) {
        return Err(malformed());
    }
    Ok(OpenedSealedContent {
        binding: SealedContentBinding {
            key: WorldKeyId {
                world,
                generation,
                mint,
            },
            window,
            kind,
            from,
            to,
        },
        payload,
    })
}

/// A forward reader over a frame or a body.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A `u32`-length-prefixed field.
    fn counted(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(len as usize)
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex32(text: &str) -> Result<[u8; 32]> {
    let bad = || refused("a sealed content id is two 64-digit hex halves");
    if text.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Purges every shelved packet under `tags`, retired or not, and every mirror
/// of `world`, in the caller's write transaction. Returns the packets purged.
pub(super) fn purge_sealed_world_content_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    world: EntityId,
    tags: &[[u8; 32]],
) -> Result<u64> {
    let mut purged = 0u64;
    for tag in tags {
        let prefix = format!("{}:", hex32(tag));
        for key in SHELF.scan_keys(store, wtxn, prefix.as_bytes())? {
            if SHELF.delete(store, wtxn, &key)? {
                purged += 1;
            }
        }
        for key in RETIRED.scan_keys(store, wtxn, prefix.as_bytes())? {
            RETIRED.delete(store, wtxn, &key)?;
        }
    }
    let prefix = format!("{}:", world.to_hex());
    for key in MIRROR.scan_keys(store, wtxn, prefix.as_bytes())? {
        MIRROR.delete(store, wtxn, &key)?;
    }
    let suffix = format!("@{}", world.to_hex());
    for key in WINDOW_INDEX.scan_keys(store, wtxn, &[])? {
        if key.ends_with(suffix.as_str()) {
            WINDOW_INDEX.delete(store, wtxn, &key)?;
        }
    }
    Ok(purged)
}

/// Purges every packet retired [`SEALED_RETENTION_SECS`] or more before `now`.
fn expire_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>, now: u64) -> Result<u64> {
    let mut expired = 0u64;
    for (key, retired_at) in RETIRED.scan(store, wtxn)? {
        if retired_at.saturating_add(SEALED_RETENTION_SECS) <= now {
            SHELF.delete(store, wtxn, &key)?;
            RETIRED.delete(store, wtxn, &key)?;
            expired += 1;
        }
    }
    Ok(expired)
}

impl Vault {
    /// The world's current key, ready to seal its content here. Refused unless
    /// this machine may read the world now (see [`Vault::world_key`]).
    pub(crate) fn world_content_sealer(&self, world: EntityId) -> Result<WorldContentSealer> {
        if world == base_world() {
            return Err(refused("base reality has no world key"));
        }
        let key = self.world_key(world)?;
        let txn = self.store.env.read_txn()?;
        let vault_id = self
            .authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let tag = require_pad_in_txn(&self.store, &txn, key.id())?.content_tag(key.id());
        Ok(WorldContentSealer { key, vault_id, tag })
    }

    /// Seals `payload`, Loro bytes of `world`'s `window` spanning version vectors
    /// `from` to `to`, for a machine that may not read the world. Refused unless
    /// this machine may read the world and the world's sealed copies are not off.
    pub fn seal_world_content(
        &self,
        world: EntityId,
        window: &str,
        kind: SealedContentKind,
        from: &[u8],
        to: &[u8],
        payload: &[u8],
    ) -> Result<SealedResidenceContent> {
        self.require_sealed_copies(world)?;
        self.world_content_sealer(world)?
            .seal(window, kind, from, to, payload)
    }

    /// Opens a packet of `world`'s `window` on a machine that may read the world
    /// now. A packet sealed before the world's sealed copies were turned off still
    /// opens.
    pub fn open_world_content(
        &self,
        world: EntityId,
        window: &str,
        packet: &SealedResidenceContent,
    ) -> Result<OpenedSealedContent> {
        self.world_content_sealer(world)?.open(window, packet)
    }

    /// Refused when `world`'s sealed copies are off.
    pub(crate) fn require_sealed_copies(&self, world: EntityId) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        if self
            .authority_view_readonly_in_txn(&txn)?
            .world_privacy(world)
            .sealed
            == SealedCopies::Off
        {
            return Err(refused("the world's sealed copies are off"));
        }
        Ok(())
    }

    /// Whether a sealed copy of `world` may rest on `destination` (DEC-0005): a
    /// machine the owner marked "yours" unless the world's sealed copies are off,
    /// any other holder (the cloud, a hosted node) only under "cloud and my
    /// machines". A world readable everywhere travels readable, never sealed.
    pub fn sealed_copy_may_rest_on_in(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
        destination: Destination,
    ) -> Result<bool> {
        if world == base_world() {
            return Ok(false);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let privacy = fold.world_privacy(world);
        if privacy.read == EffectiveRead::Everywhere {
            return Ok(false);
        }
        Ok(match privacy.sealed {
            SealedCopies::Off => false,
            SealedCopies::MyMachines => matches!(
                destination,
                Destination::Machine(machine) if fold.trusted_machine(machine).is_some()
            ),
            SealedCopies::CloudAndMyMachines => true,
        })
    }

    /// [`Self::sealed_copy_may_rest_on_in`] in its own read snapshot: the
    /// destination question a relay door asks before it forwards a packet.
    pub fn sealed_copy_may_rest_on(
        &self,
        world: EntityId,
        destination: Destination,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.sealed_copy_may_rest_on_in(&txn, world, destination)
    }

    /// This install as a destination: its enrolled machine, or unknown
    /// before it has one. Never another machine.
    pub(crate) fn local_destination_in(&self, txn: &heed::RoTxn<'_>) -> Result<Destination> {
        Ok(match crate::identity::read_machine_id_in_txn(self, txn)? {
            Some(machine) => Destination::Machine(machine),
            None => Destination::Unknown,
        })
    }

    /// The newest shelved packet of `window`, the one a relay answer for
    /// that window forwards. Empty when none is shelved under it.
    pub fn sealed_window_packets(&self, window: &str) -> Result<Vec<SealedResidenceContent>> {
        let Some(id) = self.sealed_window_packet_id(window)? else {
            return Ok(Vec::new());
        };
        Ok(self.sealed_world_content(&id)?.into_iter().collect())
    }

    fn sealed_window_packet_id(&self, window: &str) -> Result<Option<SealedContentId>> {
        let txn = self.store.env.read_txn()?;
        WINDOW_INDEX
            .get(&self.store, &txn, &window.to_owned())?
            .map(|bytes| SealedContentId::from_hex(&String::from_utf8_lossy(&bytes)))
            .transpose()
    }

    /// Records `id` as `window`'s newest shelved packet, retiring the one it
    /// replaces. The retired packet stays on the shelf for its retention, so
    /// a reader behind it can still be served by id; window answers forward
    /// only the newest.
    pub(crate) fn note_sealed_window_packet(
        &self,
        window: &str,
        id: &SealedContentId,
    ) -> Result<()> {
        if let Some(previous) = self.sealed_window_packet_id(window)?
            && previous != *id
        {
            self.retire_sealed_world_content(&previous)?;
        }
        self.with_write_txn_grouped(|wtxn| {
            WINDOW_INDEX.put(
                &self.store,
                wtxn,
                &window.to_owned(),
                &id.to_hex().into_bytes(),
            )
        })
    }

    /// Shelves `packet` on this home node, which needs no world key and reads
    /// nothing inside it. Refused when an envelope names another vault, or no key
    /// whose pad is here carries the packet's tag (a deleted world's included).
    /// Idempotent; also purges packets retired 30 days ago.
    pub fn store_sealed_world_content(
        &self,
        packet: &SealedResidenceContent,
    ) -> Result<SealedContentId> {
        let id = packet.id();
        let key = id.to_hex();
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&txn)?
                .vault_id
                .ok_or_else(|| refused("the vault has no authority genesis yet"))?
        };
        if !packet.names_vault(&vault_id) {
            return Err(refused("the packet names another vault"));
        }
        self.with_write_txn_grouped(|wtxn| {
            if !live_pad_tag_in_txn(&self.store, wtxn, &packet.tag)? {
                return Err(refused("no key whose pad is here carries the packet's tag"));
            }
            let now = self.instant_in_txn(wtxn)?.secs();
            expire_in_txn(&self.store, wtxn, now)?;
            if !SHELF.contains(&self.store, wtxn, &key)? {
                SHELF.put(&self.store, wtxn, &key, &packet.bytes)?;
            }
            Ok(id)
        })
    }

    /// One shelved packet.
    pub fn sealed_world_content(
        &self,
        id: &SealedContentId,
    ) -> Result<Option<SealedResidenceContent>> {
        let txn = self.store.env.read_txn()?;
        SHELF
            .get(&self.store, &txn, &id.to_hex())?
            .map(|bytes| SealedResidenceContent::from_bytes(&bytes))
            .transpose()
    }

    /// Every shelved packet, with when it was retired, if it was.
    pub fn sealed_world_content_ids(&self) -> Result<Vec<(SealedContentId, Option<u64>)>> {
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for key in SHELF.scan_keys(&self.store, &txn, &[])? {
            let retired = RETIRED.get(&self.store, &txn, &key)?;
            out.push((SealedContentId::from_hex(&key)?, retired));
        }
        Ok(out)
    }

    /// Marks a shelved packet retired: a newer one replaces it. It is purged
    /// [`SEALED_RETENTION_SECS`] later. `false` when the packet is not here or
    /// was retired before, whose clock this never resets.
    pub fn retire_sealed_world_content(&self, id: &SealedContentId) -> Result<bool> {
        let key = id.to_hex();
        self.with_write_txn_grouped(|wtxn| {
            if !SHELF.contains(&self.store, wtxn, &key)?
                || RETIRED.contains(&self.store, wtxn, &key)?
            {
                return Ok(false);
            }
            let now = self.instant_in_txn(wtxn)?.secs();
            RETIRED.put(&self.store, wtxn, &key, &now)?;
            Ok(true)
        })
    }

    /// Purges every packet retired [`SEALED_RETENTION_SECS`] ago or more.
    /// Returns how many.
    pub fn expire_sealed_world_content(&self) -> Result<u64> {
        self.with_write_txn_grouped(|wtxn| {
            let now = self.instant_in_txn(wtxn)?.secs();
            expire_in_txn(&self.store, wtxn, now)
        })
    }
}
