//! Sealed-bundle codecs shared by the [`bundle`](self) children.
//!
//! Wire constants, frame/outer/part codecs and counters moved out of the
//! bundle root (FIX 10384): whole items, `pub(super)` visibility, no
//! behaviour change. The root re-exports every name so existing
//! `super::X` paths keep resolving.
use super::{
    Argon2Cost, EntityId, Envelope, Error, GENERATION_LEN, HybridPublicKey, HybridSecretKey, Kek,
    OpenKey, OpenPolicy, Purpose, Result, SEALED_BUNDLE_PAD_STEP_BYTES, SealKey, SealParams,
    SealedBundleGeneration, SecretError, SuiteId, SysRng, WORLD_KEY_EPOCH, WorldKeyId, WrapType,
    Zeroizing, os_fill, refused, seal,
};
/// The pad object's size step. Pads are small: a bundle's step would cost 64 MiB
/// a day for a few kilobytes.
pub(super) const SEALED_KEY_PADS_STEP_BYTES: usize = 64 * 1024;
/// Reader capsules come in whole multiples of this, blanks included.
pub(super) const SLOT_STEP: usize = 16;

pub(super) const FRAME_VERSION: u8 = 1;
/// The byte before an upload's owner work request in a bundle body.
pub(super) const REQUEST_TAG: u8 = 1;
pub(super) const SLOT_LABEL: &[u8] = b"oneiron/sealed-vault-slot/v1\0";
pub(super) const PART_LABEL: &[u8] = b"oneiron/sealed-vault-part/v1\0";
pub(super) const BUNDLE_LABEL: &[u8] = b"oneiron/sealed-vault-bundle/v1\0";
pub(super) const SECTION_LABEL: &[u8] = b"oneiron/sealed-vault-section/v1\0";
pub(super) const PADS_LABEL: &[u8] = b"oneiron/sealed-key-pads/v2\0";
pub(super) const SIGNATURE_CONTEXT: &str = "oneiron/sealed-vault-bundle-signature/v1";
pub(super) const SECTION_KEY_CONTEXT: &str = "oneiron/sealed-vault-section-key/v1";
pub(super) const SECTION_TAG_CONTEXT: &str = "oneiron/sealed-vault-section-tag/v1";
/// The E0 recipients: a capsule names no reader, and a part or a section no world.
pub(super) const SLOT_RECIPIENT: &[u8] = b"oneiron/sealed-vault-slot";
pub(super) const BODY_RECIPIENT: &[u8] = b"oneiron/sealed-vault-body";
pub(super) const SECTION_RECIPIENT: &[u8] = b"oneiron/sealed-vault-section";
pub(super) const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
pub(super) const KEM: SuiteId = SuiteId::KEM_X25519_MLKEM1024_V1;
pub(super) const SYMMETRIC: &[WrapType] = &[WrapType::SymmetricKek];
pub(super) const HYBRID: &[WrapType] = &[WrapType::HybridCapsule];
/// The most body one envelope carries, under E0's 16 MiB plaintext bound.
pub(super) const CHUNK: usize = 8 * 1024 * 1024;
/// The smallest padded section body.
pub(super) const SECTION_PAD_FLOOR: usize = 4096;
pub(super) const KEY_ID_LEN: usize = 40;
pub(super) const SLOT_PLAINTEXT_LEN: usize = SLOT_LABEL.len() + GENERATION_LEN + 32;
/// label ‖ digest (32) ‖ index (4) ‖ count (4).
pub(super) const PART_HEADER_LEN: usize = PART_LABEL.len() + 32 + 4 + 4;

/// A key erase opens a kept pad object with.
#[cfg(feature = "sync")]
pub(super) enum EraseKey {
    /// This machine's capsule.
    Machine,
    /// A grant of the object's outer key to this machine, sealed by an old
    /// reader or the kit since (FIX 4271).
    AdmissionGrant,
    /// The recovery kit the owner hands that one erase; nothing keeps it.
    Kit,
}

/// The keys erase opens each kept pad object with, in order (CALLS:
/// SEALED_BUNDLE_ERASE_KEY_SOURCE): this machine's capsule, then a grant
/// sealed to it since, then a kit the owner hands it. So a machine added after
/// older generations were sealed sweeps them unattended once an old reader
/// granted it access, and with the kit before that (FIX 3355, FIX 4271).
#[cfg(feature = "sync")]
pub(super) const SEALED_BUNDLE_ERASE_KEY_SOURCE: &[EraseKey] =
    &[EraseKey::Machine, EraseKey::AdmissionGrant, EraseKey::Kit];

/// What a new pad object holds of a world deleted here (CALLS:
/// SEALED_BUNDLE_NEW_PAD_DELETED_WORLD).
pub(super) enum DeletedWorldPads {
    /// None of its pads: its section no longer rides either (FIX 4275). Its pad
    /// rows here and every kept object stay as they are; erase strips those.
    Omit,
}

pub(super) const SEALED_BUNDLE_NEW_PAD_DELETED_WORLD: DeletedWorldPads = DeletedWorldPads::Omit;

/// A bundle or a pad object: its frame magic, its envelope purpose, its size step.
#[derive(Clone, Copy)]
pub(super) struct Kind {
    pub(super) magic: &'static [u8; 4],
    pub(super) purpose: Purpose,
    pub(super) step: usize,
}

pub(super) const BUNDLE: Kind = Kind {
    magic: b"OSVB",
    purpose: Purpose::SealedVaultBundle,
    step: SEALED_BUNDLE_PAD_STEP_BYTES,
};
pub(super) const PADS: Kind = Kind {
    magic: b"OSKP",
    purpose: Purpose::SealedKeyPads,
    step: SEALED_KEY_PADS_STEP_BYTES,
};

/// One sealed object's bytes and the generation its frame names.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct SealedObject {
    pub(super) generation: SealedBundleGeneration,
    pub(super) bytes: Vec<u8>,
}

impl std::fmt::Debug for SealedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedObject")
            .field("generation", &self.generation)
            .field("len", &self.bytes.len())
            .finish()
    }
}
/// The outer key in one anonymous capsule per reader, then blanks to a whole
/// multiple of [`SLOT_STEP`]. A blank seals a random key to a throwaway keypair,
/// so no holder tells it from a reader's.
pub(super) fn seal_slots(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    readers: &[HybridPublicKey],
) -> Result<Vec<Envelope>> {
    let id = generation.to_bytes();
    let params = seal_params(kind.purpose, vault_id, &id, SLOT_RECIPIENT);
    let count = readers.len().div_ceil(SLOT_STEP).max(1) * SLOT_STEP;
    let mut blanks = Vec::with_capacity(count - readers.len());
    for _ in readers.len()..count {
        let blank = HybridSecretKey::generate(&mut SysRng)
            .map_err(|_| refused("os entropy unavailable"))?;
        blanks.push(blank.public_key().clone());
    }
    let mut slots = Vec::with_capacity(count);
    for (index, public) in readers.iter().chain(&blanks).enumerate() {
        let mut key = Zeroizing::new(*outer);
        if index >= readers.len() {
            os_fill(&mut key[..])?;
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(SLOT_PLAINTEXT_LEN));
        plaintext.extend_from_slice(SLOT_LABEL);
        plaintext.extend_from_slice(&id);
        plaintext.extend_from_slice(&key[..]);
        let sealed = seal(
            &params,
            SealKey::Hybrid {
                recipient: public,
                kem_suite: KEM,
            },
            &plaintext,
            &mut SysRng,
        )
        .map_err(|_| refused("sealing failed"))?;
        slots.push(sealed);
    }
    Ok(slots)
}

/// The outer key from the first capsule `secret` opens.
pub(super) fn open_slots(
    kind: Kind,
    vault_id: &[u8; 32],
    frame: &Frame,
    secret: &HybridSecretKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let id = frame.generation.to_bytes();
    let policy = OpenPolicy {
        purpose: kind.purpose,
        vault_id,
        recipient: SLOT_RECIPIENT,
        key_id: &id,
        wraps: HYBRID,
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    for slot in &frame.slots {
        let Ok(plaintext) = slot.open(OpenKey::Hybrid(secret), &policy) else {
            continue;
        };
        if plaintext.len() == SLOT_PLAINTEXT_LEN
            && plaintext.starts_with(SLOT_LABEL)
            && plaintext[SLOT_LABEL.len()..SLOT_LABEL.len() + GENERATION_LEN] == id
        {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&plaintext[SLOT_LABEL.len() + GENERATION_LEN..]);
            return Ok(key);
        }
    }
    // Typed, so a relay whose take this machine cannot open defers its slot.
    Err(Error::Secret(SecretError::SealedBundleNoCapsule))
}

/// Frames `body` under the outer key behind `slots`, padded inside the
/// ciphertext so the object is `total` bytes, or the smallest positive multiple
/// of the kind's step it fits in.
pub(super) fn seal_outer(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    slots: &[Envelope],
    mut body: Zeroizing<Vec<u8>>,
    total: Option<usize>,
) -> Result<Vec<u8>> {
    let too_large = || refused("the sealed object outgrows its size");
    let id = generation.to_bytes();
    let kek = Kek::from_bytes_ref(outer);
    let params = seal_params(kind.purpose, vault_id, &id, BODY_RECIPIENT);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(kind.magic);
    bytes.push(FRAME_VERSION);
    bytes.extend_from_slice(&id);
    let slot_count = u16::try_from(slots.len()).map_err(|_| too_large())?;
    bytes.extend_from_slice(&slot_count.to_be_bytes());
    for slot in slots {
        let byte_len = slot.len();
        let len = u32::try_from(byte_len).map_err(|_| refused("a sealed part is too large"))?;
        bytes.reserve(4 + byte_len);
        bytes.extend_from_slice(&len.to_be_bytes());
        slot.write_to(&mut bytes)?;
    }
    // A part's frame bytes beyond its chunk: the length prefix and the envelope
    // around the part header.
    let probe = seal(
        &params,
        SealKey::SymmetricKek(&kek),
        &[0u8; PART_HEADER_LEN],
        &mut SysRng,
    )
    .map_err(|_| refused("sealing failed"))?;
    let per_part = 4 + probe.len();
    let fixed = bytes.len() + 4;
    let total = match total {
        Some(total) => total,
        None => fitting_total(kind.step, fixed, per_part, body.len()).ok_or_else(too_large)?,
    };
    let (count, room) = fit(total, fixed, per_part)
        .filter(|(_, room)| *room >= body.len())
        .ok_or_else(too_large)?;
    body.resize(room, 0);
    bytes.reserve(total.saturating_sub(bytes.len()));
    let count_bytes = u32::try_from(count).map_err(|_| too_large())?.to_be_bytes();
    bytes.extend_from_slice(&count_bytes);
    seal_parts(&params, &kek, &body, &even_sizes(room, count), |part| {
        let byte_len = part.len();
        let len = u32::try_from(byte_len).map_err(|_| refused("a sealed part is too large"))?;
        bytes.reserve(4 + byte_len);
        bytes.extend_from_slice(&len.to_be_bytes());
        part.write_to(&mut bytes)?;
        Ok(())
    })?;
    if bytes.len() != total {
        return Err(refused("the sealed object missed its size"));
    }
    Ok(bytes)
}

/// The parts an object of `total` bytes holds after `fixed` frame bytes, and the
/// body bytes they carry: `None` when not even one part fits.
pub(super) fn fit(total: usize, fixed: usize, per_part: usize) -> Option<(usize, usize)> {
    let room = total.checked_sub(fixed)?;
    let count = room.div_ceil(per_part + CHUNK).max(1);
    Some((count, room.checked_sub(count.checked_mul(per_part)?)?))
}

/// The smallest positive multiple of `step` whose parts carry `len` body bytes.
pub(super) fn fitting_total(
    step: usize,
    fixed: usize,
    per_part: usize,
    len: usize,
) -> Option<usize> {
    let mut steps = len.checked_add(fixed)?.div_ceil(step).max(1);
    loop {
        let total = steps.checked_mul(step)?;
        if fit(total, fixed, per_part).is_some_and(|(_, room)| room >= len) {
            return Some(total);
        }
        steps = steps.checked_add(1)?;
    }
}

/// `len` bytes in `count` parts, as even as can be.
pub(super) fn even_sizes(len: usize, count: usize) -> Vec<usize> {
    let (each, extra) = (len / count, len % count);
    (0..count)
        .map(|index| each + usize::from(index < extra))
        .collect()
}

/// Seals `body` in parts of `sizes` bytes. Each part names the body's digest, its
/// index and the count, so parts of two bodies never mix.
pub(super) fn seal_parts(
    params: &SealParams<'_>,
    kek: &Kek,
    body: &[u8],
    sizes: &[usize],
    mut push: impl FnMut(Envelope) -> Result<()>,
) -> Result<()> {
    let digest = *blake3::hash(body).as_bytes();
    let count = u32::try_from(sizes.len()).map_err(|_| refused("too many sealed parts"))?;
    let mut at = 0usize;
    for (index, size) in sizes.iter().enumerate() {
        let chunk = body
            .get(at..at + size)
            .ok_or_else(|| refused("the sealed parts outrun their body"))?;
        at += size;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(PART_HEADER_LEN + size));
        plaintext.extend_from_slice(PART_LABEL);
        plaintext.extend_from_slice(&digest);
        plaintext.extend_from_slice(&(index as u32).to_be_bytes());
        plaintext.extend_from_slice(&count.to_be_bytes());
        plaintext.extend_from_slice(chunk);
        push(
            seal(params, SealKey::SymmetricKek(kek), &plaintext, &mut SysRng)
                .map_err(|_| refused("sealing failed"))?,
        )?;
    }
    if at != body.len() {
        return Err(refused("the sealed parts fall short of their body"));
    }
    Ok(())
}

/// Opens `parts` back into one body, refusing parts out of order, of another
/// body, or missing.
pub(super) fn open_parts(
    policy: &OpenPolicy<'_>,
    kek: &Kek,
    parts: &[Envelope],
) -> Result<Zeroizing<Vec<u8>>> {
    let disagree = || refused("the sealed parts disagree");
    let mut body = Zeroizing::new(Vec::new());
    let mut expected: Option<[u8; 32]> = None;
    for (index, part) in parts.iter().enumerate() {
        let plaintext = part
            .open(OpenKey::SymmetricKek(kek), policy)
            .map_err(|_| refused("a sealed part does not open under its key"))?;
        if plaintext.len() < PART_HEADER_LEN || !plaintext.starts_with(PART_LABEL) {
            return Err(disagree());
        }
        let header = &plaintext[PART_LABEL.len()..PART_HEADER_LEN];
        let digest: [u8; 32] = header[..32].try_into().map_err(|_| disagree())?;
        let at = u32::from_be_bytes([header[32], header[33], header[34], header[35]]);
        let of = u32::from_be_bytes([header[36], header[37], header[38], header[39]]);
        if at as usize != index
            || of as usize != parts.len()
            || expected.is_some_and(|first| first != digest)
        {
            return Err(disagree());
        }
        expected = Some(digest);
        body.extend_from_slice(&plaintext[PART_HEADER_LEN..]);
    }
    if expected != Some(*blake3::hash(&body).as_bytes()) {
        return Err(disagree());
    }
    Ok(body)
}

pub(super) fn seal_params<'a>(
    purpose: Purpose,
    vault_id: &'a [u8; 32],
    key_id: &'a [u8],
    recipient: &'a [u8],
) -> SealParams<'a> {
    SealParams {
        suite: AEAD,
        purpose,
        epoch: WORLD_KEY_EPOCH,
        key_id,
        recipient,
        vault_id,
    }
}

pub(super) fn symmetric_policy<'a>(
    purpose: Purpose,
    vault_id: &'a [u8; 32],
    key_id: &'a [u8],
    recipient: &'a [u8],
) -> OpenPolicy<'a> {
    OpenPolicy {
        purpose,
        vault_id,
        recipient,
        key_id,
        wraps: SYMMETRIC,
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    }
}

/// A parsed frame: the capsules, then the body's parts.
pub(super) struct Frame {
    pub(super) generation: SealedBundleGeneration,
    pub(super) slots: Vec<Envelope>,
    pub(super) parts: Vec<Envelope>,
}

/// An outer layer opened: what a pad rewrite keeps, and the padded body.
pub(super) struct OpenedOuter {
    pub(super) generation: SealedBundleGeneration,
    pub(super) slots: Vec<Envelope>,
    pub(super) outer: Zeroizing<[u8; 32]>,
    pub(super) body: Zeroizing<Vec<u8>>,
}

pub(super) fn open_outer(
    kind: Kind,
    vault_id: &[u8; 32],
    bytes: &[u8],
    secret: &HybridSecretKey,
) -> Result<OpenedOuter> {
    let frame = parse_frame(kind, bytes)?;
    let outer = open_slots(kind, vault_id, &frame, secret)?;
    open_framed(kind, vault_id, frame, outer)
}

/// [`open_outer`] with `outer`, a key the caller holds already, as from an
/// admission grant (FIX 4271): the body's AEAD is the proof that it is the
/// object's own outer key. The frame's capsules are kept, unopened.
#[cfg(feature = "sync")]
pub(super) fn open_outer_with_key(
    kind: Kind,
    vault_id: &[u8; 32],
    bytes: &[u8],
    outer: Zeroizing<[u8; 32]>,
) -> Result<OpenedOuter> {
    open_framed(kind, vault_id, parse_frame(kind, bytes)?, outer)
}

/// The body of `frame` under `outer`.
pub(super) fn open_framed(
    kind: Kind,
    vault_id: &[u8; 32],
    frame: Frame,
    outer: Zeroizing<[u8; 32]>,
) -> Result<OpenedOuter> {
    let id = frame.generation.to_bytes();
    let policy = symmetric_policy(kind.purpose, vault_id, &id, BODY_RECIPIENT);
    let body = open_parts(&policy, &Kek::from_bytes_ref(&outer), &frame.parts)?;
    Ok(OpenedOuter {
        generation: frame.generation,
        slots: frame.slots,
        outer,
        body,
    })
}

/// magic (4) ‖ version (1) ‖ generation (24) ‖ capsule count (2) ‖ capsules ‖ part
/// count (4) ‖ parts, each envelope `u32`-length-prefixed, and nothing after.
pub(super) fn parse_frame(kind: Kind, bytes: &[u8]) -> Result<Frame> {
    let malformed = || refused("malformed sealed vault object");
    if bytes.is_empty() || bytes.len() % kind.step != 0 {
        return Err(malformed());
    }
    let mut cursor = Cursor { bytes, at: 0 };
    if cursor.take(4) != Some(&kind.magic[..]) || cursor.take(1) != Some(&[FRAME_VERSION][..]) {
        return Err(malformed());
    }
    let generation =
        SealedBundleGeneration::from_bytes(cursor.take(GENERATION_LEN).ok_or_else(malformed)?)?;
    let id = generation.to_bytes();
    let mut vault = None;
    let slot_count = u16::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut slots = Vec::new();
    for _ in 0..slot_count {
        slots.push(parse_envelope(
            &mut cursor,
            kind.purpose,
            WrapType::HybridCapsule,
            &id,
            SLOT_RECIPIENT,
            &mut vault,
        )?);
    }
    let part_count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut parts = Vec::new();
    for _ in 0..part_count {
        parts.push(parse_envelope(
            &mut cursor,
            kind.purpose,
            WrapType::SymmetricKek,
            &id,
            BODY_RECIPIENT,
            &mut vault,
        )?);
    }
    if slots.is_empty() || parts.is_empty() || cursor.at != bytes.len() {
        return Err(malformed());
    }
    Ok(Frame {
        generation,
        slots,
        parts,
    })
}

/// One `u32`-length-prefixed canonical envelope of `purpose` and `wrap`, bound to
/// `key_id` and `recipient`, naming the same vault as the ones before it.
pub(super) fn parse_envelope(
    cursor: &mut Cursor<'_>,
    purpose: Purpose,
    wrap: WrapType,
    key_id: &[u8],
    recipient: &[u8],
    vault: &mut Option<Vec<u8>>,
) -> Result<Envelope> {
    let malformed = || refused("malformed sealed vault object");
    let envelope =
        Envelope::parse(cursor.counted().ok_or_else(malformed)?).map_err(|_| malformed())?;
    let header = envelope.header();
    let same_vault = *vault.get_or_insert_with(|| header.vault_id.clone()) == header.vault_id;
    if header.purpose != purpose
        || header.wrap != wrap
        || header.suite != AEAD
        || header.key_id != key_id
        || header.recipient != recipient
        || !same_vault
    {
        return Err(malformed());
    }
    Ok(envelope)
}
pub(super) fn put_counted(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| refused("a sealed part is too large"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A forward reader over a frame or a body.
pub(super) struct Cursor<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) at: usize,
}

impl<'a> Cursor<'a> {
    pub(super) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A `u32`-length-prefixed field.
    pub(super) fn counted(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(len as usize)
    }

    /// A key id as [`WorldKeyId::envelope_key_id`] spells it.
    pub(super) fn key_id(&mut self) -> Option<WorldKeyId> {
        Some(WorldKeyId {
            world: EntityId::from_bytes(self.array()?).ok()?,
            generation: u64::from_be_bytes(self.array()?),
            mint: self.array()?,
        })
    }

    pub(super) fn rest_is_zero(&self) -> bool {
        self.bytes[self.at..].iter().all(|byte| *byte == 0)
    }
}
