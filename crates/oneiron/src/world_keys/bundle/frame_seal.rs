//! The seal of a body into parts and of the parts into an outer frame, and
//! the bundle and section body encodings sealed so.
//! `super` owns the frame parse, the open, and the body decodings.
//!
//! A body streams (FIX 11947): its [`BodySource`] writes it piece by piece,
//! the same bytes on every call. One write digests it and a last one fills
//! each part's plaintext in turn, so no body, padding or payload is ever
//! joined beside its pieces. A bundle body is also written once first, to
//! sign it, and its last write frees the base and each fresh section's parts
//! as they go into the frame. The sealed bytes are those a whole body seals to.

use super::*;

/// The zeros a streamed body's padding is written from.
static ZEROS: [u8; 64 * 1024] = [0; 64 * 1024];

/// A body sealed in parts as it streams (FIX 11947).
pub(super) trait BodySource {
    /// The body's length in bytes.
    fn byte_len(&self) -> usize;

    /// Writes the whole body to `put`; every call writes the same bytes.
    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;

    /// Writes the body a last time, freeing each piece it owns once written.
    fn write_last(self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>
    where
        Self: Sized,
    {
        self.write(put)
    }
}

impl BodySource for &[u8] {
    fn byte_len(&self) -> usize {
        self.len()
    }

    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        put(self)
    }
}

/// A whole body, wiped once its last write is done.
impl BodySource for Zeroizing<Vec<u8>> {
    fn byte_len(&self) -> usize {
        self.len()
    }

    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        put(self)
    }
}

/// `head`, then `body`.
pub(super) struct Headed<B> {
    head: Zeroizing<Vec<u8>>,
    body: B,
}

impl<B: BodySource> BodySource for Headed<B> {
    fn byte_len(&self) -> usize {
        self.head.len() + self.body.byte_len()
    }

    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        put(&self.head)?;
        self.body.write(put)
    }

    fn write_last(self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        put(&self.head)?;
        self.body.write_last(put)
    }
}

/// `body`, then `zeros` zero bytes.
struct Padded<B> {
    body: B,
    zeros: usize,
}

impl<B: BodySource> BodySource for Padded<B> {
    fn byte_len(&self) -> usize {
        self.body.byte_len() + self.zeros
    }

    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.body.write(put)?;
        put_zeros(put, self.zeros)
    }

    fn write_last(self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.body.write_last(put)?;
        put_zeros(put, self.zeros)
    }
}

fn put_zeros(put: &mut dyn FnMut(&[u8]) -> Result<()>, mut len: usize) -> Result<()> {
    while len > 0 {
        let run = len.min(ZEROS.len());
        put(&ZEROS[..run])?;
        len -= run;
    }
    Ok(())
}

/// A section payload its caller writes, the same bytes on every call.
#[cfg(feature = "sync")]
pub(super) struct WrittenPayload<W> {
    write: W,
    len: usize,
}

#[cfg(feature = "sync")]
impl<W: Fn(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>> WrittenPayload<W> {
    /// `write`'s payload, its length counted by writing it once.
    pub(super) fn new(write: W) -> Result<Self> {
        let mut len = 0usize;
        write(&mut |bytes: &[u8]| {
            len += bytes.len();
            Ok(())
        })?;
        Ok(Self { write, len })
    }
}

#[cfg(feature = "sync")]
impl<W: Fn(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>> BodySource for WrittenPayload<W> {
    fn byte_len(&self) -> usize {
        self.len
    }

    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        (self.write)(put)
    }
}

/// [`put_counted`], into a stream.
pub(super) fn write_counted(put: &mut dyn FnMut(&[u8]) -> Result<()>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| refused("a sealed part is too large"))?;
    put(&len.to_be_bytes())?;
    put(bytes)
}

/// Frames `body` under the outer key behind `slots`, padded inside the
/// ciphertext so the object is `total` bytes, or the smallest positive multiple
/// of the kind's step it fits in. The body and its padding stream into the
/// frame's parts, never joined (FIX 11947).
pub(super) fn seal_outer(
    kind: Kind,
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    outer: &[u8; 32],
    slots: &[Envelope],
    body: impl BodySource,
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
        put_counted(&mut bytes, &slot.to_bytes())?;
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
    let per_part = 4 + probe.to_bytes().len();
    let fixed = bytes.len() + 4;
    let len = body.byte_len();
    let total = match total {
        Some(total) => total,
        None => fitting_total(kind.step, fixed, per_part, len).ok_or_else(too_large)?,
    };
    let (count, room) = fit(total, fixed, per_part)
        .filter(|(_, room)| *room >= len)
        .ok_or_else(too_large)?;
    bytes.reserve(total.saturating_sub(bytes.len()));
    let count_bytes = u32::try_from(count).map_err(|_| too_large())?.to_be_bytes();
    bytes.extend_from_slice(&count_bytes);
    let padded = Padded {
        body,
        zeros: room - len,
    };
    seal_parts(&params, &kek, padded, &even_sizes(room, count), |part| {
        put_counted(&mut bytes, &part.to_bytes())
    })?;
    if bytes.len() != total {
        return Err(refused("the sealed object missed its size"));
    }
    Ok(bytes)
}

/// The parts an object of `total` bytes holds after `fixed` frame bytes, and the
/// body bytes they carry: `None` when not even one part fits.
fn fit(total: usize, fixed: usize, per_part: usize) -> Option<(usize, usize)> {
    let room = total.checked_sub(fixed)?;
    let count = room.div_ceil(per_part + CHUNK).max(1);
    Some((count, room.checked_sub(count.checked_mul(per_part)?)?))
}

/// The smallest positive multiple of `step` whose parts carry `len` body bytes.
fn fitting_total(step: usize, fixed: usize, per_part: usize, len: usize) -> Option<usize> {
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
fn even_sizes(len: usize, count: usize) -> Vec<usize> {
    let (each, extra) = (len / count, len % count);
    (0..count)
        .map(|index| each + usize::from(index < extra))
        .collect()
}

/// Seals `body` in parts of `sizes` bytes as it streams: one write digests
/// it, a last one fills each part's plaintext in turn. Each part names the
/// body's digest, its index and the count, so parts of two bodies never mix.
fn seal_parts(
    params: &SealParams<'_>,
    kek: &Kek,
    body: impl BodySource,
    sizes: &[usize],
    push: impl FnMut(Envelope) -> Result<()>,
) -> Result<()> {
    let count = u32::try_from(sizes.len()).map_err(|_| refused("too many sealed parts"))?;
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    body.write(&mut |bytes: &[u8]| {
        hasher.update(bytes);
        Ok(())
    })?;
    let digest = *hasher.finalize().as_bytes();
    let largest = sizes.iter().copied().max().unwrap_or_default();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(PART_HEADER_LEN + largest));
    plaintext.extend_from_slice(PART_LABEL);
    plaintext.extend_from_slice(&digest);
    let mut sealer = PartSealer {
        params,
        kek,
        sizes,
        count,
        sealed: 0,
        plaintext,
        push,
    };
    sealer.start_part();
    body.write_last(&mut |bytes: &[u8]| sealer.put(bytes))?;
    sealer.finish()
}

/// A streamed body's parts, sealed as their bytes arrive. Each part's
/// plaintext, label ‖ the body's digest (32) ‖ its index (4) ‖ the count (4)
/// ‖ its bytes, fills one buffer, sized once for the largest and wiped on
/// drop, an error's partial part included.
struct PartSealer<'s, F> {
    params: &'s SealParams<'s>,
    kek: &'s Kek,
    sizes: &'s [usize],
    count: u32,
    /// The parts sealed so far.
    sealed: usize,
    plaintext: Zeroizing<Vec<u8>>,
    push: F,
}

impl<F: FnMut(Envelope) -> Result<()>> PartSealer<'_, F> {
    /// Takes the body's next `bytes`.
    fn put(&mut self, mut bytes: &[u8]) -> Result<()> {
        loop {
            self.seal_filled()?;
            if bytes.is_empty() {
                return Ok(());
            }
            let size = *self
                .sizes
                .get(self.sealed)
                .ok_or_else(|| refused("the sealed parts fall short of their body"))?;
            let take = (PART_HEADER_LEN + size - self.plaintext.len()).min(bytes.len());
            let (chunk, rest) = bytes.split_at(take);
            self.plaintext.extend_from_slice(chunk);
            bytes = rest;
        }
    }

    /// Seals the part the buffer holds once it is full, and each empty part
    /// after it.
    fn seal_filled(&mut self) -> Result<()> {
        while let Some(&size) = self.sizes.get(self.sealed) {
            if self.plaintext.len() != PART_HEADER_LEN + size {
                break;
            }
            let part = seal(
                self.params,
                SealKey::SymmetricKek(self.kek),
                &self.plaintext,
                &mut SysRng,
            )
            .map_err(|_| refused("sealing failed"))?;
            (self.push)(part)?;
            self.sealed += 1;
            self.start_part();
        }
        Ok(())
    }

    /// Clears the buffer back to the header of the next part.
    fn start_part(&mut self) {
        self.plaintext.truncate(PART_LABEL.len() + 32);
        self.plaintext
            .extend_from_slice(&(self.sealed as u32).to_be_bytes());
        self.plaintext.extend_from_slice(&self.count.to_be_bytes());
    }

    /// Seals the last parts, refusing a body that ended before them.
    fn finish(mut self) -> Result<()> {
        self.seal_filled()?;
        if self.sealed != self.sizes.len() {
            return Err(refused("the sealed parts outrun their body"));
        }
        Ok(())
    }
}

/// A bundle body's signed content: base length (8) ‖ base ‖ section count (4)
/// ‖ sections ‖ capsule count (4) ‖ capsules, then, for an upload published on
/// the owner's request, 1 ‖ the request's entry hash (32).
pub(super) struct BundleContent<'b> {
    base: Zeroizing<Vec<u8>>,
    /// The fresh sections, then those carried on from an earlier generation.
    fresh: Vec<SealedBundleSection>,
    carried: Vec<&'b SealedBundleSection>,
    authorities: &'b [SealedWorldAuthority],
    request: Option<AuthorityEntryHash>,
    /// Its length, counted as it was signed.
    len: usize,
}

impl BundleContent<'_> {
    fn section_count(&self) -> Result<[u8; 4]> {
        let count = u32::try_from(self.fresh.len() + self.carried.len())
            .map_err(|_| refused("too many sections"))?;
        Ok(count.to_be_bytes())
    }
}

impl BodySource for BundleContent<'_> {
    fn byte_len(&self) -> usize {
        self.len
    }

    fn write(&self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        put(&(self.base.len() as u64).to_be_bytes())?;
        put(&self.base)?;
        put(&self.section_count()?)?;
        for section in &self.fresh {
            section.write(put)?;
        }
        for section in &self.carried {
            section.write(put)?;
        }
        write_capsules(self.authorities, self.request, put)
    }

    /// [`Self::write`], wiping and freeing the base once it is written, and
    /// each fresh section's parts as each is.
    fn write_last(self, put: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let count = self.section_count()?;
        let Self {
            base,
            fresh,
            carried,
            authorities,
            request,
            ..
        } = self;
        put(&(base.len() as u64).to_be_bytes())?;
        put(&base)?;
        drop(base);
        put(&count)?;
        for section in fresh {
            section.write_last(put)?;
        }
        for section in carried {
            section.write(put)?;
        }
        write_capsules(authorities, request, put)
    }
}

/// capsule count (4) ‖ each capsule, then 1 ‖ `request` when there is one.
fn write_capsules(
    authorities: &[SealedWorldAuthority],
    request: Option<AuthorityEntryHash>,
    put: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let count = u32::try_from(authorities.len()).map_err(|_| refused("too many capsules"))?;
    put(&count.to_be_bytes())?;
    for capsule in authorities {
        capsule.write(put)?;
    }
    if let Some(request) = request {
        put(&[REQUEST_TAG])?;
        put(&request)?;
    }
    Ok(())
}

/// label ‖ vault (32) ‖ generation (24) ‖ publisher (16) ‖ signature (64) ‖
/// content ([`BundleContent`]). The signature covers vault, generation,
/// publisher and the content; the zeros after are padding, so a body with no
/// request ends at its capsules, as every generation sealed before the field
/// existed does. The content is written once here, to sign it (FIX 11947).
pub(super) fn bundle_body<'b>(
    plan: &SealPlan,
    generation: SealedBundleGeneration,
    base: Zeroizing<Vec<u8>>,
    fresh: Vec<SealedBundleSection>,
    carried: Vec<&'b SealedBundleSection>,
    authorities: &'b [SealedWorldAuthority],
) -> Result<Headed<BundleContent<'b>>> {
    let mut content = BundleContent {
        base,
        fresh,
        carried,
        authorities,
        request: plan.request,
        len: 0,
    };
    let mut hasher = signature_hasher(&plan.vault_id, generation, plan.publisher);
    let mut len = 0usize;
    content.write(&mut |bytes: &[u8]| {
        hasher.update(bytes);
        len += bytes.len();
        Ok(())
    })?;
    content.len = len;
    let signature = plan.signing.sign(hasher.finalize().as_bytes()).to_bytes();
    let mut head = Zeroizing::new(Vec::with_capacity(
        BUNDLE_LABEL.len() + 32 + GENERATION_LEN + 16 + 64,
    ));
    head.extend_from_slice(BUNDLE_LABEL);
    head.extend_from_slice(&plan.vault_id);
    head.extend_from_slice(&generation.to_bytes());
    head.extend_from_slice(plan.publisher.as_bytes());
    head.extend_from_slice(&signature);
    Ok(Headed {
        head,
        body: content,
    })
}

/// The hasher a bundle's signed digest starts as: vault, generation and
/// publisher hashed, wiped on drop.
fn signature_hasher(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    publisher: EntityId,
) -> Zeroizing<blake3::Hasher> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(SIGNATURE_CONTEXT));
    hasher.update(vault_id);
    hasher.update(&generation.to_bytes());
    hasher.update(publisher.as_bytes());
    hasher
}

pub(super) fn signed_digest(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    publisher: EntityId,
    content: &[u8],
) -> [u8; 32] {
    let mut hasher = signature_hasher(vault_id, generation, publisher);
    hasher.update(content);
    *hasher.finalize().as_bytes()
}

/// A section body's padded size: a power of two from 4 KiB, then whole chunks.
pub(super) fn section_padded_len(unpadded: usize) -> usize {
    if unpadded <= CHUNK {
        unpadded.next_power_of_two().max(SECTION_PAD_FLOOR)
    } else {
        unpadded.div_ceil(CHUNK) * CHUNK
    }
}

/// Seals a section body in parts of at most [`CHUNK`] bytes as `payload`
/// streams: label ‖ vault (32) ‖ key id (40) ‖ payload length (8) ‖ payload ‖
/// zeros.
pub(super) fn seal_section_body(
    params: &SealParams<'_>,
    kek: &Kek,
    vault_id: &[u8; 32],
    key: &WorldKeyId,
    payload: impl BodySource,
    push: impl FnMut(Envelope) -> Result<()>,
) -> Result<()> {
    let mut head = Zeroizing::new(Vec::with_capacity(
        SECTION_LABEL.len() + 32 + KEY_ID_LEN + 8,
    ));
    head.extend_from_slice(SECTION_LABEL);
    head.extend_from_slice(vault_id);
    head.extend_from_slice(&key.envelope_key_id());
    head.extend_from_slice(&(payload.byte_len() as u64).to_be_bytes());
    let unpadded = head.len() + payload.byte_len();
    let len = section_padded_len(unpadded);
    let body = Padded {
        body: Headed {
            head,
            body: payload,
        },
        zeros: len - unpadded,
    };
    seal_parts(
        params,
        kek,
        body,
        &even_sizes(len, len.div_ceil(CHUNK)),
        push,
    )
}
