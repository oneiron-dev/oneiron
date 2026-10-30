//! The seal of a body into parts and of the parts into an outer frame, and
//! the bundle and section body encodings sealed so.
//! `super` owns the frame parse, the open, and the body decodings.

use super::*;

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

/// label ‖ vault (32) ‖ generation (24) ‖ publisher (16) ‖ signature (64) ‖ base
/// length (8) ‖ base ‖ section count (4) ‖ sections ‖ capsule count (4) ‖
/// capsules, then, for an upload published on the owner's request, 1 ‖ the
/// request's entry hash (32). The signature covers vault, generation, publisher
/// and everything after it; the zeros after are padding, so a body with no
/// request ends at its capsules, as every generation sealed before the field
/// existed does.
pub(super) fn encode_bundle_body(
    plan: &SealPlan,
    generation: SealedBundleGeneration,
    base: &[u8],
    sections: &[SealedBundleSection],
    authorities: &[SealedWorldAuthority],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    body.extend_from_slice(BUNDLE_LABEL);
    body.extend_from_slice(&plan.vault_id);
    body.extend_from_slice(&generation.to_bytes());
    body.extend_from_slice(plan.publisher.as_bytes());
    let signature_at = body.len();
    body.extend_from_slice(&[0u8; 64]);
    let content_at = body.len();
    body.extend_from_slice(&(base.len() as u64).to_be_bytes());
    body.extend_from_slice(base);
    let count = u32::try_from(sections.len()).map_err(|_| refused("too many sections"))?;
    body.extend_from_slice(&count.to_be_bytes());
    for section in sections {
        section.encode(&mut body)?;
    }
    let count = u32::try_from(authorities.len()).map_err(|_| refused("too many capsules"))?;
    body.extend_from_slice(&count.to_be_bytes());
    for capsule in authorities {
        capsule.encode(&mut body)?;
    }
    if let Some(request) = plan.request {
        body.push(REQUEST_TAG);
        body.extend_from_slice(&request);
    }
    let digest = signed_digest(
        &plan.vault_id,
        generation,
        plan.publisher,
        &body[content_at..],
    );
    body[signature_at..content_at].copy_from_slice(&plan.signing.sign(&digest).to_bytes());
    Ok(body)
}

pub(super) fn signed_digest(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    publisher: EntityId,
    content: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SIGNATURE_CONTEXT);
    hasher.update(vault_id);
    hasher.update(&generation.to_bytes());
    hasher.update(publisher.as_bytes());
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

/// label ‖ vault (32) ‖ key id (40) ‖ payload length (8) ‖ payload ‖ zeros.
pub(super) fn encode_section_body(
    vault_id: &[u8; 32],
    key: &WorldKeyId,
    payload: &[u8],
) -> Zeroizing<Vec<u8>> {
    let unpadded = SECTION_LABEL.len() + 32 + KEY_ID_LEN + 8 + payload.len();
    let mut body = Zeroizing::new(Vec::with_capacity(section_padded_len(unpadded)));
    body.extend_from_slice(SECTION_LABEL);
    body.extend_from_slice(vault_id);
    body.extend_from_slice(&key.envelope_key_id());
    body.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    body.extend_from_slice(payload);
    body.resize(section_padded_len(unpadded), 0);
    body
}
