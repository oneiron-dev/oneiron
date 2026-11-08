//! Sealed-bundle body decoders, pad encoding and section keys.
//!
//! The bundle root keeps the existing child paths. Bundle and section bodies
//! are encoded by the streaming writer in `frame_seal`.
use super::{
    BTreeSet, BUNDLE_LABEL, Cursor, EntityId, GENERATION_LEN, KEY_ID_LEN, Kek, OpenedBundleSection,
    OpenedVaultBundle, PADS_LABEL, REQUEST_TAG, Result, SECTION_KEY_CONTEXT, SECTION_LABEL,
    SealedBundleGeneration, SealedBundleSection, SealedWorldAuthority, WorldKey, WorldKeyId,
    Zeroizing, refused, section_padded_len, signed_digest,
};
pub(super) fn decode_bundle_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    body: &[u8],
) -> Result<OpenedVaultBundle> {
    let malformed = || refused("the bundle's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(BUNDLE_LABEL.len()) != Some(BUNDLE_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(GENERATION_LEN) != Some(&generation.to_bytes()[..])
    {
        return Err(refused("the bundle names another vault or generation"));
    }
    let publisher =
        EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
    let signature: [u8; 64] = cursor.array().ok_or_else(malformed)?;
    let content_at = cursor.at;
    let base_len = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let base = usize::try_from(base_len)
        .ok()
        .and_then(|len| cursor.take(len))
        .ok_or_else(malformed)?;
    let base = Zeroizing::new(base.to_vec());
    let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut sections = Vec::new();
    let mut tags = BTreeSet::new();
    for _ in 0..count {
        let section = SealedBundleSection::parse(&mut cursor, vault_id)?;
        if !tags.insert(section.tag) {
            return Err(malformed());
        }
        sections.push(section);
    }
    let authorities = SealedWorldAuthority::parse_all(&mut cursor)?;
    // The request, when the content names one; a padding zero, or the body's
    // end, is none, and is not signed content.
    let mut content_end = cursor.at;
    let request = match cursor.take(1) {
        None | Some([0]) => None,
        Some([REQUEST_TAG]) => {
            let request = cursor.array().ok_or_else(malformed)?;
            content_end = cursor.at;
            Some(request)
        }
        Some(_) => return Err(malformed()),
    };
    let signed = signed_digest(
        vault_id,
        generation,
        publisher,
        &body[content_at..content_end],
    );
    if !cursor.rest_is_zero() {
        return Err(malformed());
    }
    Ok(OpenedVaultBundle {
        vault_id: *vault_id,
        generation,
        publisher,
        signature,
        request,
        signed,
        base,
        sections,
        authorities,
    })
}

/// `BLAKE3-derive_key(context, vault ‖ key id ‖ world key)`: a section's key or
/// its tag. Only a holder of the world key computes either.
pub(super) fn section_digest(context: &str, vault_id: &[u8; 32], key: &WorldKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    section_digest_into(context, vault_id, key, &mut out);
    out
}

/// The section's key, derived as [`section_digest`] under
/// [`SECTION_KEY_CONTEXT`] straight into guarded storage (FIX 6048).
pub(super) fn section_kek(vault_id: &[u8; 32], key: &WorldKey) -> Kek {
    let mut out = Zeroizing::new([0u8; 32]);
    section_digest_into(SECTION_KEY_CONTEXT, vault_id, key, &mut out);
    Kek::from_zeroizing(out)
}

/// `BLAKE3-derive_key(context, vault id ‖ key id ‖ key)`, written into `out`.
pub(super) fn section_digest_into(
    context: &str,
    vault_id: &[u8; 32],
    key: &WorldKey,
    out: &mut [u8; 32],
) {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(vault_id);
    hasher.update(&key.id().envelope_key_id());
    hasher.update(key.expose());
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    // The hasher's block buffer and the reader's state still hold the key's bytes.
    zeroize::Zeroize::zeroize(&mut hasher);
    zeroize::Zeroize::zeroize(&mut reader);
}

pub(super) fn decode_section_body(
    vault_id: &[u8; 32],
    key: &WorldKeyId,
    body: &[u8],
) -> Result<OpenedBundleSection> {
    let malformed = || refused("the bundle section's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(SECTION_LABEL.len()) != Some(SECTION_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(KEY_ID_LEN) != Some(&key.envelope_key_id()[..])
    {
        return Err(refused("the section names another vault or key"));
    }
    let len = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let payload = usize::try_from(len)
        .ok()
        .and_then(|len| cursor.take(len))
        .ok_or_else(malformed)?;
    let payload = Zeroizing::new(payload.to_vec());
    if !cursor.rest_is_zero() || body.len() != section_padded_len(cursor.at) {
        return Err(malformed());
    }
    Ok(OpenedBundleSection { key: *key, payload })
}

/// label ‖ vault (32) ‖ generation (24) ‖ count (4) ‖ each key id (40) ‖ pad (32)
/// ‖ learned at (8, big-endian) ‖ index count (4) ‖ each key id (40) ‖ the tag of
/// the section sealed under it (32), leaving out `without`'s keys.
pub(super) fn encode_pads_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    entries: &[(WorldKeyId, Zeroizing<[u8; 32]>, u64)],
    index: &[(WorldKeyId, [u8; 32])],
    without: Option<EntityId>,
) -> Result<Zeroizing<Vec<u8>>> {
    let kept: Vec<_> = entries
        .iter()
        .filter(|(key, _, _)| Some(key.world) != without)
        .collect();
    let indexed: Vec<_> = index
        .iter()
        .filter(|(key, _)| Some(key.world) != without)
        .collect();
    let count = u32::try_from(kept.len()).map_err(|_| refused("too many pads"))?;
    let indexed_count =
        u32::try_from(indexed.len()).map_err(|_| refused("too many indexed sections"))?;
    let mut body = Zeroizing::new(Vec::with_capacity(
        PADS_LABEL.len()
            + 32
            + GENERATION_LEN
            + 8
            + kept.len() * (KEY_ID_LEN + 32 + 8)
            + indexed.len() * (KEY_ID_LEN + 32),
    ));
    body.extend_from_slice(PADS_LABEL);
    body.extend_from_slice(vault_id);
    body.extend_from_slice(&generation.to_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    for (key, pad, learned_at) in kept {
        body.extend_from_slice(&key.envelope_key_id());
        body.extend_from_slice(&pad[..]);
        body.extend_from_slice(&learned_at.to_be_bytes());
    }
    body.extend_from_slice(&indexed_count.to_be_bytes());
    for (key, tag) in indexed {
        body.extend_from_slice(&key.envelope_key_id());
        body.extend_from_slice(tag);
    }
    Ok(body)
}

/// A pad object's body, opened.
pub(super) struct PadsBody {
    pub(super) pads: Vec<(WorldKeyId, Zeroizing<[u8; 32]>, u64)>,
    pub(super) index: Vec<(WorldKeyId, [u8; 32])>,
}

pub(super) fn decode_pads_body(
    vault_id: &[u8; 32],
    generation: SealedBundleGeneration,
    body: &[u8],
) -> Result<PadsBody> {
    let malformed = || refused("the pad object's body is malformed");
    let mut cursor = Cursor { bytes: body, at: 0 };
    if cursor.take(PADS_LABEL.len()) != Some(PADS_LABEL)
        || cursor.take(32) != Some(&vault_id[..])
        || cursor.take(GENERATION_LEN) != Some(&generation.to_bytes()[..])
    {
        return Err(refused("the pad object names another vault or generation"));
    }
    let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut pads = Vec::new();
    for _ in 0..count {
        let key = cursor.key_id().ok_or_else(malformed)?;
        let pad = Zeroizing::new(cursor.array().ok_or_else(malformed)?);
        let learned_at = u64::from_be_bytes(cursor.array().ok_or_else(malformed)?);
        pads.push((key, pad, learned_at));
    }
    let indexed = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
    let mut index = Vec::new();
    for _ in 0..indexed {
        let key = cursor.key_id().ok_or_else(malformed)?;
        index.push((key, cursor.array().ok_or_else(malformed)?));
    }
    if !cursor.rest_is_zero() {
        return Err(malformed());
    }
    Ok(PadsBody { pads, index })
}
