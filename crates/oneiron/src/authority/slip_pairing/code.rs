//! A pairing code and its link: the typed code, its keyed row hash, the
//! binding transcript the joining device signs, and the link's text form.

use super::*;

/// The one reader of a typed code: case-blind, with `O`, `I` and `L` read as
/// `0`, `1` and `1`.
fn normalize_code(code: &str) -> Result<String> {
    let normalized: String = code
        .chars()
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            upper => upper,
        })
        .collect();
    if normalized.len() != CODE_LEN || !normalized.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
        return Err(invalid_authority());
    }
    Ok(normalized)
}
/// Keyed by the issuer secret, so a copied vault file alone cannot search the
/// 40-bit code space.
pub(super) fn pairing_row_key(issuer: &HostSlipIssuer, code: &str) -> Result<String> {
    let key = blake3::derive_key(CODE_HASH_CONTEXT, issuer.secret());
    let hash = blake3::keyed_hash(&key, normalize_code(code)?.as_bytes());
    Ok(hash.to_hex().to_string())
}
/// Client signs this transcript with its newly generated connection key.
/// Code possession without that private key cannot authenticate the result.
pub fn pairing_binding_transcript(
    code: &str,
    binding_key: &[u8; 32],
    holder_ref: &str,
) -> Result<Vec<u8>> {
    pairing_binding_transcript_pinned(code, binding_key, holder_ref, None)
}
/// [`pairing_binding_transcript`] for a link that keeps a checkpoint pin: it
/// also binds the link's challenge and the pin's digest, under its own domain.
/// With no pin it is the unpinned transcript.
pub fn pairing_binding_transcript_pinned(
    code: &str,
    binding_key: &[u8; 32],
    holder_ref: &str,
    pin: Option<&PairingPinRef>,
) -> Result<Vec<u8>> {
    let code = normalize_code(code)?;
    if holder_ref.is_empty() || holder_ref.len() > 256 {
        return Err(invalid_authority());
    }
    let mut msg = match pin {
        None => b"oneiron/pairing-binding/v2\0".to_vec(),
        Some(_) => b"oneiron/pairing-binding/pinned/v1\0".to_vec(),
    };
    msg.extend_from_slice(code.as_bytes());
    msg.extend_from_slice(binding_key);
    if let Some(pin) = pin {
        msg.extend_from_slice(&pin.challenge);
        msg.extend_from_slice(&pin.digest);
    }
    msg.extend_from_slice(holder_ref.as_bytes());
    Ok(msg)
}
/// One string pairs on its own: the server origin, the code and the holder the
/// owner fixed. The code rides in the fragment, which a browser never sends to
/// a server, and the string is its own QR payload.
#[must_use]
pub fn format_pairing_link(origin: &str, code: &str, holder_ref: &str) -> String {
    format_pinned_pairing_link(origin, code, holder_ref, None)
}
/// [`format_pairing_link`] for a link that keeps a checkpoint pin: the
/// fragment adds the challenge and the pin's digest, each as 64 lower-case hex.
#[must_use]
pub fn format_pinned_pairing_link(
    origin: &str,
    code: &str,
    holder_ref: &str,
    pin: Option<&PairingPinRef>,
) -> String {
    let origin = origin.trim_end_matches('/');
    match pin {
        None => format!("{origin}/pair#{code}.{holder_ref}"),
        Some(pin) => format!(
            "{origin}/pair#{code}.{holder_ref}.{}.{}",
            lower_hex(&pin.challenge),
            lower_hex(&pin.digest)
        ),
    }
}
/// The inverse of [`format_pairing_link`]: `(origin, code, holder_ref)`. A
/// link that keeps a checkpoint pin is refused here.
pub fn parse_pairing_link(link: &str) -> Result<(String, String, String)> {
    match parse_pinned_pairing_link(link)? {
        (origin, code, holder_ref, None) => Ok((origin, code, holder_ref)),
        _ => Err(invalid_authority()),
    }
}
/// The inverse of [`format_pinned_pairing_link`]: `(origin, code, holder_ref,
/// pin)`.
pub fn parse_pinned_pairing_link(
    link: &str,
) -> Result<(String, String, String, Option<PairingPinRef>)> {
    let (location, fragment) = link.split_once('#').ok_or_else(invalid_authority)?;
    let origin = location
        .strip_suffix("/pair")
        .filter(|origin| !origin.is_empty())
        .ok_or_else(invalid_authority)?;
    let mut parts = fragment.split('.');
    let (Some(code), Some(holder_ref)) = (parts.next(), parts.next()) else {
        return Err(invalid_authority());
    };
    let pin = match (parts.next(), parts.next(), parts.next()) {
        (None, None, None) => None,
        (Some(challenge), Some(digest), None) => Some(PairingPinRef {
            challenge: hex32(challenge).ok_or_else(invalid_authority)?,
            digest: hex32(digest).ok_or_else(invalid_authority)?,
        }),
        _ => return Err(invalid_authority()),
    };
    let holder = crate::EntityId::from_hex(holder_ref).map_err(|_| invalid_authority())?;
    if holder.to_hex() != holder_ref {
        return Err(invalid_authority());
    }
    Ok((
        origin.to_owned(),
        normalize_code(code)?,
        holder_ref.to_owned(),
        pin,
    ))
}
fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
/// 64 lower-case hex characters as 32 bytes.
fn hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
pub(super) fn draw_code() -> String {
    use rand_core::{OsRng, RngCore};
    let bits = OsRng.next_u64();
    (0..CODE_LEN)
        .map(|at| char::from(CODE_ALPHABET[((bits >> (at * 5)) & 0x1f) as usize]))
        .collect()
}
