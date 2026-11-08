//! Decoding and validation of the stored widen proposal rows (moved from `widen/mod.rs`, FIX 19106).

use super::*;

pub(super) fn decode_delta(bytes: &[u8]) -> Result<WidenDelta> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_row());
    }
    let Value::Array(parts) = value else {
        return Err(invalid_row());
    };
    let [version, kind, bound] = parts.as_slice() else {
        return Err(invalid_row());
    };
    if version.as_u64() != Some(1) {
        return Err(invalid_row());
    }
    if kind.as_str() == Some(CONTACT_DISCLOSURE_WIDEN_KIND) {
        let proposal = ContactDisclosureProposal::from_value(bound)?;
        if contact_disclosure_widen_delta(&proposal)? != bytes {
            return Err(invalid_row());
        }
        return Ok(WidenDelta::ContactDisclosure(proposal));
    }
    let kind = kind
        .as_str()
        .and_then(WidenKind::parse)
        .ok_or_else(invalid_row)?;
    let bound = decode_bound_value(bound)?;
    if canonical_widen_delta(kind, &bound)? != bytes {
        return Err(invalid_row());
    }
    Ok(WidenDelta::Bound(bound))
}
pub(super) fn proposal_ref(
    delta: &[u8],
    proposer: &str,
    owner: &str,
    created: u64,
    expires: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WIDEN_PROPOSALS.decl().prefix);
    for field in [
        delta,
        proposer.as_bytes(),
        owner.as_bytes(),
        &created.to_be_bytes(),
        &expires.to_be_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_hex().to_string()
}
/// The hex64 reference shape every widen row has always been keyed by. Kept
/// as a gate ahead of storage rather than folded into the key type, so a
/// caller-supplied `reference` that fails the shape check is refused the
/// SAME [`GateError::InvalidConsentBound`]-flavored `invalid_row()` it always
/// was, before the key ever reaches the table.
pub(super) fn validate_reference_shape(reference: &str) -> Result<()> {
    if reference.len() != 64
        || !reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_row());
    }
    Ok(())
}
/// The effect a rejection of `proposal` denies: its reference and its
/// frozen delta, so the denial receipt names exactly what was declined.
pub(super) fn widen_rejection_digest(proposal: &WidenProposal) -> EffectDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WIDEN_REJECT_DIGEST_DOMAIN);
    for field in [
        proposal.proposal_ref.as_bytes(),
        proposal.canonical_delta.as_slice(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    EffectDigest::from_bytes(*hasher.finalize().as_bytes())
}
pub(super) fn validate_row(row: StoredProposal, reference: &str) -> Result<StoredProposal> {
    validate_row_fields(&row, reference)?;
    Ok(row)
}
pub(super) fn validate_row_fields(row: &StoredProposal, reference: &str) -> Result<()> {
    let p = &row.proposal;
    decode_delta(&p.canonical_delta)?;
    if row.version != 1
        || p.proposal_ref != reference
        || p.expires_at <= p.created_at
        || p.expires_at - p.created_at > 3600
        || crate::EntityId::from_hex(&p.proposer).is_err()
        || normalized_ref("widen owner", p.owner_ref.clone())? != p.owner_ref
        || proposal_ref(
            &p.canonical_delta,
            &p.proposer,
            &p.owner_ref,
            p.created_at,
            p.expires_at,
        ) != reference
    {
        return Err(invalid_row());
    }
    Ok(())
}
