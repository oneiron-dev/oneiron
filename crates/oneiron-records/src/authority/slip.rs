//! Moved from `crates/oneiron/src/authority/slip.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use oneiron_authority::authority::MAX_WIRE_BYTES;
use oneiron_authority::authority::SlipClaims;
use oneiron_authority::authority::canonical;
use oneiron_authority::authority::invalid_authority;
use oneiron_authority::federation::Scope;
use oneiron_base::error::Result as EngineResult;
pub use oneiron_verb_wire::authority::slip::SlipCaveat;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

pub const MAX_CAVEATS: usize = 64;

pub const MINT_CONTEXT: &[u8] = b"oneiron/capability-slip/v0/mint\0";

pub const CAVEAT_CONTEXT: &[u8] = b"oneiron/capability-slip/v0/caveat\0";

/// A pact bound the caveats carry, as the meet folds it: one grant, its
/// bounds intersected.
pub type PactBound = Option<(
    oneiron_contracts::entity_id::EntityId,
    oneiron_authority::federation::FederationDirectionScope,
)>;

/// Meets one authenticated caveat into `effective`: the one meet live
/// verification and a transferred removal archive's bounds (FIX-LIST 8224)
/// both take. A caveat naming a floor, or a second pact, refuses.
pub fn meet_caveat(
    effective: &mut SlipClaims,
    pact: &mut PactBound,
    records_constrained: &mut bool,
    caveat: &SlipCaveat,
) -> EngineResult<()> {
    if caveat.scope.as_ref().is_some_and(|scope| {
        matches!(&scope.verbs, oneiron_authority::federation::ScopeAxis::Some(verbs)
            if verbs.iter().any(|verb| oneiron_authority::credential_door::names_a_floor(verb)))
    }) || caveat
        .records
        .iter()
        .flatten()
        .chain(caveat.channels.iter().flatten())
        .any(|token| oneiron_authority::credential_door::names_a_floor(token))
    {
        return Err(invalid_authority());
    }
    if let Some(scope) = &caveat.scope {
        effective.scope = effective.scope.meet(scope);
    }
    if let Some(expiry) = caveat.expires_at {
        effective.expires_at = effective.expires_at.min(expiry);
    }
    if let Some(ttl) = caveat.ttl_secs {
        effective.ttl_secs = effective.ttl_secs.min(ttl);
    }
    effective.single_use |= caveat.single_use;
    if let Some(comm) = caveat.comm {
        effective.comm = Some(super::effective_slip_comm(effective.comm).min(comm));
    }
    if let Some((grant, bound)) = &caveat.pact {
        bound.validate()?;
        *pact = Some(match pact.as_ref() {
            Some((prior_grant, prior)) if prior_grant == grant => (*grant, prior.intersect(bound)),
            Some(_) => return Err(invalid_authority()),
            None => (*grant, bound.clone()),
        });
    }
    if let Some(records) = &caveat.records {
        effective.records = if *records_constrained {
            effective.records.intersection(records).cloned().collect()
        } else {
            records.clone()
        };
        *records_constrained = true;
        if effective.records.is_empty() {
            effective.scope = Scope::default();
        }
    }
    if let Some(channels) = &caveat.channels {
        effective.channels = effective.channels.intersection(channels).cloned().collect();
        // Empty channels carry no credential-door authority. A disjoint
        // meet must not turn a channel-bound slip into a generic reader.
        if effective.channels.is_empty() {
            effective.scope = Scope::default();
        }
    }
    Ok(())
}

/// The verb a transferred holder's bounds must carry to take any of a
/// removal archive (CALLS "REMOVAL_ARCHIVE_TRANSFER_VERB", accepted by the
/// Engine 10-22 05:3x): the scoped export's own.
pub const REMOVAL_ARCHIVE_TRANSFER_VERB: &str = "export";

pub fn mint_transcript(claims: &SlipClaims) -> EngineResult<Vec<u8>> {
    let mut bytes = MINT_CONTEXT.to_vec();
    bytes.extend_from_slice(&canonical(claims)?);
    Ok(bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(value: &str) -> EngineResult<Vec<u8>> {
    if value.len() > MAX_WIRE_BYTES * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_authority());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(nibble(pair[0]) * 16 + nibble(pair[1]))
        })
        .collect()
}
