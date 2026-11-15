//! The claims a Psych Mirror profile reads (untangle 6.9i; canon ARCH-0025).
//!
//! A profile key (a PERSON, a facet and a world) admits the active,
//! surfaced claims about that PERSON born in that facet and lying in that
//! world, below the restricted band. The engine ranks them by the Psych
//! Mirror source selection (connectivity, affect salience, recency,
//! entropy), renders the words the model reads, and names each landed
//! source by the claim, the exact stored revision read and the content hash
//! of its words (FIX 11766). The Dreamer's crate job picks the profile's
//! sources from the ranked list; it never reads or sends their words.

use super::{PsychMirrorSourceCandidate, PsychProfileKey, PsychProfileSource};
use super::{PsychProfileSourceWords, rank_psych_mirror_sources};
use crate::claim::{ClaimBody, ClaimSource, ClaimSubject, ScopedRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::consolidation_evidence::swarm_evidence_content_hash;
use crate::{EntityId, Result, Vault};

/// The lowest sensitivity band the Dreamer never reads into a profile, the
/// consolidation neighbourhood's own floor: a profile's prose cannot be cut
/// by band, so it reads only the bands below this one.
pub(crate) const PSYCH_PROFILE_RESTRICTED_BAND: u8 = 3;

/// How many ranked claims one key's sources page serves, best first. The
/// job fills at most 50 slots round robin by predicate from them, so the
/// list reaches well past the slots for a key whose top claims share one
/// predicate.
pub(crate) const PSYCH_PROFILE_CANDIDATE_LIMIT: usize = 500;

/// One claim a profile key admits, as a read served it.
#[derive(Clone)]
pub(crate) struct ProfileClaim {
    /// The claim.
    pub(crate) claim: EntityId,
    /// When the vault learned the revision read.
    pub(crate) learned_at: u64,
    /// The claim body read, without its record header.
    pub(crate) body: Vec<u8>,
    /// That body, decoded.
    pub(crate) decoded: ClaimBody,
}

impl ProfileClaim {
    /// The content hash of the words read, the hash a profile source pins.
    pub(crate) fn content_hash(&self) -> [u8; 32] {
        swarm_evidence_content_hash(&self.body)
    }

    /// `predicate: value` on one line, as the model reads it.
    fn line(&self) -> String {
        let value = self
            .decoded
            .value
            .as_str()
            .map_or_else(|| self.decoded.value.to_string(), str::to_owned);
        one_line(&format!("{}: {value}", self.decoded.predicate))
    }
}

/// The key a claim about `person` falls under when a profile may read it:
/// the claim is about exactly that PERSON, active and surfaced, and below
/// the restricted band. Its facet is `None` when it was born in the vault's
/// default facet.
pub(crate) fn admitted_key(
    person: EntityId,
    default_facet: EntityId,
    decoded: &ClaimBody,
) -> Option<PsychProfileKey> {
    if decoded.subject != ClaimSubject::Entity(person)
        || !crate::claim::claim_surfaceable(decoded)
        || crate::claim::claim_sensitivity_band(decoded)
            .is_none_or(|band| band >= PSYCH_PROFILE_RESTRICTED_BAND)
    {
        return None;
    }
    Some(PsychProfileKey {
        person,
        facet: (decoded.scope_facet != default_facet).then_some(decoded.scope_facet),
        world: decoded.world,
    })
}

/// Every claim about `person` that `read` serves in `txn`, with the key
/// each falls under; a claim no profile may read is left out.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn person_claims_in(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Vec<(PsychProfileKey, ProfileClaim)>> {
    let default_facet = vault.default_facet_in_txn(txn)?;
    let ids = vault.claims_for_subject_in_txn(txn, &person)?;
    let rows = read.get_entities_parts_in_txn(txn, &ids)?;
    let mut claims = Vec::new();
    for (claim, row) in ids.into_iter().zip(rows) {
        let Some((ENTITY_TYPE_CLAIM, learned_at, body)) = row else {
            continue;
        };
        let Ok(decoded) = crate::claim::decode_claim_body(&body, false) else {
            continue;
        };
        let Some(key) = admitted_key(person, default_facet, &decoded) else {
            continue;
        };
        claims.push((
            key,
            ProfileClaim {
                claim,
                learned_at,
                body,
                decoded,
            },
        ));
    }
    Ok(claims)
}

/// The claims `key` admits that `read` serves in `txn`, in claim order.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn key_claims_in(
    vault: &Vault,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    key: &PsychProfileKey,
) -> Result<Vec<ProfileClaim>> {
    Ok(person_claims_in(vault, read, txn, key.person)?
        .into_iter()
        .filter_map(|(found, claim)| (found == *key).then_some(claim))
        .collect())
}

/// `claims` in the Psych Mirror source selection's rank order, best first,
/// at most [`PSYCH_PROFILE_CANDIDATE_LIMIT`] of them. A claim's
/// connectivity is its evidence references against the key's most cited
/// claim (canon's fan-in, read off the claim itself); ties break by claim.
///
/// # Errors
///
/// A claim whose selection signals do not compute.
pub(crate) fn ranked(claims: Vec<ProfileClaim>, now_secs: u64) -> Result<Vec<ProfileClaim>> {
    let citations: Vec<usize> = claims
        .iter()
        .map(|claim| claim.decoded.evidence_refs().map_or(0, |refs| refs.len()))
        .collect();
    let most = citations.iter().copied().max().unwrap_or(0);
    let mut candidates: Vec<PsychMirrorSourceCandidate> = Vec::with_capacity(claims.len());
    for (claim, cited) in claims.iter().zip(&citations) {
        let connectivity = if most == 0 {
            0.0
        } else {
            *cited as f32 / most as f32
        };
        candidates.push(
            crate::context_pack::psych_mirror_source_candidate_from_claim(
                claim.claim,
                claim.claim,
                connectivity,
                claim.learned_at,
                &claim.decoded,
            )?,
        );
    }
    let order = rank_psych_mirror_sources(&candidates, now_secs, PSYCH_PROFILE_CANDIDATE_LIMIT)?;
    let mut by_id: std::collections::BTreeMap<EntityId, ProfileClaim> = claims
        .into_iter()
        .map(|claim| (claim.claim, claim))
        .collect();
    Ok(order
        .into_iter()
        .filter_map(|selected| by_id.remove(&selected.source_id))
        .collect())
}

/// The facts as the model reads them, one per line in `claims` order, as
/// the psych-mirror skill names them: `predicate: value`, marked with where
/// the claim came from. A tool's output, a generated claim and a claim of
/// no source read as inferred, as their confidence weight does.
pub(crate) fn prompt_lines(claims: &[ProfileClaim]) -> String {
    claims
        .iter()
        .map(|claim| {
            let mark = match claim.decoded.source {
                Some(ClaimSource::UserStated) => "stated",
                Some(ClaimSource::Observed) => "observed",
                Some(ClaimSource::Imported) => "imported",
                _ => "inferred",
            };
            format!("{} ({mark})", claim.line())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The source record of `claim`, read live in `txn` (FIX 11766): the claim,
/// its live revision, whose body the read served, and the content hash of
/// those words. `None` when the claim's row is gone.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn profile_source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &ProfileClaim,
) -> Result<Option<PsychProfileSource>> {
    let Some(revision) = vault.live_revision_in_txn(txn, &claim.claim)? else {
        return Ok(None);
    };
    Ok(Some(PsychProfileSource {
        revision_ref: claim.claim,
        document_ref: claim.claim,
        world_ref: claim.decoded.world,
        document_revision: revision,
        words: PsychProfileSourceWords::Record {
            content: claim.content_hash(),
        },
    }))
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
