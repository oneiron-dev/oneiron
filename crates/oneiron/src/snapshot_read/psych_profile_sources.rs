//! The ranked claims one Psych Mirror profile key reads (untangle 6.9i):
//! the active, surfaced claims about the key's PERSON, born in its facet and
//! lying in its world, below the restricted band, best first by the Psych
//! Mirror source selection.
//!
//! The owner reads under its proof. A live Steward reader reads only claims
//! its grant and scoped read both reach; an unread claim is absent and
//! counted nowhere. A candidate carries its claim's served version, its
//! predicate, band and source, and no words: a bound profile step cites the
//! versions, and the engine renders the words it serves.

use serde::{Deserialize, Serialize};

use super::SourceVersion;
use super::source_version::blake3_ref;
use super::strength_observations::{
    observation_reader_scope_for_actor_in_txn, observed_claim_reads_in_txn,
};
use crate::claim::{ClaimReadStatus, ClaimSource, ScopedRead, ScopedReadResult};
use crate::dreamer_runner::DreamerAttemptBinding;
use crate::federation::Scope;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::psych_profile::PsychProfileKey;
use crate::psych_profile::sources::{ProfileClaim, key_claims_in, ranked};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Result, Vault};

/// The verb this page answers.
const PSYCH_PROFILE_SOURCES_PAGE_VERB: &str = "vault.consolidation.psych_profile.sources.page";

/// The profile key whose ranked claims a reader asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PsychProfileSourcesPageRequest {
    /// The PERSON the profile describes.
    pub person: EntityId,
    /// The facet the claims were born in; absent for the vault's default.
    #[serde(default)]
    pub facet: Option<EntityId>,
    /// The WORLD the claims lie in; absent for world-free claims.
    #[serde(default)]
    pub world: Option<EntityId>,
}

impl PsychProfileSourcesPageRequest {
    /// The profile key this request names.
    #[must_use]
    pub fn key(&self) -> PsychProfileKey {
        PsychProfileKey {
            person: self.person,
            facet: self.facet,
            world: self.world,
        }
    }
}

/// One key's ranked claims, best first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsychProfileSourcesPage {
    pub candidates: Vec<PsychProfileCandidate>,
    /// More ranked claims read for this caller than the page's byte bound
    /// holds; the page keeps the best-ranked prefix.
    pub more: bool,
}

/// One claim a profile may read, as this caller's read serves it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsychProfileCandidate {
    /// The claim's version as served: a bound profile step cites it.
    pub version: SourceVersion,
    pub predicate: String,
    /// The claim's sensitivity band, below the restricted band.
    pub band: Option<u8>,
    /// Where the claim came from.
    pub source: Option<ClaimSource>,
}

/// Pages `input`'s key through the caller's live reach and scoped read.
///
/// # Errors
///
/// No owner proof or live Steward read grant, and storage failures.
pub fn psych_profile_sources_page(
    memory: &Memory<'_>,
    input: &PsychProfileSourcesPageRequest,
) -> MemoryResult<ScopedReadResult<PsychProfileSourcesPage>> {
    sources_page(memory, input, None)
}

/// [`psych_profile_sources_page`] for a profile attempt's bound client:
/// `binding` is proved in the page's own read, and the page serves only the
/// key the attempt names.
///
/// # Errors
///
/// As [`psych_profile_sources_page`]; `FORBIDDEN` for another key; the
/// binding's refusals.
pub(crate) fn psych_profile_sources_page_bound(
    memory: &Memory<'_>,
    input: &PsychProfileSourcesPageRequest,
    binding: &DreamerAttemptBinding,
) -> MemoryResult<ScopedReadResult<PsychProfileSourcesPage>> {
    if binding.psych_profile_key() != Some(input.key()) {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a psych profile attempt reads only the profile key it names",
            &["Page the key the attempt input names."],
        ));
    }
    sources_page(memory, input, Some(binding))
}

/// The one page body, with the binding of a bound call to prove in its read.
fn sources_page(
    memory: &Memory<'_>,
    input: &PsychProfileSourcesPageRequest,
    binding: Option<&DreamerAttemptBinding>,
) -> MemoryResult<ScopedReadResult<PsychProfileSourcesPage>> {
    let vault = memory.vault();
    let bounds = vault.snapshot_read_settings()?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let _pins = read.prepare_point_read::<MemoryError>()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.prove_read_authority_in_txn(&txn)?;
    if let Some(binding) = binding {
        binding.check_in_txn(&txn)?;
    }
    let scope = psych_profile_reader_scope_in_txn(memory, &txn)?;
    let key = input.key();
    let now_secs = vault.store.clock.now_recorded_at();
    read.read_projected_in_txn(&txn, &[], None, |txn, _| {
        let claims = served_profile_claims_in_txn(vault, txn, &read, scope.as_ref(), &key)?;
        let mut page = PsychProfileSourcesPage {
            candidates: Vec::new(),
            more: false,
        };
        let mut bytes = 0u64;
        for claim in ranked(claims, now_secs)? {
            let candidate = PsychProfileCandidate {
                version: served_version(&claim),
                predicate: claim.decoded.predicate.clone(),
                band: crate::claim::claim_sensitivity_band(&claim.decoded),
                source: claim.decoded.source,
            };
            let size = serde_json::to_vec(&candidate)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?
                .len() as u64;
            if bytes.saturating_add(size) > bounds.page_bytes {
                page.more = true;
                break;
            }
            bytes = bytes.saturating_add(size);
            page.candidates.push(candidate);
        }
        Ok(page)
    })
}

/// The live grant's record scope, or the whole vault for the proven owner
/// and a base agent whose manifest rows still stand in place of a grant.
///
/// # Errors
///
/// `FORBIDDEN` for any other caller, and storage failures.
pub(crate) fn psych_profile_reader_scope_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<Option<Scope>> {
    let vault = memory.vault();
    if let Ok(owner) = memory.embedded_owner(PSYCH_PROFILE_SOURCES_PAGE_VERB) {
        owner.revalidate_as_vault_owner_in_txn(vault, txn)?;
        return Ok(None);
    }
    match observation_reader_scope_for_actor_in_txn(vault, txn, memory.actor())? {
        Some(scope) => Ok(scope),
        None => Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "psych profile sources read for the owner under its proof or a live Steward reader",
            &[],
        )),
    }
}

/// The claims `key` admits that the caller reads in `txn`: the scope
/// reaches each claim's record and the scoped read finds it live.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn served_profile_claims_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    scope: Option<&Scope>,
    key: &PsychProfileKey,
) -> Result<Vec<ProfileClaim>> {
    let mut served = Vec::new();
    for claim in key_claims_in(vault, read, txn, key)? {
        if observed_claim_reads_in_txn(vault, txn, read, scope, claim.claim)? {
            served.push(claim);
        }
    }
    Ok(served)
}

/// The version of `claim` as its read served it, as `source_version_in_txn`
/// names a CLAIM.
pub(crate) fn served_version(claim: &ProfileClaim) -> SourceVersion {
    SourceVersion {
        entity: claim.claim,
        entity_type: ENTITY_TYPE_CLAIM,
        learned_at: claim.learned_at,
        revision: blake3_ref(&claim.content_hash()),
        projection: None,
    }
}
