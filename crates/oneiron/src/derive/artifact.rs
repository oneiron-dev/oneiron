//! Typed derived artifacts (kind 5): a person's `about` lines and a
//! PsychProfile snapshot, each through its validated publish under the
//! actor's live `derive` grant, never a bare side-table put (X03).

use super::batch::{DerivedPersonAbout, DerivedPsychProfile, ItemRef};
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::claim::ScopedRead;
use crate::dreamer_consolidation::{about_facts_in, publish_person_about_in_txn};
use crate::error::{Error, RecordError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::ports::{DependencyIndex, SourceSpan};
use crate::psych_profile::sources::{ProfileClaim, admitted_key, profile_source_in};
use crate::psych_profile::{
    PsychProfile, PsychProfileKey, PsychProfileSource, psych_profile_entity_id,
};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The refusal of a profile whose subject is no live row the actor reads.
pub const PROFILE_SUBJECT_UNREAD: &str = "gate.deny.derive.profile_subject_unread";

/// The refusal of a profile one of whose source records the actor does not
/// read.
pub const PROFILE_SOURCE_UNREAD: &str = "gate.deny.derive.profile_source_unread";

/// The refusal of a profile whose body or source words the substrate
/// refuses.
pub const PROFILE_MALFORMED: &str = "gate.deny.derive.profile_malformed";

/// The refusal of a profile citing a claim no profile of its key may read:
/// one not about its PERSON, not active and surfaced, at or above the
/// restricted band, or born in another facet or world.
const PROFILE_SOURCE_INELIGIBLE: &str = "gate.deny.derive.profile_source_ineligible";

/// The reason a landed artifact's receipt names.
const ARTIFACT_ALLOWED: &str = "gate.allow.derive.artifact";

/// What a person `about` item is written from, as an actor reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonAboutFacts {
    /// The digest of the facts about the person the actor reads: the item's
    /// `written_from`.
    pub digest: [u8; 32],
    /// The bands that take a line, lowest first: each band with facts at or
    /// below it.
    pub bands: Vec<u8>,
}

impl Vault {
    /// What `actor` writes a person `about` item for `person` from: the
    /// digest of the facts it reads about the person, and the bands that
    /// take a line.
    ///
    /// # Errors
    ///
    /// The vault's.
    pub fn person_about_facts(
        &self,
        actor: WriteActor,
        person: EntityId,
    ) -> Result<PersonAboutFacts> {
        let read = super::actor_read(self, actor)?;
        self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let (digest, bands) = about_facts_in(self, &read, &txn, person)?;
        Ok(PersonAboutFacts { digest, bands })
    }
}

/// Stages a person `about` item: the derive verdict over the PERSON, then
/// the validated publish in a savepoint of `txn`.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_about_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedPersonAbout,
) -> Result<ItemOutcome> {
    let person = context.resolve(&item.person)?;
    let actor = context.stamp.actor;
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Derive,
        Some(person),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, person, refusal.token()),
    };
    let read = super::actor_read(vault, actor)?;
    let lines: Vec<(u8, String)> = item
        .lines
        .iter()
        .map(|line| (line.band, line.text.clone()))
        .collect();
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match publish_person_about_in_txn(
        vault,
        &mut savepoint,
        &read,
        person,
        item.written_from,
        &lines,
        context.now,
    )? {
        Ok(()) => savepoint.commit()?,
        Err(refusal) => {
            savepoint.abort();
            return refuse(vault, txn, context, person, refusal.token());
        }
    }
    landed(vault, txn, context, person, &allowance)
}

/// Stages a PsychProfile item: the derive verdict over its subject, every
/// source record read by the actor, then the substrate's own put (its
/// source-words check and world placement) in a savepoint of `txn`. A
/// profile from the wire cites claims: each must be one its key admits,
/// read by the actor, and its exact words are read here, in the commit's
/// own write, at the version the batch rechecked. Every source record is
/// registered as a dependency of the landed profile, so erasing one
/// withdraws it; a withdrawn profile's regeneration clears its stale mark
/// through the regeneration fence.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_profile_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedPsychProfile,
) -> Result<ItemOutcome> {
    let subject = item.profile.subject_ref;
    let id = psych_profile_entity_id(&PsychProfileKey {
        person: subject,
        facet: item.facet,
        world: item.world,
    });
    let actor = context.stamp.actor;
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Derive,
        Some(subject),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, id, refusal.token()),
    };
    let read = super::actor_read(vault, actor)?;
    if read
        .get_entities_parts_in_txn(txn, &[subject])?
        .iter()
        .any(Option::is_none)
    {
        return refuse(vault, txn, context, id, PROFILE_SUBJECT_UNREAD);
    }
    let profile = if item.cites.is_empty() {
        item.profile.clone()
    } else {
        let sources = match cited_profile_sources_in(vault, txn, &read, item)? {
            Ok(sources) => sources,
            Err(token) => return refuse(vault, txn, context, id, token),
        };
        match item.profile.clone().with_sources(sources) {
            Ok(profile) => profile,
            Err(_) => return refuse(vault, txn, context, id, PROFILE_MALFORMED),
        }
    };
    let mut documents: Vec<EntityId> = profile
        .sources
        .iter()
        .map(|source| source.document_ref)
        .collect();
    documents.sort_unstable();
    documents.dedup();
    let mut spans = Vec::with_capacity(documents.len());
    for (document, row) in documents
        .iter()
        .zip(read.get_entities_parts_in_txn(txn, &documents)?)
    {
        let Some((_, learned_at, _)) = row else {
            return refuse(vault, txn, context, id, PROFILE_SOURCE_UNREAD);
        };
        spans.push(SourceSpan {
            document: *document,
            frontier: learned_at,
        });
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match land_profile_in_txn(vault, &mut savepoint, &id, &profile, &spans) {
        Ok(()) => savepoint.commit()?,
        Err(Error::Record(RecordError::InvalidPsychProfileBody(_))) => {
            savepoint.abort();
            return refuse(vault, txn, context, id, PROFILE_MALFORMED);
        }
        Err(error) => return Err(error),
    }
    landed(vault, txn, context, id, &allowance)
}

/// The source record of each claim `item` cites, read by `read` in `txn`,
/// or the refusal token of the first that is not one its key admits or the
/// actor does not read.
fn cited_profile_sources_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    item: &DerivedPsychProfile,
) -> Result<std::result::Result<Vec<PsychProfileSource>, &'static str>> {
    let key = PsychProfileKey {
        person: item.profile.subject_ref,
        facet: item.facet,
        world: item.world,
    };
    let mut claims = Vec::with_capacity(item.cites.len());
    for cited in &item.cites {
        match cited {
            ItemRef::Stored(id) => claims.push(*id),
            ItemRef::Local(_) => return Ok(Err(PROFILE_SOURCE_UNREAD)),
        }
    }
    let default_facet = vault.default_facet_in_txn(txn)?;
    let rows = read.get_entities_parts_in_txn(txn, &claims)?;
    let mut sources = Vec::with_capacity(claims.len());
    for (claim, row) in claims.into_iter().zip(rows) {
        let Some((ENTITY_TYPE_CLAIM, learned_at, body)) = row else {
            return Ok(Err(PROFILE_SOURCE_UNREAD));
        };
        let Ok(decoded) = crate::claim::decode_claim_body(&body, false) else {
            return Ok(Err(PROFILE_SOURCE_INELIGIBLE));
        };
        if admitted_key(key.person, default_facet, &decoded) != Some(key) {
            return Ok(Err(PROFILE_SOURCE_INELIGIBLE));
        }
        let claim = ProfileClaim {
            claim,
            learned_at,
            body,
            decoded,
        };
        let Some(source) = profile_source_in(vault, txn, &claim)? else {
            return Ok(Err(PROFILE_SOURCE_UNREAD));
        };
        sources.push(source);
    }
    Ok(Ok(sources))
}

/// Puts `profile` at `id` and registers each of `spans`, its source
/// records at the versions read, as a dependency of the landed row. A
/// withdrawn profile's regeneration clears its stale mark through the
/// regeneration fence; any other profile's old registrations are replaced.
fn land_profile_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    profile: &PsychProfile,
    spans: &[SourceSpan],
) -> Result<()> {
    vault.put_psych_profile_in_txn(txn, id, profile)?;
    let written_at = vault
        .get_raw_in(txn, id)?
        .as_deref()
        .and_then(crate::batch::EntityMetadataHeader::parse)
        .map(|header| header.learned_at)
        .ok_or(Error::InvariantViolation(
            "a landed psych profile reads no row",
        ))?;
    // RED PIN (6.9i PR 2 proof): no source is registered as a dependency.
    let _ = (written_at, spans);
    Ok(())
}

fn landed(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    row: EntityId,
    allowance: &crate::gate::DeriveAllowance,
) -> Result<ItemOutcome> {
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(row),
        &[ARTIFACT_ALLOWED.to_owned()],
        allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows: vec![row],
        approval: None,
        receipt: Some(receipt),
    })
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    row: EntityId,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, Some(row), &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
