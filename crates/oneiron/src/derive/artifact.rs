//! Typed derived artifacts (kind 5): a person's `about` lines and a
//! PsychProfile snapshot, each through its validated publish under the
//! actor's live `derive` grant, never a bare side-table put (X03).

use super::batch::{DerivedPersonAbout, DerivedPsychProfile};
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::dreamer_consolidation::{about_facts_in, publish_person_about_in_txn};
use crate::error::{Error, RecordError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::psych_profile::{PsychProfileKey, psych_profile_entity_id};
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
/// source-words check and world placement) in a savepoint of `txn`.
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
    let documents: Vec<EntityId> = item
        .profile
        .sources
        .iter()
        .map(|source| source.document_ref)
        .collect();
    if read
        .get_entities_parts_in_txn(txn, &documents)?
        .iter()
        .any(Option::is_none)
    {
        return refuse(vault, txn, context, id, PROFILE_SOURCE_UNREAD);
    }
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match vault.put_psych_profile_in_txn(&mut savepoint, &id, &item.profile) {
        Ok(()) => savepoint.commit()?,
        Err(Error::Record(RecordError::InvalidPsychProfileBody(_))) => {
            savepoint.abort();
            return refuse(vault, txn, context, id, PROFILE_MALFORMED);
        }
        Err(error) => return Err(error),
    }
    landed(vault, txn, context, id, &allowance)
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
