//! Federated entity-blob admission and grading.
//! The entry point is `admit_federated_entity_blob`.
//! Owned by `super`.

#[cfg(feature = "sync")]
use std::collections::BTreeMap;

use loro::LoroDoc;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{restamp_federated_claim_source, validate_claim_body_and_decode};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN,
    ENTITY_TYPE_WORLD,
};
use crate::sync::loro_support::{map_for_each_value_bytes, map_insert_bytes};

#[cfg(feature = "sync")]
use super::super::validators::{admit_federated_authority_log, validate_federated_pack};
use super::routing::{GuestCopy, Routes, rename_world_edge_subject};
use super::{
    ImportGrading, refuse_peer_agent_definition_widening, validate_admitted_replicated_body,
};

/// Copies the rows `routes` lands in `part` from `source` into `target`, each
/// under the id it lands under.
#[cfg(feature = "sync")]
pub(super) fn copy_admitted_entities(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    source: &LoroDoc,
    target: &LoroDoc,
    grading: ImportGrading,
    routes: &Routes<'_>,
    part: usize,
) -> Result<()> {
    let source_entities = source.get_map("entities");
    let target_entities = target.get_map("entities");
    let rtxn = vault.store.env.read_txn()?;
    // Each authority row is judged beside the part's others (FIX 2535, 2989).
    let authority =
        super::super::authority_beside::AuthorityBeside::gather(&source_entities, |key| {
            routes.entity_part(key) == Some(part)
        });
    let beside = || authority.rows();
    let mut result = Ok(());
    map_for_each_value_bytes(&source_entities, |key, value| {
        if result.is_err() || routes.entity_part(key) != Some(part) {
            return;
        }
        result = admit_federated_entity_blob_graded(
            vault,
            policy,
            &rtxn,
            key,
            value,
            ImportCopy {
                grading,
                guest: routes.guest_copy(),
                beside: &beside,
            },
        )
        .and_then(|(here, blob)| map_insert_bytes(&target_entities, &here.to_hex(), &blob));
    });
    result
}

#[cfg(feature = "sync")]
pub(crate) fn admit_federated_entity_blob(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    txn: &heed::RoTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
) -> Result<Vec<u8>> {
    admit_federated_entity_blob_graded(
        vault,
        policy,
        txn,
        key,
        value,
        ImportCopy {
            grading: ImportGrading::Imported {
                scale: super::super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
            },
            guest: None,
            beside: &|| Ok(BTreeMap::new()),
        },
    )
    .map(|(_, blob)| blob)
}

/// How one import's rows are copied: the sending peer's grading, a guest's
/// copy, and the import's authority rows each one of them is judged beside
/// (FIX 2535, 2989).
#[cfg(feature = "sync")]
#[derive(Clone, Copy)]
struct ImportCopy<'a> {
    grading: ImportGrading,
    guest: Option<GuestCopy<'a>>,
    beside: crate::authority::RowsBeside<'a>,
}

/// [`admit_federated_entity_blob`] with the sending peer's `grading` for a
/// CLAIM, TURN or CONVERSATION, and the id the row lands under: the key it
/// came under, but for a guest's WORLD. A guest's CLAIM lands in its foreign
/// WORLD copy (FIX 3497), and a guest's WORLD row under that copy's id, its
/// bytes as they came (FIX 3657). An AUTHORITY_LOG row is judged beside the
/// import's other authority rows (`beside`, FIX 2535, 2989).
#[cfg(feature = "sync")]
fn admit_federated_entity_blob_graded(
    vault: &Vault,
    policy: &crate::gate::PolicyManifestResolution,
    txn: &heed::RoTxn<'_>,
    key: &str,
    value: Option<&[u8]>,
    copy: ImportCopy<'_>,
) -> Result<(EntityId, Vec<u8>)> {
    let ImportCopy {
        grading,
        guest,
        beside,
    } = copy;
    let blob = value.ok_or(Error::InvalidKey)?;
    let id = EntityId::from_hex(key).map_err(|_| Error::InvalidKey)?;
    if key != id.to_hex() {
        return Err(Error::InvalidKey);
    }

    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if crate::sync::pack_sync::is_pack_handle(header.entity_type) {
        validate_federated_pack(&vault.store, txn, blob)?;
        return Ok((id, blob.to_vec()));
    }
    if header.entity_type != ENTITY_TYPE_CLAIM {
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            admit_federated_authority_log(
                vault,
                txn,
                &id,
                &blob[ENTITY_METADATA_HEADER_LEN..],
                beside,
            )?;
            return Ok((id, blob.to_vec()));
        }
        // A guest's WORLD row lands under the foreign id its CLAIMs in that
        // world name here, in the window it came in: WORLD is no window's
        // world carrier (`entity_world`). Its body is unsigned and kept as
        // it came. No leaf in it is authority here: a world's privacy and
        // owner come only from a signed `AuthorityOp::WorldPrivacy`, and none
        // of the sender's names this id. The key was judged as it came; the
        // checks bound to a row's id judge the id it lands under.
        let here = match guest {
            Some(guest) if header.entity_type == ENTITY_TYPE_WORLD => {
                crate::federation::foreign_world_for(guest.source, id)?.entity_id()
            }
            _ => id,
        };
        // A guest's AGENT_DEF world and saved-query worlds name the WORLDs
        // that land under foreign ids here (FIX 3892); every check below
        // judges the renamed body.
        let renamed = match guest {
            Some(guest) => super::world_refs::rename_typed_world_refs(
                header.entity_type,
                guest.saved_query,
                &blob[ENTITY_METADATA_HEADER_LEN..],
                guest.worlds,
            )?
            .map(|body| [&blob[..ENTITY_METADATA_HEADER_LEN], body.as_slice()].concat()),
            None => None,
        };
        let blob = renamed.as_deref().unwrap_or(blob);
        // The same registry classification decides writability and admission.
        // Unknown bytes cannot become peer-writable because they lie in a range.
        vault
            .store
            .validate_public_entity_type(header.entity_type)?;
        if crate::federation::selector_range_of(header.entity_type).is_none()
            && vault
                .structural_kind_registration(header.entity_type)
                .is_none_or(|registration| registration.family.is_none())
        {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        validate_admitted_replicated_body(
            &here,
            header.entity_type,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?;
        refuse_peer_agent_definition_widening(&vault.store, txn, &here, blob)?;
        if matches!(grading, ImportGrading::Imported { .. })
            && matches!(
                header.entity_type,
                ENTITY_TYPE_TURN | ENTITY_TYPE_CONVERSATION
            )
        {
            return restamp_federated_transcript(blob).map(|blob| (here, blob));
        }
        return Ok((here, blob.to_vec()));
    }

    let body = validate_claim_body_and_decode(&blob[ENTITY_METADATA_HEADER_LEN..], true)?;
    let mut body = match grading {
        ImportGrading::Imported { scale } => {
            downweight_federated_claim(restamp_federated_claim_source(body), scale)?
        }
        ImportGrading::FirstParty => body,
    };
    if let Some(guest) = guest {
        // Its world is the recipient's before the gate judges it, so the copy
        // the gate passes is the copy every later step sees.
        body.world =
            Some(crate::federation::guest_claim_world(guest.source, body.world)?.entity_id());
        rename_world_edge_subject(&mut body.subject, guest.worlds);
        super::world_refs::rename_entity_subject(&mut body.subject, guest.worlds);
    }
    crate::gate::check_federated_claim_admission(&vault.store, &body, policy)?;
    let encoded = crate::claim::encode_claim_body(&body)?;

    let mut admitted = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + encoded.len());
    admitted.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    admitted.extend_from_slice(&encoded);
    Ok((id, admitted))
}

/// The source a foreign TURN or CONVERSATION is stamped with (OF-149).
pub(crate) const FEDERATION_IMPORT_SOURCE: &str = "federation";

/// A peer's TURN or CONVERSATION is imported evidence, never the owner's live
/// words, unless the peer is a verified member ([`ImportGrading::FirstParty`]):
/// its body is stamped with the federation import source unless the peer
/// already named one. The stamp is a birth fact, so a peer row landing
/// on an unstamped local one is refused by the put door, never relabelled.
/// An empty body (a deleted shell) carries no words and passes unchanged.
#[cfg(feature = "sync")]
fn restamp_federated_transcript(blob: &[u8]) -> Result<Vec<u8>> {
    let body = &blob[ENTITY_METADATA_HEADER_LEN..];
    if body.is_empty() {
        return Ok(blob.to_vec());
    }
    let refused = || -> Error {
        RecordError::InvalidConversationBody("a federated transcript body must be a map").into()
    };
    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| refused())?;
    if cursor.position() != body.len() as u64 {
        return Err(refused());
    }
    let rmpv::Value::Map(mut entries) = value else {
        return Err(refused());
    };
    let key = crate::memory::IMPORTED_SOURCE_KEY;
    match entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key))
        .count()
    {
        0 => entries.push((
            rmpv::Value::from(key),
            rmpv::Value::from(FEDERATION_IMPORT_SOURCE),
        )),
        1 => return Ok(blob.to_vec()),
        _ => return Err(refused()),
    }
    let mut encoded = Vec::with_capacity(blob.len() + 32);
    encoded.extend_from_slice(&blob[..ENTITY_METADATA_HEADER_LEN]);
    rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(entries)).map_err(|_| refused())?;
    Ok(encoded)
}

/// ARCH-0043 requires a down-weight but does not prescribe a factor. The
/// sending peer's owner-set scale applies, by default
/// [`super::super::DEFAULT_FEDERATED_CONFIDENCE_SCALE`] for every federated role. A
/// verified member's claims take none ([`ImportGrading::FirstParty`]).
fn downweight_federated_claim(
    mut body: crate::claim::ClaimBody,
    scale: f32,
) -> Result<crate::claim::ClaimBody> {
    const AUDIT_KEY: &str = "federated_original_confidence";
    let original = body.confidence;
    body.confidence *= scale;
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        // The wrapper and value record carry the same confidence. Keep both
        // graded values equal so admission cannot create an invalid replay row.
        let mut record = crate::provenance::decode_edge_provenance_body(&body.value)?;
        record.confidence = body.confidence;
        body.value = crate::provenance::encode_edge_provenance_value(&record);
    }
    let mut entries = match body.scope.take() {
        Some(rmpv::Value::Map(entries)) => entries,
        Some(scope) => vec![(rmpv::Value::from("pre_federated_confidence_scope"), scope)],
        None => Vec::new(),
    };
    entries.retain(|(key, _)| key.as_str() != Some(AUDIT_KEY));
    entries.push((rmpv::Value::from(AUDIT_KEY), rmpv::Value::F32(original)));
    body.scope = Some(rmpv::Value::Map(entries));
    Ok(body)
}
