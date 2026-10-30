//! Federated import admission: window admit, claim revalidation, entity copy, authority-log door, and tombstone rejection.

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, ExportMode, LoroDoc};
#[cfg(feature = "sync")]
use xxhash_rust::xxh3::xxh3_64;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncProtocolValidation};
use crate::federation::{MembershipStanding, PactDelivery};
use crate::sync::loro_support::map_for_each_tombstone_value;
use crate::sync::schema::create_window_doc;
use crate::sync::types::WindowKey;

#[cfg(feature = "sync")]
use super::edge::{copy_admitted_edges, pending_births, refuse_non_binary_edges};
use crate::error::SyncError;
#[cfg(test)]
use crate::error::RecordError;

mod birth_scope;
mod blobs;
mod revalidate;
mod routing;
mod state;
mod world_refs;

pub(crate) use self::state::{AdmittedUpdate, StagedBirths};
pub(in crate::sync) use self::state::staged_births;
use self::routing::Routes;
pub(in crate::sync) use self::revalidate::{
    revalidate_admitted_federated_claims, revalidate_admitted_facet_stamps,
};
#[cfg(feature = "test-hooks")]
pub use self::revalidate::put_selector_test_federation_grant;
use self::blobs::copy_admitted_entities;
pub(crate) use self::blobs::{admit_federated_entity_blob, FEDERATION_IMPORT_SOURCE};

/// Role carried by a member/guest federation import path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FederationAdmissionRole {
    Member,
    Guest,
}

impl FederationAdmissionRole {
    const fn origin(self) -> &'static str {
        match self {
            Self::Member => "federation_admission.member",
            Self::Guest => "federation_admission.guest",
        }
    }
}

/// How admission grades a federated CLAIM, TURN or CONVERSATION (FIX 360).
#[cfg(feature = "sync")]
#[derive(Debug, Clone, Copy)]
enum ImportGrading {
    /// Imported evidence: a claim is restamped `src=imported` and its
    /// confidence scaled by `scale`; a transcript takes the federation import
    /// stamp.
    Imported { scale: f32 },
    /// A verified member's write in this shared vault, first-party to it
    /// (ARCH-0043): a claim keeps its source and confidence, and a transcript
    /// takes no import stamp.
    FirstParty,
}

/// Produces locally admitted window update bytes for a member/guest federation
/// import.
///
/// The incoming CRDT update is decoded into an unobserved scratch doc. Claim
/// entities are re-stamped to `src=imported` and evaluated against the local
/// source-trust floor before any bytes are copied into the returned update.
/// The returned doc is freshly authored with a federation admission origin,
/// so callers can import it through the ordinary replay/materialization path
/// without giving the original remote op ids trust-blind write authority.
///
/// No facet stamp a peer sends onto a row this vault lacks is in the
/// returned update. With no sender named here, nothing can bind such a stamp
/// to its row's birth, so it is dropped (`copy_admitted_edges`).
#[cfg(feature = "sync")]
pub fn admit_federated_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Result<Vec<u8>> {
    Ok(admit_window_update(
        vault,
        key,
        update,
        role,
        None,
        ImportGrading::Imported {
            scale: super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
        },
        None,
    )?
    .bytes)
}

/// [`admit_federated_window_update`] for an update the federation peer
/// `peer` sent. Its facet stamps onto rows this vault lacks wait out of the
/// update ([`AdmittedUpdate`]) until the peer's birth of each row applies.
/// Its claims are graded as imported evidence, and no pact source remaps
/// them: the door the federation import calls is
/// [`admit_peer_window_update_as`].
#[cfg(feature = "sync")]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::sync) fn admit_peer_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    peer: EntityId,
) -> Result<AdmittedUpdate> {
    admit_guest_window_update(vault, key, update, role, peer, None)
}

/// [`admit_peer_window_update`] for a guest whose pact names `guest`, its
/// source vault: each of its CLAIMs lands in its foreign WORLD copy
/// ([`Routes`], FIX 3497).
#[cfg(feature = "sync")]
fn admit_guest_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    peer: EntityId,
    guest: Option<&[u8; 32]>,
) -> Result<AdmittedUpdate> {
    let lane = crate::federation::facet_read::HeldLane::Peer(peer).key();
    // The owner's scale for this peer, read once for the whole update.
    let scale = vault.federation_peer_confidence(&peer)?;
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(lane),
        ImportGrading::Imported { scale },
        guest,
    )
}

/// [`admit_peer_window_update`] at the `standing` the peer's own grant gives
/// it here (`FederationPeer::membership`, FIX 360). A member's update, sent
/// as one, is first-party to this shared vault: its claims are neither
/// restamped `src=imported` nor downweighted, and the claim gate still judges
/// them; its TURN and CONVERSATION rows take no federation import stamp. A
/// scoped guest's update, or one sent as a guest's, keeps guest grading, and
/// its CLAIMs land in the foreign WORLD copies the source vault `delivery`
/// names derives (FIX 3497). A guest's update with no unambiguous active pact
/// (`delivery` is `None`) has no such source and is refused, never landed as
/// this vault's own.
#[cfg(feature = "sync")]
pub(in crate::sync) fn admit_peer_window_update_as(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    (peer, standing): (EntityId, MembershipStanding),
    delivery: Option<&PactDelivery>,
) -> Result<AdmittedUpdate> {
    let first_party = role == FederationAdmissionRole::Member
        && matches!(standing, MembershipStanding::Member { .. });
    if !first_party {
        let delivery = delivery.ok_or_else(|| {
            super::codec::selector_err(crate::error::SyncSelectorValidation::GrantInactive)
        })?;
        return admit_guest_window_update(
            vault,
            key,
            update,
            role,
            peer,
            Some(&delivery.source_vault),
        );
    }
    let lane = crate::federation::facet_read::HeldLane::Peer(peer).key();
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(lane),
        ImportGrading::FirstParty,
        None,
    )
}

/// [`admit_federated_window_update`] for a foreign artifact staged under
/// `receipt_id`. Its facet stamps onto rows this vault lacks wait under the
/// receipt until the confirmation's import births the rows
/// ([`staged_births`]).
#[cfg(feature = "sync")]
pub(crate) fn admit_staged_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    receipt_id: &[u8; 32],
) -> Result<AdmittedUpdate> {
    admit_window_update(
        vault,
        key,
        update,
        role,
        Some(staged_lane(receipt_id)),
        ImportGrading::Imported {
            scale: super::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
        },
        None,
    )
}

#[cfg(feature = "sync")]
fn staged_lane(receipt_id: &[u8; 32]) -> String {
    crate::federation::facet_read::HeldLane::Staged(*receipt_id).key()
}

/// `guest` is the source vault a guest's pact names: with one, the update's
/// CLAIMs land in their foreign WORLD copies ([`Routes`], FIX 3497), and the
/// admitted update holds one part per window it lands in.
#[cfg(feature = "sync")]
fn admit_window_update(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    lane: Option<String>,
    grading: ImportGrading,
    guest: Option<&[u8; 32]>,
) -> Result<AdmittedUpdate> {
    let remote = create_window_doc("federation-remote", key);
    remote.import(update).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import federated update",
            source,
        })
    })?;

    refuse_non_binary_edges(&remote.get_map("edges"))?;
    let policy = vault
        .with_write_txn_grouped(|wtxn| crate::gate::resolve_policy_manifest(&vault.store, wtxn))?;

    reject_federated_tombstones(&remote)?;
    // The withheld CLAIMs and the contained cross-world edges (FIX 3660).
    let mut terminal = crate::sync::quarantine::TerminalRejectionBatch::new(key.as_str());
    let routes = match guest {
        Some(source) => Routes::plan(vault, key, &remote, source, &mut terminal)?,
        None => Routes::unrouted(key),
    };
    // Every part's rows and edges are copied before any birth is: a ref to a
    // row another part carries is not one admission dropped.
    let mut copied = Vec::with_capacity(routes.keys.len());
    for (part, part_key) in routes.keys.iter().enumerate() {
        let admitted = create_admission_doc(part_key, update, role, guest)?;
        copy_admitted_entities(vault, &policy, &remote, &admitted, grading, &routes, part)?;
        birth_scope::copy_birth_scopes(&remote, &admitted, routes.guest_copy(), grading)?;
        let edges = routes.edges_of(&remote, part)?;
        let early = copy_admitted_edges(
            vault,
            part_key,
            &remote.get_map("entities"),
            &admitted.get_map("entities"),
            &edges
                .as_ref()
                .map_or_else(|| remote.get_map("edges"), |edges| edges.get_map("edges")),
            &admitted.get_map("edges"),
        )?;
        if part == 0 {
            crate::sync::note::copy_judged(vault, &remote, &admitted)?;
        }
        copied.push((admitted, early));
    }
    terminal.commit(vault)?;

    // The sender is another vault, as far as its rows' births go: a ref to a
    // row admission dropped is masked, under that lane's key.
    let withheld = match &lane {
        Some(lane) => crate::provenance::birth::WithheldKey::for_destination(
            vault,
            format!("admit:{lane}").as_bytes(),
        )?,
        None => crate::provenance::birth::WithheldKey::fresh(),
    };
    // A row the copy lands under another id than the sender's, a guest's
    // WORLD (FIX 3657), keeps the birth the sender carried for it.
    let renamed = routes
        .worlds
        .iter()
        .map(|(sender, here)| (*here, *sender))
        .collect::<BTreeMap<_, _>>();
    let carried = (copied.len() > 1 || !renamed.is_empty()).then(|| {
        copied
            .iter()
            .flat_map(|(admitted, _)| {
                admitted
                    .get_map("entities")
                    .keys()
                    .filter_map(|key| EntityId::from_hex(&key).ok())
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>()
    });
    let mut parts = Vec::with_capacity(copied.len());
    for ((admitted, early), part_key) in copied.into_iter().zip(&routes.keys) {
        match &carried {
            Some(carried) => crate::sync::row_birth::copy_births_carried_to_other_vault(
                &remote, &admitted, &withheld, carried, &renamed,
            )?,
            None => crate::sync::row_birth::copy_births_within(
                &remote,
                &admitted,
                crate::sync::row_birth::BirthReach::OtherVault(&withheld),
            )?,
        }
        // Its born-with text never enters the admitted bytes: the import keeps
        // it beside the rows that land, a renamed row's under its id here.
        let born_with = super::born_with::admitted_born_with(&remote, &admitted, &renamed);
        let births = match &lane {
            Some(lane) => pending_births(
                vault,
                lane,
                &admitted.get_map("entities"),
                &early.with_birth,
            )?,
            None => Vec::new(),
        };
        let peer_rows = crate::sync::ingest::carry_peer_rows(&admitted)?;
        let delivered = crate::sync::ingest::delivered_rows(&admitted.get_map("entities"));
        admitted.commit_with(CommitOptions::new().origin(role.origin()));
        let rows = admitted.get_map("entities").len() + admitted.get_map("edges").len();
        let bytes = admitted
            .export(ExportMode::all_updates())
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))?;
        parts.push(AdmittedUpdate {
            key: part_key.clone(),
            bytes,
            rows: rows as u64,
            early,
            births,
            peer_rows,
            delivered,
            born_with,
            lane: lane.clone(),
            routed: Vec::new(),
        });
    }
    let mut parts = parts.into_iter();
    let mut admitted = parts.next().ok_or(Error::InvariantViolation(
        "an admitted update lands in its own window first",
    ))?;
    admitted.routed = parts.collect();
    Ok(admitted)
}

/// The doc one part of an admission is authored in. Its op ids derive from
/// the window it lands in, the update, the role and, for a guest's update, the
/// source vault its CLAIMs are remapped under (FIX 3497), so one op id never
/// carries two payloads. The domain is v1 since a WORLD target lands under its
/// foreign id before its row arrives (FIX 3891): the same update now admits
/// other bytes.
#[cfg(feature = "sync")]
fn create_admission_doc(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    guest: Option<&[u8; 32]>,
) -> Result<LoroDoc> {
    let doc = LoroDoc::new();
    doc.set_peer_id(federated_admission_peer_id(key, update, role, guest))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroSetPeerId, e))?;
    let _entities = doc.get_map("entities");
    let _edges = doc.get_map("edges");
    let _tombstones = doc.get_map("tombstones");
    doc.commit();
    Ok(doc)
}

#[cfg(feature = "sync")]
fn federated_admission_peer_id(
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
    guest: Option<&[u8; 32]>,
) -> u64 {
    let mut material = Vec::with_capacity(
        b"oneiron.federation.admission.peer.v1".len()
            + role.origin().len()
            + key.as_str().len()
            + std::mem::size_of::<u64>()
            + update.len(),
    );
    material.extend_from_slice(b"oneiron.federation.admission.peer.v1");
    material.extend_from_slice(&(role.origin().len() as u64).to_le_bytes());
    material.extend_from_slice(role.origin().as_bytes());
    material.extend_from_slice(&(key.as_str().len() as u64).to_le_bytes());
    material.extend_from_slice(key.as_str().as_bytes());
    material.extend_from_slice(&(update.len() as u64).to_le_bytes());
    material.extend_from_slice(update);
    if let Some(source) = guest {
        material.extend_from_slice(&(source.len() as u64).to_le_bytes());
        material.extend_from_slice(source);
    }

    match xxh3_64(&material) {
        0 => 1,
        u64::MAX => u64::MAX - 1,
        peer_id => peer_id,
    }
}

/// Refuses a peer's agent definition that turns the one stored at `id` back
/// on, read in `txn`. Turning a definition back on is the owner's, and a peer
/// is not the owner. Typed as the peer's bytes, so the frame quarantines.
#[cfg(feature = "sync")]
fn refuse_peer_agent_definition_widening(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF
        && crate::agent_def::agent_definition_put_widens_in_txn(
            store,
            txn,
            id,
            &blob[ENTITY_METADATA_HEADER_LEN..],
        )?
    {
        return Err(Error::Artifact(
            crate::error::ArtifactError::InvalidAgentDefBody(
                "a federation peer cannot turn an agent definition back on or change its models",
            ),
        ));
    }
    Ok(())
}

/// Per-kind body validation for the non-CLAIM federation admission arm.
///
/// FED-1093: kind WRITABILITY is not admission. This arm previously checked
/// only that the metadata header parsed and that the type byte was not
/// engine-authored, then copied the peer's bytes verbatim — so a body that
/// `apply_put` is guaranteed to refuse (a TASK carrying no role, an undecodable
/// SKILL) entered the ADMITTED doc. The staged foreign import then pinned that
/// doc's digest, the confirmation marked the receipt `Confirmed`
/// unconditionally, and replay quarantined the offending row and continued —
/// so the operator consented to an import that silently dropped it. The
/// confirm GCs the staged content in the same txn, and the artifact's
/// `receipt_id` is re-derived from its own bytes, so the drop cannot be undone
/// by re-presenting it. CLAIM and AUTHORITY_LOG already refuse their invalid
/// bodies at this door; every other kind whose body schema is PINNED refuses
/// here too, before any receipt exists.
///
/// Only the STATELESS half of `apply_put`'s per-kind chain is mirrored, and it
/// delegates to the very same validators, so this door cannot judge a body
/// materialization would accept. Store-reading rules (authority-log store-key
/// binding and gate policy) stay where they can
/// read a transaction — this is a fail-closed prefilter, never the authority:
/// materialization still re-validates every row it is handed. Kinds with no
/// pinned body schema stay opaque here exactly as they are at the storage
/// layer, and the maintenance kinds are unreachable — the writability test
/// above has already rejected them.
///
/// A FACET is a scenario mask, never a store for PERSON identity: an
/// identity-shaped FACET body takes the shared sync identity refusal before an
/// import receipt can be staged, so a peer cannot confirm bytes that
/// materialization must discard.
#[cfg(feature = "sync")]
fn validate_admitted_replicated_body(id: &EntityId, entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type != crate::registry::ENTITY_TYPE_AGENT_DEF {
        crate::agent_def::validate_put_at_seeded_id(id, entity_type, None)?;
    }
    validate_sync_identity_body(entity_type, body)?;
    match entity_type {
        crate::registry::ENTITY_TYPE_RECEIPT_RECORD => {
            crate::receipt::validate_receipt_record_body(id, body)?;
        }
        crate::registry::ENTITY_TYPE_TASK => {
            crate::habit::task_role_from_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_CODE_ARTIFACT => {
            crate::code_artifact::validate_code_artifact_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_BLOB_ARTIFACT => {
            crate::blob_artifact::validate_blob_artifact_body_bytes(body)?;
        }
        crate::registry::ENTITY_TYPE_SKILL => {
            crate::skill::decode_skill_record(body)?;
        }
        crate::registry::ENTITY_TYPE_AGENT_DEF => {
            let definition = crate::agent_def::decode_agent_definition(body)?;
            crate::agent_def::validate_reserved_logical_id(id, &definition)?;
            crate::agent_def::validate_put_at_seeded_id(id, entity_type, Some(&definition))?;
        }
        _ => {}
    }
    Ok(())
}

/// The one sync identity-body refusal. PERSON holds identity and a FACET is a
/// scenario mask, so a FACET body shaped as a persona or relationship is
/// refused. Federated body admission and raw full-window admission both call
/// this; neither copies the predicate.
#[cfg(feature = "sync")]
pub(in crate::sync) fn validate_sync_identity_body(entity_type: u8, body: &[u8]) -> Result<()> {
    if entity_type == crate::registry::ENTITY_TYPE_FACET
        && crate::companion::is_identity_facet_body(body)
    {
        return Err(Error::InvalidClaimBody(
            "FACET cannot carry PERSON identity",
        ));
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn reject_federated_tombstones(source: &LoroDoc) -> Result<()> {
    let mut has_tombstone = false;
    map_for_each_tombstone_value(&source.get_map("tombstones"), |_, _| {
        has_tombstone = true;
    });
    if has_tombstone {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::FederatedTombstoneAdmission,
        ));
    }
    Ok(())
}

#[cfg(all(test, feature = "sync"))]
mod retired_facet_tests {
    use super::*;

    #[test]
    fn valid_legacy_facet_refused_before_sync_admission_but_scenario_is_allowed() {
        let person = crate::test_util::entity(0x71);
        let id = crate::test_util::entity(0x72);
        let legacy = crate::companion::tests::support::retired_persona_facet_body(person);
        assert!(matches!(
            validate_admitted_replicated_body(&id, crate::registry::ENTITY_TYPE_FACET, &legacy),
            Err(Error::Record(RecordError::InvalidCompanionRecordBody(_)))
        ));
        let scenario = rmp_serde::to_vec_named(&serde_json::json!({
            "kind": "scenario", "person_ref": person.to_hex()
        }))
        .expect("scenario fixture");
        assert!(
            validate_admitted_replicated_body(&id, crate::registry::ENTITY_TYPE_FACET, &scenario,)
                .is_ok()
        );
    }
}

#[cfg(all(test, feature = "sync"))]
mod suppression_carrier_tests {
    use super::*;
    use crate::receipt::{ReceiptKind, ReceiptRecord};
    use serde::Serialize;

    #[derive(Serialize)]
    struct ForgedCarrier {
        intent_id: [u8; 32],
        receipt: ReceiptRecord,
    }

    #[test]
    fn replicated_admission_refuses_truncated_and_wrong_id_suppression_assets() {
        let id = EntityId::from_bytes([0x87; 16]).expect("fixture id");
        let malformed = b"invalid receipt";
        assert!(
            validate_admitted_replicated_body(
                &id,
                crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                malformed
            )
            .is_err()
        );
        let receipt = ReceiptRecord {
            receipt_id: format!(
                "outbound:suppression:{}",
                crate::entity_id::bytes_to_hex_lower(&[0x88; 32])
            ),
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 1,
            actor: None,
            on_behalf_of: None,
            outcome: "suppressed".to_owned(),
            job_ref: None,
            trigger_ref: None,
            policy_trace: Vec::new(),
            fields: [
                ("suppression".to_owned(), "dedupe".to_owned()),
                ("dedupe_key".to_owned(), "same".to_owned()),
            ]
            .into(),
        };
        let body = rmp_serde::to_vec_named(&ForgedCarrier {
            intent_id: [0x88; 32],
            receipt,
        })
        .expect("encode forged carrier");
        assert!(
            validate_admitted_replicated_body(
                &id,
                crate::registry::ENTITY_TYPE_RECEIPT_RECORD,
                &body
            )
            .is_err()
        );
    }
}
