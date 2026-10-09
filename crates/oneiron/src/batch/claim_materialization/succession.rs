//! Claim succession: a weakening or a facet fork births a new claim from its
//! predecessor's exact body, never rewriting the predecessor.

use rmpv::Value;

use super::demotion::successor_body;
use super::{ClaimMaterialization, binding_error};
use crate::batch::{ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSource, ClaimSuccession, decode_claim_body, encode_claim_body};
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::write_envelope::{
    MachineWriteSignature, SourceLineage, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
    WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY, WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY, WriteActor,
    WriteEnvelope, WriteProvenance, write_envelope_evidence,
};
use crate::{EntityId, Vault};

/// The writer that births a claim successor. A successor is written under
/// this writer's own authority and stamp, never its predecessor's author's:
/// continuing a claim lends no one the right its author had to write it. The
/// predecessor stays the successor's provenance: the edges the caller links,
/// the evidence and source lineage the successor carries forward, and the
/// provenance record that names it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct SuccessionWriter {
    /// `None` is the host's own unattributed act, written unbound like any
    /// raw local write.
    actor: Option<WriteActor>,
    /// A machine act: a non-human actor, or a decision declared `Generated`.
    /// Its successor is `Generated`, so it never supersedes user truth.
    generated: bool,
    /// The door that acts, recorded in the successor's provenance.
    surface: &'static str,
}

impl SuccessionWriter {
    /// `declared` is the source the acting door declares for its decision.
    pub(crate) fn new(
        actor: Option<WriteActor>,
        declared: ClaimSource,
        surface: &'static str,
    ) -> Self {
        Self {
            // The stamp must re-derive from the actor a ledger event records,
            // so it carries no authority frontier.
            actor: actor.map(|actor| WriteActor::new(actor.entity_ref(), actor.actor_class())),
            generated: declared == ClaimSource::Generated
                || actor.is_some_and(|actor| actor.actor_class() != EdgeActorClass::Human),
            surface,
        }
    }

    /// The acting writer, which also signs the close of a MACHINE-born
    /// predecessor its successor supersedes (`None`: the host's own act).
    pub(crate) const fn actor(&self) -> Option<WriteActor> {
        self.actor
    }

    /// Refuses a machine writer's successor of user truth before anything is
    /// written. Every machine succession closes its predecessor, and a
    /// `Generated` claim never supersedes a `UserStated` or legacy unstamped
    /// one (ARCH-0026: the host stamps machine writes `Generated`).
    pub(crate) fn require_may_succeed(&self, prior: &ClaimBody) -> Result<()> {
        if !self.generated {
            return Ok(());
        }
        let mut successor = prior.clone();
        successor.source = Some(ClaimSource::Generated);
        Vault::require_source_trust_supersession_rights(&successor, prior)
    }

    /// The successor body this writer births from `prior`, its active
    /// predecessor, and the envelope it writes under (`None`: unbound). The
    /// body is `prior`'s with the one delta `succession` permits; only its
    /// source and evidence stamp change hands. A machine writer stamps
    /// `Generated`; a person keeps the predecessor's source. A MACHINE
    /// writer's body still has to be signed: its envelope carries a zeroed
    /// signature slot until then.
    pub(crate) fn successor(
        &self,
        predecessor: &EntityId,
        prior: &ClaimBody,
        succession: ClaimSuccession,
    ) -> Result<(ClaimBody, Option<WriteEnvelope>)> {
        let mut next = successor_body(prior, succession)?;
        let source = if self.generated {
            Some(ClaimSource::Generated)
        } else {
            prior.source
        };
        next.source = source;
        next.evidence = carried_evidence(prior);
        let Some(actor) = self.actor else {
            return Ok((next, None));
        };
        let source = source.unwrap_or(ClaimSource::UserStated);
        let mut lineage = SourceLineage::of(source);
        for carried in prior_lineage(prior) {
            lineage = lineage.with(carried);
        }
        let provenance = WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from(self.surface)),
            (
                Value::from("predecessor"),
                Value::Binary(predecessor.as_bytes().to_vec()),
            ),
        ]))?;
        let mut envelope =
            WriteEnvelope::with_lineage(actor, source, provenance, prior.approval, lineage);
        if let Some(tag) = &prior.session_tag {
            envelope = envelope.with_session_tag(tag);
        }
        if actor.actor_class() == EdgeActorClass::System {
            envelope = envelope.with_machine_signature(MachineWriteSignature {
                public_key: [0; 32],
                signature: [0; 64],
            });
        }
        next.source = Some(source);
        next.evidence = Some(write_envelope_evidence(&envelope, next.evidence.take()));
        Ok((next, Some(envelope)))
    }
}

/// The evidence a successor carries forward: the evidence its predecessor's
/// writer supplied, without that writer's stamp. A raw predecessor's
/// evidence carries no stamp, so it travels whole.
fn carried_evidence(prior: &ClaimBody) -> Option<Value> {
    match &prior.evidence {
        Some(Value::Map(entries))
            if entries
                .iter()
                .any(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)) =>
        {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
                .map(|(_, value)| value.clone())
        }
        evidence => evidence.clone(),
    }
}

/// The source classes the predecessor's history drew on: its declared source
/// and its stamped lineage.
fn prior_lineage(prior: &ClaimBody) -> Vec<ClaimSource> {
    let mut sources: Vec<ClaimSource> = prior.source.into_iter().collect();
    if let Some(Value::Map(entries)) = &prior.evidence
        && let Some((_, Value::Array(stamped))) = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY))
    {
        sources.extend(
            stamped
                .iter()
                .filter_map(|value| value.as_str().and_then(ClaimSource::parse)),
        );
    }
    sources
}

impl ClaimMaterialization {
    /// Whether a succession may copy this claim: its row is live (no
    /// tombstone, deletion fence, pending delete or erased source) and no
    /// deletion of it is in flight. A hard delete's fence commits with its
    /// publication, before the purge, so the bytes it still holds are never
    /// permission to copy them under a fresh id.
    pub(crate) fn succession_source_live(
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        claim: &EntityId,
    ) -> Result<bool> {
        Ok(
            crate::vault::live_entity_row_in_txn(store, txn, claim)?.is_live()
                && crate::deletion::topology_delete_reservation_in_txn(store, txn, claim)?
                    .is_none(),
        )
    }

    /// Admit only a claim successor whose body is its predecessor's with the
    /// one delta `succession` permits, plus its ClaimOf edge at the
    /// predecessor's current (possibly decayed) weight and its facet stamp:
    /// a weakening keeps the predecessor's `facet_of` edges, a fork wears its
    /// new mask's when asked to. The successor is `writer`'s, stamped as
    /// [`SuccessionWriter::successor`] says and gated under its envelope; a
    /// MACHINE writer signs it with its own retained signer and gives it its
    /// own signed birth. A MACHINE predecessor is copied only once its signed
    /// history verifies. A deleted predecessor, or one whose deletion is in
    /// flight, has no successor. The caller links or closes the predecessor
    /// in the same txn.
    pub(crate) fn apply_successor(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        predecessor: &EntityId,
        successor: &EntityId,
        succession: ClaimSuccession,
        writer: SuccessionWriter,
        now: u64,
    ) -> Result<()> {
        if !Self::succession_source_live(&vault.store, txn, predecessor)? {
            return Err(Error::EntityNotFound);
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, predecessor)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        if crate::authority::machine_claim_needs_history(&vault.store, txn, &prior)?
            && !machine_predecessor_admitted(vault, txn, predecessor, &prior)?
        {
            return Err(binding_error());
        }
        writer.require_may_succeed(&prior)?;
        let (mut next, mut envelope) = writer.successor(predecessor, &prior, succession)?;
        let mut claim_of = None;
        if let crate::claim::ClaimSubject::Entity(subject) = prior.subject {
            let mut weight = None;
            for entry in crate::ports::EdgeStoreRead::port_edges(
                &vault.store,
                txn,
                predecessor,
                crate::ports::EdgeDirection::Out,
                Some(crate::edge::EdgeKind::ClaimOf),
                None,
            )? {
                let edge = entry?;
                if edge.target == subject && weight.replace(edge.weight).is_some() {
                    return Err(binding_error());
                }
            }
            claim_of = Some((subject, weight.ok_or(binding_error())?));
        }
        let stamps = match succession {
            ClaimSuccession::Weakening { .. } => {
                let mut stamps = Vec::new();
                for entry in crate::ports::EdgeStoreRead::port_edges(
                    &vault.store,
                    txn,
                    predecessor,
                    crate::ports::EdgeDirection::Out,
                    Some(crate::edge::EdgeKind::FacetOf),
                    None,
                )? {
                    let edge = entry?;
                    stamps.push((edge.target, edge.weight));
                }
                stamps
            }
            ClaimSuccession::Fork { facet, stamp } => {
                stamp.then_some((facet, 1.0)).into_iter().collect()
            }
        };
        let signed = envelope
            .as_ref()
            .is_some_and(|envelope| envelope.actor().actor_class() == EdgeActorClass::System);
        if let Some(envelope) = envelope.as_mut().filter(|_| signed) {
            vault.resign_machine_successor_in_txn(txn, successor, &mut next, envelope)?;
        }
        let occurred = crate::temporal::TimeRange {
            start: header.occurred_start,
            end: now,
        };
        let data = encode_claim_body(&next)?;
        let mut ops = vec![BatchOp::Put {
            id: *successor,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at: now,
            data: data.clone(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        if let Some((subject, weight)) = claim_of {
            ops.push(BatchOp::Edge {
                src: *successor,
                kind: crate::edge::EdgeKind::ClaimOf,
                tgt: subject,
                weight,
                vad: crate::affect::Vad::NEUTRAL,
            });
        }
        for (facet, weight) in stamps {
            ops.push(BatchOp::Edge {
                src: *successor,
                kind: crate::edge::EdgeKind::FacetOf,
                tgt: facet,
                weight,
                vad: crate::affect::Vad::NEUTRAL,
            });
        }
        let transition = crate::batch::VerifiedClaimTransition::after_validated_succession(
            &vault.store,
            txn,
            predecessor,
            &ops[0],
        )?;
        let mut bindings = Vec::new();
        if let Some(envelope) = envelope.clone() {
            let binding = Self {
                id: *successor,
                occurred,
                learned_at: now,
                data,
                reserved: false,
                envelope,
                prior: None,
                approval: false,
            };
            binding.validate_actor(&vault.store, txn)?;
            bindings.push(binding);
        }
        let text_index_trusted = vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire);
        crate::batch::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            ops,
            text_index_trusted,
            // A fresh fork is a birth like any other, so an Auto critical
            // claim gets its critical-confirm attachment. A weakening lands
            // only once a critical demotion's owner clear has settled.
            ApplyOpsGateMode::new(false, matches!(succession, ClaimSuccession::Fork { .. }))
                .with_claim_materializations(bindings)
                .with_verified_claim_transitions(vec![transition]),
        )?;
        match envelope {
            Some(envelope) if signed => {
                crate::claim::history_store::stage_machine_birth_after_candidate(
                    &vault.store,
                    &vault.config,
                    &vault.analyzer,
                    txn,
                    *successor,
                    &next,
                    &envelope,
                    occurred,
                    now,
                    text_index_trusted,
                    false,
                )
            }
            _ => Ok(()),
        }
    }
}

/// A MACHINE claim's content is copied only while its trusted signed history
/// verifies against the current row: an unverified one, such as a replicated
/// row whose history has not arrived, is not admitted content.
fn machine_predecessor_admitted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        &vault.store,
        vault.config.privacy.posture,
        txn,
    )?;
    crate::authority::machine_claim_read_admitted(&vault.store, txn, &fold, id, body)
}
