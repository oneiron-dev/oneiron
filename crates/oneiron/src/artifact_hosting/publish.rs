//! The OF-327 artifact-publish dispatch door and its share-style receipt projection.

use super::*;

impl OutboundDispatchPipeline {
    /// Authorize one exact public pointer update before making it visible. Gate,
    /// live grant, taint, pointer and admission all share one write transaction.
    pub(super) fn dispatch_artifact_publish(
        self,
        vault: &Vault,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<ArtifactPublishVerbOutcome> {
        validate_artifact_id(&request.artifact)?;
        let snapshot = vault
            .resolve_artifact_snapshot_by_fork(&request.artifact, &request.fork_hash)?
            .ok_or(Error::EntityNotFound)?;
        let key = publish_admission_key(request.publish_id);
        let mut wtxn = vault.store.env.write_txn()?;
        let actor_type = vault
            .get_entity_type_in_txn(&wtxn, &request.actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
        crate::provenance::validate_actor_class(actor_type, request.actor.actor_class())?;
        if let Some(raw) = vault.store.vault_meta.get(&wtxn, &key)? {
            let admission = decode_publish_admission(&raw)?;
            check_replay_binding(&admission, request, snapshot.code_artifact_id)?;
            let gate = admitted_gate(vault, &wtxn, &admission)?;
            let receipt = publish_receipt(request.publish_id, &admission, &gate);
            // An earlier effect remains receipted even if its pointer was
            // subsequently unpublished or moved. Replay never resurrects it.
            drop(wtxn);
            let pointer = vault
                .artifact_pointer(&request.artifact, request.channel)?
                .filter(|pointer| pointer.fork_hash == request.fork_hash);
            return Ok(ArtifactPublishVerbOutcome {
                status: ArtifactPublishVerbStatus::Published,
                pointer,
                receipt: Some(receipt),
                gate_decision_ref: format!("gate:{}", admission.gate_id.to_hex()),
            });
        }
        let effect = ExternalEffectGateInput {
            actor: GateActor {
                actor_class: request.actor.actor_class().gate_actor_class().to_owned(),
                actor_ref: Some(request.actor.entity_ref().to_hex()),
                delegation_grant_ref: None,
            },
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(request.actor.entity_ref()),
                ..GateProvenanceHandles::default()
            },
            verb: "publish".to_owned(),
            channel: "artifact".to_owned(),
            channel_identity_ref: None,
            counterparty: Some(request.artifact.clone()),
            brief_ref: None,
            send_ref: Some(format!(
                "artifact:{}:{}:{}:{}",
                request.publish_id.to_hex(),
                request.artifact,
                request.channel.as_str(),
                artifact_hex(&request.fork_hash),
            )),
            standing_grant_ref: None,
            scoped_mcp_call: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: false,
            has_permission: true,
            policy_risk: ExternalEffectPolicyRisk::HoldToProposal,
        };
        let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
        let (gate_id, decision, _) =
            gate::check_external_effect_policy(&vault.store, &mut wtxn, &effect, &policy, true)?;
        if decision.outcome() != GateOutcome::Allow {
            wtxn.commit()?;
            return Ok(ArtifactPublishVerbOutcome {
                status: ArtifactPublishVerbStatus::Proposed,
                pointer: None,
                receipt: None,
                gate_decision_ref: format!("gate:{}", gate_id.to_hex()),
            });
        }
        let pointer =
            publish_artifact_pointer_in_txn(vault, &mut wtxn, &snapshot, request.channel)?;
        let admission = ArtifactPublishAdmission {
            artifact: request.artifact.clone(),
            channel: request.channel.key_byte(),
            fork_hash: request.fork_hash,
            code_artifact_id: snapshot.code_artifact_id,
            actor: request.actor.entity_ref(),
            actor_class: request.actor.actor_class().gate_actor_class().to_owned(),
            gate_id,
            occurred_at: request.occurred_at,
            stale_taint_override: pointer.stale_taint_override,
        };
        let bytes = serde_json::to_vec(&admission)
            .map_err(|_| Error::InvariantViolation("artifact publish admission encode"))?;
        vault.store.vault_meta.put(&mut wtxn, &key, &bytes)?;
        wtxn.commit()?;
        let rtxn = vault.store.env.read_txn()?;
        let gate = admitted_gate(vault, &rtxn, &admission)?;
        Ok(ArtifactPublishVerbOutcome {
            status: ArtifactPublishVerbStatus::Published,
            pointer: Some(pointer),
            receipt: Some(publish_receipt(request.publish_id, &admission, &gate)),
            gate_decision_ref: format!("gate:{}", gate_id.to_hex()),
        })
    }
}

pub(super) fn publish_artifact_pointer_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    snapshot: &ArtifactSnapshotRef,
    channel: ArtifactPointerChannel,
) -> Result<ArtifactPointer> {
    if !crate::codebase::codebase_artifact_snapshot_matches_in_txn(
        &vault.store,
        wtxn,
        &snapshot.code_artifact_id,
        &snapshot.artifact,
        &snapshot.fork_hash,
    )? {
        return Err(Error::EntityNotFound);
    }
    let refs = exhaust_taint_refs_in_txn(&vault.store, wtxn, &snapshot.code_artifact_id)?;
    let stale_taint_override = match taint_state_for_refs_in_txn(&vault.store, wtxn, &refs)? {
        ArtifactTaintState::Clean | ArtifactTaintState::TaintedLive => false,
        ArtifactTaintState::TaintedStale => {
            if !allow_stale_publish_in_txn(&vault.store, wtxn)? {
                return Err(Error::Secret(SecretError::TaintedArtifactStale {
                    artifact: snapshot.artifact.clone(),
                }));
            }
            true
        }
    };
    put_artifact_pointer_in_txn(
        &vault.store,
        wtxn,
        &snapshot.artifact,
        channel,
        &snapshot.fork_hash,
        stale_taint_override,
    )?;
    Ok(ArtifactPointer {
        artifact: snapshot.artifact.clone(),
        channel,
        fork_hash: snapshot.fork_hash,
        code_artifact_id: snapshot.code_artifact_id,
        stale_taint_override,
    })
}

fn publish_admission_key(id: EntityId) -> Vec<u8> {
    [ARTIFACT_PUBLISH_ADMISSION_PREFIX, id.as_bytes().as_slice()].concat()
}

fn decode_publish_admission(raw: &[u8]) -> Result<ArtifactPublishAdmission> {
    let admission: ArtifactPublishAdmission = serde_json::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("artifact publish admission"))?;
    if admission.channel > ARTIFACT_CHANNEL_PREVIEW {
        return Err(Error::CorruptedIndex("artifact publish channel"));
    }
    Ok(admission)
}

fn check_replay_binding(
    admission: &ArtifactPublishAdmission,
    request: &ArtifactPublishVerbRequest,
    code_artifact_id: EntityId,
) -> Result<()> {
    if admission.artifact != request.artifact
        || admission.channel != request.channel.key_byte()
        || admission.fork_hash != request.fork_hash
        || admission.code_artifact_id != code_artifact_id
        || admission.actor != request.actor.entity_ref()
        || admission.actor_class != request.actor.actor_class().gate_actor_class()
        || admission.occurred_at != request.occurred_at
    {
        return Err(Error::InvariantViolation("artifact publish id rebound"));
    }
    Ok(())
}

fn admitted_gate(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    admission: &ArtifactPublishAdmission,
) -> Result<crate::store::GateDecisionRecord> {
    let gate = vault
        .store
        .gate_decision_in_txn(txn, admission.gate_id)?
        .ok_or(Error::CorruptedIndex("artifact publish gate missing"))?;
    if gate.outcome != "allow"
        || gate.redacted_at.is_some()
        || gate.content_kind != "external_effect"
        || gate.actor_ref.as_deref() != Some(admission.actor.to_hex().as_str())
        || gate.actor_class != admission.actor_class
    {
        return Err(Error::CorruptedIndex("artifact publish gate binding"));
    }
    Ok(gate)
}

fn publish_receipt(
    id: EntityId,
    admission: &ArtifactPublishAdmission,
    gate: &crate::store::GateDecisionRecord,
) -> ReceiptRecord {
    let gate_ref = format!("gate:{}", admission.gate_id.to_hex());
    ReceiptRecord {
        receipt_id: format!("share:artifact:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at: admission.occurred_at,
        actor: Some(admission.actor.to_hex()),
        on_behalf_of: None,
        outcome: "published".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: std::iter::once(gate_ref.clone())
            .chain(crate::receipt::gate_decision_receipt(gate).policy_trace)
            .collect(),
        fields: BTreeMap::from([
            ("artifact".to_owned(), admission.artifact.clone()),
            (
                "channel".to_owned(),
                if admission.channel == ARTIFACT_CHANNEL_PUBLISHED {
                    "published".to_owned()
                } else {
                    "preview".to_owned()
                },
            ),
            ("fork_hash".to_owned(), artifact_hex(&admission.fork_hash)),
            (
                "code_artifact_id".to_owned(),
                admission.code_artifact_id.to_hex(),
            ),
            ("gate_receipt_ref".to_owned(), gate_ref),
            (
                "stale_taint_override".to_owned(),
                admission.stale_taint_override.to_string(),
            ),
        ]),
    }
}

pub(crate) fn artifact_publish_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, ARTIFACT_PUBLISH_ADMISSION_PREFIX)?
    {
        let (key, value) = row?;
        let raw_id = key
            .strip_prefix(ARTIFACT_PUBLISH_ADMISSION_PREFIX)
            .ok_or(Error::CorruptedIndex("artifact publish admission key"))?;
        let id = EntityId::from_bytes(
            raw_id
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact publish admission key"))?,
        )
        .map_err(|_| Error::CorruptedIndex("artifact publish admission key"))?;
        let admission = decode_publish_admission(&value)?;
        let gate = admitted_gate(vault, txn, &admission)?;
        let receipt = publish_receipt(id, &admission, &gate);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}
