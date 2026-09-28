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
        let mut wtxn = vault.store.env.write_txn()?;
        if let Some(admission) = read_publish_admission(vault, &wtxn, &request.publish_id)? {
            check_replay_binding(&admission, request)?;
            let gate = admitted_gate(vault, &wtxn, &admission)?;
            let receipt = publish_receipt(request.publish_id, &admission, &gate);
            // An earlier effect remains receipted even if its pointer was
            // subsequently unpublished or moved. Replay never resurrects it.
            drop(wtxn);
            let owner = vault.resolve_export_owner(&request.artifact, request.export)?;
            let pointer = vault
                .artifact_pointer(&request.artifact, request.channel)?
                .filter(|pointer| {
                    pointer.export == admission.export
                        && pointer.serve_tier == admission.serve_tier
                        && owner == Some(admission.export_entity_id)
                });
            return Ok(ArtifactPublishVerbOutcome {
                status: ArtifactPublishVerbStatus::Published,
                pointer,
                receipt: Some(receipt),
                gate_decision_ref: format!("gate:{}", admission.gate_id.to_hex()),
            });
        }
        let snapshot = match request.export {
            ArtifactExportRef::ForkHash(hash) => Some(
                vault
                    .resolve_artifact_snapshot_by_fork(&request.artifact, &hash)?
                    .ok_or(Error::EntityNotFound)?,
            ),
            ArtifactExportRef::BlobVersion { .. } => None,
        };
        let export_entity_id = if let Some(snapshot) = &snapshot {
            snapshot.code_artifact_id
        } else {
            vault
                .resolve_export_owner_in_txn(&wtxn, &request.artifact, request.export)?
                .ok_or(Error::EntityNotFound)?
        };
        let actor_type = vault
            .get_entity_type_in_txn(&wtxn, &request.actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
        crate::provenance::validate_actor_class(actor_type, request.actor.actor_class())?;
        let effect = publish_effect(request);
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
        let pointer = if let Some(snapshot) = &snapshot {
            publish_artifact_pointer_in_txn(
                vault,
                &mut wtxn,
                snapshot,
                request.channel,
                request.serve_tier,
            )?
        } else {
            vault.publish_export_pointer_in_txn(
                &mut wtxn,
                &request.artifact,
                request.channel,
                request.export,
                request.serve_tier,
            )?
        };
        let admission = ArtifactPublishAdmission {
            artifact: request.artifact.clone(),
            channel: request.channel.key_byte(),
            export: request.export,
            export_entity_id,
            actor: request.actor.entity_ref(),
            actor_class: request.actor.actor_class().gate_actor_class().to_owned(),
            gate_id,
            occurred_at: request.occurred_at,
            stale_taint_override: pointer.stale_taint_override,
            serve_tier: request.serve_tier,
        };
        ARTIFACT_ADMISSIONS.put(&vault.store, &mut wtxn, &request.publish_id, &admission)?;
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

pub(super) fn artifact_publish_approval_digest(
    vault: &Vault,
    request: &ArtifactPublishVerbRequest,
) -> Result<crate::consent::EffectDigest> {
    validate_artifact_id(&request.artifact)?;
    vault
        .resolve_export_owner(&request.artifact, request.export)?
        .ok_or(Error::EntityNotFound)?;
    let actor_type = vault
        .get_entity_type(&request.actor.entity_ref())?
        .ok_or(Error::EntityNotFound)?;
    crate::provenance::validate_actor_class(actor_type, request.actor.actor_class())?;
    gate::external_effect_approval_digest(&publish_effect(request))
        .ok_or(Error::InvariantViolation("artifact publish approval bound"))
}

fn publish_effect(request: &ArtifactPublishVerbRequest) -> ExternalEffectGateInput {
    let tier = match request.serve_tier {
        ArtifactServeTier::Private => "private".to_owned(),
        ArtifactServeTier::Public => "public".to_owned(),
        ArtifactServeTier::LinkToken(capability) => format!("link:{}", artifact_hex(&capability.0)),
        ArtifactServeTier::WorldMembers(world_id) => format!("world:{world_id}"),
    };
    let export_ref = match request.export {
        ArtifactExportRef::ForkHash(hash) => artifact_hex(&hash),
        ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        } => {
            format!("blob:{}:{version}", artifact_id.to_hex())
        }
    };
    ExternalEffectGateInput {
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
        brief_ref: Some(format!(
            "artifact:{}:{}:{}:{}:{}",
            request.publish_id.to_hex(),
            request.artifact,
            request.channel.as_str(),
            export_ref,
            tier,
        )),
        send_ref: Some(format!(
            "artifact:{}:{}:{}:{}:{}",
            request.publish_id.to_hex(),
            request.artifact,
            request.channel.as_str(),
            export_ref,
            tier,
        )),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::HoldToProposal,
    }
}

pub(super) fn publish_artifact_pointer_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    snapshot: &ArtifactSnapshotRef,
    channel: ArtifactPointerChannel,
    serve_tier: ArtifactServeTier,
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
        ArtifactExportRef::ForkHash(snapshot.fork_hash),
        stale_taint_override,
        serve_tier,
    )?;
    Ok(ArtifactPointer {
        artifact: snapshot.artifact.clone(),
        channel,
        export: ArtifactExportRef::ForkHash(snapshot.fork_hash),
        stale_taint_override,
        serve_tier,
    })
}

fn read_publish_admission(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ArtifactPublishAdmission>> {
    let admission = ARTIFACT_ADMISSIONS
        .get(&vault.store, txn, id)
        .map_err(|error| {
            if error.kind() == crate::ErrorKind::SideTableRow {
                Error::CorruptedIndex("artifact publish admission")
            } else {
                error
            }
        })?;
    if admission
        .as_ref()
        .is_some_and(|record| record.channel > ARTIFACT_CHANNEL_PREVIEW)
    {
        return Err(Error::CorruptedIndex("artifact publish channel"));
    }
    if let Some(ref record) = admission
        && let ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        } = record.export
        && (version == 0
            || record.artifact != artifact_id.to_hex()
            || record.export_entity_id != artifact_id)
    {
        return Err(Error::CorruptedIndex("artifact publish blob binding"));
    }
    Ok(admission)
}

fn check_replay_binding(
    admission: &ArtifactPublishAdmission,
    request: &ArtifactPublishVerbRequest,
) -> Result<()> {
    if admission.artifact != request.artifact
        || admission.channel != request.channel.key_byte()
        || admission.export != request.export
        || admission.actor != request.actor.entity_ref()
        || admission.actor_class != request.actor.actor_class().gate_actor_class()
        || admission.occurred_at != request.occurred_at
        || admission.serve_tier != request.serve_tier
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
    let mut fields = BTreeMap::from([
        ("artifact".to_owned(), admission.artifact.clone()),
        (
            "channel".to_owned(),
            if admission.channel == ARTIFACT_CHANNEL_PUBLISHED {
                "published".to_owned()
            } else {
                "preview".to_owned()
            },
        ),
        ("gate_receipt_ref".to_owned(), gate_ref.clone()),
        (
            "serve_tier".to_owned(),
            format!("{:?}", admission.serve_tier),
        ),
        (
            "stale_taint_override".to_owned(),
            admission.stale_taint_override.to_string(),
        ),
    ]);
    match admission.export {
        ArtifactExportRef::ForkHash(hash) => {
            fields.insert("fork_hash".to_owned(), artifact_hex(&hash));
            fields.insert(
                "code_artifact_id".to_owned(),
                admission.export_entity_id.to_hex(),
            );
        }
        ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        } => {
            fields.insert("blob_artifact_id".to_owned(), artifact_id.to_hex());
            fields.insert("blob_version".to_owned(), version.to_string());
        }
    }
    ReceiptRecord {
        receipt_id: format!("share:artifact:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at: admission.occurred_at,
        actor: Some(admission.actor.to_hex()),
        on_behalf_of: None,
        outcome: "published".to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: std::iter::once(gate_ref)
            .chain(crate::receipt::gate_decision_receipt(gate).policy_trace)
            .collect(),
        fields,
    }
}

/// The admitted publish's original decision remains necessary for idempotent
/// replay and its receipt even after pointer removal or snapshot eviction.
pub(crate) fn artifact_publish_gate_refs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<std::collections::HashSet<crate::store::GateDecisionId>> {
    let mut ids = std::collections::HashSet::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, ARTIFACT_PUBLISH_ADMISSION_PREFIX)?
    {
        let (key, raw) = row?;
        let id = key
            .strip_prefix(ARTIFACT_PUBLISH_ADMISSION_PREFIX)
            .ok_or(Error::CorruptedIndex("artifact publish admission key"))?;
        let _: [u8; 16] = id
            .try_into()
            .map_err(|_| Error::CorruptedIndex("artifact publish admission key"))?;
        ids.insert(decode_publish_admission(&raw)?.gate_id);
    }
    Ok(ids)
}

pub(crate) fn artifact_publish_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for row in ARTIFACT_ADMISSIONS.iter_from(&vault.store, txn, &[])? {
        let (id, admission) = row?;
        if admission.channel > ARTIFACT_CHANNEL_PREVIEW {
            return Err(Error::CorruptedIndex("artifact publish channel"));
        }
        let gate = admitted_gate(vault, txn, &admission)?;
        let receipt = publish_receipt(id, &admission, &gate);
        if query.matches(&receipt) {
            crate::receipt::retain_newest_receipt(&mut receipts, receipt, query.limit);
        }
    }
    Ok(receipts)
}
