//! Typed inputs for owner configuration and policy-governed outbound decisions.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Result, Vault};

use super::{PolicyClassifyRequest, PolicyClassifySubject, PolicyRowChange, PolicyRowReceipt};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRowChangeRequest {
    pub change: PolicyRowChange,
}

/// No verdict, caller identity, policy document or attestation is accepted here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyOutboundRequest {
    pub subject: PolicyClassifySubject,
    pub content: String,
    #[serde(default)]
    pub world_ref: Option<String>,
    #[serde(default)]
    pub project_ref: Option<String>,
}

impl PolicyOutboundRequest {
    /// Read named scope records under the caller's credential before classifying.
    pub fn into_request(self, memory: &Memory<'_>) -> MemoryResult<PolicyClassifyRequest> {
        memory.with_verified_actor_write_txn(|_| Ok(()))?;
        let refs: Vec<String> = self.world_ref.iter().chain(self.project_ref.iter()).cloned().collect();
        if !refs.is_empty() {
            memory.hydrate(&refs)?;
        }
        Ok(PolicyClassifyRequest {
            subject: self.subject,
            content: self.content,
            world_ref: self.world_ref,
            project_ref: self.project_ref,
            caller_ref: Some(memory.actor().to_hex()),
            concerned_person: None,
        })
    }
}

pub fn change_owner_policy_row(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PolicyRowChangeRequest,
) -> Result<PolicyRowReceipt> {
    vault.change_policy_row(owner, input.change, crate::unix_seconds_now())
}

/// Validate configured patterns with the classifier's own compiler.
pub(crate) fn validate_owner_patterns(
    patterns: &[super::PolicyPatternRule],
    row_refs: &[String],
) -> Result<()> {
    super::pattern::compile_pattern_rules(patterns, &|category| row_refs.iter().any(|row| row == category))
        .map(|_| ())
        .map_err(|defect| crate::Error::InvalidConfig(format!("{} {}", defect.field, defect.reason)))
}

/// A hosted decision emits evidence and never accepts it back as authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedRelayDecision {
    pub service_identity: String,
    pub verdict: Option<super::PolicyClassifyVerdict>,
    pub degraded: Option<super::RelayBoundaryDegrade>,
    pub resolution: Option<super::RelayResolution>,
    pub hosted_evidence: Option<super::HostedPassEvidence>,
    pub receipt_ref: Option<String>,
    pub final_content: Option<String>,
    pub outbound_halted: bool,
    pub system_notice: Option<String>,
    pub system_notices: Vec<crate::store::GateSystemNoticeRecord>,
}

/// Enforce the relay's own pass, including its fail-closed outage and notice.
/// The identity, policy, verdict source and notice text all belong to the host.
#[expect(clippy::too_many_arguments)]
pub async fn enforce_hosted_relay(
    vault: &Vault,
    request: PolicyClassifyRequest,
    domain: &super::AttestedRelayDomain,
    registry: &super::EdgeServiceRegistry,
    config: &super::PolicyModelConfig,
    safeguard: Option<super::RelaySafeguardTier<'_>>,
    verdicts: &dyn super::VaultSideVerdictSource,
    unavailable_notice: &str,
) -> Result<HostedRelayDecision> {
    validate_hosted_relay_notice(config, unavailable_notice)?;
    let policy = registry.hosted_legal_policy(domain.service_identity()).ok_or_else(|| {
        crate::Error::InvalidConfig("no hosted policy is bound to the attested relay".to_owned())
    })?;
    let (pass, receipt_ref) = vault.relay_boundary_pass_with_receipt(
        request.clone(), domain, registry, config, safeguard, verdicts,
    ).await?;
    let halted = pass.must_halt_relay();
    let verdict = pass.boundary_verdict().cloned();
    let mut system_notices: Vec<_> = verdict.as_ref().and_then(|verdict| {
        super::notice::policy_notice(verdict.decision, &verdict.category, Some(policy), config)
    }).into_iter().collect();
    if halted && pass.degraded().is_some() {
        system_notices.push(crate::store::GateSystemNoticeRecord {
            notice_type: "policy_relay_unavailable".to_owned(),
            channel: super::notice::SYSTEM_NOTICE_CHANNEL.to_owned(),
            voice: super::notice::SYSTEM_NOTICE_VOICE_SYSTEM.to_owned(),
            audience: super::notice::SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL.to_owned(),
            body: unavailable_notice.to_owned(),
            row_ref: None,
            setting_change_offer: super::notice::safe_setting_change_offer(config.hosted_local_model_offer.as_ref()),
            policy_plane: Some(super::PolicyPlane::HostedLegal.as_str().to_owned()),
            policy_version: Some(policy.version.clone()),
            docs_url: Some(policy.docs_url.clone()),
        });
    }
    let hosted_evidence = match &pass {
        super::RelayBoundaryPass::Classified(classified) => classified.hosted_evidence.clone(),
        _ => None,
    };
    Ok(HostedRelayDecision {
        service_identity: domain.service_identity().to_owned(),
        verdict,
        degraded: pass.degraded(),
        resolution: pass.resolution(),
        hosted_evidence,
        receipt_ref,
        final_content: (!halted).then_some(request.content),
        outbound_halted: halted,
        system_notice: super::notice::default_system_notice(&system_notices),
        system_notices,
    })
}

/// Validate a hosted door against the engine's existing notice bounds.
pub fn validate_hosted_relay_notice(config: &super::PolicyModelConfig, body: &str) -> Result<()> {
    if config.hosted_outage_policy != super::HostedOutagePolicy::Halt
        || body.trim().is_empty()
        || body.len() > crate::store::GATE_SYSTEM_NOTICE_BODY_MAX_LEN
        || super::notice::safe_setting_change_offer(config.hosted_local_model_offer.as_ref()).is_none() {
        return Err(crate::Error::InvalidConfig(
            "a hosted policy door needs halt posture, a bounded service notice and a local-model offer".to_owned(),
        ));
    }
    Ok(())
}

/// Embedded owner-plane calls use the same engine with no fabricated model answer.
pub fn enforce_owner_policy_embedded(memory: &Memory<'_>, input: PolicyOutboundRequest) -> MemoryResult<super::PolicyModelEnforcement> {
    let request = input.into_request(memory)?;
    memory.vault().enforce_policy_model(request).map_err(Into::into)
}

/// All policy contributions the resolver may read, including the default manifest.
pub fn policy_manifest_sources(vault: &Vault) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store, &txn, crate::registry::ENTITY_TYPE_POLICY_MANIFEST, None,
    )?.collect()
}
