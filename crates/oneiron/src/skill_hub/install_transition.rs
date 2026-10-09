//! One transaction-local skill install plan and its finalized, loadable result.
use super::{HubRef, MarketplaceFit, SkillCapabilitySurface, package_codec::invalid};
use crate::{
    Vault,
    claim::ClaimApprovalStatus,
    entity_id::EntityId,
    error::Result,
    skill::{SkillContentHash, SkillLifecycle, SkillRecord, skill_loadable},
    temporal::TimeRange,
};

/// Lifecycle observed at the end of the install operation, not at source fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallLifecycle {
    Candidate,
    Active,
    Stale,
    Quarantined,
    Superseded,
}
impl InstallLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
        }
    }
}
impl From<SkillLifecycle> for InstallLifecycle {
    fn from(value: SkillLifecycle) -> Self {
        match value {
            SkillLifecycle::Candidate => Self::Candidate,
            SkillLifecycle::Active => Self::Active,
            SkillLifecycle::Stale => Self::Stale,
            SkillLifecycle::Quarantined => Self::Quarantined,
            SkillLifecycle::Superseded => Self::Superseded,
        }
    }
}

/// The locally owned decision that prevented an installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallHoldReason {
    SourceOnly,
    RulesHit,
    CodeAutoInstallOff,
    NoFit,
    LocalApproval,
    UnloadableApproval,
    Stale,
    Quarantined,
    Superseded,
}
impl InstallHoldReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceOnly => "source_only",
            Self::RulesHit => "rules_hit",
            Self::CodeAutoInstallOff => "code_auto_install_off",
            Self::NoFit => "not_fit",
            Self::LocalApproval => "local_decision",
            Self::UnloadableApproval => "unloadable_approval",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
        }
    }
}

/// A result may claim installed only when the committed record passes the loader's predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallDisposition {
    Installed,
    AlreadyInstalled,
    PendingPermission,
    NotInstalled(InstallHoldReason),
}
impl InstallDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::AlreadyInstalled => "already_installed",
            Self::PendingPermission => "ask_permissions",
            Self::NotInstalled(reason) => reason.as_str(),
        }
    }
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::PendingPermission)
    }
}

/// No caller can mint a success without checking the committed skill row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InstallResult {
    pub(super) lifecycle: InstallLifecycle,
    pub(super) disposition: InstallDisposition,
}
impl InstallResult {
    pub(super) fn finalized(record: &SkillRecord, disposition: InstallDisposition) -> Result<Self> {
        match disposition {
            InstallDisposition::Installed | InstallDisposition::AlreadyInstalled
                if !skill_loadable(record) =>
            {
                return Err(invalid("installed skill is not loadable"));
            }
            InstallDisposition::PendingPermission
                if record.lifecycle_status != SkillLifecycle::Candidate
                    || record.approval_status != ClaimApprovalStatus::Auto =>
            {
                return Err(invalid("permission ask is not an answerable candidate"));
            }
            _ => {}
        }
        Ok(Self {
            lifecycle: record.lifecycle_status.into(),
            disposition,
        })
    }
}

/// Exact source/capabilities that the fit rung evaluated; the write checks them again.
#[derive(Debug, Clone)]
pub(super) struct InstallBinding {
    pub(super) source: HubRef,
    pub(super) hash: SkillContentHash,
    pub(super) capabilities: SkillCapabilitySurface,
}
impl InstallBinding {
    pub(super) fn new(
        source: &HubRef,
        hash: SkillContentHash,
        capabilities: &SkillCapabilitySurface,
    ) -> Self {
        Self {
            source: source.clone(),
            hash,
            capabilities: capabilities.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PostFitOrigin {
    Marketplace,
    Pack,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallAction {
    Activate(PostFitOrigin),
    OwnerAnswer,
    AlreadyInstalled,
    PendingPermission,
    Preserve(InstallHoldReason),
}

/// The only post-fit transition table. Arrival never revives a locally inactive holder.
#[derive(Debug, Clone)]
pub(super) struct InstallPlan {
    binding: InstallBinding,
    action: InstallAction,
}
impl InstallPlan {
    fn new(binding: InstallBinding, action: InstallAction) -> Self {
        Self { binding, action }
    }

    pub(super) fn marketplace(
        record: &SkillRecord,
        binding: InstallBinding,
        fit: MarketplaceFit,
        blocked: bool,
        code_allowed: bool,
    ) -> Self {
        let action = match record.lifecycle_status {
            SkillLifecycle::Stale => InstallAction::Preserve(InstallHoldReason::Stale),
            SkillLifecycle::Quarantined => InstallAction::Preserve(InstallHoldReason::Quarantined),
            SkillLifecycle::Superseded => InstallAction::Preserve(InstallHoldReason::Superseded),
            SkillLifecycle::Active if skill_loadable(record) => InstallAction::AlreadyInstalled,
            SkillLifecycle::Active => {
                InstallAction::Preserve(InstallHoldReason::UnloadableApproval)
            }
            SkillLifecycle::Candidate if record.approval_status != ClaimApprovalStatus::Auto => {
                InstallAction::Preserve(InstallHoldReason::LocalApproval)
            }
            SkillLifecycle::Candidate if blocked => {
                InstallAction::Preserve(InstallHoldReason::RulesHit)
            }
            SkillLifecycle::Candidate if !code_allowed => {
                InstallAction::Preserve(InstallHoldReason::CodeAutoInstallOff)
            }
            SkillLifecycle::Candidate => match fit {
                MarketplaceFit::Ready => InstallAction::Activate(PostFitOrigin::Marketplace),
                MarketplaceFit::Ask => InstallAction::PendingPermission,
                MarketplaceFit::NoFit => InstallAction::Preserve(InstallHoldReason::NoFit),
            },
        };
        Self::new(binding, action)
    }

    pub(super) fn pack(
        record: &SkillRecord,
        binding: InstallBinding,
        active: bool,
        blocked: bool,
        code_allowed: bool,
    ) -> Self {
        let fit = if active {
            MarketplaceFit::Ready
        } else {
            MarketplaceFit::Ask
        };
        let mut plan = Self::marketplace(record, binding, fit, blocked, code_allowed);
        if !active && matches!(plan.action, InstallAction::PendingPermission) {
            plan.action = InstallAction::Preserve(if blocked {
                InstallHoldReason::RulesHit
            } else {
                InstallHoldReason::CodeAutoInstallOff
            });
        }
        if matches!(
            plan.action,
            InstallAction::Activate(PostFitOrigin::Marketplace)
        ) {
            plan.action = InstallAction::Activate(PostFitOrigin::Pack);
        }
        plan
    }

    pub(super) fn owner_answer(record: &SkillRecord, binding: InstallBinding) -> Self {
        let action = if record.lifecycle_status == SkillLifecycle::Candidate
            && record.approval_status == ClaimApprovalStatus::Auto
        {
            InstallAction::OwnerAnswer
        } else {
            InstallAction::Preserve(InstallHoldReason::LocalApproval)
        };
        Self::new(binding, action)
    }

    pub(super) fn is_owner_answerable(&self) -> bool {
        matches!(self.action, InstallAction::OwnerAnswer)
    }
}

impl Vault {
    /// Executes and verifies the plan against the same write frontier as the receipt.
    pub(super) fn execute_hub_install_plan_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        plan: &InstallPlan,
        occurred: TimeRange,
        learned_at: u64,
        authorization: Option<&crate::consent::ApproveOnceAuthorization>,
    ) -> Result<InstallResult> {
        let record = self.read_skill_record_in_txn(txn, entity)?;
        if record.content_hash != Some(plan.binding.hash)
            || self
                .read_admitted_capability_surface_in_txn(txn, entity)?
                .as_ref()
                != Some(&plan.binding.capabilities)
        {
            return Err(invalid(
                "fit decision no longer matches source and permissions",
            ));
        }
        self.check_hub_source_alias(txn, entity, &plan.binding.source, plan.binding.hash)?;
        // Re-derive the transition under this writer lock. Source arrival may add
        // aliases, but never supersedes a local lifecycle or approval decision.
        match plan.action {
            InstallAction::Activate(_) | InstallAction::PendingPermission
                if record.lifecycle_status != SkillLifecycle::Candidate
                    || record.approval_status != ClaimApprovalStatus::Auto =>
            {
                return Err(invalid("post-fit install state changed"));
            }
            InstallAction::AlreadyInstalled if !skill_loadable(&record) => {
                return Err(invalid("previous install is no longer loadable"));
            }
            InstallAction::Preserve(InstallHoldReason::Stale)
                if record.lifecycle_status != SkillLifecycle::Stale =>
            {
                return Err(invalid("stale holder changed"));
            }
            InstallAction::Preserve(InstallHoldReason::Quarantined)
                if record.lifecycle_status != SkillLifecycle::Quarantined =>
            {
                return Err(invalid("quarantined holder changed"));
            }
            InstallAction::Preserve(InstallHoldReason::Superseded)
                if record.lifecycle_status != SkillLifecycle::Superseded =>
            {
                return Err(invalid("superseded holder changed"));
            }
            _ => {}
        }
        let disposition = match plan.action {
            InstallAction::Activate(_) | InstallAction::OwnerAnswer => {
                if record.lifecycle_status != SkillLifecycle::Candidate
                    || record.approval_status != ClaimApprovalStatus::Auto
                    || super::import_receipt::marketplace_hash_blocked_in_txn(
                        &self.store,
                        txn,
                        plan.binding.hash,
                    )?
                {
                    return Err(invalid("post-fit install decision moved"));
                }
                let mut updated = record;
                updated.lifecycle_status = SkillLifecycle::Active;
                if matches!(plan.action, InstallAction::OwnerAnswer) {
                    updated.approval_status = ClaimApprovalStatus::Approved;
                }
                let data = crate::skill::encode_skill_record(&updated)?;
                let proof = match plan.action {
                    InstallAction::OwnerAnswer => super::HubAdmissionProof::consent(
                        &self.store,
                        txn,
                        *entity,
                        &data,
                        authorization.ok_or_else(|| invalid("owner authorization missing"))?,
                    )?,
                    InstallAction::Activate(PostFitOrigin::Marketplace) => {
                        super::HubAdmissionProof::marketplace(*entity, &data, plan.binding.hash)
                    }
                    InstallAction::Activate(PostFitOrigin::Pack) => {
                        super::HubAdmissionProof::post_fit(*entity, &data, plan.binding.hash)
                    }
                    _ => unreachable!(),
                };
                self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)?;
                InstallDisposition::Installed
            }
            InstallAction::AlreadyInstalled => InstallDisposition::AlreadyInstalled,
            InstallAction::PendingPermission => InstallDisposition::PendingPermission,
            InstallAction::Preserve(reason) => InstallDisposition::NotInstalled(reason),
        };
        let stored = self.read_skill_record_in_txn(txn, entity)?;
        InstallResult::finalized(&stored, disposition)
    }
}
