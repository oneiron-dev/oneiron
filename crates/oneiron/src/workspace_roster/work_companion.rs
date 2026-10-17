//! The org's `work_companion` policy (ONEIRON-ARCH-0063).
//!
//! `choose` is the default: a member brings her own companion, who wears the
//! workspace's work facet and its clamps, or starts a work companion here.
//! `suggest` recommends the work companion without hiding the other way.
//! `require` admits a work companion only. The policy governs this org vault
//! alone, never a member's personal vault or personal companion, and it
//! admits no one: membership still comes from an accepted invitation.
//!
//! # One field of the stored preset
//!
//! The policy is stored beside the workspace preset in its one `PRESET` row,
//! not in a second settings registry. Onboarding reads it in the transaction
//! that binds the member's companion, never from the caller, and it is no
//! part of the intent digest: an owner changing it never turns a resumed
//! onboarding into a different request.

use super::*;
use crate::edge::EdgeActorClass;
use crate::error::GateError;
use crate::federation::SharedVaultWrite;
use crate::memory::{Memory, MemoryResult};
use serde::{Deserialize, Serialize};

/// How a workspace admits its members' companions.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WorkCompanionPolicy {
    /// Bring your own companion or start a work companion.
    #[default]
    Choose,
    /// Both, with the work companion recommended.
    Suggest,
    /// A work companion only.
    Require,
}

impl WorkCompanionPolicy {
    /// Pinned on-disk spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Choose => "choose",
            Self::Suggest => "suggest",
            Self::Require => "require",
        }
    }

    /// Parses a pinned spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "choose" => Some(Self::Choose),
            "suggest" => Some(Self::Suggest),
            "require" => Some(Self::Require),
            _ => None,
        }
    }

    /// Whether this policy admits `choice`: only `require` refuses, and only
    /// a brought companion.
    #[must_use]
    pub fn admits(self, choice: &CompanionChoice) -> bool {
        !(self == Self::Require && choice.is_bring())
    }

    /// Whether this policy recommends a work companion to a member who
    /// brought her own. Advisory: it never refuses.
    #[must_use]
    pub fn suggests_against(self, choice: &CompanionChoice) -> bool {
        self == Self::Suggest && choice.is_bring()
    }
}

/// The reason a `require` workspace refuses a brought companion. Callers
/// match on it; the refusal never falls back to a work companion birth.
pub const WORK_COMPANION_REQUIRED: &str =
    "workspace work_companion policy is require: start a work companion; a brought one is refused";

impl Vault {
    /// `workspace`'s `work_companion` policy. A workspace nobody has
    /// onboarded into or established has no preset yet, so it has no policy
    /// to read.
    pub fn workspace_work_companion(&self, workspace: &str) -> Result<WorkCompanionPolicy> {
        validate_name(
            workspace,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        Ok(read_preset_row(self, workspace)?
            .ok_or(Error::EntityNotFound)?
            .work_companion)
    }

    /// Sets `workspace`'s `work_companion` policy.
    ///
    /// `owner` is revalidated in the writing transaction: the vault's owner,
    /// or an admin whose named workspace-settings power over the workspace's
    /// vault still holds there. A roster row or plain membership never sets
    /// it. Members already onboarded keep their companions; the policy binds
    /// each companion step that runs after it.
    pub fn set_workspace_work_companion(
        &self,
        workspace: &str,
        policy: WorkCompanionPolicy,
        owner: &AuthenticatedOwner,
    ) -> Result<()> {
        validate_name(
            workspace,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        let key = workspace.to_owned();
        self.with_write_txn_grouped(|txn| {
            let mut row = PRESET
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            require_settings_authority_in_txn(self, txn, row.preset.workspace_vault_id, owner)?;
            if row.work_companion != policy {
                row.work_companion = policy;
                PRESET.put(&self.store, txn, &key, &row)?;
            }
            Ok(())
        })
    }

    /// Establishes `preset` with its `work_companion` policy before anyone
    /// is onboarded, so an owner can set `require` ahead of the first member.
    ///
    /// `owner` is revalidated in the writing transaction under the same
    /// settings authority as [`Self::set_workspace_work_companion`]. The
    /// preset is checked as onboarding checks it; a `workspace_ref` bound to
    /// a different preset refuses, and an identical retry writes nothing.
    /// Only the `PRESET` row is written: no member, grant, mailbox or
    /// companion, and no house anchor. Onboarding still does those, and
    /// keeps the policy established here.
    pub fn establish_workspace_preset(
        &self,
        preset: &WorkspaceRosterPreset,
        policy: WorkCompanionPolicy,
        owner: &AuthenticatedOwner,
    ) -> Result<()> {
        let key = preset.workspace_ref.clone();
        self.with_write_txn_grouped(|txn| {
            require_settings_authority_in_txn(self, txn, preset.workspace_vault_id, owner)?;
            super::steps::validate_workspace_preset_in_txn(self, txn, preset)?;
            let existing = PRESET.get(&self.store, txn, &key)?;
            if let Some(existing) = &existing
                && existing.preset != *preset
            {
                return Err(invalid(
                    "workspace_ref is already bound to a different workspace preset",
                ));
            }
            if existing.is_none_or(|row| row.work_companion != policy) {
                let row = super::records::PresetRow {
                    preset: preset.clone(),
                    work_companion: policy,
                };
                PRESET.put(&self.store, txn, &key, &row)?;
            }
            Ok(())
        })
    }
}

/// The person behind `owner`, live in `txn`, as the vault's owner or as an
/// admin holding the workspace-settings power over `vault_id`. Enrollment
/// authority alone does not confer it.
fn require_settings_authority_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    owner: &AuthenticatedOwner,
) -> Result<()> {
    let actor = owner.revalidate_person_in_txn(vault, txn)?;
    if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Ok(());
    }
    vault
        .authorize_shared_vault_write_in_txn(
            txn,
            vault_id,
            &WriteActor::new(actor, EdgeActorClass::Human),
            &SharedVaultWrite::WorkspaceSettings,
        )
        .map_err(|error| match error {
            Error::Claim(crate::error::ClaimError::ActorLacksClaimAuthority { .. }) => {
                invalid("work_companion is a workspace setting: owner or admin settings power")
            }
            other => other,
        })
}

impl Memory<'_> {
    /// `workspace`'s `work_companion` policy, which every member it governs
    /// may read.
    pub fn workspace_work_companion_get(
        &self,
        workspace: &str,
    ) -> MemoryResult<WorkCompanionPolicy> {
        Ok(self.vault().workspace_work_companion(workspace)?)
    }

    /// Sets `workspace`'s `work_companion` policy for the owner who made this
    /// request in person, and answers the policy now in force. Only the
    /// owner proof a host bound for this surface's own actor carries it; an
    /// agent's or a room turn's surface sets nothing.
    pub fn workspace_work_companion_set(
        &self,
        workspace: &str,
        policy: WorkCompanionPolicy,
    ) -> MemoryResult<WorkCompanionPolicy> {
        let refused = || {
            Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "work_companion changes only on the owner's own authenticated request",
            ))
        };
        if self.room_turn().is_some() || self.actor_class() != EdgeActorClass::Human {
            return Err(refused().into());
        }
        let owner = self.owner_authorship().ok_or_else(refused)?;
        if owner.actor_for_read(self.vault())? != self.actor() {
            return Err(refused().into());
        }
        self.vault()
            .set_workspace_work_companion(workspace, policy, owner)?;
        Ok(policy)
    }
}
