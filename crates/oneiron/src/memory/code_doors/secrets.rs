//! The repo secret doors (FIX 7608 slice 8, owner ruling SECRETS-IN-REPOS =
//! A: "on the current code, the vault opens a proposal: move the key to the
//! secret store, put a reference in its place, add the .env line to
//! .gitignore, and add a .env.example"). `vault.code.secrets.get` reads a
//! repository's marked keys and the remediations linked to them;
//! `vault.code.secrets.propose` stages the one remediation bundle at the
//! current HEAD, through the engine's own proposer. Both are owner doors,
//! as every code door is (`Memory::code_owner`). Neither reads, returns
//! or logs a value, span or excerpt: a key is named by its custody handle.

use serde::{Deserialize, Serialize};

use super::*;
use crate::code_document::CodeOpProvenance;
use crate::repo_mutation::proposal::{OwnerRequestAttribution, RepoProposalReview};
use crate::repo_mutation::{
    RepoSecretMarkEntry, RepoSecretMarkSeen, RepoSecretRemediation, RepoSecretRemediationAction,
    RepoSecretRemediationLinkEntry, RepoSecretRemediationRequest, RepoSecretRemediationStatus,
    RepoSecretUnresolved,
};
use crate::store::critic_lens::LensCatalog;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_doors::secrets::{
    CodeRepoSecretMark, CodeRepoSecretProposeRequest, CodeRepoSecretRemediation,
    CodeRepoSecretRemediationAction, CodeRepoSecretRemediationLink,
    CodeRepoSecretRemediationStatus, CodeRepoSecretSeen, CodeRepoSecretUnresolved,
    CodeRepoSecretsView,
};

impl Memory<'_> {
    /// `vault.code.secrets.get`: the repository's marked keys and the
    /// remediations linked to it, value-free.
    pub fn code_repo_secrets_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRepoRequest,
    ) -> MemoryResult<CodeRepoSecretsView> {
        self.code_owner(owner)?;
        let repo_ref = self.code_repo(input.repo)?;
        let marks = self.vault.repo_secret_marks(&repo_ref)?;
        self.code_listed(
            marks
                .marks
                .iter()
                .filter_map(|mark| mark.custody)
                .chain(marks.links.iter().map(|link| link.proposal)),
        )?;
        Ok(CodeRepoSecretsView {
            repo: input.repo,
            marks: marks.marks.into_iter().map(mark_view).collect(),
            remediations: marks.links.into_iter().map(link_view).collect(),
        })
    }

    /// `vault.code.secrets.propose`: stages ONE native bundle moving the
    /// marked keys out of the repository's current code. It only proposes:
    /// review and the existing landing gate decide the rest.
    pub fn code_repo_secrets_propose_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRepoSecretProposeRequest,
    ) -> MemoryResult<CodeRepoSecretRemediation> {
        let attribution = OwnerRequestAttribution::new("vault.code.secrets.propose", &input)?;
        let actor = self.code_owner(owner)?;
        let repo_ref = self.code_repo(input.repo)?;
        let provenance = &input.op_provenance;
        for id in [
            provenance.turn,
            provenance.activity,
            provenance.intent,
            provenance.substrate_ref,
        ]
        .into_iter()
        .flatten()
        {
            self.code_readable(id, None)?;
        }
        let remediation = self.vault.propose_repo_secret_remediation_as_owner(
            owner,
            input.repo,
            RepoSecretRemediationRequest {
                repo_ref,
                actor_id: actor,
                session_id: None,
                provenance_claim_id: None,
                op_provenance: input.op_provenance,
                actor_class: Some(self.actor_class),
                review: input.catalog.map_or(
                    RepoProposalReview::VaultDefault,
                    RepoProposalReview::Explicit,
                ),
            },
            &attribution,
        )?;
        if let Some(proposal) = remediation.proposal {
            self.produced_from([proposal]);
        }
        Ok(remediation_view(input.repo, remediation))
    }
}

fn mark_view(mark: RepoSecretMarkEntry) -> CodeRepoSecretMark {
    CodeRepoSecretMark {
        mark: mark.mark,
        operation: mark.operation,
        blob: mark.blob,
        path: mark.path,
        kind: mark.detector_kind,
        seen: match mark.seen {
            RepoSecretMarkSeen::RefMove { name, new_commit } => {
                CodeRepoSecretSeen::RefMove { name, new_commit }
            }
            RepoSecretMarkSeen::Quarantine => CodeRepoSecretSeen::Quarantine,
            RepoSecretMarkSeen::SyncLanding => CodeRepoSecretSeen::SyncLanding,
        },
        custody: mark.custody,
        handle: mark.handle,
        marked_at: mark.marked_at,
    }
}

fn link_view(link: RepoSecretRemediationLinkEntry) -> CodeRepoSecretRemediationLink {
    CodeRepoSecretRemediationLink {
        state: link.state,
        proposal: link.proposal,
        commit: link.commit,
        paths: link.paths,
        linked_at: link.linked_at,
    }
}

fn remediation_view(
    repo: EntityId,
    remediation: RepoSecretRemediation,
) -> CodeRepoSecretRemediation {
    CodeRepoSecretRemediation {
        repo,
        status: match remediation.status {
            RepoSecretRemediationStatus::Proposed => CodeRepoSecretRemediationStatus::Proposed,
            RepoSecretRemediationStatus::Unresolved => CodeRepoSecretRemediationStatus::Unresolved,
            RepoSecretRemediationStatus::Stale => CodeRepoSecretRemediationStatus::Stale,
            RepoSecretRemediationStatus::Clean => CodeRepoSecretRemediationStatus::Clean,
        },
        base_commit: remediation.base_commit,
        proposal: remediation.proposal,
        actions: remediation
            .actions
            .into_iter()
            .map(|action| match action {
                RepoSecretRemediationAction::ReplaceLiterals { path, env_names } => {
                    CodeRepoSecretRemediationAction::ReplaceLiterals { path, env_names }
                }
                RepoSecretRemediationAction::RemoveDotenv { path } => {
                    CodeRepoSecretRemediationAction::RemoveDotenv { path }
                }
                RepoSecretRemediationAction::WriteExample { path, names } => {
                    CodeRepoSecretRemediationAction::WriteExample { path, names }
                }
                RepoSecretRemediationAction::IgnoreDotenv { entries } => {
                    CodeRepoSecretRemediationAction::IgnoreDotenv { entries }
                }
                RepoSecretRemediationAction::DeclareEnvNames { env_names } => {
                    CodeRepoSecretRemediationAction::DeclareEnvNames { env_names }
                }
            })
            .collect(),
        unresolved: remediation
            .unresolved
            .into_iter()
            .map(
                |RepoSecretUnresolved {
                     path,
                     reason,
                     custody,
                 }| CodeRepoSecretUnresolved {
                    path,
                    reason: reason.as_str().to_owned(),
                    custody,
                },
            )
            .collect(),
    }
}
