//! The owner's activation of a held hub Candidate (OF-213, OF-575): a pack
//! held for its OSV advisories, or a pack whose only code is organs, installs
//! on the owner's word. A hook pack keeps its replay
//! ([`Vault::qualify_pack_hooks`]) and a travelling agent its world
//! ([`Vault::place_pack_agent_world`]).
use super::admission::{PACK_CANDIDATE, PackCommit};
use super::{HookAuthor, PackCandidateReason, PackFitVerdict, PackInstallDisposition, invalid};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Vault, error::Result};

impl Vault {
    /// The owner activates the Candidate of `source_id`. A pack held for its
    /// advisories installs with them accepted; a pack whose only code is
    /// organs installs with that code admitted, advisories or not. In one
    /// writer the source is screened again and every other hold applies as
    /// the hub install would; the receipt's `owner_activated` names each hold
    /// the owner lifted.
    pub fn activate_pack_candidate(
        &self,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
    ) -> Result<PackInstallDisposition> {
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let candidate = self
            .candidate_pack(&source)?
            .ok_or_else(|| invalid("the pack is not a Candidate"))?;
        let organs_only = source.code_is_organs_only();
        let mut lifted = Vec::new();
        match candidate.candidate_reason {
            Some(PackCandidateReason::Advisories) => lifted.push(PackCandidateReason::Advisories),
            Some(PackCandidateReason::CodeAutoInstallOff) if organs_only => {}
            _ => {
                return Err(invalid(
                    "only a pack held for advisories or for its organ code activates here",
                ));
            }
        }
        if organs_only {
            lifted.push(PackCandidateReason::CodeAutoInstallOff);
        }
        let hub = crate::skill_hub::HubRef::new(
            EntityId::from_hex(&candidate.hub_id)?,
            candidate.hub_ref.clone(),
            super::hub_pin(&candidate.pin_type, &candidate.pin_value)?,
        )?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            if PACK_CANDIDATE
                .get(&self.store, &*txn, &candidate.content_hash)?
                .as_ref()
                != Some(&candidate)
            {
                return Err(invalid("the Candidate changed"));
            }
            let publisher = match self.hook_author_in_txn(&*txn, &candidate)? {
                HookAuthor::ForeignActor {
                    identity,
                    hub,
                    grant,
                    ..
                } => Some(crate::skill_hub::ForeignSkillPublisher {
                    identity,
                    hub,
                    grant_ref: grant,
                }),
                HookAuthor::Owner | HookAuthor::Agent { .. } => None,
            };
            if let Some(publisher) = &publisher {
                self.check_publisher_in_txn(&*txn, publisher)?;
            }
            if let Some(reason) =
                self.screen_pack_in_txn(&*txn, &source, &[], &candidate.publisher)?
            {
                return Ok(PackInstallDisposition::Blocked { reason });
            }
            let disposition = self.commit_pack_install_in_txn(
                txn,
                &source,
                &PackCommit {
                    source_id,
                    hub: &hub,
                    publisher: &candidate.publisher,
                    foreign: publisher.as_ref(),
                    verdict: PackFitVerdict {
                        fits: true,
                        rules_hit: false,
                        code_auto_install: organs_only,
                    },
                    permissions: &candidate.permissions,
                    qualification: None,
                    world: None,
                    owner_activated: &lifted,
                },
            )?;
            if let PackInstallDisposition::Installed(receipt) = &disposition {
                self.follow_pack_hook_update_in_txn(txn, owner, receipt, source_id, &source)?;
            }
            Ok(disposition)
        })
    }
}
