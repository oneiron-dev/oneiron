//! The owner's activation of a held hub Candidate (OF-213, OF-575): a pack
//! held for its OSV advisories, or a pack whose only code is organs, installs
//! on the owner's word. A connector can also activate on source-bound probe
//! evidence. A hook pack keeps its replay
//! ([`Vault::qualify_pack_hooks`]) and a travelling agent its world
//! ([`Vault::place_pack_agent_world`]).
use super::admission::{PACK_CANDIDATE, PackCommit};
use super::qualify::validate_qualification;
use super::{
    HookAuthor, PackCandidateReason, PackFitVerdict, PackInstallDisposition, PackKind,
    PackQualifier, invalid,
};
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
        self.activate_pack_candidate_with_qualifier(owner, source_id, None)
    }

    /// Activates the original stored connector Candidate using engine-qualified
    /// evidence. Its hub, publisher and permissions remain the Candidate's;
    /// hooks still require their separate replay qualification.
    pub fn activate_qualified_connector_pack_candidate(
        &self,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
        qualifier: &dyn PackQualifier,
    ) -> Result<PackInstallDisposition> {
        self.activate_pack_candidate_with_qualifier(owner, source_id, Some(qualifier))
    }

    fn activate_pack_candidate_with_qualifier(
        &self,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
        qualifier: Option<&dyn PackQualifier>,
    ) -> Result<PackInstallDisposition> {
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let candidate = self
            .candidate_pack(&source)?
            .ok_or_else(|| invalid("the pack is not a Candidate"))?;
        let organs_only = source.code_is_organs_only();
        let qualified_connector = qualifier.is_some();
        if qualified_connector
            && (source.manifest().kind != PackKind::Connector || !source.hooks().is_empty())
        {
            return Err(invalid("only a connector without hooks qualifies here"));
        }
        let mut lifted = Vec::new();
        match candidate.candidate_reason {
            Some(PackCandidateReason::Advisories) => lifted.push(PackCandidateReason::Advisories),
            Some(PackCandidateReason::CodeAutoInstallOff) if organs_only || qualified_connector => {
            }
            Some(PackCandidateReason::QualificationRequired) if qualified_connector => {}
            _ => {
                return Err(invalid(if qualified_connector {
                    "only a connector held for advisories, code admission or qualification activates here"
                } else {
                    "only a pack held for advisories or for its organ code activates here"
                }));
            }
        }
        if organs_only || qualified_connector {
            lifted.push(PackCandidateReason::CodeAutoInstallOff);
        }
        let qualification = qualifier
            .map(|qualifier| -> Result<_> {
                let qualified = qualifier.qualify(&source)?;
                validate_qualification(&source, &qualified)?;
                Ok(qualified)
            })
            .transpose()?;
        let hub = crate::skill_hub::HubRef::new(
            EntityId::from_hex(&candidate.hub_id)?,
            candidate.hub_ref.clone(),
            super::hub_pin(&candidate.pin_type, &candidate.pin_value)?,
        )?;
        let disposition = self.with_write_txn_grouped(|txn| {
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
                        code_auto_install: organs_only || qualified_connector,
                    },
                    permissions: &candidate.permissions,
                    qualification: qualification.as_ref(),
                    world: None,
                    owner_activated: &lifted,
                },
            )?;
            if let PackInstallDisposition::Installed(receipt) = &disposition {
                self.follow_pack_hook_update_in_txn(txn, owner, receipt, source_id, &source)?;
            }
            Ok(disposition)
        })?;
        // The bindings changed once the install committed.
        if matches!(disposition, PackInstallDisposition::Installed(_)) {
            self.verb_hook_bindings_changed();
        }
        Ok(disposition)
    }
}
