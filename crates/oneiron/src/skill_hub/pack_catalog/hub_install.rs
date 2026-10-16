//! Served hub install (OF-519, OF-213): the owner names a configured hub, a
//! folder and a pin; fetch, the owner's fit rung and the ordinary install door
//! run in turn. Everything installs; code lands Candidate until its sandbox
//! suite qualifies it. Hooks bind only on the owner's own consent
//! ([`Vault::bind_pack_hooks`]).
use super::{
    PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource, invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::skill_hub::{
    GitEndpointSkillHubAdapter, HttpEndpointSkillHubAdapter, HubPin, HubRef, SkillHubKind,
};
use crate::{EntityId, TimeRange, Vault, error::Result};

/// The fit rung for a pack the owner asked for: it fits. A rules hit is the
/// screen's to find; code waits as a Candidate.
struct OwnerAskedFit;
impl PackFitPolicy for OwnerAskedFit {
    fn evaluate(
        &self,
        _source: &PackSource,
        _permissions: &PackPermissions,
    ) -> Result<PackFitVerdict> {
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: false,
        })
    }
}

/// A pin from its wire spelling and value.
pub fn hub_pin(pin_type: &str, value: &str) -> Result<HubPin> {
    let value = value.to_owned();
    Ok(match pin_type {
        "semver" => HubPin::Semver(value),
        "tag" => HubPin::Tag(value),
        "commit" => HubPin::Commit(value),
        "content_hash" => HubPin::ContentHash(value),
        _ => {
            return Err(invalid(
                "a hub install needs a semver, tag, commit or content_hash pin",
            ));
        }
    })
}

impl Vault {
    /// Install the pack at `folder` of a configured hub, pinned. The named
    /// publisher is admitted as a foreign actor for this hub first.
    pub fn install_pack_from_hub(
        &self,
        owner: &AuthenticatedOwner,
        hub: EntityId,
        folder: &str,
        pin: HubPin,
        publisher: &str,
    ) -> Result<PackInstallDisposition> {
        let row = self.skill_hub_record(&hub)?;
        let publisher = self.admit_skill_publisher(owner, publisher, hub)?;
        let reference = HubRef::new(hub, folder, pin.clone())?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        match row.kind {
            SkillHubKind::Git => {
                let HubPin::Commit(commit) = &pin else {
                    return Err(invalid("a Git hub installs at a commit pin"));
                };
                let adapter = GitEndpointSkillHubAdapter::new(hub, &row.endpoint, commit)?;
                self.install_pack_from_adapter(
                    &adapter,
                    &reference,
                    &publisher,
                    &OwnerAskedFit,
                    occurred,
                    at,
                )
            }
            SkillHubKind::HttpIndex => {
                let adapter = HttpEndpointSkillHubAdapter::new(hub, &row.endpoint)?;
                self.install_pack_from_adapter(
                    &adapter,
                    &reference,
                    &publisher,
                    &OwnerAskedFit,
                    occurred,
                    at,
                )
            }
            SkillHubKind::LocalDir => {
                Err(invalid("a local folder installs through vault.packs.put"))
            }
        }
    }
}
