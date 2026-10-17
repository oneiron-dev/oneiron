//! Served hub install (OF-519, OF-213): the owner names a configured hub, a
//! folder and a pin; fetch, the owner's fit rung and the ordinary install door
//! run in turn. Everything installs; code lands Candidate until its sandbox
//! suite qualifies it; a hook pack's suite is its replay
//! ([`Vault::qualify_pack_hooks`]). Hooks first bind only on the owner's own
//! consent ([`Vault::bind_pack_hooks`]); a same-capability update rebinds
//! them, and a wider one asks again.
use super::{
    PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource, invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::skill_hub::ref_sync::{RefFetch, pinned_tracking};
use crate::skill_hub::{
    GitEndpointSkillHubAdapter, HttpEndpointSkillHubAdapter, HubPin, HubRef, MODEL_PACK_NAME,
    SkillHubKind,
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

    /// Owner door: sync an installed hub pack to its ref's policy (OF-213).
    /// The ref's stored row picks the bytes, else the installed pin. A fetch
    /// marks its revision seen; only an install marks it trusted. A source
    /// whose dependencies carry advisories lands Candidate, and the installed
    /// pack stays selected.
    pub fn sync_pack_from_hub(
        &self,
        owner: &AuthenticatedOwner,
        name: &str,
    ) -> Result<PackInstallDisposition> {
        if name == MODEL_PACK_NAME {
            return self.sync_model_catalog(owner);
        }
        let installed = self
            .installed_pack(name)?
            .ok_or_else(|| invalid("no pack is installed under that name"))?;
        let hub = EntityId::from_hex(&installed.hub_id)?;
        let tracked = match self.hub_ref_sync(&hub, &installed.hub_ref)? {
            Some(tracked) => tracked,
            None => pinned_tracking(HubRef::new(
                hub,
                installed.hub_ref.clone(),
                hub_pin(&installed.pin_type, &installed.pin_value)?,
            )?)?,
        };
        let fallback = (installed.pin_type == "commit").then_some(installed.pin_value.as_str());
        let publisher = self.admit_skill_publisher(owner, &installed.publisher, hub)?;
        let at = self.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let (source_id, pinned, revision) = match self.hub_ref_fetch(&tracked, fallback)? {
            RefFetch::Git(adapter, reference) => {
                let (id, pinned) =
                    self.fetch_pack_from_adapter(&adapter, &reference, &publisher, occurred, at)?;
                (id, pinned, adapter.resolved_commit().to_owned())
            }
            RefFetch::Http(adapter, reference) => {
                let (id, pinned) =
                    self.fetch_pack_from_adapter(&adapter, &reference, &publisher, occurred, at)?;
                let hash = self
                    .get_pack_source(&id)?
                    .ok_or_else(|| invalid("fetched pack is missing"))?
                    .content_hash()
                    .to_hex();
                (id, pinned, hash)
            }
        };
        self.mark_hub_ref(&tracked, &revision, false)?;
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("fetched pack is missing"))?;
        if source.manifest().name != name {
            return Err(invalid("the synced ref holds another pack"));
        }
        let ask = self.prepare_pack_install(source_id, &pinned, &publisher, &OwnerAskedFit)?;
        let disposition = self.install_pack(&ask)?;
        if let PackInstallDisposition::Installed(receipt) = &disposition {
            self.mark_hub_ref(&tracked, &revision, true)?;
            // A hook pack's update lands Candidate until its test; one that
            // installs here takes its hooks with it, under the update rule.
            self.with_write_txn_grouped(|txn| {
                self.follow_pack_hook_update_in_txn(txn, owner, receipt, source_id, &source)
            })?;
        }
        Ok(disposition)
    }
}
