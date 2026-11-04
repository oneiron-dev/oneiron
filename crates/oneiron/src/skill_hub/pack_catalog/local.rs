//! The owner's own pack install, `vault.packs.put` (ARCH-0080 §8, slice 1),
//! and the vault's `local` pack. A put is the owner's consent: it installs
//! the folder and binds its hooks in one transaction. A resident agent puts
//! the `local` pack too, and binds the hooks it wrote as its own (§7).
use super::admission::{PACK_INSTALL, PackCommit, pack_permissions, refuse_engine_namespace};
use super::hooks::HookBinder;
use super::{
    PackAdapter, PackFitVerdict, PackInstallDisposition, PackInstallReceipt, PackInstallStatus,
    PackKind, PackQualification, PackQualifier, PackSource, PackTree, invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::skill_hub::{HubFile, HubPin, HubRef};
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, WriteActor, error::Result};

/// The vault's own pack, kind capability, for its own hooks. Vault open
/// creates it; it never publishes to a hub (ARCH-0080 local pack).
pub const LOCAL_PACK_NAME: &str = "local";
/// The `hub_ref` an owner's put records: the verb, not a hub.
const PUT_REF: &str = "vault.packs.put";
// A plain manifest scalar may hold `'` inside (`manifest::scalar` refuses
// only a leading `'`), so the description keeps its apostrophe.
const LOCAL_PACK_MD: &str = "---\nname: local\ndescription: This vault's own hooks. It never publishes to a hub.\nversion: 1\nkind: capability\n---\n";

fn put_ref(source: &PackSource) -> Result<HubRef> {
    Ok(HubRef {
        hub_id: EntityId::derive(
            crate::entity_id::derived_domains::BUILTIN_CONNECTOR_PACK_HUB,
            &[PUT_REF.as_bytes()],
        )?,
        ref_string: PUT_REF.to_owned(),
        pin: HubPin::ContentHash(source.content_hash().to_hex()),
    })
}

impl Vault {
    /// `vault.packs.put`: the owner installs a pack folder, or replaces the
    /// one installed under its name. The put is the consent for its hooks.
    /// A script adapter still lands Candidate until its sandbox qualifies it.
    /// Organ builds and lens components in the folder are held as blob
    /// assets of the source.
    pub fn put_pack(
        &self,
        owner: &AuthenticatedOwner,
        files: Vec<HubFile>,
    ) -> Result<PackInstallDisposition> {
        let tree = PackSource::from_tree(files)?;
        self.put_pack_source(HookBinder::Owner(owner), tree, None)
    }

    /// `vault.packs.put` by a resident agent (ARCH-0080 §7, §8 local pack):
    /// the agent replaces the `local` pack, and each hook whose body it
    /// wrote binds as its own, in a claim stamped with the agent, reading and
    /// acting at the agent's own ceiling. A hook that asks wider (Skip, Ask
    /// or Rewrite on another actor's verbs, or blocking) also becomes the
    /// owner's proposal, in the same write (§10). A binding another author
    /// stands on is left as it is; the owner sees every binding and turns any
    /// off. A put of any other pack is refused.
    pub fn put_local_pack_as_agent(
        &self,
        agent: &WriteActor,
        files: Vec<HubFile>,
    ) -> Result<PackInstallDisposition> {
        if agent.actor_class() != EdgeActorClass::Agent {
            return Err(invalid("an agent's put takes an agent writer"));
        }
        let tree = PackSource::from_tree(files)?;
        if tree.source.manifest.name != LOCAL_PACK_NAME {
            return Err(invalid("an agent puts the local pack only"));
        }
        self.put_pack_source(HookBinder::Agent(*agent), tree, None)
    }

    /// Owner-authored connectors use the same source-bound qualification as
    /// hub installs. The owner put supplies consent, not a wire-probe bypass.
    pub fn put_qualified_pack(
        &self,
        owner: &AuthenticatedOwner,
        files: Vec<HubFile>,
        qualifier: &dyn PackQualifier,
    ) -> Result<PackInstallDisposition> {
        let tree = PackSource::from_tree(files)?;
        refuse_engine_namespace(&tree.source)?;
        let qualification = qualifier.qualify(&tree.source)?;
        super::qualify::validate_qualification(&tree.source, &qualification)?;
        self.put_pack_source(HookBinder::Owner(owner), tree, Some(qualification))
    }

    fn put_pack_source(
        &self,
        binder: HookBinder<'_>,
        tree: PackTree,
        qualification: Option<PackQualification>,
    ) -> Result<PackInstallDisposition> {
        let source = &tree.source;
        refuse_engine_namespace(source)?;
        let hub = put_ref(source)?;
        // The put is the owner's consent, advisories included: the tree's OSV
        // row is evidence on its hash, and holds nothing here.
        let advisories = self.pack_advisories(source, false, crate::unix_seconds_now())?;
        let disposition = self.with_write_txn_grouped(|txn| {
            let holder = match binder {
                HookBinder::Owner(owner) => owner.revalidate_in_txn(self, txn)?,
                HookBinder::Agent(agent) => {
                    self.verify_write_actor_in_txn(txn, &agent)?;
                    agent.entity_ref()
                }
            }
            .to_hex();
            let at = crate::unix_seconds_now();
            let occurred = TimeRange { start: at, end: at };
            let source_id = self.stage_pack_source_in_txn(txn, source, occurred, at)?;
            self.hold_organ_builds_in_txn(txn, &source_id, &tree, occurred, at)?;
            self.hold_lens_components_in_txn(txn, &source_id, &tree, occurred, at)?;
            self.scan_and_ingest_pack_source_in_txn(txn, source, occurred, at)?;
            self.ingest_pack_advisories_in_txn(txn, &advisories, occurred, at)?;
            if let Some(reason) = self.screen_pack_in_txn(txn, source, &[], &holder)? {
                return Ok(PackInstallDisposition::Blocked { reason });
            }
            let prior = self.installed_pack_in_txn(txn, &source.manifest.name)?;
            let permissions = pack_permissions(source, prior.as_ref())?;
            let verdict = PackFitVerdict {
                fits: true,
                rules_hit: false,
                code_auto_install: qualification.is_some()
                    || !matches!(source.manifest.adapter, Some(PackAdapter::Script(_))),
            };
            let disposition = self.commit_pack_install_in_txn(
                txn,
                source,
                &PackCommit {
                    source_id,
                    hub: &hub,
                    publisher: &holder,
                    foreign: None,
                    verdict,
                    permissions: &permissions,
                    qualification: qualification.as_ref(),
                    world: None,
                    owner_activated: &[],
                },
            )?;
            if matches!(disposition, PackInstallDisposition::Installed(_)) {
                self.bind_hooks_in_txn(txn, binder, source_id, source)?;
            }
            Ok(disposition)
        })?;
        // The bindings changed once the put committed.
        if matches!(disposition, PackInstallDisposition::Installed(_)) {
            self.verb_hook_bindings_changed();
        }
        Ok(disposition)
    }
}

/// Vault open creates the `local` pack once, like the bootstrap skills. A
/// later put replaces it; this never does.
pub(super) fn seed_local_pack(vault: &Vault) -> Result<()> {
    let name = LOCAL_PACK_NAME.to_owned();
    if PACK_INSTALL.contains(&vault.store, &vault.store.env.read_txn()?, &name)? {
        return Ok(());
    }
    let source = PackSource::from_files(vec![HubFile::new("PACK.md", LOCAL_PACK_MD.as_bytes())])?;
    let hub = put_ref(&source)?;
    vault.with_write_txn_grouped(|txn| {
        if PACK_INSTALL.contains(&vault.store, txn, &name)? {
            return Ok(());
        }
        let source_id =
            vault.stage_pack_source_in_txn(txn, &source, TimeRange { start: 0, end: 0 }, 0)?;
        let content_hash = source.content_hash().to_hex();
        let receipt = PackInstallReceipt {
            source_id: source_id.to_hex(),
            pack_name: name.clone(),
            content_hash: content_hash.clone(),
            kind: PackKind::Capability,
            adapter: None,
            engine_version: None,
            status: PackInstallStatus::Active,
            candidate_reason: None,
            hub_id: hub.hub_id.to_hex(),
            hub_ref: hub.ref_string.clone(),
            pin_type: hub.pin.pin_type().to_owned(),
            pin_value: content_hash,
            publisher: "vault".to_owned(),
            permissions: pack_permissions(&source, None)?,
            qualification_report_hash: None,
            connector_qualification: None,
            runtime: None,
            sections: Vec::new(),
            predicates: Vec::new(),
            kinds: Vec::new(),
            skills: Vec::new(),
            agent: None,
            installed_at: 0,
            notices: Vec::new(),
            owner_activated: Vec::new(),
        };
        PACK_INSTALL.put(&vault.store, txn, &name, &receipt)?;
        Ok(())
    })
}
