//! [PACK-HOOK-BIND-CRITICALITY-FLOOR]: the owner's own pack-hook writes land
//! on a vault with the shipped manifest. A binding is an Approved
//! `agent.connector_subscription` claim under the owner's envelope. No rule
//! of the shipped manifest names `agent.`, so the predicate resolves critical
//! by fallback, and an Approved stamp without the owner's proof pends at
//! `gate.pending.criticality_floor`. Each owner door below now carries that
//! proof, revalidated in its writing transaction, as the owner's other
//! approvals do ([CRITICALITY-FLOOR-PENDS-OWNER-WRITES]).
//!
//! - The owner's put of a pack binds its hook, Approved and live.
//! - The owner's dial turns that binding off and on again.
//! - The owner's removal of the pack stops the binding.
//!
//! On main the put is refused at the floor, so no hook of an owner's pack
//! binds there. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test pack_hook_owner_floor`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookAuthor, PackHookBinding, PackInstallDisposition};
use oneiron::store::GateDecisionId;
use oneiron::{ClaimApprovalStatus, ClaimLifecycleStatus, EntityId, Vault, VaultConfig};

/// The pack the owner puts: an author-scoped name, as a hub pack has.
const PACK: &str = "example.hookfloor";
/// Its one hook.
const HOOK: &str = "fact-note";

const PACK_MD: &str = "---
name: example.hookfloor
description: One fact hook the owner binds.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook the owner's put binds.
";

const HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:example.hookfloor.input\"]
actors: [\"human\"]
phase: fact
outcomes: [\"propose\"]
---
Propose one note per landed input claim.
";

const BODY_JS: &str = "return {
  kind: \"propose\",
  claim: {
    subject: input.claim.subject,
    predicate: \"example.hookfloor.note\",
    confidence: 1,
    value: { note: input.claim.value }
  }
};
";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault opened with the shipped default manifest and its owner's
    /// proof, as an embedded owner holds it.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            owner_proof,
            _directory: directory,
        }
    }

    /// The owner's put of the pack, which binds its hook; answers the
    /// binding's id.
    fn put_pack(&self) -> EntityId {
        let files = vec![
            HubFile::new("PACK.md", PACK_MD),
            HubFile::new(format!("hooks/{HOOK}/HOOK.md"), HOOK_MD),
            HubFile::new(format!("hooks/{HOOK}/body.js"), BODY_JS),
        ];
        match self.vault.put_pack(&self.owner_proof, files) {
            Ok(PackInstallDisposition::Installed(receipt)) => {
                assert_eq!(receipt.pack_name, PACK);
            }
            other => panic!("the owner's put installs the pack and binds its hook: {other:?}"),
        }
        let bindings = self.bindings();
        assert_eq!(bindings.len(), 1, "one binding: {bindings:?}");
        let (id, binding) = &bindings[0];
        assert_eq!(binding.hook, HOOK);
        assert_eq!(binding.owner, self.owner);
        assert_eq!(binding.author, HookAuthor::Owner);
        assert!(binding.enabled);
        *id
    }

    /// This pack's live bindings, enabled or not.
    fn bindings(&self) -> Vec<(EntityId, PackHookBinding)> {
        self.vault
            .pack_hook_bindings()
            .expect("read bindings")
            .into_iter()
            .filter(|(_, binding)| binding.pack == PACK)
            .collect()
    }

    /// The binding at `id` reads back enabled as `enabled`, in its claim:
    /// Approved and live, the owner's act landed, not parked.
    fn assert_landed(&self, id: EntityId, enabled: bool) {
        let body = self
            .vault
            .get_claim(&id)
            .expect("read binding claim")
            .expect("the binding claim stands");
        assert_eq!(body.predicate, "agent.connector_subscription");
        assert_eq!(body.approval, ClaimApprovalStatus::Approved);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        let bindings = self.bindings();
        let binding = bindings
            .iter()
            .find(|(bound, _)| *bound == id)
            .map(|(_, binding)| binding)
            .expect("the binding is listed");
        assert_eq!(binding.enabled, enabled);
    }
}

#[test]
fn the_owners_put_binds_its_hook_approved_on_a_shipped_manifest_vault() {
    let f = Fixture::new();
    let id = f.put_pack();
    f.assert_landed(id, true);
}

#[test]
fn the_owners_dial_turns_the_binding_off_and_on() {
    let f = Fixture::new();
    let id = f.put_pack();

    f.vault
        .set_pack_hook_enabled(&f.owner_proof, id, false)
        .expect("the owner's dial turns the hook off");
    f.assert_landed(id, false);

    f.vault
        .set_pack_hook_enabled(&f.owner_proof, id, true)
        .expect("the owner's dial turns the hook on");
    f.assert_landed(id, true);
}

#[test]
fn the_owners_removal_of_the_pack_stops_its_binding() {
    let f = Fixture::new();
    let id = f.put_pack();

    let receipt = f
        .vault
        .remove_pack(&f.owner_proof, PACK)
        .expect("the owner removes the pack");
    assert_eq!(receipt.pack_name, PACK);
    f.assert_landed(id, false);
}
