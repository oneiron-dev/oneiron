//! World privacy P6b: the host's own node (Engine ruling, 2026-10-14). Managed
//! serve signs this install's machine into the roster as a `HostedNode`, under
//! the host root. It is never the owner's, so never a world key's recipient,
//! and once the owner removes it no restart enrols it again.
use super::machine_identity::own_encryption_key;
use super::*;
use crate::store::GateDecisionId;
use crate::{Vault, VaultConfig};

fn open_hosted(path: &std::path::Path) -> Vault {
    let mut config = VaultConfig::default();
    config.privacy = crate::config::VaultPrivacyConfig {
        posture: crate::HostingPrivacyPosture::Hosted,
        data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
            key_ref: "host-node-test".into(),
        },
    };
    let vault = Vault::open(path, config).unwrap();
    // As managed serve does after its open gates: this install's key slots.
    let vault_id = vault.authority_fold().unwrap().vault_id;
    if let Some(vault_id) = vault_id {
        own_encryption_key(&vault, vault_id);
    }
    vault
}

#[test]
fn the_hosts_node_is_never_mine_and_never_returns_once_removed() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = crate::test_support::test_host_issuer();
    let vault = open_hosted(dir.path());
    vault.ensure_host_root_slip(&issuer).unwrap();
    let person = crate::vault::embedded_owner_actor_id().unwrap();
    vault.bind_host_owner_for_test(&issuer, person).unwrap();
    let vault_id = vault.authority_fold().unwrap().vault_id.unwrap();
    own_encryption_key(&vault, vault_id);

    let node = vault.provision_host_node(&issuer).unwrap();
    let id = vault.local_machine().unwrap().unwrap().id;
    let roster = node.roster.as_ref().unwrap();
    assert_eq!(roster.profile.machine, id);
    assert_eq!(roster.profile.role, MachineRole::HostedNode);
    assert_eq!(roster.profile.owner, person);
    // A restart finds its own node and appends nothing.
    let heads = vault.authority_fold().unwrap().append_heads;
    assert_eq!(vault.provision_host_node(&issuer).unwrap(), node);
    let fold = vault.authority_fold().unwrap();
    assert_eq!(fold.append_heads, heads);
    // Never mine, so never a recipient: wraps go to trusted identities only.
    assert!(fold.trusted_machine(id).is_none());
    assert!(!vault.local_machine().unwrap().unwrap().mine);

    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            id,
            MachineRole::Removed,
            None,
        )
        .unwrap();
    drop(vault);
    let vault = open_hosted(dir.path());
    let heads = vault.authority_fold().unwrap().append_heads;
    assert!(vault.provision_host_node(&issuer).is_err());
    let fold = vault.authority_fold().unwrap();
    assert_eq!(fold.append_heads, heads);
    assert!(fold.machine(id).unwrap().roster.as_ref().unwrap().removed);
}

/// A hosted owner without the operator's per-vault capability is refused his
/// checkpoint root choice, and the refusal names the rule (the owner's
/// QUORUM-HOST-ROOT = C: the host key signs a hosted vault's checkpoints) and
/// the self-host and relay route, with no bound kind (census L9-61; RULING
/// L9-61-CHECKPOINT = A).
#[test]
fn a_hosted_checkpoint_root_choice_names_the_host_key_rule_and_the_self_host_route() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = crate::test_support::test_host_issuer();
    let vault = open_hosted(dir.path());
    vault.ensure_host_root_slip(&issuer).unwrap();
    let person = crate::vault::embedded_owner_actor_id().unwrap();
    vault.bind_host_owner_for_test(&issuer, person).unwrap();
    let vault_id = vault.authority_fold().unwrap().vault_id.unwrap();
    own_encryption_key(&vault, vault_id);
    let _node = vault.provision_host_node(&issuer).unwrap();
    assert!(!vault.checkpoint_policy_selection_available());
    let owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let choice = CheckpointRootChoice {
        roots: vec![AuthorityKey::Ed25519([7; 32])],
        quorum: 1,
        hardware: false,
    };
    let refused = vault.set_checkpoint_policy_as(
        &ActAuthority::Owner(owner, ActSurface::ThisInstall),
        Some(choice),
        None,
    );
    let Err(crate::error::Error::Record(crate::error::RecordError::CheckpointPolicyRefused(
        reason,
    ))) = refused
    else {
        panic!("{refused:?}");
    };
    assert!(
        reason.starts_with("hosted checkpoint root selection requires"),
        "{reason}"
    );
    assert!(
        reason.contains("on a hosted vault the host key signs its checkpoints"),
        "{reason}"
    );
    assert!(
        reason.contains("a self-hosted or relay vault's owner chooses its roots"),
        "{reason}"
    );
    for kind in ["law", "provider", "capacity"] {
        assert!(!reason.contains(kind), "{reason}");
    }
}
