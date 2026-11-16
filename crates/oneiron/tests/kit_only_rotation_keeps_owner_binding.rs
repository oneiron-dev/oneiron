//! The kit-only rotation keeps the owner's `human` binding when the
//! generation it revokes held it (Sol carry-fix D3, 16 Nov). On a
//! self-hosted vault whose owner holds no other `human` binding, the kit's
//! activation binds the owner to the root's authority key R, generation 0,
//! as `human` (the enrolment's own rule). Switching to kit-only revokes
//! generation 0, and the revocation ends its binding; the rotation then
//! binds the owner to generation 1, signed by generation 1.
//!
//! Red at the kit-only head `508c21a6a468` with this file (the rotation has
//! no bind step there): the switch succeeds and the last assertion fails
//! ("the owner's human binding moved to generation 1"), because no active
//! `human` binding names the owner after the switch. Green at `178baf7b0f0`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test kit_only_rotation_keeps_owner_binding`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::root_recovery::released_authority_seed;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::world_keys::{NoRecoveryBox, RecoveryPreset, RecoveryRootSeed};
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// A self-hosted vault whose owner's only `human` binding is the kit's R,
/// generation 0: the host root's binding of the owner moves to an agent
/// before the kit is confirmed, so the activation's enrolment binds R.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    person: EntityId,
    vault_id: [u8; 32],
    pieces: Vec<oneiron::store::recovery_kit::KitPiece>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
    vault.ensure_host_root_slip(&issuer).expect("the host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the data key");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let issued = vault
        .issue_world_kit(
            &proof(&vault, person),
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::RecoveryCode(CodeKeeping::Paper),
                    PieceHome::TrustedPerson,
                    PieceHome::SecurityKey,
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
        )
        .expect("a kit");
    // The host key holds one live binding: binding it to an agent leaves
    // the owner with no `human` binding.
    bind_host_actor(&vault, &issuer, EntityId::now(), "agent")
        .expect("the host key bound to an agent");
    let fixture = Fixture {
        _dir: dir,
        vault,
        _issuer: issuer,
        person,
        vault_id,
        pieces: issued.pieces,
    };
    fixture
        .vault
        .confirm_world_kit(
            &fixture.owner(),
            &fixture.kit_refs(),
            None,
            &BTreeSet::new(),
        )
        .expect("the kit confirms");
    fixture
}

impl Fixture {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    fn kit_refs(&self) -> Vec<&oneiron::store::recovery_kit::KitPiece> {
        self.pieces.iter().take(2).collect()
    }

    /// Generation `generation`'s key, via the box's bytes.
    fn generation_key(&self, generation: u32) -> AuthorityKey {
        let secret = restore_kit(
            self.vault_id,
            KitSecretKind::RecoveryRoot,
            &self.kit_refs(),
            None,
        )
        .expect("two pieces restore the seed");
        let seed = RecoveryRootSeed::from_restored_kit(secret).expect("the seed");
        let signing =
            SigningKey::from_bytes(&released_authority_seed(&seed, &self.vault_id, generation));
        AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
    }

    /// The keys bound to the owner as `human`, active.
    fn human_keys(&self) -> Vec<AuthorityKey> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .iter()
            .filter(|(_, binding)| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_class == "human"
                    && binding.actor_ref == self.person
            })
            .map(|(key, _)| key.clone())
            .collect()
    }
}

#[test]
fn the_kit_only_switch_moves_the_owners_binding_from_generation_0_to_generation_1() {
    let fixture = fixture();
    assert_eq!(
        fixture.vault.privacy_posture(),
        HostingPrivacyPosture::SelfHostLocal,
        "premise: a self-hosted vault"
    );
    let gen0 = fixture.generation_key(0);
    let gen1 = fixture.generation_key(1);
    assert_eq!(
        fixture.human_keys(),
        vec![gen0],
        "premise: the kit's activation bound the owner to generation 0, their only human binding"
    );

    fixture
        .vault
        .set_recovery_preset_with_kit_as(
            &fixture.authority(),
            RecoveryPreset::NobodyButMe,
            &fixture.kit_refs(),
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("the switch with the kit");
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::NobodyButMe,
        "the switch landed"
    );

    assert_eq!(
        fixture.human_keys(),
        vec![gen1],
        "the owner's human binding moved to generation 1"
    );
}
