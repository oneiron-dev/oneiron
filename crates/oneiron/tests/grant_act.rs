//! The general grant act (Fable pass 28 R2): a person's giving of a FEDERATION_GRANT row is a
//! signed act in the row's own write, committing to the row's terms under the row's own key.
//! The row stands on that act alone: a row with no act, a row widened in place, a row under
//! another key, and a row put again after its end stand for nothing; a counted end ends it; a
//! rule never gives; no row is keyed by an all-zero key.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use oneiron::test_doors::grant_act::{
    end_member_grant, give_member_grant, give_member_grant_by_rule, put_keyed_member_grant,
    put_unkeyed_member_grant,
};
use oneiron::test_doors::grant_standing::{grant_line, standing_member_grant_act};
use oneiron::{EntityId, Vault, VaultConfig};

const VAULT_ID: u64 = 7;
const TERMS_KEY: [u8; 32] = [0x5a; 32];

/// A vault whose install carries acts, and the person who decides.
struct Carrier {
    dir: tempfile::TempDir,
    vault: Vault,
    person: EntityId,
}

fn carrier() -> Carrier {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = HostSlipIssuer::from_secret(b"grant-act-r2a").expect("fixture host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry acts");
    Carrier { dir, vault, person }
}

fn member_grant(role: FederationGrantRole, preset: FederationGrantPreset) -> FederationGrant {
    FederationGrant::new(
        FederationGrantScope::vault(VAULT_ID),
        EntityId::now(),
        role,
        preset,
    )
}

#[test]
fn a_given_member_grant_stands_on_its_act() {
    let Carrier { dir, vault, person } = carrier();
    let id = EntityId::now();
    let grant = member_grant(FederationGrantRole::Member, FederationGrantPreset::Member);
    let act = give_member_grant(&vault, id, &grant, &TERMS_KEY, person).expect("person gives");
    let now = vault.now_recorded_at();
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("standing read"),
        Some(act),
        "the row stands on the act that gives it"
    );
    assert_eq!(
        grant_line(&vault, id).expect("line read"),
        Some((Some(act), false))
    );
    // The act is read back from the stored log: it decodes and folds again.
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopened vault");
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("standing read after reopen"),
        Some(act)
    );
}

#[test]
fn a_member_row_without_its_act_stands_for_nothing() {
    let Carrier { vault, .. } = carrier();
    let grant = member_grant(FederationGrantRole::Member, FederationGrantPreset::Member);
    let unkeyed = EntityId::now();
    put_unkeyed_member_grant(&vault, unkeyed, &grant).expect("row put");
    let keyed = EntityId::now();
    put_keyed_member_grant(&vault, keyed, &grant, &TERMS_KEY).expect("row put");
    let now = vault.now_recorded_at();
    for id in [unkeyed, keyed] {
        assert_eq!(
            standing_member_grant_act(&vault, id, now).expect("read"),
            None
        );
        assert_eq!(grant_line(&vault, id).expect("line read"), None);
    }
}

#[test]
fn a_member_row_widened_in_place_stands_for_nothing() {
    let Carrier { vault, person, .. } = carrier();
    let id = EntityId::now();
    let grant = member_grant(FederationGrantRole::Member, FederationGrantPreset::Member);
    let act = give_member_grant(&vault, id, &grant, &TERMS_KEY, person).expect("person gives");
    let widened = FederationGrant::new(
        FederationGrantScope::vault(VAULT_ID),
        grant.member_ref,
        FederationGrantRole::Admin,
        FederationGrantPreset::Admin,
    );
    put_keyed_member_grant(&vault, id, &widened, &TERMS_KEY).expect("widened row put");
    let now = vault.now_recorded_at();
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("read"),
        None,
        "the act does not open to the widened row"
    );
    // The row put back without its key keeps its terms and still stands for nothing.
    put_unkeyed_member_grant(&vault, id, &grant).expect("unkeyed row put");
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("read"),
        None
    );
    // The row as given stands again: the giving is still live.
    put_keyed_member_grant(&vault, id, &grant, &TERMS_KEY).expect("row put back");
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("read"),
        Some(act)
    );
}

#[test]
fn an_ended_member_grant_stands_for_nothing() {
    let Carrier { vault, person, .. } = carrier();
    let id = EntityId::now();
    let grant = member_grant(FederationGrantRole::Member, FederationGrantPreset::Member);
    let act = give_member_grant(&vault, id, &grant, &TERMS_KEY, person).expect("person gives");
    end_member_grant(&vault, id, person).expect("person ends");
    let now = vault.now_recorded_at();
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("read"),
        None
    );
    assert_eq!(
        grant_line(&vault, id).expect("line read"),
        Some((Some(act), true)),
        "the end is forever; the row stays and confers nothing"
    );
    // The row put again as it was given, with its key, still stands for nothing.
    put_keyed_member_grant(&vault, id, &grant, &TERMS_KEY).expect("row put again");
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("read"),
        None,
        "no row put after the end gives the Grant back"
    );
}

/// Catches a commitment that ignores its key: the row as given, under another key, stands for
/// nothing.
#[test]
fn a_member_row_under_another_key_stands_for_nothing() {
    let Carrier { vault, person, .. } = carrier();
    let id = EntityId::now();
    let grant = member_grant(FederationGrantRole::Member, FederationGrantPreset::Member);
    let act = give_member_grant(&vault, id, &grant, &TERMS_KEY, person).expect("person gives");
    put_keyed_member_grant(&vault, id, &grant, &[0xa5; 32]).expect("row put under another key");
    let now = vault.now_recorded_at();
    assert_eq!(
        standing_member_grant_act(&vault, id, now).expect("read"),
        None,
        "the act opens with the row's own key alone"
    );
    assert_eq!(
        grant_line(&vault, id).expect("line read"),
        Some((Some(act), false))
    );
}

/// An all-zero key is a key anyone can guess: no writer keys a row by it, so nothing is
/// written.
#[test]
fn no_member_row_is_keyed_by_an_all_zero_key() {
    let Carrier { vault, person, .. } = carrier();
    let id = EntityId::now();
    let grant = member_grant(FederationGrantRole::Member, FederationGrantPreset::Member);
    assert!(give_member_grant(&vault, id, &grant, &[0; 32], person).is_err());
    assert!(put_keyed_member_grant(&vault, id, &grant, &[0; 32]).is_err());
    assert_eq!(grant_line(&vault, id).expect("line read"), None);
}

#[test]
fn a_rule_never_gives() {
    let Carrier { vault, .. } = carrier();
    let id = EntityId::now();
    assert!(
        give_member_grant_by_rule(&vault, id).is_err(),
        "a rule only ends a Grant"
    );
    assert_eq!(grant_line(&vault, id).expect("line read"), None);
}
