//! The owner's four lifetime keys. Each lifetime below was a constant no one could move; it is
//! now the default of a Setting key the owner sets (a longer lifetime is the looser value, so
//! only the owner raises it):
//! - `secrets.grant.max_ttl_secs` (one hour): a secret grant asking for longer is cut to it;
//! - `support.grant.max_ttl_secs` (one day): a support grant asking for longer is refused;
//! - `federation.invitation.ttl_secs` (fourteen days): how long a shared vault invitation
//!   stays open;
//! - `federation.delegate.max_ttl_secs` (ninety days): a Delegate expiring later is refused.
//!
//! For each key, two tests: with no row set the default holds as it did before the key, and
//! once the owner raises the key the longer lifetime is granted and stands.
//!
//! `cargo test --locked -p oneiron --all-features --test owner_lifetime_cap_keys`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole, SUPPORT_GRANT_MAX_TTL_SECS,
    SupportGrantQuery, SupportGrantRequest, SupportGrantStatus, SupportHolderClass,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, MAX_DELEGATE_TTL_SECS, SHARED_INVITATION_TTL_SECS, Scope,
    ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling, SharedVaultChange,
    decode_federation_grant_body,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::secret_lease::{
    NoSecretHostDelivery, SECRET_GRANT_MAX_TTL_SECS, SecretGrantCaller, SecretGrantRef,
    SecretGrantTarget,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

/// The instant every vault on a manual clock opens at.
const T0: u64 = 1_800_000_000;
const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;
/// The shared vault's id. Not 7, the own-device residence scope's id.
const SHARED: u64 = 43;
/// The secret the door grants read, and its value.
const SECRET: &str = "owen-slack";
const SECRET_VALUE: &[u8] = b"xoxb-lifetime-key-value";
/// When the owner registers the secret.
const CUSTODY_AT: u64 = 1_780_000_000;
const CHALLENGE: &[u8] = b"owner-lifetime-cap-keys";

/// The owner sets `key` to `secs` at the vault scope.
fn raise(vault: &Vault, owner: &AuthenticatedOwner, key: &str, secs: u64) {
    let raised = vault.set_setting(
        SettingCaller::Owner(owner),
        SetSetting::vault_value(key, json!(secs)),
    );
    assert!(
        matches!(raised, Ok(SetSettingOutcome::Applied { .. })),
        "the owner sets `{key}` to {secs} seconds: {raised:?}"
    );
}

/// A live PERSON.
fn person(vault: &Vault, at: u64) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            b"owner lifetime keys fixture",
        )
        .expect("person row");
    id
}

/// An owned vault whose owner holds one secret that a `slack.auth_test` door grant reads. The
/// vault drops first.
struct Custody {
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn custody() -> Custody {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .register_secret_as_owner(
            &owner,
            &OwnerSecretRegistration {
                name: SECRET,
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    // The effector of the `slack.auth_test` operation.
                    effector: "connector:slack".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: SECRET_VALUE,
            },
            CUSTODY_AT,
        )
        .expect("register the secret");
    Custody {
        vault,
        actor,
        owner,
        _dir: dir,
    }
}

/// The owner mints a door grant on the secret asking for `ttl_secs`, and the grant redeems at
/// its door: the lifetime the grant was given.
fn door_grant_lifetime(custody: &Custody, ttl_secs: u64) -> u64 {
    let vault = &custody.vault;
    let caller = SecretGrantCaller::of(&vault.memory(custody.actor, EdgeActorClass::Human), None)
        .expect("the grant's caller");
    let target = SecretGrantTarget::Operation {
        name: "slack.auth_test".to_owned(),
    };
    let minted = vault
        .mint_secret_grant_for_name(
            &caller,
            SECRET,
            target.clone(),
            Some(ttl_secs),
            None,
            &mut NoSecretHostDelivery,
        )
        .expect("mint the door grant");
    let grant = SecretGrantRef::new(minted.grant.grant_id, caller.holder());
    let mut sent = Vec::new();
    vault
        .redeem_secret_grant_at_door(&grant, &target, &mut |value: &[u8]| {
            sent = value.to_vec();
            Ok(())
        })
        .expect("redeem the grant at its door");
    assert_eq!(
        sent, SECRET_VALUE,
        "the grant stands: its door sends the value"
    );
    minted.grant.expires_at - minted.grant.granted_at
}

#[test]
fn a_secret_grant_is_cut_to_one_hour_until_the_owner_raises_the_cap() {
    let custody = custody();
    assert_eq!(
        door_grant_lifetime(&custody, 2 * HOUR),
        SECRET_GRANT_MAX_TTL_SECS,
        "with no cap set, a two-hour ask is cut to one hour"
    );
}

#[test]
fn a_raised_secret_grant_cap_lets_a_longer_grant_stand() {
    let custody = custody();
    raise(
        &custody.vault,
        &custody.owner,
        "secrets.grant.max_ttl_secs",
        2 * HOUR,
    );
    assert_eq!(
        door_grant_lifetime(&custody, 5 * HOUR),
        2 * HOUR,
        "under a two-hour cap a five-hour ask is cut to two hours, not to one"
    );
}

/// One rooted, owner-bound vault on a clock the test moves, with one named WORLD for a
/// support grant to read. The vault drops first.
struct Rooted {
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    world: EntityId,
    _dir: tempfile::TempDir,
}

fn rooted(seed: u8) -> Rooted {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES])
        .expect("independent host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let world = vault
        .create_world(&proof, "Support visit", T0)
        .expect("named WORLD");
    Rooted {
        vault,
        clock,
        issuer,
        proof,
        world,
        _dir: dir,
    }
}

/// What the owner approves for one support person: read over the one named WORLD, for
/// `ttl_secs`. The holder is a new live PERSON; `key` is the support party's own key.
fn support_request(rooted: &Rooted, key: &HostSlipIssuer, ttl_secs: u64) -> SupportGrantRequest {
    SupportGrantRequest {
        holder: person(&rooted.vault, T0),
        holder_class: SupportHolderClass::Human,
        holder_key: key.binding_key(),
        scope: Scope {
            worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(rooted.world)])),
            facets: ScopeAxis::All,
            bands: ScopeAxis::All,
            audience: ScopeAxis::All,
            verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
            sensitivity: SensitivityCeiling::AtMost(Sensitivity::Restricted),
        },
        records: BTreeSet::new(),
        ttl_secs: Some(ttl_secs),
        purpose: "restore the calendar view".to_owned(),
        ticket_ref: None,
        comm: None,
        repairs: BTreeSet::new(),
    }
}

/// The support party's own key, independent of the host's.
fn support_key(seed: u8) -> HostSlipIssuer {
    HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES]).expect("the support party's own key")
}

#[test]
fn a_support_grant_over_one_day_is_refused_until_the_owner_raises_the_cap() {
    let rooted = rooted(0x51);
    let over = rooted.vault.mint_support_grant(
        &rooted.proof,
        &rooted.issuer,
        support_request(&rooted, &support_key(0x61), SUPPORT_GRANT_MAX_TTL_SECS + 1),
    );
    assert!(
        over.is_err(),
        "with no cap set, a support grant over one day is refused: {over:?}"
    );
    let minted = rooted
        .vault
        .mint_support_grant(
            &rooted.proof,
            &rooted.issuer,
            support_request(&rooted, &support_key(0x62), SUPPORT_GRANT_MAX_TTL_SECS),
        )
        .expect("a one-day support grant mints");
    assert_eq!(
        minted.grant.delegation.wall_expires_at - minted.grant.delegation.approved_at,
        SUPPORT_GRANT_MAX_TTL_SECS
    );
}

#[test]
fn a_raised_support_grant_cap_lets_a_longer_grant_stand() {
    let rooted = rooted(0x52);
    raise(
        &rooted.vault,
        &rooted.proof,
        "support.grant.max_ttl_secs",
        7 * DAY,
    );
    let over = rooted.vault.mint_support_grant(
        &rooted.proof,
        &rooted.issuer,
        support_request(&rooted, &support_key(0x63), 7 * DAY + 1),
    );
    assert!(
        over.is_err(),
        "the raised cap still bounds a support grant: {over:?}"
    );
    let key = support_key(0x64);
    let minted = rooted
        .vault
        .mint_support_grant(
            &rooted.proof,
            &rooted.issuer,
            support_request(&rooted, &key, 3 * DAY),
        )
        .expect("a three-day support grant mints under the raised cap");
    let delegation = &minted.grant.delegation;
    assert_eq!(
        delegation.wall_expires_at - delegation.approved_at,
        3 * DAY,
        "the grant's wall deadline is three days after its approval"
    );
    assert!(
        delegation.validate().is_ok(),
        "the delegation's own shape, which a log import and a slip check read, names no ceiling"
    );

    // Two days on, past the default one-day cap, the grant still stands: its slip verifies
    // for the support party, and the owner's list shows it active.
    rooted.clock.set(T0 + 2 * DAY);
    let signature = key
        .binding_proof(&minted.slip, CHALLENGE)
        .expect("the support party's holder proof");
    let verified = rooted.vault.verify_capability_slip(
        &rooted.issuer.public_key(),
        &minted.slip,
        CHALLENGE,
        &signature,
    );
    assert!(
        verified.is_ok(),
        "the three-day support slip verifies two days after its mint: {:?}",
        verified.err()
    );
    let listed = rooted
        .vault
        .list_support_grants(
            &rooted.proof,
            SupportGrantQuery {
                limit: 10,
                include_inactive: false,
            },
        )
        .expect("the owner lists support grants");
    assert!(
        listed.iter().any(|row| row.slip_id == minted.grant.slip_id
            && matches!(row.status, SupportGrantStatus::Active)),
        "the three-day support grant is listed active two days after its mint"
    );
}

/// A shared vault whose only member is its Owner, on a clock the test moves. The vault drops
/// first.
struct Shared {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner_proof: AuthenticatedOwner,
    /// The Owner's own grant: the parent of the Delegates below.
    owner_grant: EntityId,
    _dir: tempfile::TempDir,
}

fn shared() -> Shared {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let creation = vault
        .initialize_shared_vault(&owner_proof, SHARED, None, &[], T0)
        .expect("shared vault");
    let owner_grant = EntityId::from_hex(&creation.grant_refs[0]).expect("the Owner's grant id");
    Shared {
        vault,
        clock,
        owner_proof,
        owner_grant,
        _dir: dir,
    }
}

/// The Owner invites a new person as a Member: the invitee's proof and their one open
/// invitation's id and lifetime.
fn invite(shared: &Shared) -> (AuthenticatedOwner, String, u64) {
    let invitee = person(&shared.vault, 1);
    let invited = shared
        .vault
        .add_shared_member(&shared.owner_proof, SHARED, invitee, Some(Role::Member))
        .expect("the Owner invites a Member");
    let SharedVaultChange::MemberInvited {
        invitation,
        expires_at,
        ..
    } = invited.change
    else {
        panic!("the Owner's add is an invitation");
    };
    let proof = shared
        .vault
        .authenticate_owner(invitee, &invitee.to_hex(), true, GateDecisionId::now())
        .expect("invitee proof");
    let open = shared
        .vault
        .shared_invitations(&proof, SHARED)
        .expect("the invitee's open invitations");
    assert_eq!(open.len(), 1, "one open invitation");
    assert_eq!(open[0].id, invitation);
    assert_eq!(open[0].expires_at, expires_at);
    (proof, invitation, open[0].expires_at - open[0].issued_at)
}

/// How many invitations to the shared vault the invitee still has open.
fn open_invitations(shared: &Shared, invitee: &AuthenticatedOwner) -> usize {
    shared
        .vault
        .shared_invitations(invitee, SHARED)
        .expect("the invitee's open invitations")
        .len()
}

#[test]
fn an_invitation_stays_open_fourteen_days_until_the_owner_sets_a_lifetime() {
    let shared = shared();
    let (invitee, invitation, lifetime) = invite(&shared);
    assert_eq!(lifetime, SHARED_INVITATION_TTL_SECS);

    shared.clock.set(T0 + 15 * DAY);
    assert_eq!(
        open_invitations(&shared, &invitee),
        0,
        "with no lifetime set, the invitation is closed fifteen days on"
    );
    let late = shared
        .vault
        .accept_shared_invitation(&invitee, SHARED, &invitation);
    assert!(
        late.is_err(),
        "with no lifetime set, the invitation is not accepted fifteen days on"
    );
}

#[test]
fn a_raised_invitation_lifetime_keeps_the_invitation_open_longer() {
    let shared = shared();
    raise(
        &shared.vault,
        &shared.owner_proof,
        "federation.invitation.ttl_secs",
        30 * DAY,
    );
    let (invitee, invitation, lifetime) = invite(&shared);
    assert_eq!(lifetime, 30 * DAY);

    shared.clock.set(T0 + 15 * DAY);
    assert_eq!(
        open_invitations(&shared, &invitee),
        1,
        "under a thirty-day lifetime the invitation is still open fifteen days on"
    );
    let accepted = shared
        .vault
        .accept_shared_invitation(&invitee, SHARED, &invitation);
    assert!(
        accepted.is_ok(),
        "under a thirty-day lifetime the invitee accepts fifteen days on: {:?}",
        accepted.err()
    );
}

/// The Owner mints a Delegate for a new person from the Owner's own grant, expiring at
/// `expires_at`.
fn delegate(shared: &Shared, expires_at: u64) -> oneiron::Result<EntityId> {
    shared.vault.create_federation_delegate(
        &shared.owner_proof,
        shared.owner_grant,
        person(&shared.vault, 1),
        T0,
        expires_at,
    )
}

/// The expiry the stored Delegate grant `id` carries.
fn delegate_expiry(vault: &Vault, id: EntityId) -> Option<u64> {
    let body = vault
        .get(&id)
        .expect("grant row")
        .expect("the stored Delegate");
    let grant = decode_federation_grant_body(&body).expect("a grant");
    assert_eq!(grant.role, Role::Delegate);
    grant.expires_at
}

#[test]
fn a_delegate_past_ninety_days_is_refused_until_the_owner_raises_the_cap() {
    let shared = shared();
    let over = delegate(&shared, T0 + MAX_DELEGATE_TTL_SECS + 1);
    assert!(
        over.is_err(),
        "with no cap set, a Delegate expiring past ninety days is refused: {over:?}"
    );
    let at_cap = delegate(&shared, T0 + MAX_DELEGATE_TTL_SECS).expect("a ninety-day Delegate");
    assert_eq!(
        delegate_expiry(&shared.vault, at_cap),
        Some(T0 + MAX_DELEGATE_TTL_SECS)
    );
}

#[test]
fn a_raised_delegate_cap_lets_a_longer_delegate_stand() {
    let shared = shared();
    raise(
        &shared.vault,
        &shared.owner_proof,
        "federation.delegate.max_ttl_secs",
        365 * DAY,
    );
    let over = delegate(&shared, T0 + 365 * DAY + 1);
    assert!(
        over.is_err(),
        "the raised cap still bounds a Delegate: {over:?}"
    );
    let longer =
        delegate(&shared, T0 + 200 * DAY).expect("a 200-day Delegate mints under the raised cap");
    assert_eq!(
        delegate_expiry(&shared.vault, longer),
        Some(T0 + 200 * DAY),
        "the stored Delegate decodes with its 200-day expiry"
    );
}
