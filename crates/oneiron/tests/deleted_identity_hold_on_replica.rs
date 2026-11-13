//! A replica that never held a deleted self-held identity still keeps its
//! address (census L3-14; Engine RULING L3-14 = A, 13 Nov 20:49; ARCH-0063
//! #never-recycle-delete-built, the follow-up A2 of H102).
//!
//! The deleting vault keeps the hold in its own assignment slot. A vault
//! that joins after the delete never receives the row, so it gets no slot.
//! It does receive the identity's `channel_identity.*` claims, which the
//! delete closed `retracted` and kept. Admission now reads the hold from
//! those, so a fresh identity at the deleted address is refused on the
//! replica, as on the vault that deleted it. A delegated identity's delete
//! frees its address, there and on the replica.
//!
//! Vault A makes the identity in [`WINDOW`] and deletes it. Only then does
//! A open the window and vault B take all of it, so B never holds the row.
//!
//! A retracted head is what holds the address, so no writer may make one
//! (Engine RULING L3-14-RETAINED-HOLD-FORGE = A, 14 Nov 05:22): at the local
//! generic claim door a `channel_identity.*` claim is born Active, about a
//! live CHANNEL_IDENTITY row. A forged hold then cannot block the owner's
//! own create, and a correction head on a live identity still re-keys it
//! (OF-272).
//!
//! `cargo test --locked -p oneiron --all-features --test deleted_identity_hold_on_replica`.
// MemoryKeystore needs test-support (it forwards oneiron-keystore/test-keystore).
#![cfg(all(feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use loro::ExportMode;
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, DelegatedGrant, DelegatedGrantScope,
    DelegatedProvisionRequest, PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_CHANNEL, PREDICATE_CHANNEL_IDENTITY_SHAPE, SelfHeldShape,
    delegated_custody_scopes,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION,
    SecretCustodyStatus, decode_secret_custody_body,
};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::LoadedWindow;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DeleteReason, EntityId,
    ErrorKind, HnswConfig, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The window every row here lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`]: each identity is requested, so
/// learned, then.
const T0: u64 = 1_773_532_800;

const CHANNEL: &str = "email";

/// The custody record a delegated row is made true by.
const CUSTODY_NAME: &str = "oauth/gmail/member";

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test/model@v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// A vault with a process-memory keystore, as a host opens one: a delete
/// signs its receipt with this install's key.
fn open_vault() -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), config())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    // FIX 7957/9599: isolate subject-month work from bootstrap notifications.
    for key in vault.sync_state_keys_with_prefix("lm:w:1970-01:")? {
        vault.sync_state_delete(&key)?;
    }
    Ok((dir, vault))
}

fn agent() -> EntityId {
    EntityId::from_bytes([0x52; 16]).expect("agent id")
}

/// A requested self-held mailbox at `address`, learned at [`T0`].
fn self_held(address: &str) -> ChannelIdentity {
    ChannelIdentity::requested(
        CHANNEL,
        address,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent()),
        T0,
    )
}

/// Registers the OAuth grant a delegated row at `mailbox` is made true by:
/// a live custody record whose `connector:gmail` binding grants read and
/// names the mailbox as its subject. Out of the crate the record is built
/// through the public codec's key map.
fn register_delegated_custody(vault: &Vault, mailbox: &str) -> TestResult {
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:gmail")),
        (
            Value::from("tier_ceiling"),
            Value::from(u64::from(CustodyTier::T0Doored.as_u8())),
        ),
        (
            Value::from("scopes"),
            Value::Array(
                delegated_custody_scopes(CHANNEL, mailbox)
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            ),
        ),
    ]);
    let key = |i: usize| Value::from(SECRET_CUSTODY_BODY_KEYS[i]);
    let body = Value::Map(vec![
        (
            key(0),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (key(1), Value::from(CUSTODY_NAME)),
        (key(2), Value::from(CustodyClass::CrossVault.as_str())),
        (key(3), Value::from(true)),
        (key(4), Value::Binary(b"member-oauth-token".to_vec())),
        (key(5), Value::from(SecretCustodyStatus::Active.as_str())),
        (key(6), Value::from(T0)),
        (key(7), Value::Nil),
        (key(8), Value::from(0_u64)),
        (key(9), Value::Array(vec![binding])),
        (key(10), Value::from("")),
        (key(11), Value::Array(vec![])),
        (key(12), floor),
        (key(13), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.register_secret(decode_secret_custody_body(&bytes)?)?;
    Ok(())
}

/// What vault B, which never held the deleted row, ended with.
struct Replica {
    a: Arc<Vault>,
    b: Arc<Vault>,
    _window_b: LoadedWindow,
    _window_a: Arc<LoadedWindow>,
    _manager_a: Arc<WindowManager>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// Vault A makes the identity at `id` through `make` and deletes it for
/// `reason`. Then A opens [`WINDOW`] and vault B, opened fresh, takes all of
/// it. Fixture checks: B holds no row of the identity, and every claim A
/// held about it before the delete reached B.
fn replica_after_delete(
    id: EntityId,
    address: &str,
    make: impl FnOnce(&Vault) -> TestResult,
    reason: DeleteReason,
) -> TestResult<Replica> {
    let (dir_a, a) = open_vault()?;
    make(a.as_ref())?;
    if a.channel_identity_by_assignment(CHANNEL, address)?
        .map(|(held, _)| held)
        != Some(id)
    {
        return Err(format!("fixture: A routes {address} to no identity").into());
    }
    let claims = a.claims_for_subject(&id)?;
    if claims.is_empty() {
        return Err("fixture: the identity has no claims on A".into());
    }
    a.delete_entity_with_reason(&id, reason)
        .map_err(|error| format!("fixture: A's delete: {error:?}"))?;

    let manager_a = Arc::new(WindowManager::new(
        Arc::clone(&a),
        Arc::new(Materializer::new()),
        "node-a",
    ));
    let window_a = manager_a.open_window(&WindowKey::new(WINDOW))?;
    let (dir_b, b) = open_vault()?;
    let materializer_b = Arc::new(Materializer::new());
    let window_b = LoadedWindow::new("node-b", WindowKey::new(WINDOW), &b, &materializer_b);
    let all = window_a
        .doc
        .export(ExportMode::all_updates())
        .map_err(|error| format!("fixture: A's window export: {error:?}"))?;
    window_b
        .doc
        .import(&all)
        .map_err(|error| format!("fixture: B's window import: {error:?}"))?;

    if b.get_raw(&id)?.is_some_and(|row| !row.is_empty()) {
        return Err("fixture: B holds the deleted row".into());
    }
    for claim in &claims {
        if b.get_raw(claim)?.is_none() {
            return Err(format!(
                "fixture: A's claim {} about the identity did not reach B",
                claim.to_hex()
            )
            .into());
        }
    }
    Ok(Replica {
        a,
        b,
        _window_b: window_b,
        _window_a: window_a,
        _manager_a: manager_a,
        _dirs: (dir_a, dir_b),
    })
}

/// A self-held identity at `address`, deleted on A for `reason`: a fresh id
/// at its address is refused on A, and on B, which never held the row.
fn deleted_self_held_address_stays_held(address: &str, reason: DeleteReason) -> TestResult {
    let id = EntityId::now();
    let replica = replica_after_delete(
        id,
        address,
        |a| Ok(a.create_channel_identity(&id, &self_held(address))?),
        reason,
    )?;
    let on_a = replica
        .a
        .create_channel_identity(&EntityId::now(), &self_held(address))
        .expect_err("fixture: the deleting vault keeps the address (H102)");
    assert_eq!(on_a.kind(), ErrorKind::ChannelIdentityAlreadyExists);

    let on_b = replica
        .b
        .create_channel_identity(&EntityId::now(), &self_held(address));
    assert_eq!(
        on_b.as_ref().map_err(oneiron::Error::kind),
        Err(ErrorKind::ChannelIdentityAlreadyExists),
        "a replica that never held the deleted row must not recycle {address}",
    );
    assert!(
        replica
            .b
            .channel_identity_by_assignment(CHANNEL, address)?
            .is_none(),
        "the deleted address routes nothing on the replica",
    );
    Ok(())
}

#[test]
fn a_replica_that_never_held_a_soft_deleted_identity_refuses_its_address() -> TestResult {
    deleted_self_held_address_stays_held("soft-delete@example.test", DeleteReason::UserDelete)
}

#[test]
fn a_replica_that_never_held_a_hard_deleted_identity_refuses_its_address() -> TestResult {
    deleted_self_held_address_stays_held("hard-delete@example.test", DeleteReason::UserHardDelete)
}

/// Control (passes on main too): a delegated identity's delete frees its
/// address, so a fresh id there is admitted on A and on B alike.
#[test]
fn a_deleted_delegated_identity_frees_its_address_on_a_replica() -> TestResult {
    let address = "member@member-owned.example";
    let id = EntityId::now();
    let replica = replica_after_delete(
        id,
        address,
        |a| {
            register_delegated_custody(a, address)?;
            a.provision_delegated_identity(
                &id,
                DelegatedProvisionRequest {
                    channel: CHANNEL.to_owned(),
                    address_or_handle: address.to_owned(),
                    binding: ChannelIdentityBinding::agent(agent()),
                    grant: DelegatedGrant::new(CUSTODY_NAME, vec![DelegatedGrantScope::MailRead]),
                },
                T0,
            )?;
            Ok(())
        },
        DeleteReason::UserDelete,
    )?;
    replica
        .b
        .create_channel_identity(&EntityId::now(), &self_held(address))
        .expect("a deleted delegated identity's address is free on the replica");
    replica
        .a
        .create_channel_identity(&EntityId::now(), &self_held(address))
        .expect("a deleted delegated identity's address is free where it was deleted");
    Ok(())
}

/// A `channel_identity.*` head as any writer with claim write authority
/// builds it: the same constructor and fields as the engine's own heads.
fn generic_head(
    subject: EntityId,
    predicate: &str,
    value: &str,
    lifecycle: ClaimLifecycleStatus,
) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        lifecycle,
    )
    .expect("claim body")
}

/// Puts `body` at a fresh id through the public generic claim door.
fn put_generic(vault: &Vault, body: &ClaimBody) -> Result<EntityId, oneiron::Error> {
    let id = EntityId::now();
    vault.put_claim(&id, body, TimeRange { start: T0, end: T0 }, T0)?;
    Ok(id)
}

fn refused_kind(put: &Result<EntityId, oneiron::Error>) -> Option<ErrorKind> {
    put.as_ref().err().map(oneiron::Error::kind)
}

/// A plain PERSON row: an entity any writer may put claims about.
fn put_person(vault: &Vault) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("Decoy"))]),
    )?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: T0, end: T0 },
        T0,
        &body,
    )?;
    Ok(id)
}

/// RULING L3-14-RETAINED-HOLD-FORGE = A: a `channel_identity.*` claim is
/// born Active. A born-retracted address head is refused even on a live
/// identity.
#[test]
fn the_generic_claim_door_refuses_a_born_retracted_identity_head() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let id = EntityId::now();
    vault.create_channel_identity(&id, &self_held("live-holder@example.test"))?;
    let forged = put_generic(
        &vault,
        &generic_head(
            id,
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
            "victim-live@example.test",
            ClaimLifecycleStatus::Retracted,
        ),
    );
    assert_eq!(
        refused_kind(&forged),
        Some(ErrorKind::InvalidClaimBody),
        "a writer must not make a retracted channel_identity head: {forged:?}",
    );
    Ok(())
}

/// RULING L3-14-RETAINED-HOLD-FORGE = A: a `channel_identity.*` claim is
/// about a live CHANNEL_IDENTITY row. The forge the ruling closes: three
/// retracted heads naming an address, put on a PERSON the writer then
/// deletes. Every head is refused, an Active one too, so after the delete
/// the owner's own create at that address lands.
#[test]
fn identity_heads_on_another_entity_are_refused_and_cannot_hold_an_address() -> TestResult {
    let address = "victim@example.test";
    let (_dir, vault) = open_vault()?;
    let decoy = put_person(&vault)?;
    for (predicate, value) in [
        (PREDICATE_CHANNEL_IDENTITY_CHANNEL, CHANNEL),
        (PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE, address),
        (PREDICATE_CHANNEL_IDENTITY_SHAPE, "dedicated_address"),
    ] {
        let forged = put_generic(
            &vault,
            &generic_head(decoy, predicate, value, ClaimLifecycleStatus::Retracted),
        );
        assert_eq!(
            refused_kind(&forged),
            Some(ErrorKind::InvalidClaimBody),
            "a retracted {predicate} head on a PERSON must be refused: {forged:?}",
        );
    }
    let active = put_generic(
        &vault,
        &generic_head(
            decoy,
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
            address,
            ClaimLifecycleStatus::Active,
        ),
    );
    assert_eq!(
        refused_kind(&active),
        Some(ErrorKind::InvalidClaimBody),
        "an Active channel_identity head on a PERSON must be refused: {active:?}",
    );
    vault
        .delete_entity_with_reason(&decoy, DeleteReason::UserDelete)
        .map_err(|error| format!("fixture: the decoy's delete: {error:?}"))?;
    vault
        .create_channel_identity(&EntityId::now(), &self_held(address))
        .expect("no forged hold blocks the owner's own create");
    Ok(())
}

/// Control (passes on main too): the OF-272 correction still works through
/// the generic doors. An Active address head on a live identity, then its
/// supersession of the old head, re-keys the identity's slot.
#[test]
fn a_correction_head_on_a_live_identity_still_rekeys_its_slot() -> TestResult {
    let (old_address, new_address) = ("before@example.test", "after@example.test");
    let (_dir, vault) = open_vault()?;
    let id = EntityId::now();
    vault.create_channel_identity(&id, &self_held(old_address))?;
    let mut old_head = None;
    for claim in vault.claims_for_subject(&id)? {
        if vault.get_claim(&claim)?.is_some_and(|body| {
            body.predicate == PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE
                && body.lifecycle == ClaimLifecycleStatus::Active
        }) {
            old_head = Some(claim);
        }
    }
    let old_head = old_head.ok_or("fixture: the identity has no Active address head")?;
    let correction = put_generic(
        &vault,
        &generic_head(
            id,
            PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
            new_address,
            ClaimLifecycleStatus::Active,
        ),
    )
    .map_err(|error| format!("the correction head is refused: {error:?}"))?;
    vault
        .supersede_claim(&correction, &old_head, T0 + 60)
        .map_err(|error| format!("the correction's supersession is refused: {error:?}"))?;
    assert_eq!(
        vault
            .channel_identity_by_assignment(CHANNEL, new_address)?
            .map(|(held, _)| held),
        Some(id),
        "the corrected address routes to the identity",
    );
    Ok(())
}
