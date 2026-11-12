//! [EMBEDDED-OWNER-IGNORES-BOUND-PROOF] (FIX-LIST 23014): the embedded
//! owner's door (`Memory::embedded_owner`) on a handle a host bound to a
//! credential (`Memory::with_read_proof`) admits only while that credential
//! is the owner's own live human slip that reaches the door's verb and cuts
//! nothing else: the owner's full slip, or one the owner minted to a verb
//! subset (`oneiron token read` mints `core:read`). The proof it mints
//! carries the credential, so a door that revalidates the proof refuses once
//! it is revoked. A credential cut on another axis, the owner's too, or one
//! whose verbs do not reach the door's verb, takes no owner door: an owner
//! read behind the door falls to its reader route, which reads only what the
//! credential grants. An unbound owner handle keeps the door. The clock
//! repair's writer judges a bound handle's credential by the same rule.
//!
//! Public paths only:
//! `cargo test --locked -p oneiron --all-features --test embedded_owner_bound_credential`.

use oneiron::agent_dispatch::SpendScopeId;
use oneiron::agent_dispatch::budget_doors::{OpenSpendLeaseRequest, SpendScopeRequest};
use oneiron::authority::{HostSlipIssuer, SlipClaims, VerifiedSlip};
use oneiron::federation::ScopeAxis;
use oneiron::memory::MemoryError;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The owner verb the door is asked for: `vault.budgets.lease`, a Read row,
/// takes the embedded owner's door first and its reader route on a refusal.
const VERB: &str = "vault.budgets.lease";
/// The clock repair's verb, a Write row.
const REPAIR_VERB: &str = "vault.authority.clock.repair";
/// An owner verb outside the verb-scoped credential's subset: a Write row
/// that credential neither names nor holds `core:write` for.
const OUTSIDE_VERB: &str = "vault.packs.put";
/// The launch root the owner opens. A launch root names no run, so no one
/// but the owner reads its lease.
const LAUNCH: &str = "launch-bound-owner";
/// The challenge each credential is verified on.
const CHALLENGE: &[u8] = b"oneiron-request:embedded-owner-bound-credential";
/// The id of the owner's full credential.
const FULL_SLIP: [u8; 32] = [0x71; 32];
/// The id of the owner's narrower credential.
const NARROW_SLIP: [u8; 32] = [0x72; 32];
/// The id of the owner's verb-scoped credential.
const VERB_SCOPED_SLIP: [u8; 32] = [0x73; 32];

/// A process-owned vault, as an embedded owner opens it: it holds the
/// writer lease, so the embedded owner's door admits the owner.
fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    Ok((dir, vault))
}

/// A credential of the owner's own, minted from the host root and verified
/// on the root's key. `narrow` cuts its claims: none leaves it full owner
/// grade.
fn owner_credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    slip_id: [u8; 32],
    narrow: impl FnOnce(&mut SlipClaims),
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    let root = vault.ensure_host_root_slip(issuer)?;
    let issued_at = vault.capability_slip_now()?;
    let mut claims = root.claims;
    claims.slip_id = slip_id;
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    narrow(&mut claims);
    let slip = vault.mint_capability_slip(issuer, claims)?;
    let proof = issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(vault.verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &proof)?)
}

/// The owner's credential minted to a verb subset, whole on every other
/// axis: `core:read`, as `oneiron token read` mints one for the owner, and
/// the clock repair by name. It reaches every Read row and the repair, and
/// no other Write row.
fn owner_verb_scoped_credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    owner_credential(vault, issuer, owner, VERB_SCOPED_SLIP, |claims| {
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            REPAIR_VERB.to_owned(),
        ]));
    })
}

/// The owner opens the launch root [`LAUNCH`] on the unbound handle.
fn open_launch(vault: &Vault, owner: EntityId) -> TestResult {
    oneiron::verbs::vault_budgets_lease_open(
        &vault.memory(owner, EdgeActorClass::Human),
        OpenSpendLeaseRequest {
            launch: LAUNCH.to_owned(),
            cap_units: 1_000,
            unit: "units".to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )?;
    Ok(())
}

fn launch_lease() -> SpendScopeRequest {
    SpendScopeRequest {
        scope: LAUNCH.to_owned(),
    }
}

/// The refusal `result` holds; a pass panics with `why`, at the caller.
#[track_caller]
fn refused<T>(result: Result<T, MemoryError>, why: &str) -> MemoryError {
    match result {
        Ok(_) => panic!("{why}"),
        Err(error) => error,
    }
}

#[test]
fn an_owner_handle_bound_to_the_owners_own_credential_takes_the_owner_door_until_it_is_revoked()
-> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    open_launch(&vault, owner)?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-embedded-owner-bound")?;
    let credential = owner_credential(&vault, &issuer, owner, FULL_SLIP, |_| {})?;
    let bound = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&credential);

    // While the owner's own full credential holds, the bound handle is the
    // owner's: the door admits it, and the owner reads the launch root.
    let proof = bound.embedded_owner(VERB)?;
    vault.recheck_owner(&proof)?;
    let read = oneiron::verbs::vault_budgets_lease(&bound, launch_lease())?;
    assert_eq!(read.lease.scope, SpendScopeId::launch(LAUNCH)?);

    // Revoked, the same handle takes no owner door.
    vault.revoke_capability_slip(&issuer, FULL_SLIP)?;
    let door = refused(
        bound.embedded_owner(VERB),
        "a handle bound to the owner's revoked credential still takes the owner's door",
    );
    assert_eq!(door.code, "FORBIDDEN", "{door:?}");
    assert!(
        vault.recheck_owner(&proof).is_err(),
        "the proof taken while the credential held carries it, so a door that revalidates it \
         refuses once it is revoked"
    );
    let read = refused(
        oneiron::verbs::vault_budgets_lease(&bound, launch_lease()),
        "a handle bound to the owner's revoked credential still reads the launch root",
    );
    assert_eq!(read.code, "FORBIDDEN", "{read:?}");

    // The unbound handle of the same owner keeps the door.
    let unbound = vault.memory(owner, EdgeActorClass::Human);
    vault.recheck_owner(&unbound.embedded_owner(VERB)?)?;
    let read = oneiron::verbs::vault_budgets_lease(&unbound, launch_lease())?;
    assert_eq!(read.lease.scope, SpendScopeId::launch(LAUNCH)?);
    Ok(())
}

#[test]
fn an_owner_handle_bound_to_a_narrower_credential_of_the_owners_takes_no_owner_door() -> TestResult
{
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    open_launch(&vault, owner)?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-embedded-owner-narrow")?;
    let credential = owner_credential(&vault, &issuer, owner, NARROW_SLIP, |claims| {
        claims.records.insert(owner.to_hex());
    })?;
    let bound = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&credential);

    let door = refused(
        bound.embedded_owner(VERB),
        "a handle bound to a narrower credential of the owner's takes the owner's door",
    );
    assert_eq!(door.code, "FORBIDDEN", "{door:?}");
    // The owner read behind the door falls to its reader route, and a
    // launch root is no run of the caller's.
    let read = refused(
        oneiron::verbs::vault_budgets_lease(&bound, launch_lease()),
        "a handle bound to a narrower credential of the owner's reads the launch root",
    );
    assert_eq!(read.code, "FORBIDDEN", "{read:?}");

    // The unbound handle of the same owner keeps the door.
    let unbound = vault.memory(owner, EdgeActorClass::Human);
    vault.recheck_owner(&unbound.embedded_owner(VERB)?)?;
    let read = oneiron::verbs::vault_budgets_lease(&unbound, launch_lease())?;
    assert_eq!(read.lease.scope, SpendScopeId::launch(LAUNCH)?);
    Ok(())
}

#[test]
fn a_bound_owner_handle_calls_the_clock_repair_with_its_credential() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-embedded-owner-repair")?;
    let credential = owner_credential(&vault, &issuer, owner, NARROW_SLIP, |claims| {
        claims.records.insert(owner.to_hex());
    })?;
    let bound = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&credential);

    // The repair's writer judges a verified credential again (only the
    // owner's own slip that reaches the repair and cuts nothing else acts as
    // the owner); the bare embedded caller is the owner without one.
    let caller = bound.embedded_clock_repair_caller(REPAIR_VERB)?;
    assert_eq!(
        format!("{caller:?}"),
        r#"ClockRepairCaller("verified")"#,
        "a bound handle's repair is judged on its credential, not as the bare embedded owner"
    );
    assert!(
        vault.repair_authority_clock_for(caller).is_err(),
        "the repair's writer binds the owner to a credential whose records are cut"
    );
    let caller = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_clock_repair_caller(REPAIR_VERB)?;
    assert_eq!(format!("{caller:?}"), r#"ClockRepairCaller("embedded")"#);
    Ok(())
}

#[test]
fn an_owner_handle_bound_to_the_owners_verb_scoped_credential_takes_the_owner_doors_of_its_verbs_only()
-> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    open_launch(&vault, owner)?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-embedded-owner-verbs")?;
    let credential = owner_verb_scoped_credential(&vault, &issuer, owner)?;
    let bound = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&credential);

    // `vault.budgets.lease` is a Read row and the credential holds
    // `core:read`: the door admits the owner, the proof carries the
    // credential, and the owner reads the launch root.
    let proof = bound.embedded_owner(VERB)?;
    vault.recheck_owner(&proof)?;
    let read = oneiron::verbs::vault_budgets_lease(&bound, launch_lease())?;
    assert_eq!(read.lease.scope, SpendScopeId::launch(LAUNCH)?);

    // The clock repair is a Write row the credential names: the repair's
    // writer binds the owner to it.
    vault.repair_authority_clock_for(bound.embedded_clock_repair_caller(REPAIR_VERB)?)?;

    // `vault.packs.put` is a Write row it neither names nor holds
    // `core:write` for.
    let door = refused(
        bound.embedded_owner(OUTSIDE_VERB),
        "a handle bound to the owner's verb-scoped credential takes the owner's door of a verb \
         outside its subset",
    );
    assert_eq!(door.code, "FORBIDDEN", "{door:?}");
    Ok(())
}

#[test]
fn an_owner_handle_bound_to_the_owners_revoked_verb_scoped_credential_takes_no_owner_door()
-> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    open_launch(&vault, owner)?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-embedded-owner-verbs-revoked")?;
    let credential = owner_verb_scoped_credential(&vault, &issuer, owner)?;
    let bound = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&credential);
    let proof = bound.embedded_owner(VERB)?;

    vault.revoke_capability_slip(&issuer, VERB_SCOPED_SLIP)?;
    let door = refused(
        bound.embedded_owner(VERB),
        "a handle bound to the owner's revoked verb-scoped credential still takes the owner's door",
    );
    assert_eq!(door.code, "FORBIDDEN", "{door:?}");
    assert!(
        vault.recheck_owner(&proof).is_err(),
        "the proof taken while the verb-scoped credential held carries it, so a door that \
         revalidates it refuses once it is revoked"
    );
    let read = refused(
        oneiron::verbs::vault_budgets_lease(&bound, launch_lease()),
        "a handle bound to the owner's revoked verb-scoped credential still reads the launch root",
    );
    assert_eq!(read.code, "FORBIDDEN", "{read:?}");
    assert!(
        vault
            .repair_authority_clock_for(bound.embedded_clock_repair_caller(REPAIR_VERB)?)
            .is_err(),
        "the repair's writer binds the owner to a revoked credential"
    );
    Ok(())
}
