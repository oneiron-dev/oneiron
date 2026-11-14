//! Engine RULING L6-03-WRITER-CARRY (14 Nov 06:16, "A now, C next"): when
//! the person who wrote a value that mask on write lifted rules its key no
//! secret (L6-03-WRITER-MARK = B), the revoke reaches the owner's other
//! machines as that person's own act, never as an owner act. The owner's
//! own ruling still carries as his.
//!
//! `cargo test --locked -p oneiron --all-features --test found_key_writer_carry`.

use std::sync::Arc;

use oneiron::authority::{
    ActBy, ActSurface, AuthorityOp, CustodyChange, HostSlipIssuer, MachineRole, OwnerAct,
    OwnerActKind, OwnerWorkBody,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::StructuralPutInput;
use oneiron::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_PERSON};
use oneiron::secret_custody::FoundKeyAction;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A vault with a device keystore, its embedded owner and a live PERSON who
/// does not own it, before this install has a machine profile.
fn open_vault() -> Result<(tempfile::TempDir, Vault, EntityId, EntityId), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let writer = EntityId::now();
    vault.put_entity(
        &writer,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    Ok((dir, vault, owner, writer))
}

/// Gives this install its live machine profile, so it can carry an act to
/// the owner's other machines.
fn profile_install(vault: &Vault) -> TestResult {
    let issuer = HostSlipIssuer::from_secret(b"found key writer carry host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok(())
}

/// `person`'s own proof: the owner tier for the owner, the person tier for
/// anyone else.
fn proof_of(
    vault: &Vault,
    person: EntityId,
) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    Ok(vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?)
}

/// An EVENT `writer` writes in their own name, whose notes hold the token.
fn write_event(vault: &Vault, writer: EntityId) -> EntityId {
    let receipt = vault
        .memory(writer, EdgeActorClass::Human)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({
                "name": "release",
                "notes": format!("deploy with token={TOKEN}"),
            }),
            text_fields: None,
            edges: None,
            occurred_at: 1,
            learned_at: None,
        })
        .unwrap_or_else(|error| panic!("FIXTURE: the person writes an EVENT: {error:?}"));
    EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the EVENT's id")
}

/// The handle of the key the mask lifted out of `record`, from the owner's
/// found-key list.
fn found_handle(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .ok_or("FIXTURE: the mask lifted the token into a found key")?)
}

/// The act of every custody revoke this install recorded for the owner's
/// other machines, as its authority log holds them.
fn carried_revokes(vault: &Vault) -> Result<Vec<OwnerAct>, Box<dyn std::error::Error>> {
    let mut acts = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)? {
        let entry = vault
            .get_authority_log_entry(&id)?
            .ok_or("FIXTURE: a listed authority entry exists")?;
        if let AuthorityOp::OwnerWorkRequest(request) = entry.op
            && matches!(
                request.work,
                OwnerWorkBody::Custody {
                    change: CustodyChange::Revoke,
                    ..
                }
            )
        {
            acts.push(request.act);
        }
    }
    Ok(acts)
}

/// `act` is `writer`'s own custody revoke: it names the writer, and it is
/// neither the owner's act nor an agent's.
fn assert_writers_own_revoke(act: &OwnerAct, writer: EntityId) {
    assert_eq!(act.owner, writer, "the carried revoke names its writer");
    assert_ne!(
        act.by,
        ActBy::Owner,
        "a writer is never relabelled as the owner"
    );
    assert!(
        !matches!(act.by, ActBy::Agent { .. }),
        "a writer's revoke is no agent's act: {:?}",
        act.by
    );
    assert_eq!(act.act, OwnerActKind::CustodyTransition);
    assert_eq!(act.answer, None, "a person's act answers no ask");
}

#[test]
fn a_writers_ruling_carries_its_revoke_as_the_writers_own_act() -> TestResult {
    let (_dir, vault, owner, writer) = open_vault()?;
    let record = write_event(&vault, writer);
    profile_install(&vault)?;
    let owner = proof_of(&vault, owner)?;
    let handle = found_handle(&vault, &owner, &record)?;
    assert!(
        carried_revokes(&vault)?.is_empty(),
        "FIXTURE: no revoke was carried before the ruling"
    );

    let ruled = vault.rule_found_key_not_a_secret(
        &proof_of(&vault, writer)?,
        ActSurface::ThisInstall,
        &handle,
    )?;
    assert_eq!(ruled.action, FoundKeyAction::NotASecret);
    assert_eq!(
        ruled.by,
        Some(writer),
        "FIXTURE: the writer's ruling stands"
    );

    let carried = carried_revokes(&vault)?;
    assert_eq!(
        carried.len(),
        1,
        "the writer's ruling carries its revoke to the owner's other machines: {carried:?}"
    );
    assert_writers_own_revoke(&carried[0], writer);
    Ok(())
}

#[test]
fn an_owners_ruling_still_carries_as_the_owners_act() -> TestResult {
    let (_dir, vault, owner_id, writer) = open_vault()?;
    let record = write_event(&vault, writer);
    profile_install(&vault)?;
    let owner = proof_of(&vault, owner_id)?;
    let handle = found_handle(&vault, &owner, &record)?;

    let ruled = vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert_eq!(ruled.by, Some(owner_id));

    let carried = carried_revokes(&vault)?;
    assert_eq!(
        carried.len(),
        1,
        "the owner's ruling carries its revoke: {carried:?}"
    );
    assert_eq!(
        carried[0].by,
        ActBy::Owner,
        "the owner's ruling is his own act"
    );
    assert_eq!(carried[0].owner, owner_id);
    Ok(())
}

#[test]
fn a_writers_ruling_made_before_this_install_could_sign_is_carried_later_as_theirs() -> TestResult {
    let (_dir, vault, owner, writer) = open_vault()?;
    let record = write_event(&vault, writer);
    let owner = proof_of(&vault, owner)?;
    let handle = found_handle(&vault, &owner, &record)?;
    // No machine profile yet: the ruling stands here and its carry waits.
    let ruled = vault.rule_found_key_not_a_secret(
        &proof_of(&vault, writer)?,
        ActSurface::ThisInstall,
        &handle,
    )?;
    assert_eq!(
        ruled.by,
        Some(writer),
        "FIXTURE: the writer's ruling stands"
    );
    assert!(
        carried_revokes(&vault)?.is_empty(),
        "FIXTURE: an install with no machine profile carries nothing yet"
    );

    profile_install(&vault)?;
    vault.run_pending_owner_work(|| true)?;

    let carried = carried_revokes(&vault)?;
    assert_eq!(
        carried.len(),
        1,
        "the owner work pickup carries the writer's waiting revoke: {carried:?}"
    );
    assert_writers_own_revoke(&carried[0], writer);
    Ok(())
}
