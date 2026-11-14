//! Engine RULING L6-03-CARRY-AUDIT-AUTHOR (14 Nov 08:35): the authority
//! audit row of a carried custody revoke names its author, the owner or the
//! writer person. A writer's revoke (ActBy::Person, L6-03-WRITER-CARRY) and
//! the owner's own revoke must not read the same in the owner's audit.
//!
//! Nor may a `by: Owner` act in its holder meaning read as the owner's (#7815
//! review F1-F5): anyone's own training opt-out, and a vault-wide setting a
//! shared vault's Admin decided, name that person.
//!
//! `cargo test --locked -p oneiron --all-features --test found_key_audit_author`.

use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityOp, CustodyChange, HostSlipIssuer, MachineRole, OwnerWorkBody,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::StructuralPutInput;
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The shared vault the Admin test creates.
const SHARED: u64 = 42;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A vault with a device keystore, its embedded owner and a live PERSON who
/// does not own it, with this install's live machine profile, so a ruling
/// carries its revoke to the owner's other machines.
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

/// Gives this install its live machine profile.
fn profile_install(vault: &Vault) -> TestResult {
    let issuer = HostSlipIssuer::from_secret(b"found key audit author host")?;
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

/// The AUTHORITY_LOG entry id of the one custody revoke this install
/// recorded for the owner's other machines.
fn carried_revoke_entry(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let mut revokes = Vec::new();
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
            revokes.push(id);
        }
    }
    match revokes.as_slice() {
        [one] => Ok(*one),
        other => Err(format!("FIXTURE: one carried custody revoke, found {other:?}").into()),
    }
}

/// The owner's audit row of AUTHORITY_LOG entry `entry`, as the audit verb
/// serves it.
fn served_audit_row(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    entry: EntityId,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let page = vault.authority_audit(
        owner,
        &AuthorityAuditQuery {
            limit: Some(500),
            ..AuthorityAuditQuery::default()
        },
    )?;
    let row = page
        .rows
        .into_iter()
        .find(|row| row.entry_ref == entry)
        .ok_or("FIXTURE: the owner's audit lists the carried revoke")?;
    assert_eq!(row.source_op, "owner_work_request");
    assert_eq!(row.detail.as_deref(), Some("custody"));
    Ok(serde_json::to_value(&row)?)
}

#[test]
fn a_writers_carried_revoke_names_the_writer_in_the_owners_audit() -> TestResult {
    let (_dir, vault, owner_id, writer) = open_vault()?;
    let record = write_event(&vault, writer);
    profile_install(&vault)?;
    let owner = proof_of(&vault, owner_id)?;
    let handle = found_handle(&vault, &owner, &record)?;

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

    let row = served_audit_row(&vault, &owner, carried_revoke_entry(&vault)?)?;
    assert_eq!(
        row["act_author"],
        serde_json::json!({ "by": "person", "person": writer.to_hex() }),
        "the audit row names the writer who ruled, never the owner: {row}"
    );
    Ok(())
}

#[test]
fn the_owners_carried_revoke_names_the_owner_in_his_audit() -> TestResult {
    let (_dir, vault, owner_id, writer) = open_vault()?;
    let record = write_event(&vault, writer);
    profile_install(&vault)?;
    let owner = proof_of(&vault, owner_id)?;
    let handle = found_handle(&vault, &owner, &record)?;

    let ruled = vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert_eq!(
        ruled.by,
        Some(owner_id),
        "FIXTURE: the owner's ruling stands"
    );

    let row = served_audit_row(&vault, &owner, carried_revoke_entry(&vault)?)?;
    assert_eq!(
        row["act_author"],
        serde_json::json!({ "by": "owner", "owner": owner_id.to_hex() }),
        "the audit row names the owner's own act as his: {row}"
    );
    Ok(())
}

/// The `act_author` of each row of the owner's audit whose op is
/// `source_op` and whose subject is `subject`.
fn authors_of(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    source_op: &str,
    subject: EntityId,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let page = vault.authority_audit(
        owner,
        &AuthorityAuditQuery {
            limit: Some(500),
            ..AuthorityAuditQuery::default()
        },
    )?;
    let mut authors = Vec::new();
    for row in page.rows {
        if row.source_op == source_op && row.subject_ref == Some(subject.to_hex()) {
            authors.push(serde_json::to_value(&row)?["act_author"].clone());
        }
    }
    Ok(authors)
}

#[test]
fn a_persons_own_training_opt_out_names_the_person_never_the_owner() -> TestResult {
    let (_dir, vault, owner_id, person) = open_vault()?;
    profile_install(&vault)?;
    let owner = proof_of(&vault, owner_id)?;
    vault.set_conversation_learning(&owner, ActSurface::ThisInstall, true, true, None)?;
    vault.set_conversation_training(
        &proof_of(&vault, person)?,
        ActSurface::ThisInstall,
        true,
        None,
    )?;
    vault.set_conversation_training(&owner, ActSurface::ThisInstall, true, None)?;

    assert_eq!(
        authors_of(&vault, &owner, "conversation_training", person)?,
        vec![serde_json::json!({ "by": "person", "person": person.to_hex() })],
        "a person's own opt-out names that person, never the owner"
    );
    assert_eq!(
        authors_of(&vault, &owner, "conversation_training", owner_id)?,
        vec![serde_json::json!({ "by": "person", "person": owner_id.to_hex() })],
        "the owner's own opt-out is his person act, not an owner act"
    );
    assert_eq!(
        authors_of(&vault, &owner, "conversation_training_vault", owner_id)?,
        vec![serde_json::json!({ "by": "owner", "owner": owner_id.to_hex() })],
        "the owner's own vault setting reads as his"
    );
    Ok(())
}

#[test]
fn a_shared_vault_admins_training_setting_names_the_admin_not_an_owner() -> TestResult {
    let (_dir, vault, owner_id, admin) = open_vault()?;
    profile_install(&vault)?;
    let member = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault.initialize_shared_vault(
        &proof_of(&vault, owner_id)?,
        SHARED,
        None,
        &[
            member(owner_id, FederationGrantRole::Owner),
            member(admin, FederationGrantRole::Admin),
        ],
        1,
    )?;
    let admin_proof = proof_of(&vault, admin)?;
    let invitation = vault
        .shared_invitations(&admin_proof, SHARED)?
        .into_iter()
        .find(|open| open.role == FederationGrantRole::Admin)
        .ok_or("FIXTURE: the Admin's founding invitation")?;
    vault.accept_shared_invitation(&admin_proof, SHARED, &invitation.id)?;

    vault.set_conversation_learning(&admin_proof, ActSurface::ThisInstall, true, true, None)?;
    let owner = proof_of(&vault, owner_id)?;
    vault.set_conversation_learning(&owner, ActSurface::ThisInstall, true, false, None)?;

    assert_eq!(
        authors_of(&vault, &owner, "conversation_training_vault", admin)?,
        vec![serde_json::json!({ "by": "person", "person": admin.to_hex() })],
        "an Admin's vault setting names the Admin, who owns no vault"
    );
    assert_eq!(
        authors_of(&vault, &owner, "conversation_training_vault", owner_id)?,
        vec![serde_json::json!({ "by": "owner", "owner": owner_id.to_hex() })],
        "the Owner's vault setting reads as an owner's"
    );
    Ok(())
}
