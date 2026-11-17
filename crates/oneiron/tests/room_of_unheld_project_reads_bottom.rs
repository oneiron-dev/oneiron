//! L7-39 guard (Engine RULING L7-39-OLDER-PEER = A, 14 Nov 17:31): a room
//! whose project this vault does not hold, or holds with no authority, limits
//! every read through it to no facet (`Bottom`). Main read such a room as
//! `All`, so a quarantined project opened its room to the reader's own slip
//! facets. A deleted project's home room keeps today's behaviour: it goes
//! with its project, so no read or turn reaches it.
//!
//! The facet limit is read through the `room_facet_limit` door, the axis a
//! room turn's ceiling, a named-room read and the frozen bound read.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_of_unheld_project_reads_bottom`.
#![cfg(oneiron_test_support)]

use oneiron::authority::HostSlipIssuer;
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::test_doors::room_facet_limit::room_facet_axis;
use oneiron::workspace_roster::{ProjectProofVersion, ProjectRecord, ProjectWriteProof};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A vault this process owns, with its embedded owner and a memory keystore.
/// The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    // A host installs its keystore after each open: a delete, and the
    // authority rows below, sign with this install's key.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    Ok(Fixture {
        vault,
        owner,
        _dir: dir,
    })
}

/// A FACET row.
fn facet(fixture: &Fixture) -> TestResult<EntityId> {
    let id = EntityId::now();
    fixture.vault.put_entity(
        &id,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        b"facet",
    )?;
    Ok(id)
}

/// An owner-door project under the root, led by the owner, sliced to
/// `facet`. An unsigned owner row serves its own authority at once. Returns
/// the project and its home room.
fn project(
    fixture: &Fixture,
    facet: Option<EntityId>,
    at: u64,
) -> TestResult<(EntityId, EntityId)> {
    let vault = &fixture.vault;
    let root = vault.root_project()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(root), root, fixture.owner)?;
    record.slice.facet = facet;
    vault.put_project(id, &record, at)?;
    Ok((id, EntityId::from_hex(&record.home_room)?))
}

/// An ordinary group room of the owner's, its body carrying `extra` beside
/// the ordinary keys.
fn room(fixture: &Fixture, extra: serde_json::Value) -> TestResult<EntityId> {
    let mut body = json!({
        "v": 1,
        "kind": "group",
        "member_ids": [fixture.owner.to_hex()],
        "title": "room facet guard",
    });
    for (key, value) in extra.as_object().ok_or("extra is a map")? {
        body[key] = value.clone();
    }
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body,
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// Signs `body` as the vault host over the project's current authority,
/// with a fresh slip `slip_id` minted from the host root (the
/// `sync_quarantine.rs` shape).
fn sign_as_host(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    slip_id: [u8; 32],
    id: EntityId,
    body: &mut ProjectRecord,
) -> TestResult {
    let root = vault.ensure_host_root_slip(issuer)?;
    let mut claims = root.claims;
    claims.slip_id = slip_id;
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    let slip = vault.mint_capability_slip(issuer, claims)?;
    let anchor = vault
        .project(id)?
        .ok_or("the project reads before its move")?
        .anchor()?;
    let signed_at = slip.claims.issued_at;
    let version = ProjectProofVersion::V3;
    let challenge = body
        .authority_at(version)
        .write_challenge(id, version, signed_at, &anchor)?;
    body.write_proof = Some(ProjectWriteProof {
        slip_wire: slip.to_token()?,
        holder_signature: issuer.binding_proof(&slip, &challenge)?,
        signed_at,
        anchor,
        version,
    });
    Ok(())
}

#[test]
fn a_room_naming_a_project_this_vault_does_not_hold_reads_no_facet() -> TestResult {
    let fixture = open()?;
    let work = facet(&fixture)?;
    let ordinary = room(&fixture, json!({}))?;
    let unheld = room(&fixture, json!({ "project_id": EntityId::now().to_hex() }))?;
    let (_, home) = project(&fixture, Some(work), 2)?;
    assert_eq!(
        room_facet_axis(&fixture.vault, ordinary)?,
        ScopeAxis::All,
        "an ordinary room is no project's, so no facet limits it"
    );
    assert_eq!(
        room_facet_axis(&fixture.vault, home)?,
        ScopeAxis::Some([ScopeId(work)].into()),
        "a held project's home room reads its project's facet"
    );
    assert_eq!(
        room_facet_axis(&fixture.vault, unheld)?,
        ScopeAxis::Bottom,
        "a room naming a project this vault does not hold reads no facet"
    );
    Ok(())
}

#[test]
fn a_quarantined_projects_room_reads_no_facet() -> TestResult {
    let fixture = open()?;
    let work = facet(&fixture)?;
    let (other, _) = project(&fixture, None, 2)?;
    let (moved, home) = project(&fixture, Some(work), 3)?;
    // Moving a project in the tree is a board act: the host signs it.
    let issuer = HostSlipIssuer::from_secret(b"room facet guard fixture")?;
    let slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    let mut body = fixture
        .vault
        .project(moved)?
        .ok_or("the project reads before its move")?;
    body.parents = vec![other.to_hex()];
    sign_as_host(&fixture.vault, &issuer, slip_id, moved, &mut body)?;
    fixture.vault.put_project(moved, &body, 4)?;
    assert_eq!(
        room_facet_axis(&fixture.vault, home)?,
        ScopeAxis::Some([ScopeId(work)].into()),
        "the host-signed move keeps the room's facet"
    );

    // Revoking the slip that signed the move leaves the stored project with
    // no authority: quarantined, listed for the owner only.
    fixture.vault.revoke_capability_slip(&issuer, slip_id)?;
    let frontier = fixture
        .vault
        .project_frontier(moved)?
        .ok_or("the quarantined project's row stays stored")?;
    assert!(
        frontier.effective.is_none(),
        "the revoked slip leaves the project no authority"
    );
    assert_eq!(
        room_facet_axis(&fixture.vault, home)?,
        ScopeAxis::Bottom,
        "a quarantined project's room reads no facet"
    );
    Ok(())
}

#[test]
fn a_deleted_projects_home_room_goes_with_it() -> TestResult {
    let fixture = open()?;
    let work = facet(&fixture)?;
    let (project, home) = project(&fixture, Some(work), 2)?;
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    assert!(
        fixture.vault.get(&home)?.is_some(),
        "the home room is stored"
    );
    assert!(
        owner.for_room_turn(home).is_ok(),
        "the project's leader opens a turn in its home room"
    );

    fixture
        .vault
        .delete_entity_with_reason(&project, DeleteReason::UserDelete)?;
    assert!(
        fixture.vault.project_room(home)?.is_none(),
        "the deleted project's home room reads as absent"
    );
    assert!(
        fixture.vault.get(&home)?.is_none(),
        "the home room's row goes with its project"
    );
    assert!(
        owner.for_room_turn(home).is_err(),
        "no turn opens in a deleted project's home room"
    );
    Ok(())
}
