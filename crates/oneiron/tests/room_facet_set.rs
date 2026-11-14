//! L7-39 PR 2, a room holds several facets (Engine RULINGS
//! L7-39-ROOM-FACET-SET = A, 14 Nov 17:03, and L7-39-OLDER-PEER = A, 17:31):
//! a project's home room reads through a signed facet set when its authority
//! carries one, else through the slice's facet. Only a v4 proof signs the
//! set. It holds the slice's facet (the anchor), which stays put while the
//! set exists; no project is born with one; it sits inside the writer's slip
//! facets, and a child's inside its parent's room.
//!
//! The facet limit is read through the `room_facet_limit` door; the set is
//! written through the `room_facet_set` door (the owner's door), or signed by
//! the host in a row it puts.
//!
//! PR 3, the owner's verb `vault.projects.room_facets.set`: its host door
//! runs the owner's door from the verb's request with the host's signer, and
//! the embedded handle, which holds no host issuer, sends the call to that
//! door. A writer's own signed set needs no new argument: the roster write's
//! `record` is the whole signed row.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_facet_set`.
#![cfg(oneiron_test_support)]

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_limit::room_facet_axis;
use oneiron::test_doors::room_facet_set::{
    set_room_facets, set_room_facets_by_request, with_room_facets,
};
use oneiron::workspace_roster::{
    OwnerProjectSigner, ProjectProofVersion, ProjectRecord, ProjectRosterWriteRequest,
    ProjectWriteProof,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A vault with its embedded owner bound to the host, the owner's proof and
/// the host's slip issuer; the root project carries the owner's signature.
/// The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn signer(&self) -> TestResult<OwnerProjectSigner<'_>> {
        Ok(self.vault.owner_project_signer(&self.issuer)?)
    }

    /// The owner's door: sets `project`'s room facet set.
    fn set(&self, project: EntityId, facets: Option<BTreeSet<EntityId>>) -> TestResult {
        Ok(set_room_facets(
            &self.vault,
            &self.owner_proof,
            &self.signer()?,
            project,
            facets,
        )?)
    }

    /// The owner's verb as its host door runs it, from `request`.
    fn set_by_request(&self, request: Value) -> TestResult<Value> {
        Ok(set_room_facets_by_request(
            &self.vault,
            &self.owner_proof,
            &self.signer()?,
            request,
        )?)
    }

    fn reads(&self, room: EntityId) -> TestResult<ScopeAxis<ScopeId>> {
        Ok(room_facet_axis(&self.vault, room)?)
    }
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.sign_owner_project(
        &owner_proof,
        &vault.owner_project_signer(&issuer)?,
        vault.root_project()?,
    )?;
    Ok(Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
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

fn facets<const N: usize>(ids: [EntityId; N]) -> BTreeSet<EntityId> {
    ids.into()
}

fn axis<const N: usize>(ids: [EntityId; N]) -> ScopeAxis<ScopeId> {
    ScopeAxis::Some(ids.into_iter().map(ScopeId).collect())
}

/// An owner-door project under `parent` (the root when `None`), led by the
/// owner, sliced to `facet`, `depth_remaining` levels deep. Unsigned until
/// `sign`; then the owner's first signature makes it a settled v3 head.
/// Returns the project and its home room.
fn project(
    fixture: &Fixture,
    parent: Option<EntityId>,
    facet: EntityId,
    depth_remaining: u64,
    sign: bool,
) -> TestResult<(EntityId, EntityId)> {
    let vault = &fixture.vault;
    let root = vault.root_project()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent.unwrap_or(root)), root, fixture.owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = depth_remaining;
    vault.put_project(id, &record, 2)?;
    if sign {
        vault.sign_owner_project(&fixture.owner_proof, &fixture.signer()?, id)?;
    }
    Ok((id, EntityId::from_hex(&record.home_room)?))
}

/// Signs `body`, carrying room facet set `room`, as the vault host over the
/// project's current head, with a fresh slip from the host root whose
/// facets narrow to `slip_facet` when one is named.
fn sign_as_host(
    fixture: &Fixture,
    id: EntityId,
    body: &mut ProjectRecord,
    room: Option<BTreeSet<EntityId>>,
    slip_facet: Option<EntityId>,
) -> TestResult {
    let vault = &fixture.vault;
    let mut claims = vault.ensure_host_root_slip(&fixture.issuer)?.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    if let Some(facet) = slip_facet {
        claims.scope.facets = ScopeAxis::Some([ScopeId(facet)].into());
    }
    let slip = vault.mint_capability_slip(&fixture.issuer, claims)?;
    let anchor = vault.project(id)?.ok_or("the project reads")?.anchor()?;
    let signed_at = slip.claims.issued_at;
    let version = with_room_facets(body, room);
    let challenge = body
        .authority_at(version)
        .write_challenge(id, version, signed_at, &anchor)?;
    body.write_proof = Some(ProjectWriteProof {
        slip_wire: slip.to_token()?,
        holder_signature: fixture.issuer.binding_proof(&slip, &challenge)?,
        signed_at,
        anchor,
        version,
    });
    Ok(())
}

#[test]
fn a_signed_set_opens_the_home_room_to_its_facets() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, home) = project(&fixture, None, work, 1, true)?;
    assert_eq!(
        fixture.reads(home)?,
        axis([work]),
        "a room with no set reads its project's slice facet"
    );
    fixture.set(id, Some(facets([work, health])))?;
    assert_eq!(
        fixture.reads(home)?,
        axis([work, health]),
        "the signed set opens the room to each of its facets"
    );
    fixture.set(id, None)?;
    assert_eq!(
        fixture.reads(home)?,
        axis([work]),
        "dropping the set narrows the room back to the slice facet"
    );
    Ok(())
}

#[test]
fn a_set_holds_its_projects_own_facet() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, home) = project(&fixture, None, work, 1, true)?;
    assert!(
        fixture.set(id, Some(facets([health]))).is_err(),
        "a set without the project's own facet is refused"
    );
    assert_eq!(fixture.reads(home)?, axis([work]));
    Ok(())
}

#[test]
fn the_projects_facet_stays_put_under_a_set() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, home) = project(&fixture, None, work, 1, true)?;
    fixture.set(id, Some(facets([work, health])))?;

    // The host signs a state that moves the slice facet inside the set.
    let mut body = fixture.vault.project(id)?.ok_or("the project reads")?;
    body.slice.facet = Some(health);
    sign_as_host(&fixture, id, &mut body, Some(facets([work, health])), None)?;
    assert!(
        fixture.vault.put_project(id, &body, 3).is_err(),
        "the slice facet does not move while the room holds a set, whoever signs"
    );
    assert_eq!(fixture.reads(home)?, axis([work, health]));

    // With the set dropped, the host may move it again.
    fixture.set(id, None)?;
    let mut body = fixture.vault.project(id)?.ok_or("the project reads")?;
    body.slice.facet = Some(health);
    sign_as_host(&fixture, id, &mut body, None, None)?;
    fixture.vault.put_project(id, &body, 4)?;
    assert_eq!(fixture.reads(home)?, axis([health]));
    Ok(())
}

#[test]
fn a_set_comes_after_the_projects_first_signed_state() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let root = fixture.vault.root_project()?;

    // An owner-door row carries no proof, so it carries no set.
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(root), root, fixture.owner)?;
    record.slice.facet = Some(work);
    record.depth_remaining = 1;
    with_room_facets(&mut record, Some(facets([work, health])));
    assert!(
        fixture.vault.put_project(id, &record, 2).is_err(),
        "an unsigned row with a room facet set is refused"
    );

    // An unsigned project takes the owner's first signature before a set.
    let (unsigned, home) = project(&fixture, None, work, 1, false)?;
    assert!(
        fixture.set(unsigned, Some(facets([work, health]))).is_err(),
        "a project with no signed head takes no set"
    );
    assert_eq!(fixture.reads(home)?, axis([work]));
    Ok(())
}

#[test]
fn a_childs_set_stays_inside_its_parents_room() -> TestResult {
    let fixture = open()?;
    let (work, health, travel) = (facet(&fixture)?, facet(&fixture)?, facet(&fixture)?);
    let (parent, _) = project(&fixture, None, work, 1, true)?;
    let (child, home) = project(&fixture, Some(parent), work, 0, true)?;
    assert!(
        fixture.set(child, Some(facets([work, health]))).is_err(),
        "a child's set reads no facet its parent's room does not"
    );
    fixture.set(parent, Some(facets([work, health])))?;
    assert!(
        fixture.set(child, Some(facets([work, travel]))).is_err(),
        "a child's set stays inside its parent's set"
    );
    fixture.set(child, Some(facets([work, health])))?;
    assert_eq!(fixture.reads(home)?, axis([work, health]));
    Ok(())
}

#[test]
fn a_parents_set_keeps_its_childrens_sets_inside_it() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (parent, parent_home) = project(&fixture, None, work, 1, true)?;
    let (child, home) = project(&fixture, Some(parent), work, 0, true)?;
    fixture.set(parent, Some(facets([work, health])))?;
    fixture.set(child, Some(facets([work, health])))?;
    assert!(
        fixture.set(parent, None).is_err(),
        "dropping a parent's set leaves no child's set reading a facet the parent's room does not"
    );
    assert_eq!(fixture.reads(parent_home)?, axis([work, health]));

    // With the child's set dropped first, the parent's set drops too.
    fixture.set(child, None)?;
    fixture.set(parent, None)?;
    assert_eq!(fixture.reads(parent_home)?, axis([work]));
    assert_eq!(fixture.reads(home)?, axis([work]));
    Ok(())
}

#[test]
fn a_set_outside_the_writers_slip_facets_is_refused() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, home) = project(&fixture, None, work, 1, true)?;
    let mut body = fixture.vault.project(id)?.ok_or("the project reads")?;
    sign_as_host(
        &fixture,
        id,
        &mut body,
        Some(facets([work, health])),
        Some(work),
    )?;
    assert!(
        fixture.vault.put_project(id, &body, 3).is_err(),
        "a slip that reaches only the slice facet signs no wider set"
    );
    assert_eq!(fixture.reads(home)?, axis([work]));
    Ok(())
}

#[test]
fn the_owners_verb_sets_and_drops_a_set() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, home) = project(&fixture, None, work, 1, true)?;
    let set = fixture.set_by_request(json!({
        "project": id,
        "room_facets": [work, health],
    }))?;
    assert_eq!(
        set["room_facets"],
        json!(facets([work, health])),
        "the answer names the set the room now reads through"
    );
    assert_eq!(fixture.reads(home)?, axis([work, health]));

    let dropped = fixture.set_by_request(json!({ "project": id }))?;
    assert!(
        dropped["room_facets"].is_null(),
        "a request naming no set drops it"
    );
    assert_ne!(
        set["revision"], dropped["revision"],
        "each set lands as its own signed state"
    );
    assert_eq!(fixture.reads(home)?, axis([work]));

    assert!(
        fixture
            .set_by_request(json!({ "project": id, "room_facets": [health] }))
            .is_err(),
        "the verb keeps the door's rules: a set holds its project's own facet"
    );
    assert!(
        fixture
            .set_by_request(json!({ "project": id, "facets": [work] }))
            .is_err(),
        "a request field the verb does not name is refused"
    );
    assert_eq!(fixture.reads(home)?, axis([work]));
    Ok(())
}

#[test]
fn the_embedded_handle_sends_the_owners_verb_to_the_host() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, home) = project(&fixture, None, work, 1, true)?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let refused = oneiron::task_verb::sdk::invoke(
        &memory,
        "vault.projects.room_facets.set",
        json!({ "project": id, "room_facets": [work, health] }),
    )
    .map(drop)
    .map_err(|error| format!("{error:?}"))
    .err()
    .ok_or("the embedded handle holds no host signer, so it sets no room facet set")?;
    assert!(
        refused.contains("authenticated owner and owner signer"),
        "the refusal sends the owner to the host's door, not an unknown verb: {refused}"
    );
    assert_eq!(fixture.reads(home)?, axis([work]));
    Ok(())
}

#[test]
fn a_roster_write_request_carries_a_writers_signed_set() -> TestResult {
    let fixture = open()?;
    let (work, health) = (facet(&fixture)?, facet(&fixture)?);
    let (id, _) = project(&fixture, None, work, 1, true)?;
    let mut body = fixture.vault.project(id)?.ok_or("the project reads")?;
    sign_as_host(&fixture, id, &mut body, Some(facets([work, health])), None)?;
    let request: ProjectRosterWriteRequest = serde_json::from_value(json!({
        "project": id,
        "record": serde_json::to_value(&body)?,
    }))?;
    assert_eq!(
        request.record.room_facets,
        Some(facets([work, health])),
        "vault.projects.roster.write's record carries the writer's set as signed"
    );
    assert_eq!(
        request.record.write_proof.map(|proof| proof.version),
        Some(ProjectProofVersion::V4),
        "with the v4 proof that signs it"
    );
    Ok(())
}
