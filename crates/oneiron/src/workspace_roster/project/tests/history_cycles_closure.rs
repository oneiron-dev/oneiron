//! Everything a component's decision rests on is read inside it (Sol and
//! Astra on #1434, round 15): a frozen member's re-check reaches past its
//! owner seal, a seal that supersedes another on a sibling branch still
//! installs, a frozen drain is decided with before the other members are
//! persisted, and a dark unsigned member still lists its held revisions.
use super::super::history_policy::{PROJECT_FRONTIER, ProjectHistoryPolicy};
use super::super::read::ProjectVerdict;
use super::super::revision::{ProjectRevisionHash, revisions_of_row};
use super::super::*;
use super::authority::{
    FIXTURE_HOST, put_signed_project, replay_project, root_leader, sign_project, spawn_signed,
};
use super::cycle_model::{EXTRA, KEPT};
use super::history::{copy_of, open, signed_over};
use super::history_cycles::{owner, readable, set_bound};
use super::history_resolution::put_companion;
use crate::authority::HostSlipIssuer;

fn lit(vault: &Vault, id: EntityId) -> Result<bool> {
    let frontier = vault.project_frontier(id)?.ok_or(Error::EntityNotFound)?;
    Ok(frontier.effective.is_some())
}

/// The owner seals `id` over `over` with `authority`: the seal envelope's
/// hash.
fn seal(
    vault: &Vault,
    id: EntityId,
    authority: ProjectAuthority,
    over: &ProjectRecord,
) -> Result<ProjectRevisionHash> {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let over = revisions_of_row(id, over)?.pop().ok_or_else(invalid)?.0;
    vault.seal_project(
        &owner(vault)?,
        id,
        authority,
        over,
        slip.to_token()?,
        |challenge| issuer.binding_proof(&slip, challenge),
    )
}

fn budget(vault: &Vault, max_revisions: u64) -> Result<()> {
    vault.set_project_history_policy(
        &owner(vault)?,
        ProjectHistoryPolicy {
            max_revisions,
            ..ProjectHistoryPolicy::default()
        },
    )
}

/// Bug repro (Sol r15 F1, Astra r15 F1): C1 put C under P before the owner
/// sealed C over C2; C then went under P again (C3) and back to R (C4), and
/// froze there. P's leader narrows P below C1: alone, C's re-check reaches
/// C1 through the seal's next and C serves nothing. P's board then puts P
/// under C, which ties the two: the re-check under the served views still
/// reaches C1, and C stays refused.
#[cfg(feature = "sync")]
#[test]
fn a_frozen_members_re_check_reaches_past_its_seal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root, root_row, holder) = root_leader(&vault)?;
    let (p, c, lead) = (EntityId::now(), EntityId::now(), EntityId::now());
    let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let c0 = spawn_signed(&vault, root, c, holder, lead, root_row.slice, 3)?;
    let c1 = signed_over(&vault, c, &c0, holder, |row| {
        row.parents = vec![p.to_hex()];
        row.depth_remaining = 3;
    })?;
    vault.put_project(c, &c1, 4)?;
    let c2 = signed_over(&vault, c, &c1, holder, |row| {
        row.parents = vec![root.to_hex()];
    })?;
    vault.put_project(c, &c2, 5)?;
    seal(&vault, c, c2.authority_at(ProjectProofVersion::V3), &c2)?;
    budget(&vault, 4)?;
    let sealed = vault.project(c)?.ok_or(Error::EntityNotFound)?;
    let c3 = signed_over(&vault, c, &sealed, holder, |row| {
        row.parents = vec![p.to_hex()];
        row.depth_remaining = 1;
    })?;
    vault.put_project(c, &c3, 6)?;
    let c4 = signed_over(&vault, c, &c3, holder, |row| {
        row.parents = vec![root.to_hex()];
        row.depth_remaining = 3;
    })?;
    vault.put_project(c, &c4, 7)?;
    let c5 = signed_over(&vault, c, &c4, holder, |_| {})?;
    vault.put_project(c, &c5, 8)?;
    assert!(matches!(
        vault
            .project_frontier(c)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::OverBudget { .. })
    ));
    assert!(lit(&vault, c)?);
    let narrow = signed_over(&vault, p, &p0, lead, |row| row.depth_remaining = 2)?;
    replay_project(&vault, p, &narrow, 9)?;
    assert!(!lit(&vault, c)?);
    let under_c = signed_over(&vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 2;
    })?;
    replay_project(&vault, p, &under_c, 10)?;
    assert!(!lit(&vault, c)?);
    Ok(())
}

/// Bug repro (Sol r15 F2, Astra r15 F2): L spawned C under P, the owner
/// sealed C over its birth (S1), and P's board put P under C, so C's birth
/// ties the two. A second seal over the birth (S2, S1's sibling) supersedes
/// the first: its verdict reads S1, so the seal installs in the component as
/// it does alone.
#[cfg(feature = "sync")]
#[test]
fn a_seal_superseding_one_on_a_sibling_branch_installs_in_a_component() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root, root_row, holder) = root_leader(&vault)?;
    let (p, c, lead) = (EntityId::now(), EntityId::now(), EntityId::now());
    let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let c0 = spawn_signed(&vault, p, c, lead, EntityId::now(), root_row.slice, 3)?;
    let mut authority = c0.authority_at(ProjectProofVersion::V3);
    authority.parents = vec![root.to_hex()];
    authority.depth_remaining = 3;
    seal(&vault, c, authority.clone(), &c0)?;
    let under_c = signed_over(&vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 1;
    })?;
    vault.put_project(p, &under_c, 4)?;
    assert!(lit(&vault, c)? && lit(&vault, p)?);
    // Seals move forward in time, a second at the least.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    seal(&vault, c, authority, &c0)?;
    let frontier = vault.project_frontier(c)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(frontier.disposition, ProjectDisposition::Settled);
    assert!(lit(&vault, p)?);
    Ok(())
}

/// Bug repro (Sol r15 F4, Astra r15 F3): C froze at C2 (C1 under P, C2 back
/// to R with `{kept, extra}`), and P's board put P under C with `{kept,
/// extra}`. C4, a narrowing below the frozen head, arrives as a companion
/// alone and lands by the batch end's drain: P no longer fits C, and the
/// record the batch end persists for P is the one a fresh read serves.
#[cfg(feature = "sync")]
#[test]
fn a_frozen_drain_in_a_component_persists_what_is_served() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root, mut root_row, holder) = root_leader(&vault)?;
    root_row.slice.readable = readable(KEPT | EXTRA);
    put_signed_project(&vault, root, &mut root_row, holder, 1)?;
    let (p, c, lead) = (EntityId::now(), EntityId::now(), EntityId::now());
    let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let c0 = spawn_signed(&vault, root, c, holder, lead, root_row.slice.clone(), 3)?;
    let c1 = signed_over(&vault, c, &c0, holder, |row| {
        row.parents = vec![p.to_hex()];
        row.slice.readable = readable(KEPT);
        row.depth_remaining = 1;
    })?;
    vault.put_project(c, &c1, 4)?;
    let c2 = signed_over(&vault, c, &c1, holder, |row| {
        row.parents = vec![root.to_hex()];
        row.slice.readable = readable(KEPT | EXTRA);
        row.depth_remaining = 5;
    })?;
    vault.put_project(c, &c2, 5)?;
    budget(&vault, 3)?;
    let c3 = signed_over(&vault, c, &c2, holder, |_| {})?;
    vault.put_project(c, &c3, 6)?;
    let under_c = signed_over(&vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 4;
    })?;
    vault.put_project(p, &under_c, 7)?;
    assert!(lit(&vault, c)? && lit(&vault, p)?);
    let narrow = signed_over(&vault, c, &c3, holder, |row| {
        row.slice.readable = readable(KEPT);
    })?;
    let (_, narrow) = revisions_of_row(c, &narrow)?.pop().ok_or_else(invalid)?;
    put_companion(&vault, &narrow, 8)?;
    let served = vault.project_frontier(p)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(served.effective, None);
    let txn = vault.store.env.read_txn()?;
    let record = PROJECT_FRONTIER
        .get(&vault.store, &txn, &p)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(record.effective, served.effective);
    assert_eq!(record.disposition, served.disposition);
    Ok(())
}

/// Bug repro (Sol r15 F5, Astra r15 F6): A is an owner-door project under
/// B. A host successor over A's boundary waits for its slip's mint. B's
/// board puts B under A past a bound of one world: dark, and A still lists
/// the waiting successor.
#[cfg(feature = "sync")]
#[test]
fn a_dark_unsigned_member_lists_its_held_revisions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (a, b) = (EntityId::now(), EntityId::now());
    let (holder, b0) = {
        let vault = open(&dir)?;
        let (root, root_row, holder) = root_leader(&vault)?;
        // An owner-door row needs no signed birth before the vault is rooted.
        let mut unsigned = ProjectRecord::new(a, Some(root), root, holder)?;
        vault.put_project(a, &unsigned, 1)?;
        set_bound(&vault, 1)?;
        let b0 = spawn_signed(&vault, root, b, holder, holder, root_row.slice, 2)?;
        unsigned.parents = vec![b.to_hex()];
        unsigned.depth_remaining = 5;
        vault.put_project(a, &unsigned, 3)?;
        (holder, b0)
    };
    // Signed on a copy, so this vault holds no mint for its slip.
    let (_minted_dir, minted) = copy_of(&dir)?;
    let mut successor = minted.project(a)?.ok_or(Error::EntityNotFound)?;
    sign_project(&minted, a, &mut successor, holder)?;
    let vault = open(&dir)?;
    let chain = revisions_of_row(a, &successor)?;
    for (at, (_, revision)) in (4..).zip(&chain) {
        put_companion(&vault, revision, at)?;
    }
    let waiting = chain.last().ok_or_else(invalid)?.0;
    let b1 = signed_over(&vault, b, &b0, holder, |row| {
        row.parents = vec![a.to_hex()];
        row.depth_remaining = 0;
    })?;
    let (_, b1) = revisions_of_row(b, &b1)?.pop().ok_or_else(invalid)?;
    put_companion(&vault, &b1, 10)?;
    assert!(!lit(&vault, a)? && !lit(&vault, b)?);
    let listed = vault.project_revisions(a)?;
    assert!(
        matches!(
            listed.iter().find(|(hash, _)| *hash == waiting),
            Some((_, ProjectVerdict::Pending(_)))
        ),
        "{listed:?}"
    );
    Ok(())
}
