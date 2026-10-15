//! Everything a component's decision rests on is read inside it (Sol and
//! Astra on #1434, rounds 15 to 17): a frozen member's re-check reaches past
//! its owner seal, a seal that supersedes another on a sibling branch still
//! installs, a frozen drain is decided with before the other members are
//! persisted and only within the batch's refresh rounds, a component that
//! grows in a batch is decided once, a seal the frozen record never read
//! names no parent, and a dark unsigned member still lists its held
//! revisions.
use super::super::history_policy::{PROJECT_FRONTIER, ProjectHistoryPolicy};
use super::super::read::ProjectVerdict;
use super::super::revision::{
    ProjectRevision, ProjectRevisionHash, project_revision_type, revision_entity_id,
    revisions_of_row,
};
use super::super::*;
use super::authority::{
    FIXTURE_HOST, put_signed_project, replay_authority, replay_missing_together, replay_project,
    root_leader, sign_project, sign_with, spawn_signed,
};
use super::cycle_model::{EXTRA, KEPT};
use super::history::{copy_of, open, signed_over};
use super::history_cycles::{owner, readable, set_bound};
use super::history_resolution::put_companion;
use crate::authority::{CapabilitySlip, HostSlipIssuer};

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

/// C froze at C2 (C1 under P, C2 back to R with `{kept, extra}`), and P's
/// board put P under C with `{kept, extra}`: (C, P, C4), C4 a narrowing below
/// the frozen head that only a drain lands.
fn frozen_under_p(vault: &Vault) -> Result<(EntityId, EntityId, ProjectRevision)> {
    let (root, mut root_row, holder) = root_leader(vault)?;
    root_row.slice.readable = readable(KEPT | EXTRA);
    put_signed_project(vault, root, &mut root_row, holder, 1)?;
    let (p, c, lead) = (EntityId::now(), EntityId::now(), EntityId::now());
    let p0 = spawn_signed(vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let c0 = spawn_signed(vault, root, c, holder, lead, root_row.slice, 3)?;
    let c1 = signed_over(vault, c, &c0, holder, |row| {
        row.parents = vec![p.to_hex()];
        row.slice.readable = readable(KEPT);
        row.depth_remaining = 1;
    })?;
    vault.put_project(c, &c1, 4)?;
    let c2 = signed_over(vault, c, &c1, holder, |row| {
        row.parents = vec![root.to_hex()];
        row.slice.readable = readable(KEPT | EXTRA);
        row.depth_remaining = 5;
    })?;
    vault.put_project(c, &c2, 5)?;
    budget(vault, 3)?;
    let c3 = signed_over(vault, c, &c2, holder, |_| {})?;
    vault.put_project(c, &c3, 6)?;
    let under_c = signed_over(vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 4;
    })?;
    vault.put_project(p, &under_c, 7)?;
    assert!(lit(vault, c)? && lit(vault, p)?);
    let narrow = signed_over(vault, c, &c3, holder, |row| {
        row.slice.readable = readable(KEPT);
    })?;
    let (_, narrow) = revisions_of_row(c, &narrow)?.pop().ok_or_else(invalid)?;
    Ok((c, p, narrow))
}

/// Whether `id` serves authority, checking first that the record the batch
/// end persisted for it is the one a fresh read serves.
fn persisted_as_served(vault: &Vault, id: EntityId) -> Result<bool> {
    let served = vault.project_frontier(id)?.ok_or(Error::EntityNotFound)?;
    let txn = vault.store.env.read_txn()?;
    let record = PROJECT_FRONTIER
        .get(&vault.store, &txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(record.effective, served.effective);
    assert_eq!(record.disposition, served.disposition);
    Ok(served.effective.is_some())
}

/// Bug repro (Sol r15 F4, Astra r15 F3): C4 arrives as a companion alone and
/// lands by the batch end's drain: P no longer fits C, and the record the
/// batch end persists for P is the one a fresh read serves.
#[cfg(feature = "sync")]
#[test]
fn a_frozen_drain_in_a_component_persists_what_is_served() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (_, p, narrow) = frozen_under_p(&vault)?;
    put_companion(&vault, &narrow, 8)?;
    assert!(!persisted_as_served(&vault, p)?);
    Ok(())
}

/// Bug repro (Sol and Astra r16 F2): deciding the component again after a
/// drain is a refresh round. With one round allowed, the batch end that
/// holds C4 leaves the drain for C's next refresh and persists what a fresh
/// read serves; that refresh lands it.
#[cfg(feature = "sync")]
#[test]
fn a_drain_past_the_refresh_rounds_waits_for_the_next_refresh() -> Result<()> {
    use super::super::refresh::REFRESH_ROUNDS;
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (c, p, narrow) = frozen_under_p(&vault)?;
    REFRESH_ROUNDS.with(|rounds| rounds.set(Some(1)));
    let delivered = put_companion(&vault, &narrow, 8);
    REFRESH_ROUNDS.with(|rounds| rounds.set(None));
    delivered?;
    assert!(persisted_as_served(&vault, p)?);
    vault.with_write_txn(|txn| {
        super::super::refresh_project_frontiers(
            &vault.store,
            txn,
            vault.privacy_posture(),
            &BTreeSet::from([c]),
        )
    })?;
    assert!(!persisted_as_served(&vault, p)?);
    Ok(())
}

/// Bug repro (Sol and Astra r17 F2): Q's saved record (Q2, under H) outlived
/// the revocation of Q1's slip, and the owner once put H over Q (H1, then
/// back to R). One batch holds Q3, which freezes Q once it counts and so ties
/// Q to H through its saved parent, and a row of H still waiting for its
/// mint. Every touched project counts its new rows first, so the batch end
/// decides {H, Q} once, never H alone and then again.
#[cfg(feature = "sync")]
#[test]
fn a_component_that_grows_in_a_batch_is_decided_once() -> Result<()> {
    use super::super::refresh::DECISIONS;
    let dir = tempfile::tempdir()?;
    // H, the lesser id, is refreshed first.
    let mut ids = [EntityId::now(), EntityId::now()];
    ids.sort();
    let [h, q] = ids;
    let (holder, h2, q3) = {
        let vault = open(&dir)?;
        budget(&vault, 3)?;
        let (root, root_row, holder) = root_leader(&vault)?;
        let lead = EntityId::now();
        let h0 = spawn_signed(&vault, root, h, holder, lead, root_row.slice.clone(), 2)?;
        let q0 = spawn_signed(&vault, root, q, holder, lead, root_row.slice, 3)?;
        let mut h1 = h0.clone();
        h1.parents = vec![q.to_hex()];
        sign_with(&vault, h, &mut h1, None, Some(h0.anchor()), None)?;
        let mut h2 = h1.clone();
        h2.parents = vec![root.to_hex()];
        sign_with(&vault, h, &mut h2, None, Some(h1.anchor()), None)?;
        for (at, row) in [(4, &h1), (5, &h2)] {
            let (_, revision) = revisions_of_row(h, row)?.pop().ok_or_else(invalid)?;
            put_companion(&vault, &revision, at)?;
        }
        let q1 = signed_over(&vault, q, &q0, holder, |row| {
            row.parents = vec![h.to_hex()];
            row.depth_remaining = 0;
        })?;
        vault.put_project(q, &q1, 6)?;
        let q2 = signed_over(&vault, q, &q1, holder, |_| {})?;
        vault.put_project(q, &q2, 7)?;
        assert!(lit(&vault, q)?);
        let proof = q1.write_proof.as_ref().ok_or_else(invalid)?;
        let slip = CapabilitySlip::from_token(&proof.slip_wire)?.claims.slip_id;
        vault.revoke_capability_slip(&HostSlipIssuer::from_secret(FIXTURE_HOST)?, slip)?;
        let q3 = signed_over(&vault, q, &q2, holder, |_| {})?;
        (holder, h2, q3)
    };
    // Signed on a copy, so this vault holds no mint for its slip.
    let (_copy_dir, copy) = copy_of(&dir)?;
    let waiting = signed_over(&copy, h, &h2, holder, |_| {})?;
    let vault = open(&dir)?;
    let (_, waiting) = revisions_of_row(h, &waiting)?.pop().ok_or_else(invalid)?;
    let (_, q3) = revisions_of_row(q, &q3)?.pop().ok_or_else(invalid)?;
    let kind = project_revision_type(&vault.store).ok_or_else(invalid)?;
    let before = DECISIONS.with(std::cell::Cell::get);
    vault.with_write_txn(|txn| {
        let mut batch = vault.batch_in();
        for (at, revision) in [(20, &q3), (21, &waiting)] {
            batch = batch.put_replicated(
                &revision_entity_id(revision.hash()?)?,
                kind,
                TimeRange { start: at, end: at },
                at,
                &revision.canonical_bytes()?,
            );
        }
        batch.apply(txn)
    })?;
    assert_eq!(DECISIONS.with(std::cell::Cell::get) - before, 1);
    assert!(lit(&vault, h)? && !lit(&vault, q)?);
    Ok(())
}

/// Bug repro (Sol and Astra r16 F1): C froze at C2, every saved state under
/// R, and P's board put P under C. On a copy, C's board had signed D1 under
/// P over C0, the owner had sealed it back to R (N1), and C's board had
/// signed N2 and N3 over N1. Their companions keep C past its budget and
/// touch none of its saved checks, so C names no parent but R: past a bound
/// of one world both stay lit, and the owner is asked nothing.
#[cfg(feature = "sync")]
#[test]
fn a_seal_the_frozen_record_never_read_names_no_parent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (p, c) = (EntityId::now(), EntityId::now());
    let (root, holder, p0, c0, c2) = {
        let vault = open(&dir)?;
        let (root, root_row, holder) = root_leader(&vault)?;
        let lead = EntityId::now();
        let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
        let c0 = spawn_signed(&vault, root, c, holder, lead, root_row.slice, 3)?;
        let c1 = signed_over(&vault, c, &c0, holder, |_| {})?;
        vault.put_project(c, &c1, 4)?;
        let c2 = signed_over(&vault, c, &c1, holder, |_| {})?;
        vault.put_project(c, &c2, 5)?;
        (root, holder, p0, c0, c2)
    };
    let (_copy_dir, copy) = copy_of(&dir)?;
    let d1 = signed_over(&copy, c, &c0, holder, |row| {
        row.parents = vec![p.to_hex()];
        row.depth_remaining = 0;
    })?;
    let (_, d1_row) = revisions_of_row(c, &d1)?.pop().ok_or_else(invalid)?;
    put_companion(&copy, &d1_row, 6)?;
    let mut back = d1.authority_at(ProjectProofVersion::V3);
    back.parents = vec![root.to_hex()];
    seal(&copy, c, back, &d1)?;
    let n1 = copy.project(c)?.ok_or(Error::EntityNotFound)?;
    let n2 = signed_over(&copy, c, &n1, holder, |_| {})?;
    copy.put_project(c, &n2, 7)?;
    let n3 = signed_over(&copy, c, &n2, holder, |_| {})?;
    copy.put_project(c, &n3, 8)?;
    let vault = open(&dir)?;
    vault.set_project_history_policy(
        &owner(&vault)?,
        ProjectHistoryPolicy {
            max_revisions: 3,
            cycle_worlds_max: 1,
        },
    )?;
    let c3 = signed_over(&vault, c, &c2, holder, |_| {})?;
    vault.put_project(c, &c3, 6)?;
    let p1 = signed_over(&vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 0;
    })?;
    vault.put_project(p, &p1, 7)?;
    assert!(lit(&vault, c)? && lit(&vault, p)?);
    replay_authority(&copy, &vault)?;
    let kind = project_revision_type(&copy.store).ok_or_else(invalid)?;
    // In one batch, so no refresh sees the seal before N2 and N3 keep C
    // past its budget (Sol and Astra r17 F1).
    replay_missing_together(&copy, &vault, kind)?;
    assert!(matches!(
        vault
            .project_frontier(c)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::OverBudget { .. })
    ));
    assert!(lit(&vault, c)? && lit(&vault, p)?);
    assert_eq!(vault.project_cycle_questions()?, Vec::new());
    Ok(())
}

/// Bug repro (Sol r15 F5, Astra r15 F6): A is an owner-door project under
/// B. A host successor over A's boundary waits for its slip's mint. B's
/// leader puts B under A past a bound of one world: dark, and A still lists
/// the waiting successor.
#[cfg(feature = "sync")]
#[test]
fn a_dark_unsigned_member_lists_its_held_revisions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (a, b) = (EntityId::now(), EntityId::now());
    let holder = {
        let vault = open(&dir)?;
        let (root, _, holder) = root_leader(&vault)?;
        // Owner-door births need no signed birth before the vault is rooted.
        let mut b_row = ProjectRecord::new(b, Some(root), root, holder)?;
        b_row.depth_remaining = 6;
        vault.put_project(b, &b_row, 1)?;
        let mut a_row = ProjectRecord::new(a, Some(b), b, holder)?;
        a_row.depth_remaining = 5;
        vault.put_project(a, &a_row, 2)?;
        set_bound(&vault, 1)?;
        holder
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
    // The owner signs B's row; B's leader then puts B under A.
    let mut signed = vault.project(b)?.ok_or(Error::EntityNotFound)?;
    put_signed_project(&vault, b, &mut signed, holder, 10)?;
    let b1 = signed_over(&vault, b, &signed, holder, |row| {
        row.parents = vec![a.to_hex()];
        row.depth_remaining = 0;
    })?;
    let (_, b1) = revisions_of_row(b, &b1)?.pop().ok_or_else(invalid)?;
    put_companion(&vault, &b1, 11)?;
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
