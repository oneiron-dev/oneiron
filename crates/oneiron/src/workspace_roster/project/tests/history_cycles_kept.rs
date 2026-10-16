//! A component keeps what its decision rests on (Astra #1434c): a combined
//! record keeps every world's dependencies, so a frozen read still fails on
//! a revoked one, and conflicting seals keep their lineages' parent edges,
//! so no fold decides on a partial view of a project it reads. Under one
//! seal, no fold reaches a state outside its tree.
use super::super::revision::{project_revision_type, revisions_of_row};
use super::super::*;
use super::authority::{
    FIXTURE_HOST, child_body, put_signed_project, replay_authority, replay_missing_together,
    replay_project, root_leader, sign_with, spawn_signed,
};
use super::cycle_model::{EXTRA, KEPT};
use super::history::{board_signed_s0, copy_of, head_of, open, seats_of, signed_over, without};
use super::history_cycles::readable;
use super::history_cycles_closure::{budget, lit, persisted_as_served, seal};
use super::history_resolution::{envelope, put_companion, resolution, sorted};
use crate::authority::{CapabilitySlip, HostSlipIssuer};

/// B, on P's board, signed two siblings over P0, A without X and N keeping
/// X at depth 3, and B's resolution E settles them for N. B put P under Q
/// over N (T) and Q's board put Q under P (U), as companions (T first, or
/// U): P serves its worlds' meet at N, still seating X, and freezes there
/// past a budget of five. E's slip, or T's, is then revoked.
fn a_cycle_record_resting_on(t_first: bool, revoke_t: bool) -> Result<()> {
    let (x, y, b) = (EntityId::now(), EntityId::now(), EntityId::now());
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let project = board_signed_s0(&vault, &[x, y], &[b], |row| row.depth_remaining = 6)?;
    let (p, p0) = (project.id, &project.s0);
    let other = board_signed_s0(&vault, &[], &[], |row| row.depth_remaining = 4)?;
    let (q, q0) = (other.id, &other.s0);
    let a = signed_over(&vault, p, p0, b, without(x))?;
    let n = signed_over(&vault, p, p0, b, |row| row.depth_remaining = 3)?;
    replay_project(&vault, p, &a, 3)?;
    replay_project(&vault, p, &n, 4)?;
    let (anchor, ha, hn) = (head_of(p, p0)?, head_of(p, &a)?, head_of(p, &n)?);
    let settle = resolution(&vault, p, b, anchor, vec![], sorted(vec![ha, hn]), hn)?;
    let settle_slip = CapabilitySlip::from_token(&settle.slip_wire)?
        .claims
        .slip_id;
    put_companion(&vault, &envelope(p, settle), 5)?;
    assert!(seats_of(&vault, p).contains(&x));
    let t = signed_over(&vault, p, &n, b, |row| {
        row.parents = vec![q.to_hex()];
        row.depth_remaining = 2;
    })?;
    let u = signed_over(&vault, q, q0, other.board, |row| {
        row.parents = vec![p.to_hex()];
        row.depth_remaining = 1;
    })?;
    let t_slip = (t.write_proof.as_ref())
        .map(|proof| CapabilitySlip::from_token(&proof.slip_wire))
        .ok_or_else(invalid)??
        .claims
        .slip_id;
    let (_, t) = revisions_of_row(p, &t)?.pop().ok_or_else(invalid)?;
    let (_, u) = revisions_of_row(q, &u)?.pop().ok_or_else(invalid)?;
    let order = if t_first { [&t, &u] } else { [&u, &t] };
    for (at, revision) in (6..).zip(order) {
        put_companion(&vault, revision, at)?;
    }
    assert!(matches!(
        vault
            .project_frontier(p)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::ParentCycle { anchor, .. }) if anchor == hn
    ));
    assert!(seats_of(&vault, p).contains(&x));
    budget(&vault, 5)?;
    assert!(matches!(
        vault
            .project_frontier(p)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::OverBudget { .. })
    ));
    assert!(seats_of(&vault, p).contains(&x));
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let revoked = if revoke_t { t_slip } else { settle_slip };
    vault.revoke_capability_slip(&issuer, revoked)?;
    assert!(
        !seats_of(&vault, p).contains(&x),
        "the frozen record never read E or T"
    );
    let served = vault.project_frontier(p)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(served.effective, None);
    Ok(())
}

/// Bug repro (Astra #1434c F1): the record P's worlds combined kept only
/// their common path, so past the budget the frozen read never re-checked
/// the resolution every world's walk rested on, and revoking it left X
/// seated. In both arrival orders, revoking E, or T (the world T stands in,
/// read on T's own lineage), the frozen P serves no authority.
#[test]
fn a_frozen_cycle_record_rests_on_every_worlds_dependencies() -> Result<()> {
    for (t_first, revoke_t) in [(true, false), (false, false), (true, true), (false, true)] {
        a_cycle_record_resting_on(t_first, revoke_t)?;
    }
    Ok(())
}

/// A0 seats X under R. B's board signed B1, putting B under A, and B2, back
/// under R at depth 2, both withheld. A's board put A under B without X
/// (A1), and the owner sealed A over A1 (S1); on a copy, the owner sealed A
/// over A0 (S2), keeping X. Both seals arrive, then B1 and B2 as companions
/// in `order`. The cycle then has two consistent worlds: B1 refused, so B
/// serves B0, A1 fits it, and the seals conflict; or B1 standing, so A1
/// exceeds B2, S1 falls, and S2 seats X.
fn conflicting_seals_meet_a_cycle(b1_first: bool) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (a, b, x) = (EntityId::now(), EntityId::now(), EntityId::now());
    let (a0, a1, b1, b2) = {
        let vault = open(&dir)?;
        let (root, mut root_row, holder) = root_leader(&vault)?;
        root_row.slice.readable = readable(KEPT | EXTRA);
        put_signed_project(&vault, root, &mut root_row, holder, 1)?;
        let lead = EntityId::now();
        let birth = spawn_signed(&vault, root, a, holder, lead, root_row.slice.clone(), 2)?;
        let a0 = signed_over(&vault, a, &birth, holder, |row| {
            row.roster.push(x.to_hex());
            row.depth_remaining = 5;
        })?;
        vault.put_project(a, &a0, 3)?;
        let mut kept = root_row.slice.clone();
        kept.readable = readable(KEPT);
        let b0 = spawn_signed(&vault, root, b, holder, lead, kept, 4)?;
        let b1 = signed_over(&vault, b, &b0, holder, |row| {
            row.parents = vec![a.to_hex()];
            row.slice.readable = readable(KEPT | EXTRA);
            row.depth_remaining = 3;
        })?;
        let b2 = signed_over(&vault, b, &b1, holder, |row| {
            row.parents = vec![root.to_hex()];
            row.depth_remaining = 2;
        })?;
        let a1 = signed_over(&vault, a, &a0, holder, |row| {
            row.parents = vec![b.to_hex()];
            row.roster.retain(|seat| *seat != x.to_hex());
            row.slice.readable = readable(KEPT);
            row.depth_remaining = 2;
        })?;
        vault.put_project(a, &a1, 5)?;
        (a0, a1, b1, b2)
    };
    let (_copy_dir, copy) = copy_of(&dir)?;
    seal(&copy, a, a0.authority_at(ProjectProofVersion::V3), &a0)?;
    let vault = open(&dir)?;
    // The copy's mints, before this vault writes authority rows of its own.
    replay_authority(&copy, &vault)?;
    seal(&vault, a, a1.authority_at(ProjectProofVersion::V3), &a1)?;
    let kind = project_revision_type(&copy.store).ok_or_else(invalid)?;
    replay_missing_together(&copy, &vault, kind)?;
    let conflicting = |vault: &Vault| -> Result<bool> {
        Ok(matches!(
            vault
                .project_frontier(a)?
                .map(|frontier| frontier.disposition),
            Some(ProjectDisposition::ConflictingSeals { .. })
        ))
    };
    assert!(conflicting(&vault)?);
    let (_, b1) = revisions_of_row(b, &b1)?.pop().ok_or_else(invalid)?;
    let (_, b2) = revisions_of_row(b, &b2)?.pop().ok_or_else(invalid)?;
    let order = if b1_first { [&b1, &b2] } else { [&b2, &b1] };
    for (at, revision) in (10..).zip(order) {
        put_companion(&vault, revision, at)?;
    }
    assert!(
        !seats_of(&vault, a).contains(&x),
        "a refusal read while A was open dropped S1"
    );
    assert!(conflicting(&vault)?);
    assert!(!persisted_as_served(&vault, a)?);
    persisted_as_served(&vault, b)?;
    Ok(())
}

/// Bug repro (Astra #1434c F2): conflicting seals left A with no parent
/// edges, so A folded alone, read B, and B read A while A was open: the
/// refusal B took from it dropped S1, and A served S2 alone, seating X.
/// In both arrival orders, A serves `ConflictingSeals` and no authority,
/// though one of the cycle's worlds would seat X (Engine, Astra-c).
#[test]
fn conflicting_seals_in_a_cycle_serve_no_authority() -> Result<()> {
    conflicting_seals_meet_a_cycle(true)?;
    conflicting_seals_meet_a_cycle(false)
}

/// Bug repro (Astra-c, the Engine's invariant for a fold alone): C's birth
/// under P and a second birth under R seating X conflict, and the owner
/// sealed C over the first, which fences off the second. P's leader then
/// narrows P below that birth, so the seal's lineage falls. Alone, C's fold
/// judged every held row against its parents and, with no seal standing,
/// fell back to the fenced-off birth, seating X. Every state outside the
/// seal's tree is sealed off, so C serves no authority.
#[test]
fn a_fenced_off_birth_never_stands_in_for_a_fallen_seal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let (root, root_row, holder) = root_leader(&vault)?;
    let (p, c, lead, x) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let first = spawn_signed(&vault, p, c, lead, lead, root_row.slice.clone(), 3)?;
    let other = EntityId::now();
    let mut second = child_body(&vault, root, c, holder, other, root_row.slice)?;
    second.roster.push(x.to_hex());
    sign_with(&vault, c, &mut second, Some(holder), None, None)?;
    replay_project(&vault, c, &second, 4)?;
    assert!(matches!(
        vault
            .project_frontier(c)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::ConflictingBirths { .. })
    ));
    let authority = first.authority_at(ProjectProofVersion::V3);
    seal(&vault, c, authority, &first)?;
    assert!(lit(&vault, c)?);
    let p1 = signed_over(&vault, p, &p0, lead, |row| row.depth_remaining -= 2)?;
    vault.put_project(p, &p1, 5)?;
    assert!(
        !seats_of(&vault, c).contains(&x),
        "the fold fell back to the fenced-off birth"
    );
    assert!(!lit(&vault, c)?);
    Ok(())
}
