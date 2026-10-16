//! The batch end persists what a fresh read decides across components (Sol
//! r18 F2, Astra r18 F1): a parent it freezes is refreshed before the child
//! that reads it, and a child is decided again when a parent it read drains
//! after it.
use super::super::refresh::REFRESH_ROUNDS;
use super::super::revision::{project_revision_type, revision_entity_id, revisions_of_row};
use super::super::*;
use super::authority::{put_signed_project, root_leader, spawn_signed};
use super::cycle_model::{EXTRA, KEPT};
use super::history::{open, signed_over};
use super::history_cycles::readable;
use super::history_cycles_closure::{budget, lit, persisted_as_served};
use super::history_resolution::put_companion;

/// Delivers each row's own revision as a companion, all in one batch.
fn deliver_together(vault: &Vault, rows: &[(EntityId, &ProjectRecord)], at: u64) -> Result<()> {
    let kind = project_revision_type(&vault.store).ok_or_else(invalid)?;
    let mut revisions = Vec::new();
    for (id, row) in rows {
        revisions.push(revisions_of_row(*id, row)?.pop().ok_or_else(invalid)?.1);
    }
    vault.with_write_txn(|txn| {
        let mut batch = vault.batch_in();
        for revision in &revisions {
            batch = batch.put_replicated(
                &revision_entity_id(revision.hash()?)?,
                kind,
                TimeRange { start: at, end: at },
                at,
                &revision.canonical_bytes()?,
            );
        }
        batch.apply(txn)
    })
}

/// C holds C0 to C2 within a budget of three, C2 with the slice `c2`. One
/// batch holds C3, C's board setting the slice `c3`, which freezes C at C2,
/// and P1, P's board putting P (the lesser id) under C with `{kept, extra}`.
/// C's drain leaves it at `{kept}`: P1 falls on C's bounds and P serves
/// nothing, as persisted.
fn child_of_a_parent_the_batch_freezes(c2: u8, c3: u8) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let mut ids = [EntityId::now(), EntityId::now()];
    ids.sort();
    let [p, c] = ids;
    let (root, mut root_row, holder) = root_leader(&vault)?;
    root_row.slice.readable = readable(KEPT | EXTRA);
    put_signed_project(&vault, root, &mut root_row, holder, 1)?;
    let lead = EntityId::now();
    let p0 = spawn_signed(&vault, root, p, holder, lead, root_row.slice.clone(), 2)?;
    let c0 = spawn_signed(&vault, root, c, holder, lead, root_row.slice, 3)?;
    let c1 = signed_over(&vault, c, &c0, holder, |_| {})?;
    vault.put_project(c, &c1, 4)?;
    let c2 = signed_over(&vault, c, &c1, holder, |row| {
        row.slice.readable = readable(c2);
    })?;
    vault.put_project(c, &c2, 5)?;
    budget(&vault, 3)?;
    let c3 = signed_over(&vault, c, &c2, holder, |row| {
        row.slice.readable = readable(c3);
    })?;
    let p1 = signed_over(&vault, p, &p0, holder, |row| {
        row.parents = vec![c.to_hex()];
        row.depth_remaining = 1;
    })?;
    assert!(lit(&vault, p)?);
    deliver_together(&vault, &[(c, &c3), (p, &p1)], 6)?;
    assert!(matches!(
        vault
            .project_frontier(c)?
            .map(|frontier| frontier.disposition),
        Some(ProjectDisposition::OverBudget { .. })
    ));
    assert!(!persisted_as_served(&vault, p)?);
    Ok(())
}

/// Bug repro (Sol r18 F2, Astra r18 F1, and the widening variant): a child
/// refreshed before the parent the same batch freezes read the parent's
/// undrained saved view (C3 narrowing) or its fold past the budget (C3
/// widening) and kept a record no fresh read serves. With one round, only
/// refreshing the parent first persists what is served.
#[test]
fn a_parent_the_batch_freezes_is_refreshed_before_its_child() -> Result<()> {
    REFRESH_ROUNDS.with(|rounds| rounds.set(Some(1)));
    let narrowing = child_of_a_parent_the_batch_freezes(KEPT | EXTRA, KEPT);
    let widening = child_of_a_parent_the_batch_freezes(KEPT, KEPT | EXTRA);
    REFRESH_ROUNDS.with(|rounds| rounds.set(None));
    narrowing?;
    widening
}

/// Bug repro (Sol r18 F2, Astra r18 F1, a woken parent): W froze at W2 under
/// R with `{kept, extra}`, and W's board signed W4 putting W under X with
/// `{kept}`, past X's `{extra}`: W's drain waits on X. One batch holds X1,
/// X's board widening X to `{kept, extra}`, and D1, D's board putting D (the
/// lesser id) under W. D is refreshed first and fits W; X's refresh wakes W,
/// whose drain narrows it to `{kept}`. D read W, so it is decided again: D1
/// falls on W's bounds and D serves nothing, as persisted.
#[test]
fn a_child_is_decided_again_when_a_parent_it_read_drains() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let mut ids = [EntityId::now(), EntityId::now()];
    ids.sort();
    let [d, x] = ids;
    let w = EntityId::now();
    let (root, mut root_row, holder) = root_leader(&vault)?;
    root_row.slice.readable = readable(KEPT | EXTRA);
    put_signed_project(&vault, root, &mut root_row, holder, 1)?;
    let lead = EntityId::now();
    let mut extra = root_row.slice.clone();
    extra.readable = readable(EXTRA);
    let x0 = spawn_signed(&vault, root, x, holder, lead, extra, 2)?;
    let d0 = spawn_signed(&vault, root, d, holder, lead, root_row.slice.clone(), 3)?;
    let w0 = spawn_signed(&vault, root, w, holder, lead, root_row.slice, 4)?;
    let w1 = signed_over(&vault, w, &w0, holder, |_| {})?;
    vault.put_project(w, &w1, 5)?;
    let w2 = signed_over(&vault, w, &w1, holder, |_| {})?;
    vault.put_project(w, &w2, 6)?;
    budget(&vault, 3)?;
    let w3 = signed_over(&vault, w, &w2, holder, |_| {})?;
    vault.put_project(w, &w3, 7)?;
    let w4 = signed_over(&vault, w, &w3, holder, |row| {
        row.parents = vec![x.to_hex()];
        row.slice.readable = readable(KEPT);
        row.depth_remaining = 1;
    })?;
    let (_, w4) = revisions_of_row(w, &w4)?.pop().ok_or_else(invalid)?;
    put_companion(&vault, &w4, 8)?;
    assert!(lit(&vault, w)?);
    let x1 = signed_over(&vault, x, &x0, holder, |row| {
        row.slice.readable = readable(KEPT | EXTRA);
    })?;
    let d1 = signed_over(&vault, d, &d0, holder, |row| {
        row.parents = vec![w.to_hex()];
        row.depth_remaining = 1;
    })?;
    assert!(lit(&vault, d)?);
    deliver_together(&vault, &[(x, &x1), (d, &d1)], 9)?;
    let w_view = vault
        .project_frontier(w)?
        .and_then(|frontier| frontier.effective)
        .ok_or_else(invalid)?;
    assert_eq!(
        w_view.slice.map(|slice| slice.readable),
        Some(readable(KEPT))
    );
    assert!(!persisted_as_served(&vault, d)?);
    Ok(())
}
