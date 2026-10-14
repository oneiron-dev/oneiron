//! A project past its history budget (PR 3 check 7): it serves the frontier
//! its last within-budget fold verified, lands every valid narrowing below
//! it, never freezes on forgeries, and takes no new authority until the
//! owner seals or raises the policy.
use super::super::*;
use super::authority::{
    FIXTURE_HOST, replay_authority, replay_project, replay_rows, root_leader, sign_with,
    spawn_signed,
};
use super::history::{
    board_signed_s0, copy_of, head_of, ids, open, seats_of, signed_over, without,
};
use super::history_resolution::{envelope, off_board, put_companion, resolution, sorted};
use crate::authority::{CapabilitySlip, HostSlipIssuer};
use crate::error::ErrorKind;
use ed25519_dalek::Signer;

fn owner(vault: &Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

fn over(vault: &Vault, id: EntityId) -> Result<Option<ProjectHistoryOverBudget>> {
    Ok(vault
        .projects_over_history_budget()?
        .into_iter()
        .find(|state| state.project == id))
}

fn frozen_head(vault: &Vault, id: EntityId) -> Result<Option<ProjectRevisionHash>> {
    Ok(over(vault, id)?.and_then(|state| state.frozen_head))
}

fn slip_id(row: &ProjectRecord) -> Result<[u8; 32]> {
    let proof = row.write_proof.as_ref().ok_or_else(invalid)?;
    Ok(CapabilitySlip::from_token(&proof.slip_wire)?.claims.slip_id)
}

fn companion(id: EntityId, row: &ProjectRecord) -> Result<EntityId> {
    super::super::revision::revision_entity_id(head_of(id, row)?)
}

/// `row` over `base` under `slip_wire` with a signature `sign` makes.
pub(super) fn forged_over(
    id: EntityId,
    base: &ProjectRecord,
    mut row: ProjectRecord,
    slip_wire: String,
    sign: impl FnOnce(&CapabilitySlip, &[u8]) -> Result<Vec<u8>>,
) -> Result<super::super::revision::ProjectRevision> {
    let slip = CapabilitySlip::from_token(&slip_wire)?;
    let anchor = base.anchor();
    let signed_at = slip.claims.issued_at;
    let challenge = row.authority_at(ProjectProofVersion::V3).write_challenge(
        id,
        ProjectProofVersion::V3,
        signed_at,
        Some(&anchor),
    )?;
    row.write_proof = Some(ProjectWriteProof {
        holder_signature: sign(&slip, &challenge)?,
        slip_wire,
        signed_at,
        anchor: Some(Box::new(anchor)),
        version: ProjectProofVersion::V3,
    });
    let chain = super::super::revision::revisions_of_row(id, &row)?;
    chain
        .last()
        .map(|(_, revision)| revision.clone())
        .ok_or_else(invalid)
}

/// A host slip the seal door signs with, and its issuer.
fn host_slip(vault: &Vault) -> Result<(HostSlipIssuer, CapabilitySlip)> {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    Ok((issuer, slip))
}

/// Bug repro: past the budget, main keeps folding every row it holds and
/// lets a live edit widen the project; this project serves its frozen
/// frontier, narrows by every valid removal below it, and recovers only by
/// the owner's seal or a raised policy.
#[cfg(feature = "sync")]
#[test]
fn past_its_budget_a_project_freezes_lands_removals_and_the_owners_seal_converges() -> Result<()> {
    let (x, y, w, v, u, z) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let origin = tempfile::tempdir()?;
    let project = {
        let vault = open(&origin)?;
        let project = board_signed_s0(&vault, &[x, y, w, v, u, z], &[], |_| {})?;
        // (d) Q ties within budget, then the policy drops below its history.
        let (qx, qy) = (EntityId::now(), EntityId::now());
        let q = board_signed_s0(&vault, &[qx, qy], &[], |_| {})?;
        let c1 = signed_over(&vault, q.id, &q.s0, q.leader, without(qx))?;
        vault.put_project(q.id, &c1, 3)?;
        let c2 = signed_over(&vault, q.id, &q.s0, q.leader, without(qy))?;
        replay_project(&vault, q.id, &c2, 4)?;
        vault.set_project_history_policy(
            &owner(&vault)?,
            ProjectHistoryPolicy { max_revisions: 3 },
        )?;
        assert!(matches!(
            vault.project_frontier(q.id)?.map(|f| f.disposition),
            Some(ProjectDisposition::OverBudget { frozen, .. })
                if matches!(*frozen, ProjectDisposition::Fork { .. })
        ));
        assert_eq!(seats_of(&vault, q.id), ids(&[q.leader]));
        project
    };
    let id = project.id;
    let (_a_dir, a) = copy_of(&origin)?;
    let (b_dir, b) = copy_of(&origin)?;
    let (_c_dir, c) = copy_of(&origin)?;
    let (_d_dir, d) = copy_of(&origin)?;
    let (_f_dir, f) = copy_of(&origin)?;
    let (_g_dir, g) = copy_of(&origin)?;
    let vault = open(&origin)?;
    let leader = project.leader;
    let s1 = signed_over(&vault, id, &project.s0, leader, without(x))?;
    vault.put_project(id, &s1, 5)?;
    let s2 = signed_over(&vault, id, &s1, leader, without(y))?;
    vault.put_project(id, &s2, 6)?;

    // (a) Two arrival orders freeze at different heads.
    for replica in [&a, &c, &d, &g] {
        replay_authority(&vault, replica)?;
        replay_project(replica, id, &s1, 5)?;
        replay_project(replica, id, &s2, 6)?;
    }
    replay_authority(&vault, &b)?;
    replay_project(&b, id, &s2, 6)?;
    assert_eq!(frozen_head(&a, id)?, Some(head_of(id, &s1)?));
    assert_eq!(frozen_head(&b, id)?, Some(head_of(id, &project.s0)?));
    for replica in [&a, &b] {
        assert_eq!(seats_of(replica, id), ids(&[leader, w, v, u, z]));
    }

    // (b) A live edit over a stored row off the frozen lineage is refused.
    // Every slip is minted on the origin: a replica minting under the shared
    // host key would equivocate its authority log.
    let off = signed_over(&vault, id, &project.s0, project.board, |row| {
        row.depth_remaining -= 1;
    })?;
    let widen = signed_over(&vault, id, &off, project.board, |row| {
        row.roster.push(EntityId::now().to_hex());
    })?;
    replay_authority(&vault, &a)?;
    replay_project(&a, id, &off, 7)?;
    assert_eq!(
        a.put_project(id, &widen, 8).unwrap_err().kind(),
        ErrorKind::ProjectHistoryOverBudget
    );

    // (c) A removal over the frozen head lands on both replicas; so does one
    // delivered before its parent narrowing, and one a new leader signs
    // after an intervening board act.
    let m1 = signed_over(&vault, id, &s2, leader, without(w))?;
    vault.put_project(id, &m1, 9)?;
    let m2 = signed_over(&vault, id, &m1, leader, |row| row.depth_remaining -= 1)?;
    vault.put_project(id, &m2, 10)?;
    let m3 = signed_over(&vault, id, &m2, leader, without(v))?;
    vault.put_project(id, &m3, 11)?;
    let successor = EntityId::now();
    let act = signed_over(&vault, id, &m3, project.board, |row| {
        row.leader = successor.to_hex();
        row.roster.push(successor.to_hex());
    })?;
    vault.put_project(id, &act, 12)?;
    let by_successor = signed_over(&vault, id, &act, successor, without(u))?;
    vault.put_project(id, &by_successor, 13)?;
    replay_authority(&vault, &a)?;
    replay_authority(&vault, &b)?;
    replay_project(&a, id, &m1, 9)?;
    replay_rows(&vault, &a, &[companion(id, &m3)?])?;
    assert_eq!(seats_of(&a, id), ids(&[leader, v, u, z]));
    replay_rows(&vault, &a, &[companion(id, &m2)?])?;
    assert_eq!(seats_of(&a, id), ids(&[leader, u, z]));
    replay_project(&a, id, &by_successor, 13)?;
    replay_project(&b, id, &by_successor, 13)?;
    for replica in [&a, &b] {
        assert_eq!(seats_of(replica, id), ids(&[leader, z]));
        let view = replica.project_frontier(id)?.and_then(|f| f.effective);
        assert_eq!(view.map(|view| view.leader), Some(leader.to_hex()));
    }

    // (e) The freeze survives reopen.
    drop(b);
    let b = open(&b_dir)?;
    assert_eq!(frozen_head(&b, id)?, Some(head_of(id, &project.s0)?));
    assert_eq!(seats_of(&b, id), ids(&[leader, z]));

    // (f) Revoking the frozen head's slip serves no authority; so does the
    // root's board deposing the leader that signed the project's spawn.
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    c.revoke_capability_slip(&issuer, slip_id(&s1)?)?;
    assert!(c.project(id)?.is_none());
    assert_eq!(frozen_head(&c, id)?, None);
    let (root_id, root, _) = root_leader(&d)?;
    let mut deposed = root.clone();
    deposed.leader = EntityId::now().to_hex();
    deposed.roster.push(deposed.leader.clone());
    sign_with(&d, root_id, &mut deposed, None, Some(root.anchor()), None)?;
    d.put_project(root_id, &deposed, 20)?;
    assert!(d.project(id)?.is_none());

    // (g) Forged children delivered before their parent never freeze it.
    let forger = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let leader_wire = s1
        .write_proof
        .as_ref()
        .ok_or_else(invalid)?
        .slip_wire
        .clone();
    let mut forged_rows = Vec::new();
    for depth in 1..=2 {
        let mut row = s1.clone();
        row.depth_remaining -= depth;
        let bad_signature = forged_over(id, &s1, row, leader_wire.clone(), |_, _| Ok(vec![9; 64]))?;
        put_companion(&f, &bad_signature, 30)?;
        forged_rows.push(bad_signature.hash()?);
        let mut row = s1.clone();
        row.depth_remaining -= depth + 2;
        let mut transferred = serde_json::to_value(CapabilitySlip::from_token(&leader_wire)?)
            .map_err(|_| invalid())?;
        let caveats = transferred["caveats"].as_array_mut().ok_or_else(invalid)?;
        caveats.last_mut().ok_or_else(invalid)?["next_binding_key"] =
            serde_json::to_value(forger.verifying_key().to_bytes()).map_err(|_| invalid())?;
        let transferred: CapabilitySlip =
            serde_json::from_value(transferred).map_err(|_| invalid())?;
        let stolen = forged_over(id, &s1, row, transferred.to_token()?, |slip, challenge| {
            Ok(forger
                .sign(&slip.binding_transcript(challenge)?)
                .to_bytes()
                .to_vec())
        })?;
        put_companion(&f, &stolen, 31)?;
        forged_rows.push(stolen.hash()?);
    }
    // Nor do envelopes over an anchor the replica lacks: nothing reaches them.
    let unheld = |byte| ProjectRevisionHash([byte; 32]);
    for next in [3, 4] {
        let contenders = vec![unheld(1), unheld(2)];
        let stray = resolution(
            &vault,
            id,
            project.board,
            unheld(0),
            vec![],
            contenders,
            unheld(next),
        )?;
        put_companion(&f, &envelope(id, stray), 31)?;
    }
    replay_authority(&vault, &f)?;
    replay_project(&f, id, &s1, 32)?;
    assert_eq!(over(&f, id)?, None);
    assert!(matches!(
        f.project_frontier(id)?.map(|f| f.disposition),
        Some(ProjectDisposition::Settled)
    ));
    let forged = f
        .project_revisions(id)?
        .into_iter()
        .filter(|(_, verdict)| {
            *verdict == ProjectVerdict::Quarantined("project revision signature does not verify")
        })
        .count();
    assert_eq!(forged, 4);
    // Forged rows never leave the replica that marked them.
    let doc =
        super::history_transport::exported(&f, &crate::sync::types::WindowKey::new("1970-01"))?;
    for row in forged_rows {
        let row = super::super::revision::revision_entity_id(row)?;
        assert!(
            crate::sync::loro_support::map_get_bytes(&doc.get_map("entities"), &row.to_hex())
                .is_none()
        );
    }

    // (c′) A removal whose board act moved the project under a parent this
    // replica lacks lands once that parent arrives, with no other write to
    // the frozen project; and once a too-narrow parent widens again through
    // the authority log alone.
    let (root_id, root, holder) = root_leader(&vault)?;
    let (q2, q3) = (EntityId::now(), EntityId::now());
    spawn_signed(&vault, root_id, q2, holder, holder, root.slice.clone(), 40)?;
    let q3_birth = spawn_signed(&vault, root_id, q3, holder, holder, root.slice, 41)?;
    let moved = signed_over(&vault, id, &by_successor, project.board, |row| {
        row.parents = vec![q2.to_hex()];
    })?;
    vault.put_project(id, &moved, 42)?;
    let removal = signed_over(&vault, id, &moved, successor, without(z))?;
    vault.put_project(id, &removal, 43)?;
    replay_authority(&vault, &g)?;
    replay_project(&g, id, &by_successor, 13)?;
    // The PROJECT row waits for its parent; its history travels on its own.
    replay_rows(
        &vault,
        &g,
        &[companion(id, &moved)?, companion(id, &removal)?],
    )?;
    assert!(seats_of(&g, id).contains(&z));
    replay_rows(&vault, &g, &[q2])?;
    assert_eq!(seats_of(&g, id), ids(&[leader]));
    // Q3 narrows below the project before the project moves under it.
    let narrow_q3 = signed_over(&vault, q3, &q3_birth, holder, |row| row.depth_remaining = 1)?;
    vault.put_project(q3, &narrow_q3, 44)?;
    let keeper = EntityId::now();
    let moved_again = signed_over(&vault, id, &removal, project.board, |row| {
        row.parents = vec![q3.to_hex()];
        row.roster.push(keeper.to_hex());
    })?;
    replay_project(&vault, id, &moved_again, 45)?;
    let last = signed_over(&vault, id, &moved_again, successor, without(leader))?;
    replay_project(&vault, id, &last, 46)?;
    replay_authority(&vault, &g)?;
    replay_rows(&vault, &g, &[q3])?;
    replay_project(&g, id, &last, 46)?;
    assert!(seats_of(&g, id).contains(&leader));
    // Only the authority log changes Q3: revoking the slip that narrowed it
    // lets the waiting removal land (Wonder r6 F6).
    g.revoke_capability_slip(&issuer, slip_id(&narrow_q3)?)?;
    assert!(!seats_of(&g, id).contains(&leader));

    // (h′) Two identical seal requests in one second: the second repeats.
    // Seal time is the authority clock's, which ticks from the vault's own
    // anchor, so each try starts right after a tick; a pair that load carries
    // across the next tick is two seconds and two seals, and tries again.
    let sealer = owner(&vault)?;
    let mut authority = project.s0.authority_at(ProjectProofVersion::V3);
    authority.roster = Some(BTreeSet::from([leader.to_hex(), z.to_hex()]));
    let base = head_of(id, &s2)?;
    let (issuer, slip) = host_slip(&vault)?;
    let wire = slip.to_token()?;
    let signer = |challenge: &[u8]| issuer.binding_proof(&slip, challenge);
    let seal_clock = || -> Result<u64> {
        let txn = vault.store.env.read_txn()?;
        let floor = crate::authority::AUTHORITY_FIRST_SEEN
            .get_lenient(
                &vault.store,
                &txn,
                &crate::authority::authority_first_seen_clock_key(),
            )?
            .unwrap_or(0);
        Ok(crate::authority::authority_observation_secs(
            &vault.store,
            floor,
            vault.store.clock.now_recorded_at(),
        ))
    };
    let mut first = None;
    for _ in 0..5 {
        let start = seal_clock()?;
        while seal_clock()? == start {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        first =
            Some(vault.seal_project(&sealer, id, authority.clone(), base, wire.clone(), signer)?);
        match vault.seal_project(&sealer, id, authority.clone(), base, wire.clone(), signer) {
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::ProjectAuthorityUnresolved);
                break;
            }
            Ok(_) => first = None,
        }
    }
    let first = first.ok_or_else(invalid)?;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = vault.seal_project(&sealer, id, authority, base, wire, signer)?;
    assert_ne!(first, second);

    // (h) Both replicas serve the sealed view; raising the policy clears a
    // freeze locally.
    // A window carries every revision the origin holds, both seals and the
    // revision each one seals included.
    let sealed = vault.project(id)?.ok_or(Error::EntityNotFound)?;
    let history = vault
        .project_revisions(id)?
        .into_iter()
        .map(|(hash, _)| super::super::revision::revision_entity_id(hash))
        .collect::<Result<Vec<_>>>()?;
    for replica in [&a, &b] {
        replay_authority(&vault, replica)?;
        replay_rows(&vault, replica, &history)?;
        replay_project(replica, id, &sealed, 50)?;
        assert_eq!(over(replica, id)?, None);
        assert_eq!(seats_of(replica, id), ids(&[leader, z]));
    }
    assert!(over(&g, id)?.is_some());
    g.set_project_history_policy(
        &owner(&g)?,
        ProjectHistoryPolicy {
            max_revisions: 1_000,
        },
    )?;
    assert_eq!(over(&g, id)?, None);
    Ok(())
}

/// Bug repro (Sol code r1, S8): a frozen project already applied the board
/// act A that moved it under Q; Q then narrows below A, so the removal B over
/// A, which moves the project under R, inherits A's failure and waits. Only
/// the authority log widens Q again: the retry must wait on Q, not just R.
#[test]
fn a_frozen_removal_waits_on_the_parent_project_its_ancestor_failed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let x = EntityId::now();
    let project = board_signed_s0(&vault, &[x], &[], |_| {})?;
    let id = project.id;
    let (root_id, root, holder) = root_leader(&vault)?;
    let (q, r) = (EntityId::now(), EntityId::now());
    let q_birth = spawn_signed(&vault, root_id, q, holder, holder, root.slice.clone(), 3)?;
    spawn_signed(&vault, root_id, r, holder, holder, root.slice, 4)?;
    vault.set_project_history_policy(&owner(&vault)?, ProjectHistoryPolicy { max_revisions: 2 })?;
    let moved = signed_over(&vault, id, &project.s0, project.board, |row| {
        row.parents = vec![q.to_hex()];
        row.depth_remaining -= 1;
    })?;
    vault.put_project(id, &moved, 5)?;
    assert!(over(&vault, id)?.is_some());
    let narrow_q = signed_over(&vault, q, &q_birth, holder, |row| row.depth_remaining = 1)?;
    vault.put_project(q, &narrow_q, 6)?;
    let removal = signed_over(&vault, id, &moved, project.board, |row| {
        row.parents = vec![r.to_hex()];
        without(x)(row);
    })?;
    replay_project(&vault, id, &removal, 7)?;
    assert!(seats_of(&vault, id).contains(&x));
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    vault.revoke_capability_slip(&issuer, slip_id(&narrow_q)?)?;
    assert_eq!(seats_of(&vault, id), ids(&[project.leader]));
    Ok(())
}

/// Bug repro (Astra #1434 r9 F4, Sol r9 F2): below S0, B1 narrows (A) and L
/// narrows (C); over C, B2 drops B1 (D) and B3 drops B2 (E); over D, B4
/// removes X and drops B3 (F) or keeps X (G), and B4's resolution settles D
/// for G. E then excludes D, and the tie at S0 keeps X. Past the budget the
/// frozen view rests on that resolution too, though it sits off the served
/// path: revoking its slip serves no authority.
#[cfg(feature = "sync")]
#[test]
fn revoking_a_settlement_a_frozen_view_rested_on_serves_no_authority() -> Result<()> {
    let (b1, b2, b3, b4, x, y) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let project = board_signed_s0(&vault, &[x, y], &[b1, b2, b3, b4], |_| {})?;
    let (id, s0) = (project.id, &project.s0);
    let a = signed_over(&vault, id, s0, b1, without(y))?;
    let c = signed_over(&vault, id, s0, project.leader, without(y))?;
    let d = signed_over(&vault, id, &c, b2, off_board(b1))?;
    let e = signed_over(&vault, id, &c, b3, off_board(b2))?;
    let f = signed_over(&vault, id, &d, b4, |row| {
        off_board(b3)(row);
        without(x)(row);
    })?;
    let g = signed_over(&vault, id, &d, b4, |row| row.depth_remaining -= 1)?;
    for (at, row) in (3..).zip([&a, &c, &d, &e, &f, &g]) {
        replay_project(&vault, id, row, at)?;
    }
    let (hf, hg) = (head_of(id, &f)?, head_of(id, &g)?);
    let settle = resolution(
        &vault,
        id,
        b4,
        head_of(id, &d)?,
        vec![],
        sorted(vec![hf, hg]),
        hg,
    )?;
    let settle_slip = CapabilitySlip::from_token(&settle.slip_wire)?
        .claims
        .slip_id;
    put_companion(&vault, &envelope(id, settle), 10)?;
    assert!(seats_of(&vault, id).contains(&x));
    vault.set_project_history_policy(&owner(&vault)?, ProjectHistoryPolicy { max_revisions: 1 })?;
    assert!(over(&vault, id)?.is_some());
    assert!(seats_of(&vault, id).contains(&x));
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    vault.revoke_capability_slip(&issuer, settle_slip)?;
    assert!(vault.project(id)?.is_none());
    assert_eq!(frozen_head(&vault, id)?, None);
    Ok(())
}

/// Bug repro (Astra #1434 r10 F3): L removes Y (A) over S0; over A, B2 drops
/// B1 (D) or lowers the depth (E), and B3 signs two resolutions of A's tie
/// that build on neither, one for D and one for E. Neither stands, so D
/// excludes no one and B1's removal of X over S0 (C) holds in the tie.
/// Past the budget the frozen view rests on both resolutions: revoking
/// either one's slip serves no authority.
#[cfg(feature = "sync")]
#[test]
fn revoking_a_conflicting_resolution_a_frozen_view_rested_on_serves_no_authority() -> Result<()> {
    for revoked in [0, 1] {
        let (b1, b2, b3, x, y) = (
            EntityId::now(),
            EntityId::now(),
            EntityId::now(),
            EntityId::now(),
            EntityId::now(),
        );
        let dir = tempfile::tempdir()?;
        let vault = open(&dir)?;
        let project = board_signed_s0(&vault, &[x, y], &[b1, b2, b3], |_| {})?;
        let (id, s0) = (project.id, &project.s0);
        let a = signed_over(&vault, id, s0, project.leader, without(y))?;
        let d = signed_over(&vault, id, &a, b2, off_board(b1))?;
        let e = signed_over(&vault, id, &a, b2, |row| row.depth_remaining -= 1)?;
        let c = signed_over(&vault, id, s0, b1, without(x))?;
        for (at, row) in (3..).zip([&a, &d, &e, &c]) {
            replay_project(&vault, id, row, at)?;
        }
        let (ha, hd, he) = (head_of(id, &a)?, head_of(id, &d)?, head_of(id, &e)?);
        let mut slips = Vec::new();
        for (at, next) in (10..).zip([hd, he]) {
            let settle = resolution(&vault, id, b3, ha, vec![], sorted(vec![hd, he]), next)?;
            slips.push(
                CapabilitySlip::from_token(&settle.slip_wire)?
                    .claims
                    .slip_id,
            );
            put_companion(&vault, &envelope(id, settle), at)?;
        }
        assert!(!seats_of(&vault, id).contains(&x));
        vault.set_project_history_policy(
            &owner(&vault)?,
            ProjectHistoryPolicy { max_revisions: 1 },
        )?;
        assert!(over(&vault, id)?.is_some());
        assert!(vault.project(id)?.is_some());
        let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
        vault.revoke_capability_slip(&issuer, slips[revoked])?;
        assert!(vault.project(id)?.is_none());
        assert_eq!(frozen_head(&vault, id)?, None);
    }
    Ok(())
}

/// Bug repro (Sol #1434 r12 F1): B removes X (C1) or lowers the depth (C2)
/// over S0, and R0 settles the tie for C1. Past the budget, B adds four
/// resolutions at S0 that build on R0. A fresh read re-checks the frozen
/// view by verifying R0 alone: an envelope held after the freeze spends no
/// verification there, however many arrive.
#[cfg(feature = "sync")]
#[test]
fn a_frozen_re_check_verifies_only_the_envelopes_its_view_rests_on() -> Result<()> {
    let (b, x) = (EntityId::now(), EntityId::now());
    let dir = tempfile::tempdir()?;
    let vault = open(&dir)?;
    let project = board_signed_s0(&vault, &[x], &[b], |_| {})?;
    let (id, s0) = (project.id, &project.s0);
    let c1 = signed_over(&vault, id, s0, b, without(x))?;
    let c2 = signed_over(&vault, id, s0, b, |row| row.depth_remaining -= 1)?;
    replay_project(&vault, id, &c1, 3)?;
    replay_project(&vault, id, &c2, 4)?;
    let (anchor, h1) = (head_of(id, s0)?, head_of(id, &c1)?);
    let contenders = sorted(vec![h1, head_of(id, &c2)?]);
    let mut link = envelope(
        id,
        resolution(&vault, id, b, anchor, vec![], contenders.clone(), h1)?,
    );
    put_companion(&vault, &link, 10)?;
    assert!(!seats_of(&vault, id).contains(&x));
    vault.set_project_history_policy(&owner(&vault)?, ProjectHistoryPolicy { max_revisions: 1 })?;
    for at in 11..15 {
        let prior = vec![link.hash()?];
        link = envelope(
            id,
            resolution(&vault, id, b, anchor, prior, contenders.clone(), h1)?,
        );
        put_companion(&vault, &link, at)?;
    }
    let verified = || super::super::validity::ENVELOPES_VERIFIED.with(std::cell::Cell::get);
    let before = verified();
    let served = vault.project_frontier(id)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(verified() - before, 1);
    assert!(over(&vault, id)?.is_some());
    assert!(served.effective.is_some());
    assert!(!seats_of(&vault, id).contains(&x));
    Ok(())
}
