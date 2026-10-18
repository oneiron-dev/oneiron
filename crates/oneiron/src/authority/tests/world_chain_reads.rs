//! World privacy P6b acceptance for settings edits across admitters
//! (contract §4, check 7c): validity is the same on every install, judged
//! existentially over the edit's signing chains and each chain admitter's
//! own read; strength is local, judged under the pinned trust set by the
//! multi-chain race rule. Losing standing never widens a world, and a
//! foreign admitter's edits only narrow on the owner's installs.
use super::machine_identity::request_for;
use super::owner_anchor::{YOURS, hosted_genesis, pin, profile, publish, signed};
use super::support::{ed_key, owner_act};
use super::world_privacy::settings;
use super::*;
use crate::HostingPrivacyPosture::Hosted;
use crate::world_keys::RecoveryRoot;

pub(super) fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

/// A revision of `request`'s machine that lists `seen` as the edits it saw.
pub(super) fn seeing(
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    revision: u64,
    seen: &[&AuthorityLogEntry],
) -> AuthorityOp {
    let AuthorityOp::MachineProfile(mut profile) = profile(request, role, revision) else {
        unreachable!("profile builds a machine revision")
    };
    profile.seen_world_edits = seen.iter().map(|entry| hash(entry)).collect();
    AuthorityOp::MachineProfile(profile)
}

/// A settings edit `key` signs as `machine` at `seq` on `parents`.
pub(super) fn edit(
    id: AuthorityVaultId,
    parents: &[&AuthorityLogEntry],
    (machine, key): (EntityId, &SigningKey),
    seq: u64,
    world: EntityId,
    read: ReadLocation,
) -> AuthorityLogEntry {
    signed(
        id,
        parents,
        key,
        seq,
        AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
            world,
            act: owner_act(EntityId::now(), world),
            machine,
            settings: settings(read),
        }),
    )
}

/// The fold an install pinned to `root` (or unpinned) reads.
pub(super) fn fold_under(
    entries: &[AuthorityLogEntry],
    posture: crate::HostingPrivacyPosture,
    root: Option<&RecoveryRoot>,
) -> AuthorityFold {
    fold_pinned_authority_log_for_posture(
        entries,
        &BTreeMap::new(),
        10,
        &BTreeMap::new(),
        posture,
        root.map(pin).as_ref(),
    )
}

pub(super) fn read_under(
    entries: &[AuthorityLogEntry],
    posture: crate::HostingPrivacyPosture,
    root: Option<&RecoveryRoot>,
    world: EntityId,
) -> EffectiveRead {
    fold_under(entries, posture, root).world_privacy(world).read
}

/// Valid on an install pinned to each of `roots` and on an unpinned one.
fn valid_everywhere(
    entries: &[AuthorityLogEntry],
    posture: crate::HostingPrivacyPosture,
    roots: &[&RecoveryRoot],
    row: &AuthorityLogEntry,
) -> bool {
    roots
        .iter()
        .map(|root| Some(*root))
        .chain([None])
        .all(|root| {
            fold_under(entries, posture, root)
                .valid_entries
                .contains(&hash(row))
        })
}

/// A hosted vault with two roots, the owner's and the host's, each of
/// whose anchors marks one machine of its own.
struct TwoRoots {
    id: AuthorityVaultId,
    owner: (RecoveryRoot, SigningKey),
    host: (RecoveryRoot, SigningKey),
    entries: Vec<AuthorityLogEntry>,
    a: (MachineEnrolmentRequest, SigningKey),
    h: (MachineEnrolmentRequest, SigningKey),
    marks: Vec<AuthorityLogEntry>,
}

fn two_roots(seed: u8) -> TwoRoots {
    let cloud = ed_key(seed);
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (owner_root, owner_anchor, owner_published) = publish(id, &genesis);
    let (host_root, host_anchor, host_published) = publish(id, &genesis);
    let a_key = ed_key(seed.wrapping_add(1));
    let a = request_for(id, EntityId::now(), &a_key);
    let h_key = ed_key(seed.wrapping_add(2));
    let h = request_for(id, EntityId::now(), &h_key);
    let mark_a = signed(
        id,
        &[&owner_published],
        &owner_anchor,
        2,
        profile(&a, YOURS, 1),
    );
    let mark_h = signed(
        id,
        &[&host_published],
        &host_anchor,
        2,
        profile(&h, YOURS, 1),
    );
    TwoRoots {
        id,
        owner: (owner_root, owner_anchor),
        host: (host_root, host_anchor),
        entries: vec![
            genesis,
            owner_published,
            host_published,
            mark_a.clone(),
            mark_h.clone(),
        ],
        a: (a, a_key),
        h: (h, h_key),
        marks: vec![mark_a, mark_h],
    }
}

impl TwoRoots {
    fn a(&self) -> (EntityId, &SigningKey) {
        (self.a.0.machine, &self.a.1)
    }

    fn h(&self) -> (EntityId, &SigningKey) {
        (self.h.0.machine, &self.h.1)
    }

    /// The main-log marks plus `side`, as an edit's parents.
    fn on<'e>(&'e self, side: &[&'e AuthorityLogEntry]) -> Vec<&'e AuthorityLogEntry> {
        self.marks.iter().chain(side.iter().copied()).collect()
    }

    fn with(&self, rows: &[&AuthorityLogEntry]) -> Vec<AuthorityLogEntry> {
        let mut entries = self.entries.clone();
        entries.extend(rows.iter().map(|row| (*row).clone()));
        entries
    }
}

/// 7c, foreign widening and narrowing. A host-anchored H holds W (it reads
/// on the owner's machines) under the host's admitter. Its widening is valid
/// everywhere and reads everywhere on an install pinned to the host's root,
/// but the owner's installs and an unpinned one keep `MyMachines`. Its
/// narrowing to itself leaves W readable on no owner machine and orphaned
/// under the owner's admitter, and the owner's A re-picks it, valid on every
/// install and at full strength on the owner's.
#[test]
fn a_host_machines_settings_only_narrow_on_the_owners_installs() {
    let vault = two_roots(150);
    let (owner, host) = (&vault.owner.0, &vault.host.0);
    let world = EntityId::now();
    let mine = edit(
        vault.id,
        &vault.on(&[]),
        vault.a(),
        1,
        world,
        ReadLocation::MyMachines,
    );
    let widen = edit(
        vault.id,
        &vault.on(&[&mine]),
        vault.h(),
        1,
        world,
        ReadLocation::Everywhere,
    );
    let entries = vault.with(&[&mine, &widen]);
    assert!(valid_everywhere(&entries, Hosted, &[owner, host], &widen));
    assert_eq!(
        read_under(&entries, Hosted, Some(host), world),
        EffectiveRead::Everywhere
    );
    for root in [Some(owner), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::MyMachines
        );
    }

    let h = vault.h.0.machine;
    let narrow = edit(
        vault.id,
        &vault.on(&[&mine]),
        vault.h(),
        1,
        world,
        ReadLocation::OneMachine(h),
    );
    let entries = vault.with(&[&mine, &narrow]);
    let fold = fold_under(&entries, Hosted, Some(owner));
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::OneMachine(h));
    let a = vault.a.0.machine;
    assert!(!fold.world_readable_on(world, Destination::Machine(a)));
    assert_eq!(
        fold.world_edit_standing(a, world),
        Some(WorldEditStanding::RepicksOrphan)
    );
    let repick = edit(
        vault.id,
        &vault.on(&[&narrow]),
        vault.a(),
        2,
        world,
        ReadLocation::OneMachine(a),
    );
    let entries = vault.with(&[&mine, &narrow, &repick]);
    assert!(valid_everywhere(&entries, Hosted, &[owner, host], &repick));
    assert_eq!(
        read_under(&entries, Hosted, Some(owner), world),
        EffectiveRead::OneMachine(a)
    );
}

/// 7c, no admission: an edit signed by a key no chain admits for its
/// machine is invalid on every install, whoever it names.
#[test]
fn an_edit_no_chain_admits_is_invalid_everywhere() {
    let vault = two_roots(155);
    let (owner, host) = (&vault.owner.0, &vault.host.0);
    let world = EntityId::now();
    let stranger = ed_key(158);
    for machine in [vault.a.0.machine, EntityId::now()] {
        let forged = edit(
            vault.id,
            &vault.on(&[]),
            (machine, &stranger),
            1,
            world,
            ReadLocation::Everywhere,
        );
        let entries = vault.with(&[&forged]);
        for root in [Some(owner), Some(host), None] {
            assert!(
                !fold_under(&entries, Hosted, root)
                    .valid_entries
                    .contains(&hash(&forged))
            );
        }
    }
}

/// 7c, sequential demoted widenings (Wonder R1b-F2): the holder A of
/// `OneMachine(A)` is removed or demoted on a branch it had not seen, then
/// widens W two and three times in a row. W stays `OneMachine(A)` on the
/// owner's installs and on an unpinned one. Fails before: the second
/// widening's stored prior was the first widening.
#[test]
fn sequential_demoted_widenings_never_widen() {
    for role in [
        MachineRole::Removed,
        MachineRole::Owned(MachineOwnership::WorkSchool),
    ] {
        let vault = two_roots(160);
        let owner = &vault.owner.0;
        let a = vault.a.0.machine;
        let world = EntityId::now();
        let held = edit(
            vault.id,
            &vault.on(&[]),
            vault.a(),
            1,
            world,
            ReadLocation::OneMachine(a),
        );
        let demotion = signed(
            vault.id,
            &[&vault.marks[0]],
            &vault.owner.1,
            3,
            seeing(&vault.a.0, role, 2, &[&held]),
        );
        let first = edit(
            vault.id,
            &vault.on(&[&held]),
            vault.a(),
            2,
            world,
            ReadLocation::MyMachines,
        );
        let second = edit(
            vault.id,
            &vault.on(&[&first]),
            vault.a(),
            3,
            world,
            ReadLocation::Everywhere,
        );
        let third = edit(
            vault.id,
            &vault.on(&[&second]),
            vault.a(),
            4,
            world,
            ReadLocation::Everywhere,
        );
        for rows in [
            vec![&held, &demotion, &first, &second],
            vec![&held, &demotion, &first, &second, &third],
        ] {
            let entries = vault.with(&rows);
            for root in [Some(owner), None] {
                assert_eq!(
                    read_under(&entries, Hosted, root, world),
                    EffectiveRead::OneMachine(a),
                    "{role:?}, {} widenings",
                    rows.len() - 2
                );
            }
        }
    }
}

/// 7c, a clone moves a world off its holder (Sol R1c-F1): the owner's root
/// admits A and B, and A holds W at `OneMachine(A)`. A host clone of A's id,
/// with the host's keys, widens W to `MyMachines` and then moves it to
/// `OneMachine(B)`. On the owner's installs W reads `Conflicted{A, B}`; A
/// re-picks it, valid on every install, heading the frontier, and the owner's
/// installs read `OneMachine(A)` again. Fails before: validity read an
/// all-admitted, full-strength read, where A neither held nor contended.
#[test]
fn a_clone_never_moves_a_world_off_its_holder() {
    let mut vault = two_roots(165);
    let (owner, host) = (vault.owner.0.clone(), vault.host.0.clone());
    let a = vault.a.0.machine;
    let b_key = ed_key(168);
    let b = request_for(vault.id, EntityId::now(), &b_key);
    let mark_b = signed(
        vault.id,
        &[&vault.marks[0]],
        &vault.owner.1,
        3,
        profile(&b, YOURS, 1),
    );
    let clone_key = ed_key(169);
    let clone = request_for(vault.id, a, &clone_key);
    let clone_mark = signed(
        vault.id,
        &[&vault.marks[1]],
        &vault.host.1,
        3,
        profile(&clone, YOURS, 1),
    );
    vault.entries.extend([mark_b.clone(), clone_mark.clone()]);
    vault.marks.extend([mark_b, clone_mark]);
    let world = EntityId::now();
    let held = edit(
        vault.id,
        &vault.on(&[]),
        vault.a(),
        1,
        world,
        ReadLocation::OneMachine(a),
    );
    let widened = edit(
        vault.id,
        &vault.on(&[&held]),
        (a, &clone_key),
        1,
        world,
        ReadLocation::MyMachines,
    );
    let moved = edit(
        vault.id,
        &vault.on(&[&widened]),
        (a, &clone_key),
        2,
        world,
        ReadLocation::OneMachine(b.machine),
    );
    let entries = vault.with(&[&held, &widened, &moved]);
    assert!(valid_everywhere(&entries, Hosted, &[&owner, &host], &moved));
    assert_eq!(
        read_under(&entries, Hosted, Some(&owner), world),
        EffectiveRead::Conflicted {
            contenders: BTreeSet::from([a, b.machine]),
        }
    );
    let repick = edit(
        vault.id,
        &vault.on(&[&moved]),
        vault.a(),
        2,
        world,
        ReadLocation::OneMachine(a),
    );
    let entries = vault.with(&[&held, &widened, &moved, &repick]);
    assert!(valid_everywhere(
        &entries,
        Hosted,
        &[&owner, &host],
        &repick
    ));
    let fold = fold_under(&entries, Hosted, Some(&owner));
    assert_eq!(
        fold.worlds[&world].live.keys().copied().collect::<Vec<_>>(),
        vec![hash(&repick)]
    );
    assert_eq!(fold.world_privacy(world).read, EffectiveRead::OneMachine(a));
}

/// 7c, a copied profile (Wonder R1c-F2): the host copies the owner's
/// machine A's profile verbatim, keys and proof, into its own anchor's
/// chain, and a host machine H moves W to `OneMachine(H)`. A's re-pick
/// verifies under both of A's chains and is valid on every install, in
/// either order of the two chains, because the owner's admitter gives it
/// `RepicksOrphan`. Fails before: one signing chain was chosen, and under the
/// host's admitter H holds the world.
#[test]
fn a_copied_profile_never_blocks_the_owners_re_pick() {
    for copy_saw_the_mark in [false, true] {
        let mut vault = two_roots(170);
        let (owner, host) = (vault.owner.0.clone(), vault.host.0.clone());
        let a = vault.a.0.machine;
        let h = vault.h.0.machine;
        let copy_parents: Vec<&AuthorityLogEntry> = if copy_saw_the_mark {
            vec![&vault.marks[1], &vault.marks[0]]
        } else {
            vec![&vault.marks[1]]
        };
        let copy = signed(
            vault.id,
            &copy_parents,
            &vault.host.1,
            3,
            profile(&vault.a.0, YOURS, 1),
        );
        vault.entries.insert(3, copy.clone());
        vault.marks.push(copy);
        let world = EntityId::now();
        let mine = edit(
            vault.id,
            &vault.on(&[]),
            vault.a(),
            1,
            world,
            ReadLocation::MyMachines,
        );
        let taken = edit(
            vault.id,
            &vault.on(&[&mine]),
            vault.h(),
            1,
            world,
            ReadLocation::OneMachine(h),
        );
        let repick = edit(
            vault.id,
            &vault.on(&[&taken]),
            vault.a(),
            2,
            world,
            ReadLocation::OneMachine(a),
        );
        let entries = vault.with(&[&mine, &taken, &repick]);
        assert!(
            valid_everywhere(&entries, Hosted, &[&owner, &host], &repick),
            "{copy_saw_the_mark}"
        );
        assert_eq!(
            read_under(&entries, Hosted, Some(&owner), world),
            EffectiveRead::OneMachine(a)
        );
    }
}

/// 7c, an anchor-only machine's acknowledged removal (Wonder R1o-F2; Sol
/// R1p-F2): on a hosted vault A is the owner's under the anchor alone. A
/// widens W from `OneMachine(A)` to `MyMachines` (E), and the anchor then
/// removes A with a head that lists E. Installs pinned to the anchor read
/// `MyMachines`. Fails before: the absent roster chain read as a reason
/// that fails the race.
#[test]
fn an_anchor_only_machines_acknowledged_removal_keeps_its_widening() {
    let vault = two_roots(175);
    let owner = &vault.owner.0;
    let a = vault.a.0.machine;
    let world = EntityId::now();
    let held = edit(
        vault.id,
        &vault.on(&[]),
        vault.a(),
        1,
        world,
        ReadLocation::OneMachine(a),
    );
    let widened = edit(
        vault.id,
        &vault.on(&[&held]),
        vault.a(),
        2,
        world,
        ReadLocation::MyMachines,
    );
    let removal = signed(
        vault.id,
        &[&vault.marks[0]],
        &vault.owner.1,
        3,
        seeing(&vault.a.0, MachineRole::Removed, 2, &[&widened]),
    );
    let entries = vault.with(&[&held, &widened, &removal]);
    assert_eq!(
        read_under(&entries, Hosted, Some(owner), world),
        EffectiveRead::MyMachines
    );
}

/// 7c, a poisoned trusted chain (Wonder R1n-F1): A, the owner's under the
/// anchor, widens W offline; the anchor then marks a second machine id with
/// A's key, which poisons A's chain. On installs pinned to that anchor the
/// widening is restriction-only. Fails before: the race rule named only
/// removal, demotion and conflict.
#[test]
fn a_poisoned_trusted_chain_never_acknowledges_a_widening() {
    let vault = two_roots(185);
    let owner = &vault.owner.0;
    let a = vault.a.0.machine;
    let world = EntityId::now();
    let held = edit(
        vault.id,
        &vault.on(&[]),
        vault.a(),
        1,
        world,
        ReadLocation::OneMachine(a),
    );
    let widened = edit(
        vault.id,
        &vault.on(&[&held]),
        vault.a(),
        2,
        world,
        ReadLocation::MyMachines,
    );
    let second = request_for(vault.id, EntityId::now(), &vault.a.1);
    let poison = signed(
        vault.id,
        &[&vault.marks[0]],
        &vault.owner.1,
        3,
        seeing(&second, YOURS, 1, &[&widened]),
    );
    let entries = vault.with(&[&held, &widened, &poison]);
    assert!(
        !fold_under(&entries, Hosted, Some(owner))
            .machine(a)
            .unwrap()
            .is_mine(Some(&pin(owner)))
    );
    assert_eq!(
        read_under(&entries, Hosted, Some(owner), world),
        EffectiveRead::OneMachine(a)
    );
}

/// 7c, the transition window (Sol R1b-F1): R1 admits A and B; R2 carries A
/// but not B. A, holding both marks while still pinned to R1, sets an
/// unedited W to `OneMachine(B)`. The edit is valid everywhere, W reads no
/// wider than `OneMachine(B)` on R2 installs, it is orphaned there, and A's
/// re-pick on top of it is valid: nothing stalls. Fails before: under the
/// new pin B failed the target check, the edit became invalid, and W read
/// everywhere. On an R1 install B still holds W, so A has no standing at a
/// door there, though R2's read would make its re-pick valid: a door takes
/// standing from this install's read alone (Astra code-S2-R1 A1-F3).
#[test]
fn an_edit_made_across_a_re_issue_stays_valid_and_narrow() {
    let cloud = ed_key(195);
    let genesis = hosted_genesis(&cloud);
    let id = genesis_vault_id(&genesis).unwrap();
    let (first, first_anchor, first_published) = publish(id, &genesis);
    let (second, second_anchor, second_published) = publish(id, &genesis);
    let a_key = ed_key(196);
    let a = request_for(id, EntityId::now(), &a_key);
    let b = request_for(id, EntityId::now(), &ed_key(197));
    let marks = [
        signed(
            id,
            &[&first_published],
            &first_anchor,
            2,
            profile(&a, YOURS, 1),
        ),
        signed(
            id,
            &[&first_published],
            &first_anchor,
            3,
            profile(&b, YOURS, 1),
        ),
        signed(
            id,
            &[&second_published],
            &second_anchor,
            2,
            profile(&a, YOURS, 1),
        ),
    ];
    let heads: Vec<&AuthorityLogEntry> = marks.iter().collect();
    let world = EntityId::now();
    let moved = edit(
        id,
        &heads,
        (a.machine, &a_key),
        1,
        world,
        ReadLocation::OneMachine(b.machine),
    );
    let mut entries = vec![genesis, first_published, second_published];
    entries.extend(marks.iter().cloned());
    entries.push(moved.clone());
    assert!(valid_everywhere(
        &entries,
        Hosted,
        &[&first, &second],
        &moved
    ));
    for root in [Some(&first), Some(&second), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::OneMachine(b.machine)
        );
    }
    assert_eq!(
        fold_under(&entries, Hosted, Some(&second)).world_edit_standing(a.machine, world),
        Some(WorldEditStanding::RepicksOrphan)
    );
    assert_eq!(
        fold_under(&entries, Hosted, Some(&first)).world_edit_standing(a.machine, world),
        None
    );
    let mut parents = heads.clone();
    parents.push(&moved);
    let repick = edit(
        id,
        &parents,
        (a.machine, &a_key),
        2,
        world,
        ReadLocation::OneMachine(a.machine),
    );
    entries.push(repick.clone());
    assert!(valid_everywhere(&entries, Hosted, &[&second], &repick));
    assert_eq!(
        read_under(&entries, Hosted, Some(&second), world),
        EffectiveRead::OneMachine(a.machine)
    );
}
