//! World privacy P6b acceptance for settings edits across admitters
//! (contract §4, check 7c): validity is the same on every install, judged
//! existentially over the edit's signing chains and each chain admitter's
//! own read; strength is local, judged under the pinned trust set by the
//! multi-chain race rule. Losing standing never widens a world, and a
//! foreign admitter's edits only narrow on the owner's installs.
use super::machine_identity::request_for;
use super::owner_anchor::{YOURS, hosted_genesis, pin, profile, publish, signed};
use super::support::{ed_key, genesis_entry, owner_act};
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

/// 7c, foreign narrowing only (mesh PR1a, FIX-LIST 10-19 02:16; Fable design pass
/// 29: an anchor's chain admits no carrier): A is a roster carrier via a hosted
/// bootstrap, so its settings count, while H stays host-anchor-only, so its edits
/// are invalid on every install and W reads A's setting on all three installs.
#[test]
fn a_host_machines_settings_only_narrow_on_the_owners_installs() {
    let mut vault = two_roots(150);
    let cloud = ed_key(150);
    let genesis = vault.entries[0].clone();
    let a_request = vault.a.0.clone();
    let roster_a = signed(
        vault.id,
        &[&genesis],
        &cloud,
        1,
        profile(&a_request, MachineRole::HostedNode, 1),
    );
    vault.entries.insert(1, roster_a.clone());
    vault.marks.push(roster_a);
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
    for root in [Some(owner), Some(host), None] {
        assert!(
            !fold_under(&entries, Hosted, root)
                .valid_entries
                .contains(&hash(&widen))
        );
    }
    for root in [Some(owner), Some(host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::MyMachines
        );
    }

    let narrow = edit(
        vault.id,
        &vault.on(&[&mine]),
        vault.h(),
        1,
        world,
        ReadLocation::OneMachine(vault.h.0.machine),
    );
    let entries = vault.with(&[&mine, &narrow]);
    for root in [Some(owner), Some(host), None] {
        assert!(
            !fold_under(&entries, Hosted, root)
                .valid_entries
                .contains(&hash(&narrow))
        );
    }
    for root in [Some(owner), Some(host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::MyMachines
        );
    }
    let a = vault.a.0.machine;
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
    for root in [Some(owner), Some(host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::OneMachine(a)
        );
    }
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

/// 7c, sequential widenings after a removal stay narrow, after a demotion they count
/// (mesh PR1a, FIX-LIST 10-19 02:16; only removal revokes a carrier): on a self-host
/// vault A is a roster carrier, the roster demotion saw only `held`, the removed half
/// reads `OneMachine(A)` pinned and unpinned, the WorkSchool half reads `Everywhere`.
#[test]
fn sequential_widenings_after_a_removal_never_widen_and_a_demotion_keeps_them() {
    for role in [
        MachineRole::Removed,
        MachineRole::Owned(MachineOwnership::WorkSchool),
    ] {
        let seed = 160;
        let genesis = genesis_entry(seed, 1);
        let id = genesis_vault_id(&genesis).unwrap();
        let (owner_root, _, published) = publish(id, &genesis);
        let owner = &owner_root;
        let roster_key = ed_key(seed);
        let a_key = ed_key(seed.wrapping_add(1));
        let a_request = request_for(id, EntityId::now(), &a_key);
        let a = a_request.machine;
        let roster_mark = signed(
            id,
            &[&genesis],
            &roster_key,
            1,
            profile(&a_request, YOURS, 1),
        );
        let world = EntityId::now();
        let held = edit(
            id,
            &[&roster_mark],
            (a, &a_key),
            1,
            world,
            ReadLocation::OneMachine(a),
        );
        let demotion = signed(
            id,
            &[&roster_mark],
            &roster_key,
            2,
            seeing(&a_request, role, 2, &[&held]),
        );
        let first = edit(
            id,
            &[&roster_mark, &held],
            (a, &a_key),
            2,
            world,
            ReadLocation::MyMachines,
        );
        let second = edit(
            id,
            &[&roster_mark, &first],
            (a, &a_key),
            3,
            world,
            ReadLocation::Everywhere,
        );
        let third = edit(
            id,
            &[&roster_mark, &second],
            (a, &a_key),
            4,
            world,
            ReadLocation::Everywhere,
        );
        for rows in [
            vec![&held, &demotion, &first, &second],
            vec![&held, &demotion, &first, &second, &third],
        ] {
            let mut entries = vec![genesis.clone(), published.clone(), roster_mark.clone()];
            entries.extend(rows.iter().map(|row| (*row).clone()));
            let expected = if role == MachineRole::Removed {
                EffectiveRead::OneMachine(a)
            } else {
                EffectiveRead::Everywhere
            };
            for root in [Some(owner), None] {
                assert_eq!(
                    read_under(
                        &entries,
                        crate::HostingPrivacyPosture::SelfHostLocal,
                        root,
                        world
                    ),
                    expected.clone(),
                    "{role:?}, {} widenings",
                    rows.len() - 2
                );
            }
        }
    }
}

/// 7c, a clone moves nothing (mesh PR1a, FIX-LIST 10-19 02:16; Fable design pass
/// 29: an anchor's chain admits no carrier): A and B are roster carriers via hosted
/// bootstraps, so A's hold counts, while the host's clone stays anchor-only, so its
/// edits are invalid on every install and W reads `OneMachine(A)` throughout.
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
    let cloud = ed_key(165);
    let genesis = vault.entries[0].clone();
    let a_request = vault.a.0.clone();
    let roster_a = signed(
        vault.id,
        &[&genesis],
        &cloud,
        1,
        profile(&a_request, MachineRole::HostedNode, 1),
    );
    let roster_b = signed(
        vault.id,
        &[&roster_a],
        &cloud,
        2,
        profile(&b, MachineRole::HostedNode, 1),
    );
    vault.entries.extend([roster_a.clone(), roster_b.clone()]);
    vault.marks.extend([roster_a, roster_b]);
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
    for row in [&widened, &moved] {
        for root in [Some(&owner), Some(&host), None] {
            assert!(
                !fold_under(&entries, Hosted, root)
                    .valid_entries
                    .contains(&hash(row))
            );
        }
    }
    for root in [Some(&owner), Some(&host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::OneMachine(a)
        );
    }
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
    for root in [Some(&owner), Some(&host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::OneMachine(a)
        );
    }
}

/// 7c, a copied profile never blocks the owner's re-pick (mesh PR1a, FIX-LIST 10-19
/// 02:16; Fable design pass 29): A is a roster carrier via a hosted bootstrap, H stays
/// host-anchor-only so its take is invalid everywhere, and A's re-pick heads the
/// frontier on all three installs.
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
        let cloud = ed_key(170);
        let genesis = vault.entries[0].clone();
        let a_request = vault.a.0.clone();
        let roster_a = signed(
            vault.id,
            &[&genesis],
            &cloud,
            1,
            profile(&a_request, MachineRole::HostedNode, 1),
        );
        vault.entries.insert(1, roster_a.clone());
        vault.marks.push(roster_a);
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
        for root in [Some(&owner), Some(&host), None] {
            assert!(
                !fold_under(&entries, Hosted, root)
                    .valid_entries
                    .contains(&hash(&taken)),
                "{copy_saw_the_mark}"
            );
        }
        assert!(
            valid_everywhere(&entries, Hosted, &[&owner, &host], &repick),
            "{copy_saw_the_mark}"
        );
        for root in [Some(&owner), Some(&host), None] {
            assert_eq!(
                read_under(&entries, Hosted, root, world),
                EffectiveRead::OneMachine(a),
                "{copy_saw_the_mark}"
            );
        }
    }
}

/// 7c, an anchor-only machine's edits are invalid everywhere (Fable design pass 29:
/// an anchor's chain names no carrier key): A has no roster profile, so `held` and
/// `widened` are invalid pinned or not, and W reads the default `Everywhere`.
#[test]
fn an_anchor_only_machines_acknowledged_removal_keeps_its_widening() {
    let vault = two_roots(175);
    let (owner, host) = (&vault.owner.0, &vault.host.0);
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
    for row in [&held, &widened] {
        for root in [Some(owner), Some(host), None] {
            assert!(
                !fold_under(&entries, Hosted, root)
                    .valid_entries
                    .contains(&hash(row))
            );
        }
    }
    for root in [Some(owner), Some(host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::Everywhere
        );
    }
}

/// 7c, a poisoned anchor-only chain's edits are invalid everywhere (Fable design pass
/// 29: an anchor's chain names no carrier key): A has no roster profile, so `held` and
/// `widened` are invalid pinned or not, M stays not mine under the pin, and W reads
/// the default `Everywhere`.
#[test]
fn a_poisoned_trusted_chain_never_acknowledges_a_widening() {
    let vault = two_roots(185);
    let (owner, host) = (&vault.owner.0, &vault.host.0);
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
    for row in [&held, &widened] {
        for root in [Some(owner), Some(host), None] {
            assert!(
                !fold_under(&entries, Hosted, root)
                    .valid_entries
                    .contains(&hash(row))
            );
        }
    }
    for root in [Some(owner), Some(host), None] {
        assert_eq!(
            read_under(&entries, Hosted, root, world),
            EffectiveRead::Everywhere
        );
    }
}

/// 7c, the transition window (mesh PR1a, FIX-LIST 10-19 02:16; Fable design pass 29):
/// R1 and R2 anchor A and B as before with roster bootstraps for both, so the move to
/// `OneMachine(B)` stays valid everywhere and narrow on all installs, orphaned on R2,
/// and A's re-pick lands.
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
    let roster_a = signed(
        id,
        &[&genesis],
        &cloud,
        1,
        profile(&a, MachineRole::HostedNode, 1),
    );
    let roster_b = signed(
        id,
        &[&roster_a],
        &cloud,
        2,
        profile(&b, MachineRole::HostedNode, 1),
    );
    let heads: Vec<&AuthorityLogEntry> = [&roster_a, &roster_b]
        .into_iter()
        .chain(marks.iter())
        .collect();
    let world = EntityId::now();
    let moved = edit(
        id,
        &heads,
        (a.machine, &a_key),
        1,
        world,
        ReadLocation::OneMachine(b.machine),
    );
    let mut entries = vec![
        genesis,
        first_published,
        second_published,
        roster_a.clone(),
        roster_b.clone(),
    ];
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
