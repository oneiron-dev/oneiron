//! A removed machine's install key never chooses a world's key (Astra
//! #1422c F2, F3; the Engine's Q1 and Q2). A row backdated below what this
//! install saw of the machine in the world is refused, a row above it lands
//! as honest late arrival does, and either way a key is current only while
//! a machine not removed here signed one of its counted records. No honest
//! row, and no re-wrap door, lends such a key that standing (Astra #1422d
//! F2), and no such row conflicts a key a standing machine signed or hides
//! its envelopes (F3). A machine's own record of a key stands for the bytes
//! it signed, never for other bytes under the same id (Astra #1422e F2), and
//! so does a standing record another machine signed (Astra #1422f F1).
use super::machine_identity::host;
use super::world_chain_reads::hash;
use super::world_key_arrival::{Graph, graph, over};
use super::world_key_doors::{Fresh, fresh_install, own_request};
use super::world_privacy::{settings, world_row};
use super::world_reissue::{admit, issue, pinned, set_on, sync};
use super::*;
use crate::world_keys::{Withheld, WorldKey, WorldKeyBinding, WorldKeyStatus, seal_world_key};

const HERE: EditOrigin = EditOrigin::ThisMachine;
const AT: TimeRange = TimeRange { start: 3, end: 3 };

/// The graph, and machine C, which R anchors last. B wraps K to C: a record
/// of K from a machine that is never removed. Every install learns of it.
fn graph_with_c() -> (Graph, Fresh) {
    let graph = graph();
    let c = fresh_install(&graph.host);
    admit(&graph.issuer, &graph.root, &c);
    sync(&graph.issuer.vault, &graph.b.vault);
    let status = graph
        .b
        .vault
        .ensure_world_key(&graph.b.owner, graph.world)
        .unwrap();
    assert!(matches!(status, WorldKeyStatus::Wrapped { key, .. } if key == graph.key));
    for to in [&graph.issuer, &graph.a] {
        sync(&graph.b.vault, &to.vault);
    }
    (graph, c)
}

/// Astra #1422c F2. A edits its settings twice more (E4, E5; no key
/// record), and R's anchor removes A. Someone holding A's install key, and
/// nothing else of the owner's, backdates J on K3: a record of a fresh key
/// whose mint sorts above K's, wrapped to R alone. B saw E4 and E5: it
/// refuses J past A's floor and still opens K. An install that never saw
/// them admits J, which lands above the floor as an honest late row would,
/// but K stays current there: B's record of K stands behind K, and only A's
/// stands behind J. Fails before: J's own key scope floored it only at K3,
/// so it landed on B too, and its greater mint made it current everywhere.
#[test]
fn a_removed_machines_backdated_key_never_becomes_current() {
    let (graph, _c) = graph_with_c();
    let world = graph.world;
    graph
        .a
        .vault
        .set_world_privacy_as(
            &graph.a.owner,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                sealed: SealedCopies::MyMachines,
                ..settings(ReadLocation::MyMachines)
            },
            None,
        )
        .unwrap();
    set_on(&graph.a, world, ReadLocation::MyMachines);
    for to in [&graph.issuer, &graph.b] {
        sync(&graph.a.vault, &to.vault);
    }
    let rows = graph.rows_by(&graph.issuer.vault, graph.a.machine());
    let kinds: Vec<_> = rows
        .iter()
        .map(|entry| matches!(entry.op, AuthorityOp::WorldKeyWraps(_)))
        .collect();
    assert_eq!(kinds, [false, true, true, false, false]);
    let removal = graph.removal(&graph.issuer.vault);
    let k3 = &rows[2];
    let (backdated, forged) = graph.backdated_key(k3, k3.seq + 1, over(k3));

    for row in [&removal, &backdated] {
        graph.b.vault.put_authority_log_entry(row, AT, 3).unwrap();
    }
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&backdated)));
    assert_eq!(graph.b.vault.world_key(world).unwrap().id(), &graph.key);

    let by_b = &graph.rows_by(&graph.issuer.vault, graph.b.machine())[0];
    let install = graph.receiver(&[&rows[0], &rows[1], &rows[2], by_b, &removal]);
    install
        .vault
        .pin_owner_root(&install.owner, HERE, graph.root.root)
        .unwrap();
    install
        .vault
        .put_authority_log_entry(&backdated, AT, 3)
        .unwrap();
    let fold = install.vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&backdated)));
    assert!(fold.world_key(&forged).is_some());
    assert_eq!(
        fold.current_world_key(world).map(|key| key.id),
        Some(graph.key)
    );
}

/// The Engine's Q1 on Astra #1422c: a removed machine's own backdated row
/// never launders its key through an honest one. B never saw A's later
/// edits. The holder of A's install key lands J there, then a settings edit
/// naming J, which stays live (raced, it only narrows). B's own honest edit
/// names the world's live edits, so it descends from J; K stays current on
/// B. Fails before: J was current on its greater mint as soon as it landed.
#[test]
fn a_removed_machines_key_never_becomes_current_through_an_honest_edit() {
    let (graph, _c) = graph_with_c();
    let world = graph.world;
    let removal = graph.removal(&graph.issuer.vault);
    let rows = graph.rows_by(&graph.issuer.vault, graph.a.machine());
    let (e1, k3) = (&rows[0], &rows[2]);
    let (backdated, forged) = graph.backdated_key(k3, k3.seq + 1, over(k3));
    let AuthorityOp::WorldPrivacy(edit) = &e1.op else {
        panic!("A's first row is its settings edit");
    };
    let laundering = graph.signed_as_a(
        e1,
        backdated.seq + 1,
        vec![hash(&backdated), hash(e1)],
        AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
            settings: WorldPrivacy {
                sealed: SealedCopies::MyMachines,
                ..settings(ReadLocation::MyMachines)
            },
            ..edit.clone()
        }),
    );
    for row in [&removal, &backdated, &laundering] {
        graph.b.vault.put_authority_log_entry(row, AT, 3).unwrap();
    }
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&backdated)));
    assert!(fold.worlds[&world].live.contains_key(&hash(&laundering)));

    set_on(&graph.b, world, ReadLocation::MyMachines);
    let honest = graph
        .rows_by(&graph.b.vault, graph.b.machine())
        .into_iter()
        .find(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
        .unwrap();
    assert!(honest.parent_hashes.contains(&hash(&laundering)));
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&honest)));
    assert!(fold.world_key(&forged).is_some());
    assert_eq!(
        fold.current_world_key(world).map(|key| key.id),
        Some(graph.key)
    );
    assert_eq!(graph.b.vault.world_key(world).unwrap().id(), &graph.key);
}

/// The Engine's Q2 on Astra #1422c, and F2 where only A's records stand
/// behind K. A fresh install holds E1, K2, K3, A's removal and J. A kit
/// restore opens both keys from R's wraps and lists both as usable, but
/// writes no record of either, and neither is current. The next ensure
/// here, now a machine of the owner's, mints a fresh key. Fails on
/// 72904d001, where the restore listed neither key: the floors the main
/// log's batch left beside A's removal started the fold with no vouch, which
/// held A's chain (F1). With the re-wrap guard alone removed, the restore
/// writes this install's record of J; with the current-key rule alone
/// removed, J is current.
#[test]
fn a_kit_restore_wraps_no_key_only_a_removed_machine_signed() {
    let graph = graph();
    let rows = graph.rows_by(&graph.issuer.vault, graph.a.machine());
    let k3 = &rows[2];
    let removal = graph.removal(&graph.issuer.vault);
    let (backdated, forged) = graph.backdated_key(k3, k3.seq + 1, over(k3));
    let install = graph.receiver(&[&rows[0], &rows[1], k3, &removal, &backdated]);
    let restore = install
        .vault
        .restore_world_keys(&install.owner, HERE, &graph.root.seed, None)
        .unwrap();
    let usable: BTreeSet<_> = restore.usable.iter().copied().collect();
    assert_eq!(usable, BTreeSet::from([graph.key, forged]));
    assert!(graph.rows_by(&install.vault, install.machine()).is_empty());
    let fold = install.vault.authority_fold().unwrap();
    assert!(fold.current_world_key(graph.world).is_none());

    let status = install
        .vault
        .ensure_world_key(&install.owner, graph.world)
        .unwrap();
    let WorldKeyStatus::Minted(fresh) = status else {
        panic!("a world no standing key covers mints afresh: {status:?}");
    };
    assert!(fresh != graph.key && fresh != forged);
}

/// Astra #1422c F3. R anchors C too, and A wraps K to C (K4), so A's floor
/// of the world is K4's sequence. Someone holding A's install key backdates
/// J3, a record of a fresh key on K2 at K3's sequence, which B refuses past
/// that floor; then E4, a settings edit naming J3 at K4's sequence. E4
/// shares J3's scope, so it vouches for nothing at or below the floor, and K
/// stays current. Fails before: E4's settings scope held A's floor at E1, so
/// E4 cleared J3's key floor and J3's greater mint became current.
#[test]
fn a_settings_edit_never_clears_a_key_records_floor() {
    let graph = graph();
    let c = fresh_install(&graph.host);
    admit(&graph.issuer, &graph.root, &c);
    sync(&graph.issuer.vault, &graph.a.vault);
    graph
        .a
        .vault
        .ensure_world_key(&graph.a.owner, graph.world)
        .unwrap();
    sync(&graph.a.vault, &graph.b.vault);
    let rows = graph.rows_by(&graph.b.vault, graph.a.machine());
    assert_eq!(rows.len(), 4);
    let (e1, k2, k3, k4) = (&rows[0], &rows[1], &rows[2], &rows[3]);
    let (backdated, _) = graph.backdated_key(k2, k3.seq, over(k2));
    let AuthorityOp::WorldPrivacy(edit) = &e1.op else {
        panic!("A's first row is its settings edit");
    };
    let clearing = graph.signed_as_a(
        e1,
        k4.seq,
        vec![hash(&backdated), hash(e1)],
        AuthorityOp::WorldPrivacy(edit.clone()),
    );
    for row in [&backdated, &clearing] {
        graph.b.vault.put_authority_log_entry(row, AT, 3).unwrap();
    }
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&backdated)));
    assert_eq!(
        fold.current_world_key(graph.world).map(|key| key.id),
        Some(graph.key)
    );
}

/// Astra #1422d F2. The roster admits A and B, and B pins no root. A makes
/// the world `MyMachines` and mints K for A and B. The owner publishes R; R
/// anchors A, A pins it, and R's anchor removes A. B stores it all. Someone
/// holding A's install key mints J above K on K's record, wrapped to B
/// alone. On B, still on the roster, A stands and J is current. B pins R,
/// under which A is removed: B writes no record of J or of K, reports both
/// withheld, and neither is current. A signer the new pin leaves out keeps
/// its pre-wraps (world_reissue's
/// `a_left_out_recipient_anchors_itself_back_from_records_another_signed`).
/// Fails before: J stood under the old pin, so the door wrapped it to R from
/// B, and B's record made J current under R.
#[test]
fn a_re_pin_never_wraps_a_key_whose_signers_the_new_pin_removed() {
    let host = host();
    let world = world_row(&host);
    let [issuer, a, b] = [(); 3].map(|()| fresh_install(&host));
    for install in [&a, &b] {
        host.vault
            .enroll_machine(
                &host.issuer,
                &host.owner,
                &own_request(&install.vault),
                MachineRole::Owned(MachineOwnership::Yours),
            )
            .unwrap();
    }
    for to in [&issuer, &a, &b] {
        sync(&host.vault, &to.vault);
    }
    set_on(&a, world, ReadLocation::MyMachines);
    sync(&a.vault, &issuer.vault);
    let root = issue(&issuer, &[]);
    admit(&issuer, &root, &a);
    sync(&a.vault, &issuer.vault);
    let key = a
        .vault
        .authority_fold()
        .unwrap()
        .current_world_key(world)
        .unwrap()
        .id;
    let graph = Graph {
        host,
        world,
        issuer,
        root,
        a,
        b,
        key,
    };
    let removal = graph.removal(&graph.issuer.vault);
    graph
        .issuer
        .vault
        .put_authority_log_entry(&removal, AT, 3)
        .unwrap();
    sync(&graph.issuer.vault, &graph.b.vault);
    let rows = graph.rows_by(&graph.b.vault, graph.a.machine());
    let minted = rows
        .iter()
        .find(|entry| matches!(entry.op, AuthorityOp::WorldKeyWraps(_)))
        .unwrap();
    let after = rows.last().unwrap().seq + 1;
    let b = graph.b.machine();
    let public = oneiron_crypto::HybridPublicKey::from_bytes(
        &graph
            .b
            .vault
            .machine_encryption_key(graph.host.vault_id)
            .unwrap()
            .key,
    )
    .unwrap();
    let (forged, j) = graph.forged_key(
        minted,
        after,
        over(minted),
        WrapRecipient::Machine(b),
        &public,
    );
    graph
        .b
        .vault
        .put_authority_log_entry(&forged, AT, 3)
        .unwrap();
    let fold = graph.b.vault.authority_fold().unwrap();
    assert_eq!(fold.current_world_key(world).map(|key| key.id), Some(j));

    let report = graph
        .b
        .vault
        .pin_owner_root(&graph.b.owner, HERE, graph.root.root)
        .unwrap();
    assert_eq!(report.withheld.len(), 2, "{:?}", report.withheld);
    for id in [key, j] {
        assert!(report.withheld.contains(&(id, Withheld::SignerRemoved)));
    }
    assert!(graph.rows_by(&graph.b.vault, b).is_empty());
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(fold.world_key(&j).is_some());
    assert!(fold.current_world_key(world).is_none());
}

/// Astra #1422d F3. B wraps K to C, so a machine R never removes signed K.
/// R's anchor removes A, and someone holding A's install key copies K2 with
/// another commitment, R's envelope kept, on K2 above A's floor. A fresh
/// install that holds it all restores R from the kit: the copy counts, but
/// K is not conflicted, stays current through B, and the kit opens it.
/// Fails before: the copy conflicted K, and the restore withheld it.
#[test]
fn a_removed_machines_copy_of_a_key_never_conflicts_it() {
    let (graph, _c) = graph_with_c();
    let rows = graph.rows_by(&graph.issuer.vault, graph.a.machine());
    let (k2, k3) = (&rows[1], &rows[2]);
    let removal = graph.removal(&graph.issuer.vault);
    let AuthorityOp::WorldKeyWraps(record) = &k2.op else {
        panic!("A's second row is K's record");
    };
    let copy = graph.signed_as_a(
        k2,
        k3.seq + 1,
        vec![hash(k2)],
        AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
            commitment: [0x5c; 32],
            ..record.clone()
        }),
    );
    let by_b = &graph.rows_by(&graph.issuer.vault, graph.b.machine())[0];
    let install = graph.receiver(&[&rows[0], k2, k3, by_b, &removal, &copy]);
    let restore = install
        .vault
        .restore_world_keys(&install.owner, HERE, &graph.root.seed, None)
        .unwrap();
    assert!(restore.usable.contains(&graph.key));
    let fold = install.vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&copy)));
    assert!(!fold.refused_world_keys.contains(&hash(&copy)));
    assert!(!fold.world_key(&graph.key).unwrap().conflicted);
    assert_eq!(
        fold.current_world_key(graph.world).map(|key| key.id),
        Some(graph.key)
    );
}

/// The Engine on Astra #1422d F3: a removed machine's records never push a
/// genuine envelope out. R's anchor removes A, and someone holding A's
/// install key signs four copies of K2 on K2's parents above A's floor, each
/// with R's envelope broken and a hash below K2's. A fresh install that
/// holds them restores R from the kit: R's slots still hold K2's envelope,
/// and the kit opens K. Fails before: the copies tied K2 on ancestry and
/// took R's four slots by hash, so the kit lost K.
#[test]
fn a_removed_machines_flood_of_envelopes_never_hides_a_genuine_one() {
    let graph = graph();
    let rows = graph.rows_by(&graph.issuer.vault, graph.a.machine());
    let (k2, k3) = (&rows[1], &rows[2]);
    let removal = graph.removal(&graph.issuer.vault);
    let AuthorityOp::WorldKeyWraps(record) = &k2.op else {
        panic!("A's second row is K's record");
    };
    let to_root = WrapRecipient::RecoveryRoot(graph.root.root);
    let flood: Vec<_> = (1..=u8::MAX)
        .filter_map(|flip| {
            let wraps = record
                .wraps
                .iter()
                .map(|(to, envelope)| {
                    let mut envelope = envelope.clone();
                    if *to == to_root {
                        let last = envelope.len() - 1;
                        envelope[last] ^= flip;
                    }
                    (*to, envelope)
                })
                .collect();
            let copy = graph.signed_as_a(
                k2,
                k3.seq + 1,
                k2.parent_hashes.clone(),
                AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
                    wraps,
                    ..record.clone()
                }),
            );
            (hash(&copy) < hash(k2)).then_some(copy)
        })
        .take(4)
        .collect();
    assert_eq!(flood.len(), 4);
    let mut arrival = vec![&rows[0], k2, k3, &removal];
    arrival.extend(&flood);
    let install = graph.receiver(&arrival);
    let restore = install
        .vault
        .restore_world_keys(&install.owner, HERE, &graph.root.seed, None)
        .unwrap();
    assert!(restore.usable.contains(&graph.key));
    let fold = install.vault.authority_fold().unwrap();
    for copy in &flood {
        assert!(fold.valid_entries.contains(&hash(copy)));
        assert!(!fold.refused_world_keys.contains(&hash(copy)));
    }
    assert!(
        fold.world_key(&graph.key).unwrap().wraps[&to_root]
            .iter()
            .any(|wrap| wrap.entry == hash(k2))
    );
}

/// Astra #1422e F2. R0 anchors B, which makes the world `MyMachines` and
/// mints K under id I. From an install that never saw K, R1 anchors A and
/// leaves B out, and B re-pins to R1, where its records of K do not count.
/// R1's anchor removes A, and someone holding A's install key records other
/// bytes J under I on A's admission and B's edit, wrapped to R1: under R1
/// it is I's one counted pair, and no machine that stands signed it. B
/// restores R1's kit, which opens J: B writes no record of J, J is not
/// current, and K stays current under R0. Fails before: B's own record of
/// I stood for any bytes under I, so B wrapped J, which became current
/// under R1 and conflicted K under R0.
#[test]
fn an_own_record_of_a_key_id_vouches_for_no_other_bytes() {
    let host = host();
    let world = world_row(&host);
    let [first, second, a, b] = [(); 4].map(|()| fresh_install(&host));
    let r0 = issue(&first, &[]);
    admit(&first, &r0, &b);
    set_on(&b, world, ReadLocation::MyMachines);
    let (id, genuine) = {
        let fold = b.vault.authority_fold().unwrap();
        let key = fold.current_world_key(world).unwrap();
        (key.id, key.commitment)
    };
    let root = issue(&second, &[]);
    admit(&second, &root, &a);
    sync(&second.vault, &b.vault);
    b.vault.pin_owner_root(&b.owner, HERE, root.root).unwrap();
    let graph = Graph {
        host,
        world,
        issuer: second,
        root,
        a,
        b,
        key: id,
    };
    let anchor = graph.root.seed.anchor().verifying_key().to_bytes();
    let admission = graph
        .b
        .vault
        .authority_fold()
        .unwrap()
        .machine(graph.a.machine())
        .unwrap()
        .anchored[&anchor]
        .entry;
    let removal = graph.removal(&graph.b.vault);
    graph
        .b
        .vault
        .put_authority_log_entry(&removal, AT, 3)
        .unwrap();
    let by_b = graph.rows_by(&graph.b.vault, graph.b.machine());
    let edit = by_b
        .iter()
        .find(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
        .unwrap();
    let minted = by_b
        .iter()
        .find(|entry| matches!(&entry.op, AuthorityOp::WorldKeyWraps(record) if record.key == id))
        .unwrap();
    let AuthorityOp::WorldKeyWraps(record) = &minted.op else {
        panic!("B's record of K");
    };
    assert_eq!(record.commitment, genuine);

    let j = WorldKey::other_bytes_for_test(id).unwrap();
    let to_root = WrapRecipient::RecoveryRoot(graph.root.root);
    let binding = WorldKeyBinding {
        vault_id: minted.vault_id.unwrap(),
        key: id,
        owner: record.owner,
        policy: record.policy,
        commitment: j.commitment(),
    };
    let envelope = seal_world_key(&binding, to_root, graph.root.recovery.public_key(), &j).unwrap();
    let forged = graph.signed_as_a(
        minted,
        1,
        vec![admission, hash(edit)],
        AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
            commitment: j.commitment(),
            machine: graph.a.machine(),
            wraps: vec![(to_root, envelope.to_bytes())],
            ..record.clone()
        }),
    );
    graph
        .b
        .vault
        .put_authority_log_entry(&forged, AT, 3)
        .unwrap();
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&forged)));
    let counted = fold.world_key(&id).unwrap();
    assert_eq!(counted.commitment, j.commitment());
    assert!(!counted.conflicted && !fold.world_key_stands(counted));

    graph
        .b
        .vault
        .restore_world_keys(&graph.b.owner, HERE, &graph.root.seed, None)
        .unwrap();
    let by_b = graph.rows_by(&graph.b.vault, graph.b.machine());
    assert!(by_b.iter().all(|entry| !matches!(&entry.op,
        AuthorityOp::WorldKeyWraps(record) if record.commitment == j.commitment())));
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(
        fold.current_world_key(world)
            .is_none_or(|key| key.commitment != j.commitment())
    );
    sync(&graph.b.vault, &first.vault);
    assert_eq!(pinned(&first.vault), Some(r0.root));
    let fold = first.vault.authority_fold().unwrap();
    assert_eq!(
        fold.current_world_key(world).map(|key| key.commitment),
        Some(genuine)
    );
}

/// Astra #1422f F1. R0 anchors B, which makes the world `MyMachines` and
/// mints K under id I; R0's anchor then marks B work or school, so B is not
/// mine under R0 and K still stands there. From an install that never saw
/// K, R1 anchors A and B. Someone holding A's install key records other
/// bytes J under I on A's and B's admissions and B's edit, wrapped to B,
/// and R1's anchor removes A: under R1, J is I's one counted pair, and no
/// machine that stands signed it. B pins R1, which withholds I as
/// conflicted, then pins R0 again: B is mine under R1 and not under R0, so
/// the door pre-wraps what it opened under R1. B writes no record of J, I
/// is withheld as conflicted, and J is not current on an install pinned to
/// R1. A pre-wrap of the standing pair's own bytes still happens
/// (world_reissue's `a_recipients_key_survives_an_explicit_re_assertion`).
/// Fails before: K's standing record under R0 stood for any bytes under I,
/// so B's pre-wrap signed J, which became current under R1.
#[test]
fn a_pre_wrap_signs_no_bytes_but_those_of_the_pair_that_stands() {
    let host = host();
    let world = world_row(&host);
    let [first, second, a, b] = [(); 4].map(|()| fresh_install(&host));
    let r0 = issue(&first, &[]);
    admit(&first, &r0, &b);
    set_on(&b, world, ReadLocation::MyMachines);
    let (id, genuine) = {
        let fold = b.vault.authority_fold().unwrap();
        let key = fold.current_world_key(world).unwrap();
        (key.id, key.commitment)
    };
    let home = r0.seed.anchor();
    let demotion = {
        let fold = b.vault.authority_fold().unwrap();
        let current = fold.machine(b.machine()).unwrap().anchored[&home.verifying_key().to_bytes()]
            .profile
            .clone();
        let profile = MachineProfile {
            role: MachineRole::Owned(MachineOwnership::WorkSchool),
            revision: current.revision + 1,
            ..current
        };
        anchor_signed_entry(&fold, &home, AuthorityOp::MachineProfile(profile), 2).unwrap()
    };
    b.vault.put_authority_log_entry(&demotion, AT, 3).unwrap();
    let fold = b.vault.authority_fold().unwrap();
    assert!(fold.trusted_machine(b.machine()).is_none());
    assert!(
        fold.world_key(&id)
            .is_some_and(|key| fold.world_key_stands(key))
    );

    let r1 = issue(&second, &[]);
    admit(&second, &r1, &a);
    let request = own_request(&b.vault);
    second
        .vault
        .anchor_machine(
            &second.owner,
            HERE,
            &r1.seed,
            &request,
            Some(request.code()),
            None,
        )
        .unwrap();
    sync(&second.vault, &b.vault);
    let graph = Graph {
        host,
        world,
        issuer: second,
        root: r1,
        a,
        b,
        key: id,
    };
    let anchor = graph.root.seed.anchor().verifying_key().to_bytes();
    let fold = graph.b.vault.authority_fold().unwrap();
    let admissions = [graph.a.machine(), graph.b.machine()]
        .map(|machine| fold.machine(machine).unwrap().anchored[&anchor].entry);
    let removal = graph.removal(&graph.b.vault);
    graph
        .b
        .vault
        .put_authority_log_entry(&removal, AT, 3)
        .unwrap();
    let by_b = graph.rows_by(&graph.b.vault, graph.b.machine());
    let edit = by_b
        .iter()
        .find(|entry| matches!(entry.op, AuthorityOp::WorldPrivacy(_)))
        .unwrap();
    let minted = by_b
        .iter()
        .find(|entry| matches!(&entry.op, AuthorityOp::WorldKeyWraps(record) if record.key == id))
        .unwrap();
    let AuthorityOp::WorldKeyWraps(record) = &minted.op else {
        panic!("B's record of K");
    };
    assert_eq!(record.commitment, genuine);
    let j = WorldKey::other_bytes_for_test(id).unwrap();
    let to_b = WrapRecipient::Machine(graph.b.machine());
    let public = oneiron_crypto::HybridPublicKey::from_bytes(
        &graph
            .b
            .vault
            .machine_encryption_key(graph.host.vault_id)
            .unwrap()
            .key,
    )
    .unwrap();
    let binding = WorldKeyBinding {
        vault_id: minted.vault_id.unwrap(),
        key: id,
        owner: record.owner,
        policy: record.policy,
        commitment: j.commitment(),
    };
    let envelope = seal_world_key(&binding, to_b, &public, &j).unwrap();
    let forged = graph.signed_as_a(
        minted,
        1,
        vec![admissions[0], admissions[1], hash(edit)],
        AuthorityOp::WorldKeyWraps(WorldKeyWrapsRecord {
            commitment: j.commitment(),
            machine: graph.a.machine(),
            wraps: vec![(to_b, envelope.to_bytes())],
            ..record.clone()
        }),
    );
    graph
        .b
        .vault
        .put_authority_log_entry(&forged, AT, 3)
        .unwrap();

    let report = graph
        .b
        .vault
        .pin_owner_root(&graph.b.owner, HERE, graph.root.root)
        .unwrap();
    assert!(
        report.withheld.contains(&(id, Withheld::Conflicted)),
        "{:?}",
        report.withheld
    );
    let fold = graph.b.vault.authority_fold().unwrap();
    assert!(fold.trusted_machine(graph.b.machine()).is_some());
    let counted = fold.world_key(&id).unwrap();
    assert_eq!(counted.commitment, j.commitment());
    assert!(!counted.conflicted && !fold.world_key_stands(counted));

    let report = graph
        .b
        .vault
        .pin_owner_root(&graph.b.owner, HERE, r0.root)
        .unwrap();
    assert!(
        report.withheld.contains(&(id, Withheld::Conflicted)),
        "{:?}",
        report.withheld
    );
    let by_b = graph.rows_by(&graph.b.vault, graph.b.machine());
    assert!(by_b.iter().all(|entry| !matches!(&entry.op,
        AuthorityOp::WorldKeyWraps(record) if record.commitment == j.commitment())));
    sync(&graph.b.vault, &graph.issuer.vault);
    assert_eq!(pinned(&graph.issuer.vault), Some(graph.root.root));
    let fold = graph.issuer.vault.authority_fold().unwrap();
    assert!(
        fold.current_world_key(world)
            .is_none_or(|key| key.commitment != j.commitment())
    );
}
