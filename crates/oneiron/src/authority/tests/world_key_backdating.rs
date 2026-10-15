//! A removed machine's install key never chooses a world's key (Astra
//! #1422c F2, F3; the Engine's Q1 and Q2). A row backdated below what this
//! install saw of the machine in the world is refused, a row above it lands
//! as honest late arrival does, and either way a key is current only while
//! a machine not removed here signed one of its counted records. No honest
//! row, and no re-wrap door, lends such a key that standing.
use super::world_chain_reads::hash;
use super::world_key_arrival::{Graph, graph, over};
use super::world_key_doors::{Fresh, fresh_install};
use super::world_privacy::settings;
use super::world_reissue::{admit, set_on, sync};
use super::*;
use crate::world_keys::WorldKeyStatus;

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
            HERE,
            world,
            WorldPrivacy {
                sealed: SealedCopies::MyMachines,
                ..settings(ReadLocation::MyMachines)
            },
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
