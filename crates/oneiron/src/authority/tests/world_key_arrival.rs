//! Honest rows of one machine arrive in any order (Astra #1422b F1, #1422c
//! F1). A machine's settings edits and key records of a world share one
//! sequence scope, and each names the machine's previous row there. So a
//! receiver that stores a later row first still admits every earlier one,
//! and the kit still reaches the world's only key, even once the machine is
//! removed.
use super::machine_identity::{Host, host};
use super::support::{authority_key_from_ed, sign_ed, unsigned_entry};
use super::world_chain_reads::hash;
use super::world_key_doors::{Fresh, enrol_own, fresh_install, keyed_machine, kit_seed, set};
use super::world_privacy::{settings, stored_entries, world_row};
use super::world_reissue::{Issued, admit, issue, set_on, sync};
use super::*;
use crate::world_keys::{RecoveryRootSeed, WorldKey, WorldKeyBinding, seal_world_key};
use crate::{Vault, VaultConfig};

const HERE: EditOrigin = EditOrigin::ThisMachine;
const AT: TimeRange = TimeRange { start: 3, end: 3 };

/// A host with this install's machine and an owner root, the root's kit
/// seed, and a world with a live WORLD row and no settings edit yet.
fn rooted() -> (Host, RecoveryRootSeed, EntityId) {
    let host = host();
    enrol_own(&host);
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let seed = kit_seed(host.vault_id, prepared.seed());
    host.vault
        .activate_owner_root(&host.owner, HERE, prepared, &BTreeSet::new())
        .unwrap();
    let world = world_row(&host);
    (host, seed, world)
}

/// An ordinary settings edit that keeps the world on the owner's machines.
fn keep_mine(host: &Host, world: EntityId) {
    let edit = WorldPrivacy {
        sealed: SealedCopies::MyMachines,
        ..settings(ReadLocation::MyMachines)
    };
    host.vault
        .set_world_privacy_as(&host.owner, ActSurface::ThisInstall, world, edit, None)
        .unwrap();
}

fn in_world(entry: &AuthorityLogEntry, world: EntityId) -> bool {
    match &entry.op {
        AuthorityOp::WorldPrivacy(edit) => edit.world == world,
        AuthorityOp::WorldKeyWraps(record) => record.key.world == world,
        _ => false,
    }
}

/// The world's settings edits and key records, in the order they were signed,
/// each marked true for a key record.
fn world_rows(vault: &Vault, world: EntityId) -> Vec<(AuthorityLogEntry, bool)> {
    let mut rows: Vec<_> = stored_entries(vault)
        .into_iter()
        .filter(|entry| in_world(entry, world))
        .map(|entry| {
            let record = matches!(entry.op, AuthorityOp::WorldKeyWraps(_));
            (entry, record)
        })
        .collect();
    rows.sort_by_key(|(entry, _)| entry.seq);
    rows
}

/// Astra #1422b F1, the named sequence. Machine A makes the world
/// `MyMachines` (E1; the door mints K and wraps it to A and the root in K2),
/// then edits its settings again (E3). A receiver stores E1, then E3, then
/// K2. A is lost; a fresh install restores the root from the kit, recovers K
/// and opens the world with it. E3 names K2, A's previous row of the world,
/// so it vouches for K2 under the floor it leaves. Fails before 23458ca29:
/// no edit named K2, so the receiver refused it as a rollback and the kit
/// never saw K.
#[test]
fn a_key_record_that_arrives_after_a_later_edit_still_restores_from_the_kit() {
    let (host, seed, world) = rooted();
    let Fresh {
        _backups,
        vault: fresh,
        owner,
        ..
    } = fresh_install(&host);
    set(&host, world, ReadLocation::MyMachines);
    keep_mine(&host, world);
    let key = host
        .vault
        .authority_fold()
        .unwrap()
        .current_world_key(world)
        .unwrap()
        .id;
    let rows = world_rows(&host.vault, world);
    let kinds: Vec<_> = rows.iter().map(|(_, record)| *record).collect();
    assert_eq!(kinds, [false, true, false]);
    drop(host);

    for (row, _) in [&rows[0], &rows[2], &rows[1]] {
        fresh.put_authority_log_entry(row, AT, 3).unwrap();
    }
    let restore = fresh.restore_world_keys(&owner, HERE, &seed, None).unwrap();
    assert_eq!(restore.usable, vec![key]);
    assert_eq!(fresh.world_key(world).unwrap().id(), &key);
}

/// The Engine's table over the rows one machine signs in one world: its
/// settings edits and its key records. A signs E1 (the door mints K, in
/// record K2), then E3, then, once machine B joins, K3 (K's wrap to B). For
/// every ordered pair, a receiver that stores the later row first, then the
/// earlier one, then the rest in order, admits all four: each row names the
/// one before it. Fails without the chain: one scope floors K2 under E3
/// (Astra #1422c), and K2 was refused whenever E3 or K3 arrived first.
#[test]
fn every_arrival_order_of_one_machines_world_rows_keeps_each_row() {
    let (host, _, world) = rooted();
    let history = host.vault.export_signed_authority_history().unwrap();
    let known: BTreeSet<_> = stored_entries(&host.vault).iter().map(hash).collect();
    set(&host, world, ReadLocation::MyMachines);
    keep_mine(&host, world);
    keyed_machine(&host, 171);
    host.vault.ensure_world_key(&host.owner, world).unwrap();
    let rows = world_rows(&host.vault, world);
    let kinds: Vec<_> = rows.iter().map(|(_, record)| *record).collect();
    assert_eq!(kinds, [false, true, false, true]);
    // B's mark and the other main-log rows since the export.
    let main: Vec<_> = stored_entries(&host.vault)
        .into_iter()
        .filter(|entry| !in_world(entry, world) && !known.contains(&hash(entry)))
        .map(|entry| (entry, AT, 3))
        .collect();

    for later in 1..rows.len() {
        for earlier in 0..later {
            let dir = tempfile::tempdir().unwrap();
            let receiver = Vault::open(dir.path(), VaultConfig::default()).unwrap();
            receiver.import_signed_authority_history(&history).unwrap();
            receiver.put_authority_log_entries(&main).unwrap();
            let rest = (0..rows.len()).filter(|at| *at != earlier && *at != later);
            for at in [later, earlier].into_iter().chain(rest) {
                receiver
                    .put_authority_log_entry(&rows[at].0, AT, 3)
                    .unwrap();
            }
            let fold = receiver.authority_fold().unwrap();
            for (at, (row, _)) in rows.iter().enumerate() {
                assert!(
                    fold.valid_entries.contains(&hash(row)),
                    "row {at} lost when row {later} arrived before row {earlier}"
                );
            }
        }
    }
}

/// Astra-c's vault: every install is a new install of one vault. The
/// owner's root R anchors machine A, A's only admission. A makes the world
/// `MyMachines` (E1; the door mints K for A and R in K2). R then anchors B,
/// and A wraps K to B (K3). The issuer holds every row.
pub(super) struct Graph {
    pub(super) host: Host,
    pub(super) world: EntityId,
    pub(super) issuer: Fresh,
    pub(super) root: Issued,
    pub(super) a: Fresh,
    pub(super) b: Fresh,
    pub(super) key: WorldKeyId,
}

pub(super) fn graph() -> Graph {
    let host = host();
    let world = world_row(&host);
    let issuer = fresh_install(&host);
    let a = fresh_install(&host);
    let b = fresh_install(&host);
    let root = issue(&issuer, &[]);
    admit(&issuer, &root, &a);
    set_on(&a, world, ReadLocation::MyMachines);
    admit(&issuer, &root, &b);
    sync(&issuer.vault, &a.vault);
    a.vault.ensure_world_key(&a.owner, world).unwrap();
    for to in [&issuer, &b] {
        sync(&a.vault, &to.vault);
    }
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
    let kinds: Vec<_> = graph
        .rows_by(&graph.issuer.vault, graph.a.machine())
        .iter()
        .map(|entry| matches!(entry.op, AuthorityOp::WorldKeyWraps(_)))
        .collect();
    assert_eq!(kinds, [false, true, true]);
    graph
}

impl Graph {
    /// The world's rows `machine` signed that `vault` holds, in signing
    /// order.
    pub(super) fn rows_by(&self, vault: &Vault, machine: EntityId) -> Vec<AuthorityLogEntry> {
        let mut rows: Vec<_> = stored_entries(vault)
            .into_iter()
            .filter(|entry| match &entry.op {
                AuthorityOp::WorldPrivacy(edit) => {
                    edit.world == self.world && edit.machine == machine
                }
                AuthorityOp::WorldKeyWraps(record) => {
                    record.key.world == self.world && record.machine == machine
                }
                _ => false,
            })
            .collect();
        rows.sort_by_key(|entry| entry.seq);
        rows
    }

    /// A fresh install that holds the issuer's main log, then stores `rows`
    /// one at a time, in order.
    pub(super) fn receiver(&self, rows: &[&AuthorityLogEntry]) -> Fresh {
        let install = fresh_install(&self.host);
        let main: Vec<_> = stored_entries(&self.issuer.vault)
            .into_iter()
            .filter(|entry| !in_world(entry, self.world))
            .map(|entry| (entry, AT, 3))
            .collect();
        install.vault.put_authority_log_entries(&main).unwrap();
        for row in rows {
            install.vault.put_authority_log_entry(row, AT, 3).unwrap();
        }
        install
    }

    /// R's anchor removes A, on `vault`'s heads.
    pub(super) fn removal(&self, vault: &Vault) -> AuthorityLogEntry {
        let anchor = self.root.seed.anchor();
        let fold = vault.authority_fold().unwrap();
        let current = fold.machine(self.a.machine()).unwrap().anchored
            [&anchor.verifying_key().to_bytes()]
            .profile
            .clone();
        let profile = MachineProfile {
            role: MachineRole::Removed,
            revision: current.revision + 1,
            ..current
        };
        anchor_signed_entry(&fold, &anchor, AuthorityOp::MachineProfile(profile), 2).unwrap()
    }

    /// What someone holding A's install key, and nothing else of the owner's,
    /// signs as A at `seq` on `parents`: a record of a fresh key whose mint
    /// sorts above K's, wrapped to R alone with R's public key, under the
    /// owner and settings revision of `like`, one of A's key records.
    pub(super) fn backdated_key(
        &self,
        like: &AuthorityLogEntry,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
    ) -> (AuthorityLogEntry, WorldKeyId) {
        let to_root = WrapRecipient::RecoveryRoot(self.root.root);
        self.forged_key(like, seq, parents, to_root, self.root.recovery.public_key())
    }

    /// [`Self::backdated_key`], wrapped to `to` alone with `public`.
    pub(super) fn forged_key(
        &self,
        like: &AuthorityLogEntry,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        to: WrapRecipient,
        public: &oneiron_crypto::HybridPublicKey,
    ) -> (AuthorityLogEntry, WorldKeyId) {
        let AuthorityOp::WorldKeyWraps(record) = &like.op else {
            panic!("a key record");
        };
        let key = loop {
            let key = WorldKey::mint(self.world, FIRST_GENERATION).unwrap();
            if key.id().mint > self.key.mint {
                break key;
            }
        };
        let binding = WorldKeyBinding {
            vault_id: like.vault_id.unwrap(),
            key: *key.id(),
            owner: record.owner,
            policy: record.policy,
            commitment: key.commitment(),
        };
        let envelope = seal_world_key(&binding, to, public, &key).unwrap();
        let record = WorldKeyWrapsRecord {
            key: *key.id(),
            commitment: key.commitment(),
            wraps: vec![(to, envelope.to_bytes())],
            ..record.clone()
        };
        (
            self.signed_as_a(like, seq, parents, AuthorityOp::WorldKeyWraps(record)),
            *key.id(),
        )
    }

    /// `op`, signed with A's install key at `seq` on `parents`, in `like`'s
    /// vault.
    pub(super) fn signed_as_a(
        &self,
        like: &AuthorityLogEntry,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
    ) -> AuthorityLogEntry {
        let signing = {
            let txn = self.a.vault.store.env.read_txn().unwrap();
            crate::identity::read_machine_signing_key_in_txn(&self.a.vault, &txn)
                .unwrap()
                .unwrap()
        };
        let signer = authority_key_from_ed(&signing);
        sign_ed(
            unsigned_entry(like.vault_id, seq, parents, op, signer, 2),
            &signing,
        )
    }
}

/// `entry`'s parents and `entry` itself.
pub(super) fn over(entry: &AuthorityLogEntry) -> Vec<AuthorityEntryHash> {
    let mut parents = entry.parent_hashes.clone();
    parents.push(hash(entry));
    parents
}

/// Astra #1422c F1. A fresh install with no copy of A's or B's identity
/// stores the main log and E1, then K3, then K2; R's anchor then removes A,
/// and the install restores R from the kit: K is usable. With a removed
/// machine's record past its floor beside them (a backdated J on K2's
/// parents), the same restore still reaches K. Fails before: the floor K3
/// left beside the removal started the fold with no vouch, though K3 vouches
/// for K2, and that fold, finding A's chain headed by the removal, held it in
/// every earlier state, so neither record counted and the kit lost K; with J
/// the fold with no vouch runs either way.
#[test]
fn a_kit_restore_after_a_reversed_arrival_and_a_removal_keeps_the_key() {
    let graph = graph();
    let rows = graph.rows_by(&graph.issuer.vault, graph.a.machine());
    let [e1, k2, k3] = [&rows[0], &rows[1], &rows[2]];
    let removal = graph.removal(&graph.issuer.vault);
    let (refused, _) = graph.backdated_key(k2, k2.seq, k2.parent_hashes.clone());
    for past_floor in [None, Some(&refused)] {
        let install = graph.receiver(&[e1, k3, k2, &removal]);
        if let Some(row) = past_floor {
            install.vault.put_authority_log_entry(row, AT, 3).unwrap();
            let fold = install.vault.authority_fold().unwrap();
            assert!(!fold.valid_entries.contains(&hash(row)));
        }
        let restore = install
            .vault
            .restore_world_keys(&install.owner, HERE, &graph.root.seed, None)
            .unwrap();
        assert_eq!(
            restore.usable,
            vec![graph.key],
            "a row past its floor beside: {}",
            past_floor.is_some()
        );
    }
}
