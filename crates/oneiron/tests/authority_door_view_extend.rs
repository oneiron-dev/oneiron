//! FIX [OWNER-RESERVE-PROJECTION-COST] and
//! [AUTHORITY-DOOR-VIEW-MID-BATCH-REBUILD]: every authority generation
//! rebuilt the store doors' view of the stored log from every stored row.
//! Each row was decoded and hashed again, the log's consent structure and
//! counts were rebuilt, and so was the owner reserve's projection. One
//! admitted machine's one-parent chain, one row per put, then decoded about
//! N^2 / 2 rows in all, and a batch of k rows into an N-row log decoded about
//! k (N + k), since each staged row moves the generation.
//!
//! Now the view is kept and extended by the rows stored since: each stored
//! row is decoded once, and a write that stages rows extends the view of its
//! own last staged row. The extended view equals a rebuild exactly, so no
//! door verdict changes.
//!
//! The first two are red on main and at the red pin (this test, its door and
//! the decode counter over the old view): the chain decodes about N^2 / 2
//! rows, the batch about k (N + k). The last two compare the kept view with a
//! rebuild after every row as random logs grow (joins, rows on a withheld
//! parent that lands later, strangers' roots, marks and joins, a stranger
//! machine's rows), after committed puts and inside one write with nested
//! rollbacks; they pass on main too, where every view is a rebuild.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_door_view_extend`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    OwnerRootRecord, WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_door_view::{
    door_view_differs_from_rebuild, door_view_rows_decoded, staged_door_views_differ_from_rebuild,
};
use oneiron::test_doors::replicated_authority_batch::commit_replicated_authority_rows;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// The rows the machine's chain puts one at a time.
const CHAIN_ROWS: u64 = 240;

/// The rows the machine's one replicated batch carries.
const BATCH_ROWS: u64 = 160;

/// The rows each random log grows by after its fixture.
const GROWTH_ROWS: usize = 160;

/// The rows each random log stores before the write that stages more.
const BASE_ROWS: usize = 40;

/// The random logs' seeds.
const SEEDS: [u64; 2] = [0x9E37_79B9_7F4A_7C15, 0xD1B5_4A32_D192_ED03];

/// The reserve starts the comparison judges each projected peak against:
/// under, around and past the peak of these logs (each row projects 16 KiB,
/// each ancestor pair 640 bytes).
const STARTS: [u64; 9] = [
    0,
    1 << 20,
    2 << 20,
    4 << 20,
    8 << 20,
    16 << 20,
    32 << 20,
    64 << 20,
    u64::MAX,
];

/// A rooted vault as a host starts one: the owner bound under the host root
/// and this install profiled.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Rooted {
        _dir: dir,
        vault,
        owner,
        proof,
        vault_id,
    }
}

/// A machine the owner admitted, whose install key signs world edits.
struct Machine {
    machine: EntityId,
    signing: SigningKey,
    /// The entry that carried its admission.
    admission: AuthorityEntryHash,
}

fn machine_proof(
    vault_id: &AuthorityVaultId,
    machine: EntityId,
    signing: &SigningKey,
    encryption_key: &MachineEncryptionKey,
) -> [u8; 64] {
    signing
        .sign(&machine_profile_proof_transcript(
            vault_id,
            machine,
            &signing.verifying_key().to_bytes(),
            MachineDeviceClass::Computer,
            encryption_key,
        ))
        .to_bytes()
}

fn encryption_key() -> MachineEncryptionKey {
    MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    }
}

fn admit_machine(rooted: &Rooted) -> Machine {
    let signing = SigningKey::from_bytes(&[0xF1; 32]);
    let machine = EntityId::now();
    let encryption_key = encryption_key();
    let request = MachineEnrolmentRequest {
        vault_id: rooted.vault_id,
        machine,
        machine_key: signing.verifying_key().to_bytes(),
        device_class: MachineDeviceClass::Computer,
        machine_proof: machine_proof(&rooted.vault_id, machine, &signing, &encryption_key),
        encryption_key,
        restored_from: None,
    };
    let folded = rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine")
        .into_standing()
        .expect("the owner's admission stands");
    let admission = folded
        .chains()
        .map(|(_, head)| head)
        .max_by_key(|head| head.profile.revision)
        .expect("the admission's revision")
        .entry;
    Machine {
        machine,
        signing,
        admission,
    }
}

/// `op` signed by `signing` alone at `seq` on `parents`.
fn signed(
    vault_id: AuthorityVaultId,
    signing: &SigningKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: parents,
        op,
        overlay_seed,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("hash")
}

/// `machine`'s world edit of `world`, as its install key signs one.
fn world_edit(rooted: &Rooted, machine: EntityId, world: EntityId) -> AuthorityOp {
    AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
        world,
        act: OwnerAct::by_owner(
            rooted.owner,
            OwnerActKind::WorldPrivacy,
            world,
            ActSurface::ThisInstall,
            [0; 32],
        ),
        machine,
        settings: WorldPrivacy::default(),
    })
}

/// A machine's world-edit chain put one row per write: each put's door read
/// the whole stored log again, so the doors decoded about N^2 / 2 rows. Now
/// each stored row is decoded about once. Red on main and at the red pin.
#[test]
fn a_machines_chain_put_row_by_row_decodes_each_stored_row_once() {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let world = EntityId::now();
    let mut parent = machine.admission;
    let before = door_view_rows_decoded();
    for seq in 1..=CHAIN_ROWS {
        let row = signed(
            rooted.vault_id,
            &machine.signing,
            seq,
            vec![parent],
            world_edit(&rooted, machine.machine, world),
        );
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .unwrap_or_else(|error| panic!("chain row {seq} lands: {error}"));
        parent = hash(&row);
    }
    let decoded = door_view_rows_decoded() - before;
    let stored = stored_rows(&rooted.vault);
    assert!(
        decoded <= 3 * stored,
        "the doors decoded {decoded} rows for {CHAIN_ROWS} puts into a log of {stored} rows: each \
         put read the whole stored log again"
    );
}

/// One replicated batch of a machine's chain: each staged row moved the
/// authority generation, so the door judging the next row rebuilt the view
/// from every stored and staged row, about k (N + k) decodes. Now the write
/// extends the view of its own last staged row. Red on main and at the red
/// pin.
#[test]
fn a_replicated_batch_decodes_each_staged_row_once() {
    let rooted = rooted();
    let machine = admit_machine(&rooted);
    let world = EntityId::now();
    let mut parent = machine.admission;
    let rows = (1..=BATCH_ROWS)
        .map(|seq| {
            let row = signed(
                rooted.vault_id,
                &machine.signing,
                seq,
                vec![parent],
                world_edit(&rooted, machine.machine, world),
            );
            parent = hash(&row);
            row
        })
        .collect::<Vec<_>>();
    let before = door_view_rows_decoded();
    commit_replicated_authority_rows(&rooted.vault, &rows).expect("the batch lands");
    let decoded = door_view_rows_decoded() - before;
    let stored = stored_rows(&rooted.vault);
    assert!(
        decoded <= 3 * stored,
        "the doors decoded {decoded} rows for a batch of {BATCH_ROWS} into a log of {stored} \
         rows: each staged row read the whole log again"
    );
}

fn stored_rows(vault: &Vault) -> u64 {
    vault
        .export_signed_authority_history()
        .expect("the install's history")
        .len() as u64
}

/// A seeded generator, so a failing log grows again the same way.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).expect("a small index")
    }

    fn hash(&mut self) -> AuthorityEntryHash {
        let mut hash = [0; 32];
        for chunk in hash.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        hash
    }
}

/// The kinds of row a random log grows by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// The admitted machine's world edit on one stored row.
    Chain,
    /// Its world edit on two or three stored rows.
    Join,
    /// Its world edit naming a row it signed and withholds.
    OnWithheld,
    /// A withheld row, landing after rows that name it.
    Landing,
    /// A stranger's self-signed root record.
    StrangerRoot,
    /// A stranger anchor's mark of a fresh machine.
    StrangerMark,
    /// A stranger anchor's join of its root into the main log.
    StrangerJoin,
    /// A world edit a stranger's marked machine signs.
    StrangerMachineEdit,
}

/// A stranger: its anchor, its root row, and the last sequence it signed.
struct Stranger {
    anchor: SigningKey,
    root: AuthorityEntryHash,
    seq: u64,
}

/// A log grown one row at a time beside the fixture's own rows.
struct Growth<'a> {
    rooted: &'a Rooted,
    machine: &'a Machine,
    world: EntityId,
    seq: u64,
    stored: Vec<AuthorityEntryHash>,
    withheld: Vec<AuthorityLogEntry>,
    strangers: Vec<Stranger>,
    stranger_machines: Vec<(EntityId, SigningKey, u64)>,
    /// What [`Self::next_row`] drew, kept until the row lands.
    drawn: Option<Drawn>,
    landed: BTreeSet<Kind>,
}

/// What a drawn row adds to the log's actors once it lands.
enum Drawn {
    Row(Kind),
    Stranger(Stranger),
    StrangerMachine(EntityId, SigningKey),
}

impl<'a> Growth<'a> {
    fn new(rooted: &'a Rooted, machine: &'a Machine) -> Self {
        let stored = rooted
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .iter()
            .copied()
            .collect();
        Self {
            rooted,
            machine,
            world: EntityId::now(),
            seq: 0,
            stored,
            withheld: Vec::new(),
            strangers: Vec::new(),
            stranger_machines: Vec::new(),
            drawn: None,
            landed: BTreeSet::new(),
        }
    }

    fn parents(&self, draw: &mut Draw, most: usize) -> Vec<AuthorityEntryHash> {
        let count = 1 + draw.below(most);
        let mut parents = (0..count)
            .map(|_| self.stored[draw.below(self.stored.len())])
            .collect::<Vec<_>>();
        parents.sort_unstable();
        parents.dedup();
        parents
    }

    fn edit_on(&mut self, parents: Vec<AuthorityEntryHash>) -> AuthorityLogEntry {
        self.seq += 1;
        signed(
            self.rooted.vault_id,
            &self.machine.signing,
            self.seq,
            parents,
            world_edit(self.rooted, self.machine.machine, self.world),
        )
    }

    /// The next row, by `draw`. [`Self::landed_row`] records it once stored.
    fn next_row(&mut self, draw: &mut Draw) -> AuthorityLogEntry {
        let pick = draw.below(100);
        let (kind, row) = match pick {
            45..=59 => (Kind::Join, {
                let parents = self.parents(draw, 3);
                self.edit_on(parents)
            }),
            60..=67 => {
                let beneath = self.parents(draw, 2);
                let withheld = self.edit_on(beneath);
                let mut parents = self.parents(draw, 2);
                parents.push(hash(&withheld));
                parents.sort_unstable();
                parents.dedup();
                self.withheld.push(withheld);
                (Kind::OnWithheld, self.edit_on(parents))
            }
            68..=75 if !self.withheld.is_empty() => {
                let index = draw.below(self.withheld.len());
                (Kind::Landing, self.withheld.remove(index))
            }
            76..=81 => return self.stranger_root(draw),
            82..=86 if !self.strangers.is_empty() => return self.stranger_mark(draw),
            87..=91 if !self.strangers.is_empty() => {
                let index = draw.below(self.strangers.len());
                let other = self.stored[draw.below(self.stored.len())];
                let stranger = &mut self.strangers[index];
                stranger.seq += 1;
                let mut parents = vec![stranger.root, other];
                parents.sort_unstable();
                parents.dedup();
                (
                    Kind::StrangerJoin,
                    signed(
                        self.rooted.vault_id,
                        &stranger.anchor,
                        stranger.seq,
                        parents,
                        AuthorityOp::FrontierJoin(FrontierJoin {
                            family: FrontierJoinFamily::Anchor,
                            scope: FrontierJoinScope::Main,
                        }),
                    ),
                )
            }
            92..=97 if !self.stranger_machines.is_empty() => {
                let index = draw.below(self.stranger_machines.len());
                let parents = self.parents(draw, 2);
                let (machine, signing, seq) = &mut self.stranger_machines[index];
                *seq += 1;
                (
                    Kind::StrangerMachineEdit,
                    signed(
                        self.rooted.vault_id,
                        signing,
                        *seq,
                        parents,
                        world_edit(self.rooted, *machine, self.world),
                    ),
                )
            }
            _ => (Kind::Chain, {
                let parents = self.parents(draw, 1);
                self.edit_on(parents)
            }),
        };
        self.drawn = Some(Drawn::Row(kind));
        row
    }

    fn stranger_root(&mut self, draw: &mut Draw) -> AuthorityLogEntry {
        let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
        let root = seed
            .public(&self.rooted.vault_id)
            .expect("the stranger root's public half");
        let anchor = seed.anchor();
        let parents = self.parents(draw, 1);
        let record = OwnerRootRecord {
            owner: stranger_owner(),
            root: root.id,
            recovery_key: MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: root.recovery_key.to_bytes(),
            },
            anchor_key: root.anchor_key,
        };
        let row = signed(
            self.rooted.vault_id,
            &anchor,
            1,
            parents,
            AuthorityOp::OwnerRoot(record),
        );
        self.drawn = Some(Drawn::Stranger(Stranger {
            anchor,
            root: hash(&row),
            seq: 1,
        }));
        row
    }

    fn stranger_mark(&mut self, draw: &mut Draw) -> AuthorityLogEntry {
        let index = draw.below(self.strangers.len());
        let signing = SigningKey::from_bytes(&draw.hash());
        let machine = EntityId::now();
        let encryption_key = encryption_key();
        let profile = MachineProfile {
            machine,
            owner: stranger_owner(),
            machine_key: signing.verifying_key().to_bytes(),
            device_class: MachineDeviceClass::Computer,
            machine_proof: machine_proof(&self.rooted.vault_id, machine, &signing, &encryption_key),
            encryption_key,
            role: MachineRole::Unanswered,
            revision: 1,
            seen_world_edits: BTreeSet::new(),
            carrier: None,
            act: None,
            restored_from: None,
        };
        let stranger = &mut self.strangers[index];
        stranger.seq += 1;
        let row = signed(
            self.rooted.vault_id,
            &stranger.anchor,
            stranger.seq,
            vec![stranger.root],
            AuthorityOp::MachineProfile(profile),
        );
        self.drawn = Some(Drawn::StrangerMachine(machine, signing));
        row
    }

    /// Records the row [`Self::next_row`] drew as stored.
    fn landed_row(&mut self, row: &AuthorityLogEntry) {
        self.stored.push(hash(row));
        match self.drawn.take() {
            Some(Drawn::Row(kind)) => {
                self.landed.insert(kind);
            }
            Some(Drawn::Stranger(stranger)) => {
                self.landed.insert(Kind::StrangerRoot);
                self.strangers.push(stranger);
            }
            Some(Drawn::StrangerMachine(machine, signing)) => {
                self.landed.insert(Kind::StrangerMark);
                self.stranger_machines.push((machine, signing, 0));
            }
            None => {}
        }
    }

    /// Rows the comparison bounds the log with: a fresh chain row, a fresh
    /// join on a parent no row is, a stored row, and a withheld row, which
    /// stored rows name.
    fn probes(&self, draw: &mut Draw) -> Vec<(AuthorityEntryHash, Vec<AuthorityEntryHash>)> {
        let mut join = self.parents(draw, 3);
        join.push(draw.hash());
        join.sort_unstable();
        let mut probes = vec![
            (draw.hash(), self.parents(draw, 1)),
            (draw.hash(), join),
            (self.stored[draw.below(self.stored.len())], Vec::new()),
        ];
        if let Some(withheld) = self.withheld.first() {
            probes.push((hash(withheld), withheld.parent_hashes.clone()));
        }
        probes
    }
}

/// The stranger roots' owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// Puts `row` through the local store door; a row the door refuses or holds
/// is left out of the log.
fn put(rooted: &Rooted, growth: &mut Growth<'_>, row: &AuthorityLogEntry) -> bool {
    let stored = rooted.vault.put_authority_log_entry(row, AT, 1).is_ok();
    if stored {
        growth.landed_row(row);
    } else {
        growth.drawn = None;
    }
    stored
}

/// The door view after each committed put equals a rebuild: its structure,
/// counts and projected peaks, with and without probe rows, exactly and past
/// each reserve start.
#[test]
fn kept_door_views_equal_a_rebuild_as_random_logs_grow() {
    for seed in SEEDS {
        let rooted = rooted();
        let machine = admit_machine(&rooted);
        let mut growth = Growth::new(&rooted, &machine);
        let mut draw = Draw(seed);
        let mut refused = 0;
        for step in 0..GROWTH_ROWS {
            let row = growth.next_row(&mut draw);
            if !put(&rooted, &mut growth, &row) {
                refused += 1;
            }
            let probes = growth.probes(&mut draw);
            if let Some(how) = door_view_differs_from_rebuild(&rooted.vault, &probes, &STARTS)
                .expect("the door views")
            {
                panic!(
                    "seed {seed:#x}, row {step}: the kept door view differs from a rebuild in \
                     {how}"
                );
            }
        }
        assert!(
            refused * 10 < GROWTH_ROWS,
            "guard: seed {seed:#x}: the doors refused {refused} of {GROWTH_ROWS} rows"
        );
        assert_eq!(
            growth.landed,
            BTreeSet::from([
                Kind::Chain,
                Kind::Join,
                Kind::OnWithheld,
                Kind::Landing,
                Kind::StrangerRoot,
                Kind::StrangerMark,
                Kind::StrangerJoin,
                Kind::StrangerMachineEdit,
            ]),
            "guard: seed {seed:#x}: every kind of row landed"
        );
    }
}

/// Inside one write that stages rows one at a time past the store doors, the
/// door view after each staged row equals a rebuild, through nested writes
/// that roll back a staged row after the doors read it.
#[test]
fn staged_door_views_equal_a_rebuild_through_nested_rollbacks() {
    for seed in SEEDS {
        let rooted = rooted();
        let machine = admit_machine(&rooted);
        let mut growth = Growth::new(&rooted, &machine);
        let mut draw = Draw(seed);
        for _ in 0..BASE_ROWS {
            let row = growth.next_row(&mut draw);
            put(&rooted, &mut growth, &row);
        }
        let mut rows = Vec::new();
        let mut rolled_back = BTreeSet::new();
        for index in 0..GROWTH_ROWS {
            let row = growth.next_row(&mut draw);
            let edit = matches!(growth.drawn, Some(Drawn::Row(Kind::Chain | Kind::Join)));
            if edit && draw.below(4) == 0 {
                rolled_back.insert(index);
                growth.drawn = None;
            } else {
                growth.landed_row(&row);
            }
            rows.push(row);
        }
        assert!(
            rolled_back.len() > 4,
            "guard: seed {seed:#x}: some staged rows roll back"
        );
        let probes = growth.probes(&mut draw);
        if let Some((index, how)) = staged_door_views_differ_from_rebuild(
            &rooted.vault,
            &rows,
            &rolled_back,
            &probes,
            &STARTS,
        )
        .expect("the staged door views")
        {
            panic!(
                "seed {seed:#x}, staged row {index}: the kept door view differs from a rebuild in \
                 {how}"
            );
        }
    }
}
