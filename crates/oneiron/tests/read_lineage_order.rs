//! Fable design pass 31, step L-S8 (section 1.6): a row's verdict is a
//! function of the facts the vault ends with, so the order its inputs land,
//! bind, are archived and restored, published, purged, replayed, released
//! and readmitted, and the order of the housekeeping sweeps, changes no
//! answer. Each case builds two vaults from the same facts: one applies them
//! in a random interleaving, one in a fixed order. Both must end with the
//! same reads of the row, and the fixed order with the reads the design
//! gives those facts.
//!
//! The orders the design keeps by intent are held fixed (section 1.6,
//! "Where order still shows"): the row is born before any of its inputs
//! changes, and an input's own facts keep their order (it lands before its
//! binding, its delete or its release; a delete is published before its
//! purge; `M`'s own input lands before `M` is deleted). The vault holds a
//! bound row before the facts are born, so every link is judged as it is
//! written: no fact here is an old one the migration judges later.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_order`.
#![cfg(oneiron_test_support)]

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use std::cell::Cell;

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::deletion::TombstoneReason;
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::test_doors::claim_refinement_erase::apply_replayed_tombstone;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::provenance_body_checkpoint::install_memory_keystore;
use oneiron::test_doors::read_lineage_floor::{
    asset_id_of, floor_sealed, floor_waits, publish_hard_delete_fence, travels_restricted,
};
use oneiron::test_doors::source_audience_binding::{
    bind_row, bound_row, bound_row_read_by, reads, unbound_row_read_by,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

const AT: u64 = 1_769_947_200;

/// One fact a case applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `A` lands with its source stamp and no binding yet.
    LandUnboundA,
    /// The binding of `A` lands.
    BindA,
    ArchiveA,
    RestoreA,
    /// `B` lands bound to its policy.
    LandB,
    ArchiveB,
    RestoreB,
    /// The owner's hard delete of `B` is published.
    PublishB,
    /// The purge of `B` lands.
    PurgeB,
    /// The purge's tombstone of `B` replays once more.
    ReplayB,
    /// `Y`, the input `M` waits on, lands bound to its policy.
    LandY,
    /// The owner deletes `M`.
    EraseM,
    /// A peer's soft tombstone of `M` replays.
    ReplayEraseM,
    /// The owner uploads the bytes of the ASSET `E` as a new artifact's
    /// version.
    LandE,
    /// The last artifact holding `E`'s bytes goes: the bytes are released.
    ReleaseE,
    /// The owner uploads the same bytes again, as another artifact's.
    ReadmitE,
    ArchiveR,
    RestoreR,
    /// A housekeeping pass, which runs the floor sweep.
    Sweep,
}

/// The facts of one case: how far each input's own chain of facts goes.
#[derive(Debug, Clone)]
struct Facts {
    /// 0: `A` never lands; 1: it lands unbound; 2: its binding lands too.
    a_steps: usize,
    a_archived: bool,
    b_archived: bool,
    /// 0 to 3: published, purged, replayed.
    b_erase: usize,
    y_lands: bool,
    /// 0 to 2: the owner's delete, a peer's replayed soft tombstone.
    m_erase: usize,
    /// `E`'s bytes landed and were released before `R` was born, so `R`
    /// first names `E` while it is released (case 52).
    e_released_first: bool,
    /// 0 to 3: lands, released, readmitted; or, when `e_released_first`,
    /// 0 to 1: readmitted.
    e_steps: usize,
    r_archived: bool,
    sweeps: usize,
}

impl Facts {
    /// Each input's facts in their own order; one chain per sweep.
    fn chains(&self) -> Vec<Vec<Op>> {
        let mut a = [Op::LandUnboundA, Op::BindA][..self.a_steps].to_vec();
        if self.a_steps > 0 && self.a_archived {
            a.extend([Op::ArchiveA, Op::RestoreA]);
        }
        let mut b = vec![Op::LandB];
        if self.b_archived {
            b.extend([Op::ArchiveB, Op::RestoreB]);
        }
        b.extend(&[Op::PublishB, Op::PurgeB, Op::ReplayB][..self.b_erase]);
        let mut y = Vec::new();
        if self.y_lands {
            y.push(Op::LandY);
        }
        y.extend(&[Op::EraseM, Op::ReplayEraseM][..self.m_erase]);
        let e = if self.e_released_first {
            [Op::ReadmitE][..self.e_steps.min(1)].to_vec()
        } else {
            [Op::LandE, Op::ReleaseE, Op::ReadmitE][..self.e_steps].to_vec()
        };
        let r = if self.r_archived {
            vec![Op::ArchiveR, Op::RestoreR]
        } else {
            Vec::new()
        };
        let mut chains = vec![a, b, y, e, r];
        chains.extend((0..self.sweeps).map(|_| vec![Op::Sweep]));
        chains.retain(|chain| !chain.is_empty());
        chains
    }

    /// The reads of `R` the design gives these facts (sections 1.3, 1.4).
    fn expected(&self) -> Expected {
        let m_waits = !self.y_lands;
        if self.m_erase > 0 && m_waits {
            // `M` is erased while it waits on `Y`: `R`, which waited on `M`,
            // is sealed (section 1.3, Erased).
            return Expected::Sealed;
        }
        // `E` hands over its (empty) floor once its bytes are here: at its
        // landing, which a later release keeps, or at the readmission.
        let e_waits = self.e_steps == 0;
        let waits = self.a_steps < 2 || m_waits || e_waits;
        if waits {
            Expected::Waiting
        } else {
            Expected::Whole
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Whole,
    Waiting,
    Sealed,
}

/// The ops of `chains`, taking at each step the next op of the chain that
/// `picks` names among those not drained yet. All zero picks give the fixed
/// order: each chain drained in turn.
fn interleave(chains: &[Vec<Op>], picks: &[u8]) -> Vec<Op> {
    let mut next = vec![0usize; chains.len()];
    let total: usize = chains.iter().map(Vec::len).sum();
    let mut ops = Vec::with_capacity(total);
    for step in 0..total {
        let open: Vec<usize> = (0..chains.len())
            .filter(|chain| next[*chain] < chains[*chain].len())
            .collect();
        let pick = usize::from(picks.get(step).copied().unwrap_or(0)) % open.len();
        let chain = open[pick];
        ops.push(chains[chain][next[chain]]);
        next[chain] += 1;
    }
    ops
}

/// One vault holding `R`, born from `A`, `B`, `M` and `E`, none of them
/// whole yet; `M` waits on `Y`.
struct World {
    _dir: tempfile::TempDir,
    vault: Vault,
    /// The policy `A` landed under, which its binding names.
    a_policy: Cell<Option<EntityId>>,
    /// The artifact that holds `E`'s bytes now.
    e_holder: Cell<Option<EntityId>>,
    owner: EntityId,
    common: EntityId,
    not_a: EntityId,
    not_b: EntityId,
    not_y: EntityId,
    stranger: EntityId,
    a: EntityId,
    b: EntityId,
    y: EntityId,
    m: EntityId,
    r: EntityId,
    e: EntityId,
}

/// What a case compares: the verdicts of `R` and `M`, who reads `R`, and
/// whether a restricted lane carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    r_waits: bool,
    r_sealed: bool,
    m_waits: bool,
    m_sealed: bool,
    r_read_by: Vec<(&'static str, bool)>,
    r_travels_restricted: bool,
}

fn claim_body(owner: EntityId, predicate: &str) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(owner),
        rmpv::Value::from("learnt from its inputs"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: an open CLAIM body");
    body.source = Some(ClaimSource::UserStated);
    body
}

fn made_by(owner: EntityId, inputs: &[EntityId]) -> MadeBy {
    MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: owner,
            class: MadeByClass::Stated,
            identity: "read_lineage_order.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: AT,
        trigger: None,
    }
}

impl World {
    fn new(facts: &Facts) -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
        let vault =
            Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
        // A purge mints a signed receipt.
        install_memory_keystore(&vault);
        vault
            .prepare_install_signing()
            .expect("FIXTURE: the install's signing key");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the embedded owner");
        // A bound row no fact names: floors are possible from here on, so
        // each link below is judged as it is written.
        bound_row(&vault, owner).expect("FIXTURE: a bound row");
        let (a, b, y) = (EntityId::now(), EntityId::now(), EntityId::now());
        let m = EntityId::now();
        let e = asset_of_e_bytes();
        if facts.e_released_first {
            let holder = upload(&vault, owner, E_BYTES);
            release(&vault, holder);
            assert!(
                vault.get_raw(&e).expect("FIXTURE: the read").is_none(),
                "FIXTURE: the release took the ASSET E with its bytes",
            );
        }
        put_claim_made_by(
            &vault,
            m,
            &claim_body(owner, "fact.order_m"),
            made_by(owner, &[y]),
        )
        .expect("FIXTURE: M, born from Y");
        let r = EntityId::now();
        put_claim_made_by(
            &vault,
            r,
            &claim_body(owner, "fact.order_r"),
            made_by(owner, &[a, b, m, e]),
        )
        .expect("FIXTURE: R, born from A, B, M and E");
        for (row, label) in [(m, "M"), (r, "R")] {
            assert!(
                floor_waits(&vault, row).expect("FIXTURE: the floor's state"),
                "FIXTURE: {label} waits on inputs not here yet",
            );
        }
        Self {
            _dir: dir,
            vault,
            a_policy: Cell::new(None),
            e_holder: Cell::new(None),
            owner,
            common: EntityId::now(),
            not_a: EntityId::now(),
            not_b: EntityId::now(),
            not_y: EntityId::now(),
            stranger: EntityId::now(),
            a,
            b,
            y,
            m,
            r,
            e,
        }
    }

    /// The readers of the policy of input `letter`: the owner, `common`, and
    /// every `not_x` reader but its own.
    fn readers_of(&self, letter: char) -> Vec<EntityId> {
        let mut readers = vec![self.owner, self.common];
        for (other, reader) in [('a', self.not_a), ('b', self.not_b), ('y', self.not_y)] {
            if other != letter {
                readers.push(reader);
            }
        }
        readers
    }

    fn apply(&self, op: Op) {
        match op {
            Op::LandUnboundA => {
                let policy = unbound_row_read_by(&self.vault, self.a, &self.readers_of('a'))
                    .expect("A lands with no binding");
                self.a_policy.set(Some(policy));
            }
            Op::BindA => {
                let policy = self.a_policy.get().expect("A landed before its binding");
                bind_row(&self.vault, self.a, policy).expect("A's binding lands");
            }
            Op::ArchiveA => self.archive(self.a),
            Op::RestoreA => self.restore(self.a),
            Op::LandB => {
                bound_row_read_by(&self.vault, self.b, &self.readers_of('b'))
                    .expect("B lands bound");
            }
            Op::ArchiveB => self.archive(self.b),
            Op::RestoreB => self.restore(self.b),
            Op::PublishB => {
                publish_hard_delete_fence(&self.vault, self.b).expect("B's hard delete publishes");
            }
            Op::PurgeB | Op::ReplayB => {
                apply_replayed_tombstone(&self.vault, &self.b, TombstoneReason::UserHardDelete, AT)
                    .expect("B's purge applies");
            }
            Op::LandY => {
                bound_row_read_by(&self.vault, self.y, &self.readers_of('y'))
                    .expect("Y lands bound");
            }
            Op::EraseM => {
                self.vault
                    .memory(self.owner, EdgeActorClass::Human)
                    .safe_delete(&self.m.to_hex(), SafeDeleteReason::UserDelete)
                    .expect("the owner deletes M");
            }
            Op::ReplayEraseM => {
                apply_replayed_tombstone(&self.vault, &self.m, TombstoneReason::UserDelete, AT)
                    .expect("a peer's soft tombstone of M replays");
            }
            Op::LandE | Op::ReadmitE => {
                let holder = upload(&self.vault, self.owner, E_BYTES);
                self.e_holder.set(Some(holder));
                assert!(
                    self.vault.get_raw(&self.e).expect("the read").is_some(),
                    "the upload landed the ASSET E",
                );
            }
            Op::ReleaseE => {
                let holder = self
                    .e_holder
                    .get()
                    .expect("E's bytes landed before their release");
                release(&self.vault, holder);
                self.e_holder.set(None);
            }
            Op::ArchiveR => self.archive(self.r),
            Op::RestoreR => self.restore(self.r),
            Op::Sweep => {
                self.vault
                    .housekeeping_all(HousekeepingBudget::unbounded())
                    .expect("a housekeeping pass runs the floor sweep");
            }
        }
    }

    fn archive(&self, row: EntityId) {
        archive_as_cleanup(&self.vault, &row).expect("the cleanup archives the row");
    }

    fn restore(&self, row: EntityId) {
        self.vault
            .restore_archived(&row)
            .expect("the owner restores the row");
    }

    fn observe(&self) -> Observation {
        let vault = &self.vault;
        let read = |viewer: EntityId| reads(vault, self.r, &[viewer]).expect("the read of R");
        Observation {
            r_waits: floor_waits(vault, self.r).expect("R's verdict"),
            r_sealed: floor_sealed(vault, self.r).expect("R's verdict"),
            m_waits: floor_waits(vault, self.m).expect("M's verdict"),
            m_sealed: floor_sealed(vault, self.m).expect("M's verdict"),
            r_read_by: vec![
                ("owner", read(self.owner)),
                ("common", read(self.common)),
                ("not_a", read(self.not_a)),
                ("not_b", read(self.not_b)),
                ("not_y", read(self.not_y)),
                ("stranger", read(self.stranger)),
            ],
            r_travels_restricted: travels_restricted(vault, self.r).expect("R's lane"),
        }
    }
}

const E_BYTES: &[u8] = b"read_lineage_order: the bytes of the ASSET E";

fn span() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

/// The owner uploads `bytes` as the first version of a new artifact; the
/// artifact's id.
fn upload(vault: &Vault, owner: EntityId, bytes: &[u8]) -> EntityId {
    let holder = EntityId::now();
    vault
        .put_blob_artifact(
            &holder,
            &BlobArtifactBody::new("read_lineage_order.bin", "application/octet-stream"),
            span(),
            AT,
        )
        .expect("an artifact for the bytes");
    vault
        .append_blob_artifact_version(
            &holder,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(owner, EdgeActorClass::Human),
            span(),
            AT,
        )
        .expect("the owner uploads the bytes");
    holder
}

/// The last artifact holding the bytes, `holder`, goes: the bytes and their
/// ASSET are released.
fn release(vault: &Vault, holder: EntityId) {
    vault
        .batch()
        .delete(&holder)
        .commit()
        .expect("the artifact holding the bytes goes");
}

/// The id of the ASSET that holds [`E_BYTES`]: an ASSET's id is its
/// bytes' BLAKE3 hash, under the blob artifact domain.
fn asset_of_e_bytes() -> EntityId {
    asset_id_of(blake3::hash(E_BYTES).as_bytes()).expect("the ASSET's id")
}

/// Applies `ops` to a new world built for `facts` and observes it.
fn run(facts: &Facts, ops: &[Op]) -> Observation {
    let world = World::new(facts);
    for op in ops {
        world.apply(*op);
    }
    world.observe()
}

/// The reads the design gives `expected`: the owner reads a row that waits
/// (he reads every source here), `common` reads only a whole row, no
/// `not_x` reader reads a row whose floor holds every policy, and no
/// stranger reads it.
fn check_expected(observed: &Observation, expected: Expected) -> Result<(), TestCaseError> {
    let reads_of = |who: &str| {
        observed
            .r_read_by
            .iter()
            .find(|(name, _)| *name == who)
            .map(|(_, read)| *read)
            .unwrap_or(false)
    };
    prop_assert_eq!(observed.r_sealed, expected == Expected::Sealed, "R sealed");
    prop_assert_eq!(observed.r_waits, expected == Expected::Waiting, "R waits");
    prop_assert_eq!(
        reads_of("owner"),
        expected != Expected::Sealed,
        "the owner reads R"
    );
    prop_assert_eq!(
        reads_of("common"),
        expected == Expected::Whole,
        "common reads R"
    );
    for who in ["not_a", "not_b", "not_y", "stranger"] {
        prop_assert!(!reads_of(who), "LEAK: {} reads R", who);
    }
    prop_assert!(
        !observed.r_travels_restricted,
        "LEAK: a restricted lane carries R"
    );
    Ok(())
}

fn facts_strategy() -> impl Strategy<Value = Facts> {
    (
        0usize..=2,
        any::<bool>(),
        any::<bool>(),
        0usize..=3,
        any::<bool>(),
        0usize..=2,
        any::<bool>(),
        0usize..=3,
        any::<bool>(),
        0usize..=3,
    )
        .prop_map(
            |(
                a_steps,
                a_archived,
                b_archived,
                b_erase,
                y_lands,
                m_erase,
                e_released_first,
                e_steps,
                r_archived,
                sweeps,
            )| Facts {
                a_steps,
                a_archived,
                b_archived,
                b_erase,
                y_lands,
                m_erase,
                e_released_first,
                e_steps: if e_released_first {
                    e_steps.min(1)
                } else {
                    e_steps
                },
                r_archived,
                sweeps,
            },
        )
}

proptest! {
    // Two vaults per case, each with at most 21 writes and three
    // housekeeping passes: 16 cases and 32 shrink iterations bound the
    // filesystem work. No regression file, child process or timeout.
    #![proptest_config(ProptestConfig {
        cases: 16,
        max_shrink_iters: 32,
        failure_persistence: None,
        fork: false,
        timeout: 0,
        ..ProptestConfig::default()
    })]
    #[test]
    fn a_rows_reads_do_not_depend_on_the_order_of_its_inputs_facts(
        facts in facts_strategy(),
        picks in proptest::collection::vec(any::<u8>(), 24),
    ) {
        let chains = facts.chains();
        let fixed = run(&facts, &interleave(&chains, &[]));
        check_expected(&fixed, facts.expected())?;
        let order = interleave(&chains, &picks);
        let random = run(&facts, &order);
        prop_assert_eq!(random, fixed, "the order {:?} changed R's reads", order);
    }
}
