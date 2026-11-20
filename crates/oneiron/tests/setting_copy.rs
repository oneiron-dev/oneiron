//! DESIGN 15-setting-primitive, stage 7a-4 "a move's carried rows as one copy" (section 1.6 "A
//! move across machines"; RULING SETTING-7A-4-COPY):
//! - a move in a rooted vault appends one copy that names the acts behind the rows it carried,
//!   and another machine, which holds the log and none of the rows, reads the carried row from it;
//! - the mover keeps the rows no act backs (here the engine's own row) as its own bound; another
//!   machine reads the acts alone, and neither is looser than the owner's bound;
//! - the owner's clear of a carried row is his act, so it releases the row on every machine;
//! - a name this install cannot read (an act it does not hold, or one that holds no row on the
//!   slot named) reads as the key's strictest value;
//! - a move in a vault with no authority root appends nothing and keeps the row as before;
//! - two moves of one project on two machines at once leave two copies, and the row reads their
//!   meet;
//! - a copy that leaves out a head it replaces is no valid entry: a copy never drops a bound.
//!
//! Another machine is played by this install after it forgets every row the projection wrote:
//! it then holds the log and none of those rows, as a machine that took the log from the mover.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_copy`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{
    SetSetting, SetSettingOutcome, Setter, SettingCaller, SettingChange, SettingMode, SettingScope,
    SettingSource,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::setting::{
    EnrolledMachine, SlotName, carry_settings_between, enroll_machine_with_key,
    forget_projected_setting_rows, land_setting_copy_from, ordered_cap_read, set_setting_as_engine,
    setting_change, setting_frontier_of, setting_slot_heads,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{
    AuthorityEntryHash, AuthorityOp, SettingCopy, SettingCopyName,
    authority_log_entity_id_from_hash,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

/// A key whose rows meet, lower is tighter: default 10, strictest 0.
const CAP: &str = "test.ordered_cap";
const DEFAULT: u64 = 10;
const STRICTEST: u64 = 0;
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: Option<HostSlipIssuer>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A vault with no authority root: one machine.
    fn unrooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: None,
            owner,
            owner_proof,
        }
    }

    /// A vault rooted when it opened, whose install carries the owner's acts.
    fn rooted() -> Self {
        let mut fx = Self::unrooted();
        let issuer = fx.vault.bootstrap_host_slip_issuer().expect("host issuer");
        fx.vault.ensure_host_root_slip(&issuer).expect("host root");
        fx.vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        fx.vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        fx._issuer = Some(issuer);
        fx
    }

    fn owner_sets(&self, request: SetSetting) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner_proof), request)
            .expect("the owner's change")
    }

    /// The owner sets `CAP`'s value row on the project `line` to `value`; the act it appended.
    fn owner_caps(&self, line: EntityId, value: u64) -> Option<AuthorityEntryHash> {
        let outcome = self.owner_sets(SetSetting {
            scope: SettingScope::Project(line),
            ..SetSetting::vault_value(CAP, json!(value))
        });
        let SetSettingOutcome::Applied {
            sequence: Some(sequence),
            ..
        } = outcome
        else {
            panic!("an applied change that wrote a row: {outcome:?}");
        };
        self.change_at(sequence).signed
    }

    fn change_at(&self, sequence: u64) -> SettingChange {
        setting_change(&self.vault, sequence)
            .expect("the change stream")
            .expect("the change row")
    }

    /// Runs the move hook for `project`, from the lines `before` to the lines `after`.
    fn carry(&self, project: EntityId, before: &[EntityId], after: &[EntityId]) -> usize {
        carry_settings_between(&self.vault, project, before, after).expect("the move hook runs")
    }

    /// `CAP` as a reader that knows the lines `lines` reads it: value, source and revision.
    fn cap_at(&self, lines: &[EntityId]) -> (u64, SettingSource, u64) {
        let known: Vec<SettingScope> = lines.iter().copied().map(SettingScope::Project).collect();
        let read = ordered_cap_read(&self.vault, &known).expect("the read");
        (read.value, read.source, read.revision)
    }

    /// The live acts on `CAP`'s carried row on `project`.
    fn carried_heads(&self, project: EntityId) -> Vec<AuthorityEntryHash> {
        setting_slot_heads(&self.vault, carried(project)).expect("the slot's heads")
    }

    /// The copy `hash` names, as the log holds it.
    fn copy(&self, hash: AuthorityEntryHash) -> SettingCopy {
        let entry = self
            .vault
            .get_authority_log_entry(&authority_log_entity_id_from_hash(&hash).expect("id"))
            .expect("the log")
            .expect("the entry");
        let AuthorityOp::SettingCopy(copy) = entry.op else {
            panic!("a setting copy: {:?}", entry.op);
        };
        copy
    }

    /// This install becomes another machine that took the log from the mover: it forgets every
    /// row the projection wrote, and its next pass writes them from the log alone. The rows
    /// forgotten.
    fn take_the_log_alone(&self) -> usize {
        let forgotten = forget_projected_setting_rows(&self.vault).expect("forget");
        self.vault.project_settings().expect("the pass");
        forgotten
    }

    fn second_machine(&self, seed: u8) -> EnrolledMachine {
        enroll_machine_with_key(&self.vault, &self.owner_proof, seed).expect("enrolled")
    }
}

/// `CAP`'s carried row on `project`.
fn carried(project: EntityId) -> SlotName<'static> {
    (
        CAP,
        None,
        SettingMode::Carried,
        SettingScope::Project(project),
    )
}

/// `CAP`'s value row on `line`.
fn value_row(line: EntityId) -> SlotName<'static> {
    (CAP, None, SettingMode::Value, SettingScope::Project(line))
}

#[test]
fn another_machine_reads_the_carried_row_from_the_moves_copy() {
    let fx = Fixture::rooted();
    let (moved, old, new) = (EntityId::now(), EntityId::now(), EntityId::now());
    let on_old = fx.owner_caps(old, 3).expect("the owner's act");

    assert_eq!(fx.carry(moved, &[moved, old], &[moved, new]), 1);
    let (value, source, _) = fx.cap_at(&[moved, new]);
    assert_eq!(
        (value, source),
        (3, SettingSource::Carried(SettingScope::Project(moved)))
    );
    let heads = fx.carried_heads(moved);
    assert_eq!(heads.len(), 1, "one copy on the carried row");
    let copy = fx.copy(heads[0]);
    assert_eq!(copy.rows.len(), 1, "one carried row");
    let row = &copy.rows[0];
    assert_eq!(
        (row.slot.mode, row.slot.scope.clone()),
        (SettingMode::Carried, SettingScope::Project(moved))
    );
    assert_eq!(row.seen, [0; 32], "no act named the carried row before");
    assert_eq!(
        row.names
            .iter()
            .map(|name| (name.slot.scope.clone(), name.slot.mode, name.act))
            .collect::<Vec<_>>(),
        [(SettingScope::Project(old), SettingMode::Value, on_old)],
        "it names the owner's act on the line it left"
    );

    assert_eq!(
        fx.take_the_log_alone(),
        2,
        "the owner's row on the line left, and the carried row"
    );
    let (value, source, revision) = fx.cap_at(&[moved, new]);
    assert_eq!(
        (value, source),
        (3, SettingSource::Carried(SettingScope::Project(moved))),
        "another machine reads the bound from the copy"
    );
    let written = fx.change_at(revision);
    assert_eq!(
        (written.mode, written.setter, written.by, written.signed),
        (
            SettingMode::Carried,
            Setter::Engine { ask: None },
            None,
            Some(heads[0])
        ),
        "the engine's row, credited to the copy"
    );
}

#[test]
fn the_mover_keeps_the_rows_no_act_backs_and_another_machine_reads_the_acts() {
    let fx = Fixture::rooted();
    let (moved, old, older, new) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    let on_old = fx.owner_caps(old, 5).expect("the owner's act");
    set_setting_as_engine(
        &fx.vault,
        None,
        SetSetting {
            scope: SettingScope::Project(older),
            ..SetSetting::vault_value(CAP, json!(2))
        },
    )
    .expect("the engine's own row, which no act backs");

    assert_eq!(fx.carry(moved, &[moved, old, older], &[moved, new]), 1);
    let (mover, _, _) = fx.cap_at(&[moved, new]);
    assert_eq!(mover, 2, "the mover meets every row it read");
    let heads = fx.carried_heads(moved);
    let names: Vec<SettingCopyName> = heads
        .iter()
        .flat_map(|head| fx.copy(*head).rows[0].names.clone())
        .collect();
    assert_eq!(
        names
            .iter()
            .map(|name| (name.slot.scope.clone(), name.act))
            .collect::<Vec<_>>(),
        [(SettingScope::Project(old), on_old)],
        "the copy names the owner's act alone: the engine's row has none"
    );

    fx.take_the_log_alone();
    let (other, source, _) = fx.cap_at(&[moved, new]);
    assert_eq!(
        (other, source),
        (5, SettingSource::Carried(SettingScope::Project(moved))),
        "another machine reads the acts the copy names"
    );
    assert!(
        mover <= 5 && other <= 5,
        "neither is looser than the owner's bound"
    );
}

#[test]
fn the_owners_release_of_a_carried_row_releases_it_on_every_machine() {
    let fx = Fixture::rooted();
    let (moved, old, new) = (EntityId::now(), EntityId::now(), EntityId::now());
    fx.owner_caps(old, 3).expect("the owner's act");
    fx.carry(moved, &[moved, old], &[moved, new]);
    let copy = fx.carried_heads(moved);
    assert_eq!(copy.len(), 1);

    let release = fx.owner_sets(SetSetting {
        scope: SettingScope::Project(moved),
        mode: SettingMode::Carried,
        value: None,
        ..SetSetting::vault_value(CAP, json!(0))
    });
    assert!(
        matches!(release, SetSettingOutcome::Applied { .. }),
        "the owner releases the row: {release:?}"
    );
    assert_eq!(
        fx.cap_at(&[moved, new]).0,
        DEFAULT,
        "the owner's clear releases the row here"
    );
    let heads = fx.carried_heads(moved);
    assert_eq!(heads.len(), 1, "the release is the row's one act");
    assert_ne!(heads, copy, "and it replaced the copy");

    fx.take_the_log_alone();
    assert_eq!(
        fx.cap_at(&[moved, new]).0,
        DEFAULT,
        "another machine reads the release too, not the copy"
    );
}

#[test]
fn a_name_this_install_cannot_read_reads_the_keys_strictest_value() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x61);
    let (moved, old, new) = (EntityId::now(), EntityId::now(), EntityId::now());
    let frontier = setting_frontier_of(&fx.vault, &[carried(moved)]).expect("frontier");
    let (_, counted) = land_setting_copy_from(
        &fx.vault,
        &other,
        &frontier,
        &[(carried(moved), vec![(value_row(old), [9; 32])])],
        T0,
    )
    .expect("the copy lands");
    assert!(counted, "the fold counts the copy");
    assert_eq!(
        fx.cap_at(&[moved, new]).0,
        STRICTEST,
        "an act this install does not hold reads as the strictest value"
    );

    // A name of an act that holds no row on the slot it names.
    let (elsewhere, line) = (EntityId::now(), EntityId::now());
    let on_old = fx.owner_caps(old, 6).expect("the owner's act");
    let frontier = setting_frontier_of(&fx.vault, &[carried(elsewhere)]).expect("frontier");
    let (_, counted) = land_setting_copy_from(
        &fx.vault,
        &other,
        &frontier,
        &[(carried(elsewhere), vec![(value_row(line), on_old)])],
        T0 + 1,
    )
    .expect("the copy lands");
    assert!(counted);
    assert_eq!(fx.cap_at(&[elsewhere, new]).0, STRICTEST);
}

#[test]
fn a_move_in_a_vault_with_no_authority_root_appends_no_copy() {
    let fx = Fixture::unrooted();
    let (moved, old, new) = (EntityId::now(), EntityId::now(), EntityId::now());
    assert_eq!(fx.owner_caps(old, 3), None, "one machine: the row alone");

    assert_eq!(fx.carry(moved, &[moved, old], &[moved, new]), 1);
    let (value, source, revision) = fx.cap_at(&[moved, new]);
    assert_eq!(
        (value, source),
        (3, SettingSource::Carried(SettingScope::Project(moved)))
    );
    let written = fx.change_at(revision);
    assert_eq!(
        (written.setter, written.signed),
        (Setter::Engine { ask: None }, None),
        "the carry's own row, as before stage 7a-4"
    );
    assert!(fx.carried_heads(moved).is_empty(), "no copy names the row");
}

#[test]
fn two_moves_of_one_project_on_two_machines_at_once_meet() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x62);
    let (moved, old, other_line, new) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    fx.owner_caps(old, 6).expect("the owner's act");
    let on_other_line = fx.owner_caps(other_line, 4).expect("the owner's act");
    // The other machine moves the project out of `other_line` before it hears of this move.
    let before = setting_frontier_of(&fx.vault, &[carried(moved)]).expect("frontier");

    fx.carry(moved, &[moved, old], &[moved, new]);
    assert_eq!(fx.cap_at(&[moved, new]).0, 6);
    let (_, counted) = land_setting_copy_from(
        &fx.vault,
        &other,
        &before,
        &[(carried(moved), vec![(value_row(other_line), on_other_line)])],
        T0,
    )
    .expect("the other machine's copy lands");
    assert!(counted, "the fold counts the concurrent copy");

    assert_eq!(fx.carried_heads(moved).len(), 2, "both copies are heads");
    assert_eq!(fx.cap_at(&[moved, new]).0, 4, "the row reads their meet");
    fx.take_the_log_alone();
    assert_eq!(
        fx.cap_at(&[moved, new]).0,
        4,
        "on a machine that took the log too"
    );
}

#[test]
fn a_copy_that_leaves_out_a_head_it_replaces_is_no_valid_entry() {
    let fx = Fixture::rooted();
    let other = fx.second_machine(0x63);
    let (moved, old, other_line, new) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    fx.owner_caps(old, 6).expect("the owner's act");
    let on_other_line = fx.owner_caps(other_line, 8).expect("the owner's act");
    fx.carry(moved, &[moved, old], &[moved, new]);
    let first = fx.carried_heads(moved);
    assert_eq!(first.len(), 1);

    let after = setting_frontier_of(&fx.vault, &[carried(moved)]).expect("frontier");
    let landed = land_setting_copy_from(
        &fx.vault,
        &other,
        &after,
        &[(carried(moved), vec![(value_row(other_line), on_other_line)])],
        T0,
    );
    assert!(
        !matches!(landed, Ok((_, true))),
        "a copy that drops the first copy is not counted: {landed:?}"
    );
    assert_eq!(fx.carried_heads(moved), first, "the first copy stands");
    assert_eq!(fx.cap_at(&[moved, new]).0, 6);

    let after = setting_frontier_of(&fx.vault, &[carried(moved)]).expect("frontier");
    let (_, counted) = land_setting_copy_from(
        &fx.vault,
        &other,
        &after,
        &[(
            carried(moved),
            vec![
                (carried(moved), first[0]),
                (value_row(other_line), on_other_line),
            ],
        )],
        T0 + 1,
    )
    .expect("the copy lands");
    assert!(counted, "one that names it is counted");
    assert_eq!(
        fx.cap_at(&[moved, new]).0,
        6,
        "and meets it: the looser line widens nothing"
    );
}
