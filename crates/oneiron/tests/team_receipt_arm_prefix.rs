//! The `arm:` team reference prefix is reserved (design pass 32 r2, sections
//! 3.6 and 4.5; row M2-E, the generic part of T22).
//!
//! An experiment arm's rung receipt (`arm:<arm hex>:r<rung>`) is the copy of
//! the rung's scored outcome, written once by the arm's verdict or review in
//! that outcome's own transaction. The generic receipt writer and the generic
//! outcome setter refuse the prefix, as a team reference and as the receipt an
//! outcome rests on, so no generic door creates an arm's receipt or replaces
//! its outcome. Today's setter replaces any outcome it is given.
//!
//! - The writer refuses an `arm:` team reference and an outcome resting on an
//!   `arm:` receipt, and writes nothing; an ordinary receipt still records.
//! - The setter refuses an `arm:` team reference before it reads (on the base
//!   it answers not found) and an outcome resting on an `arm:` receipt (on
//!   the base it replaces the outcome); an ordinary outcome still settles.
//!
//! Fleet command: `cargo test --locked -p oneiron --all-features --test
//! team_receipt_arm_prefix`.

use std::collections::BTreeMap;

use oneiron::claim::learning_evidence::Anchor;
use oneiron::team::pattern::{TeamAxis, TeamPattern};
use oneiron::team::receipt::{
    DecidedBy, TeamOutcome, TeamReceipt, TeamShape, record_team_receipt,
    record_team_receipt_sourced, settle_team_outcome, team_receipt,
};
use oneiron::{EntityId, Error, Vault, VaultConfig};

/// An arm's rung-one receipt reference, as the arm writer forms it.
const ARM_REF: &str = "arm:0123456789abcdef0123456789abcdef:r1";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    project: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    Fixture {
        vault,
        _dir: dir,
        project: EntityId::now(),
    }
}

impl Fixture {
    /// A solo run's receipt of the fixture's project at the root of its tree
    /// in force, with no outcome yet.
    fn receipt(&self, team_ref: &str) -> TeamReceipt {
        let tree = oneiron::task_type::type_tree(&self.vault, Some(self.project))
            .expect("the tree in force");
        TeamReceipt {
            team_ref: team_ref.to_owned(),
            project: Some(self.project),
            type_ref: tree.root(),
            pattern: TeamPattern::Solo,
            pattern_skill: None,
            axis: TeamAxis::Converge,
            models: vec!["muse-spark-1.3".to_owned()],
            shape: TeamShape {
                width: 1,
                roles: BTreeMap::from([("solo".to_owned(), 1)]),
            },
            decided_by: DecidedBy::Leader {
                actor: EntityId::now(),
            },
            coverage: None,
            confessions: None,
            spend: None,
            spend_cap: None,
            elapsed_secs: 60,
            calls: None,
            outcome: None,
            at: 1,
        }
    }
}

fn outcome(receipt: &str) -> TeamOutcome {
    TeamOutcome {
        receipt: receipt.to_owned(),
        anchor: Anchor::OwnerVerdict,
        success: true,
        at: 2,
        critics: None,
    }
}

fn assert_reserved(result: Result<impl std::fmt::Debug, Error>, what: &str) {
    match result {
        Err(Error::InvalidClaimBody(reason)) if reason.contains("arm:") => {}
        other => panic!("expected {what} to be refused as the arm: namespace; seen {other:?}"),
    }
}

#[test]
fn the_generic_receipt_writer_refuses_an_arm_reference() {
    let fixture = fixture();

    assert_reserved(
        record_team_receipt(&fixture.vault, &fixture.receipt(ARM_REF)),
        "a generic receipt named arm:",
    );
    assert_eq!(
        team_receipt(&fixture.vault, ARM_REF).expect("read"),
        None,
        "the refused receipt wrote nothing"
    );

    let mut resting_on_an_arm = fixture.receipt("run-on-arm");
    resting_on_an_arm.outcome = Some(outcome(ARM_REF));
    assert_reserved(
        record_team_receipt_sourced(&fixture.vault, &resting_on_an_arm, None, None),
        "a generic receipt whose outcome rests on an arm: receipt",
    );
    assert_eq!(
        team_receipt(&fixture.vault, "run-on-arm").expect("read"),
        None,
        "the refused receipt wrote nothing"
    );

    let ordinary = fixture.receipt("run-ordinary");
    record_team_receipt(&fixture.vault, &ordinary)
        .expect("an ordinary receipt records");
    assert_eq!(
        team_receipt(&fixture.vault, "run-ordinary").expect("read"),
        Some(ordinary)
    );
}

#[test]
fn the_generic_outcome_setter_refuses_an_arm_reference() {
    let fixture = fixture();

    // Refused before the lookup: on the base this answers not found.
    assert_reserved(
        settle_team_outcome(&fixture.vault, ARM_REF, &outcome(ARM_REF)),
        "the generic setter on an arm: receipt",
    );

    record_team_receipt(&fixture.vault, &fixture.receipt("run-1"))
        .expect("an ordinary receipt");
    assert_reserved(
        settle_team_outcome(&fixture.vault, "run-1", &outcome(ARM_REF)),
        "an outcome resting on an arm: receipt",
    );
    assert_eq!(
        team_receipt(&fixture.vault, "run-1")
            .expect("read")
            .expect("the receipt")
            .outcome,
        None,
        "the refused outcome replaced nothing"
    );

    let settled = settle_team_outcome(&fixture.vault, "run-1", &outcome("run-1-verdict"))
        .expect("an ordinary outcome settles");
    assert_eq!(settled.outcome, Some(outcome("run-1-verdict")));
}
