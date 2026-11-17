//! READ-LINEAGE step L1 (Fable design pass 30, section 4; FIX
//! [VOICE-PHONE-DERIVED-ROW-GENERIC-READ], mail half): a row written from a
//! mailbox's rows carries that mailbox's source on its floor, written in the
//! write that gives it its words, so it reads only to the mailbox's readers
//! however it names them: by an edge, or only by its birth's inputs. A floor
//! holds every policy the source-audience walk meets. A floor that names a
//! source this vault cannot read hides its row, and doctor counts it.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_floor`.
#![cfg(oneiron_test_support)]

use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::read_lineage_floor::{floor_of, walked_policies_of};
use oneiron::test_doors::source_audience_binding::{bound_row, reads, remove_policy_row};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig,
};

const AT: u64 = 1_769_947_200;

struct Mailbox {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: EntityId,
    stranger: EntityId,
    row: EntityId,
    policy: EntityId,
}

/// A vault holding one mail CONVERSATION bound to a policy read by `reader`
/// alone.
fn mailbox() -> Mailbox {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: open the vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let reader = EntityId::now();
    let (row, policy) = bound_row(&vault, reader).expect("FIXTURE: a mailbox's bound row");
    Mailbox {
        _dir: dir,
        vault,
        owner,
        reader,
        stranger: EntityId::now(),
        row,
        policy,
    }
}

/// An open CLAIM about the owner whose birth names `inputs` as its
/// evidence (`Input`), stamped in a local write; no edge names them.
fn claim_born_from(mailbox: &Mailbox, inputs: &[EntityId], value: &str) -> EntityId {
    claim_born_with(mailbox, inputs, MadeByInputRole::Input, value)
}

/// [`claim_born_from`], naming `inputs` in the birth as `role`.
fn claim_born_with(
    mailbox: &Mailbox,
    inputs: &[EntityId],
    role: MadeByInputRole,
    value: &str,
) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(mailbox.owner),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: an open CLAIM body");
    body.source = Some(ClaimSource::UserStated);
    let made_by = MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput { row: *row, role })
            .collect(),
        process: MadeByProcess {
            actor: mailbox.owner,
            class: MadeByClass::Stated,
            identity: "read_lineage_floor.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at: AT,
        trigger: None,
    };
    put_claim_made_by(&mailbox.vault, id, &body, made_by)
        .expect("FIXTURE: the CLAIM and its birth");
    id
}

/// The mail half of the held row: a CLAIM whose birth alone names a
/// mailbox's row reads only to that mailbox's readers. Before L1 the walk
/// read no birth input, so a stranger read it.
#[test]
fn a_claim_born_from_a_mailbox_row_reads_only_to_the_mailboxs_readers() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let control = claim_born_from(&mailbox, &[], "stated with no evidence");
    assert!(
        reads(&mailbox.vault, control, &[mailbox.stranger]).expect("the stranger reads control"),
        "precondition: a CLAIM with no source reads to anyone the walk asks",
    );
    assert!(
        reads(&mailbox.vault, learnt, &[mailbox.reader]).expect("the reader reads the CLAIM"),
        "the mailbox's reader reads a CLAIM learnt from it",
    );
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.stranger]).expect("the stranger reads it"),
        "LEAK: a stranger reads a CLAIM whose birth names a mailbox's row",
    );
}

/// #9289 review r1 P1: an erase takes a row's stored floor with its row, so
/// a row born from it after the erase has no source left to inherit. The
/// CLAIM `middle`, learnt from the mailbox's row, holds the mailbox's policy
/// on its floor; the owner deletes it; a CLAIM whose prompt then names
/// `middle` is born sealed (READ-LINEAGE-L3 = A) and reads to no one, the
/// mailbox's reader included. A CLAIM born from `middle` while it stood
/// keeps the mailbox's policy after the delete: only the birth's own write
/// seals.
#[test]
fn a_claim_born_from_an_erased_row_is_sealed() {
    let mailbox = mailbox();
    let middle = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let before = claim_born_from(&mailbox, &[middle], "learnt while middle stood");
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&middle.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the owner deletes the CLAIM middle");
    let after = claim_born_with(
        &mailbox,
        &[middle],
        MadeByInputRole::Prompt,
        "learnt from middle after its delete",
    );
    assert!(
        reads(&mailbox.vault, before, &[mailbox.reader]).expect("the reader reads before"),
        "a CLAIM born while middle stood keeps the mailbox's policy after the delete",
    );
    assert!(
        !reads(&mailbox.vault, before, &[mailbox.stranger]).expect("the stranger reads before"),
        "LEAK: a stranger reads a CLAIM born from middle while it stood",
    );
    for (who, label) in [
        (mailbox.stranger, "a stranger"),
        (mailbox.reader, "the mailbox's reader"),
    ] {
        assert!(
            !reads(&mailbox.vault, after, &[who]).expect("the read of after"),
            "{label} reads a CLAIM born from the deleted middle: it is not sealed, though \
             nothing here says any more whose words middle held",
        );
    }
}

/// A row written from that CLAIM by an edge carries the CLAIM's floor in
/// turn (one level per write; the source row already holds its own), and
/// each floor holds every policy the walk meets on a read of its row.
#[test]
fn a_floor_holds_every_policy_the_walk_meets() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let derived = claim_born_from(&mailbox, &[], "derived from the learnt fact");
    mailbox
        .vault
        .put_edge(&derived, EdgeKind::DerivedFrom, &learnt, 1.0)
        .expect("FIXTURE: the derived row names its source");
    let twice = claim_born_from(&mailbox, &[derived], "born from the derived row");
    for (row, label) in [
        (mailbox.row, "the bound row"),
        (learnt, "the CLAIM born from it"),
        (derived, "the row DerivedFrom that CLAIM"),
        (twice, "the CLAIM born from that row"),
    ] {
        let floor = floor_of(&mailbox.vault, row).expect("the floor");
        assert!(
            floor.contains(&mailbox.policy),
            "{label}'s floor names the mailbox's policy",
        );
        let walked = walked_policies_of(&mailbox.vault, row, &[mailbox.reader]).expect("the walk");
        assert!(
            walked.is_subset(&floor),
            "{label}'s floor {floor:?} holds every policy the walk meets {walked:?}",
        );
        assert!(
            !reads(&mailbox.vault, row, &[mailbox.stranger]).expect("the stranger's read"),
            "LEAK: a stranger reads {label}",
        );
    }
}

/// READ-LINEAGE-L3 = A, design section 4.7: a CLAIM whose floor names a
/// source this vault can no longer read reads to no one, and doctor counts
/// it as "N facts hidden: source unknown", naming nothing else.
#[test]
fn doctor_counts_the_facts_a_source_unknown_hides() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    assert_eq!(
        mailbox
            .vault
            .doctor()
            .expect("doctor")
            .facts_hidden_source_unknown,
        0,
        "precondition: every source on every floor resolves",
    );
    remove_policy_row(&mailbox.vault, mailbox.policy).expect("FIXTURE: remove the policy row");
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.reader]).expect("the former reader's read"),
        "a CLAIM whose source no longer resolves reads to no one",
    );
    assert!(
        !reads(&mailbox.vault, learnt, &[mailbox.owner]).expect("the owner's read"),
        "the owner does not read a CLAIM whose source no longer resolves",
    );
    assert_eq!(
        mailbox
            .vault
            .doctor()
            .expect("doctor")
            .facts_hidden_source_unknown,
        1,
        "doctor counts the one CLAIM its unknown source hides",
    );
}
