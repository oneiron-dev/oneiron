//! READ-LINEAGE step L1 (Fable design pass 30, section 4; FIX
//! [VOICE-PHONE-DERIVED-ROW-GENERIC-READ], mail half): a row written from a
//! mailbox's rows carries that mailbox's source on its floor, written in the
//! write that gives it its words, so it reads only to the mailbox's readers
//! however it names them: by an edge, or only by its birth's inputs.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_floor`.
#![cfg(oneiron_test_support)]

use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::source_audience_binding::{bound_row, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
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
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
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
