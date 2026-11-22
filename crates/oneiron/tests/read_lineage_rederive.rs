//! READ-LINEAGE step L1-B (Fable design pass 30, section 4.7;
//! READ-LINEAGE-L3 = A): the owner's re-derive of sealed rows. A sealed row
//! reads to no one and is never unsealed; its fact is written again as a new
//! row from the sources that resolve now, which takes its place, and doctor's
//! "N facts hidden: source unknown" falls (`read_lineage_floor` holds the
//! count's own test). Only an owner of the vault runs the act, and it
//! reports counts only.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test read_lineage_rederive`.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::SafeDeleteReason;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::source_audience_binding::{bound_row, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

const AT: u64 = 1_769_947_200;

struct Mailbox {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: EntityId,
    stranger: EntityId,
    row: EntityId,
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
    let (row, _policy) = bound_row(&vault, reader).expect("FIXTURE: a mailbox's bound row");
    Mailbox {
        _dir: dir,
        vault,
        owner,
        reader,
        stranger: EntityId::now(),
        row,
    }
}

/// An open CLAIM about the owner stating `value`, whose birth names `inputs`
/// as `role`, stamped in a local write; no edge names them.
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
            identity: "read_lineage_rederive.fixture".to_owned(),
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

/// A CLAIM stating `value`, sealed at its birth: its prompt names a CLAIM
/// learnt from the mailbox that the owner deleted first, so nothing here
/// says any more whose words it held.
fn sealed_claim(mailbox: &Mailbox, value: &str) -> EntityId {
    let middle = claim_born_with(
        mailbox,
        &[mailbox.row],
        MadeByInputRole::Input,
        "learnt from the mailbox",
    );
    mailbox
        .vault
        .memory(mailbox.owner, EdgeActorClass::Human)
        .safe_delete(&middle.to_hex(), SafeDeleteReason::UserDelete)
        .expect("FIXTURE: the owner deletes the CLAIM middle");
    claim_born_with(mailbox, &[middle], MadeByInputRole::Prompt, value)
}

/// The vault owner's proof, as `oneiron maintain` takes it.
fn owner_proof(mailbox: &Mailbox) -> AuthenticatedOwner {
    mailbox
        .vault
        .authenticate_owner(
            mailbox.owner,
            &mailbox.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("FIXTURE: the owner's proof")
}

fn hidden(vault: &Vault) -> u64 {
    vault.doctor().expect("doctor").facts_hidden_source_unknown
}

fn lifecycle(vault: &Vault, claim: EntityId) -> ClaimLifecycleStatus {
    vault
        .get_claim(&claim)
        .expect("the CLAIM's read")
        .expect("the CLAIM is held")
        .lifecycle
}

/// The re-derive closes a sealed CLAIM by the current CLAIM that states its
/// fact under a source that resolves: the sealed CLAIM stays sealed, the
/// restated one reads to the mailbox's readers, the count falls, and the
/// report names no row.
#[test]
fn rederive_closes_a_sealed_claim_by_the_claim_that_restates_it() {
    let mailbox = mailbox();
    let sealed = sealed_claim(&mailbox, "the fact");
    let twin = claim_born_with(&mailbox, &[mailbox.row], MadeByInputRole::Input, "the fact");
    let report = mailbox
        .vault
        .rederive_sealed_rows(&owner_proof(&mailbox))
        .expect("the owner's re-derive");
    assert_eq!(
        (report.sealed, report.superseded, report.kept),
        (1, 1, 0),
        "the re-derive closes the one sealed CLAIM by its restatement",
    );
    assert_eq!(
        lifecycle(&mailbox.vault, sealed),
        ClaimLifecycleStatus::Superseded,
        "the sealed CLAIM is superseded",
    );
    for who in [mailbox.owner, mailbox.reader, mailbox.stranger] {
        assert!(
            !reads(&mailbox.vault, sealed, &[who]).expect("the sealed CLAIM's read"),
            "LEAK: the re-derive unsealed the sealed CLAIM",
        );
    }
    assert!(
        reads(&mailbox.vault, twin, &[mailbox.reader]).expect("the restatement's read"),
        "the mailbox's reader reads the restated fact",
    );
    assert!(
        !reads(&mailbox.vault, twin, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads the restated fact",
    );
    assert_eq!(hidden(&mailbox.vault), 0, "doctor counts no fact hidden");
    let shown = serde_json::to_string(&report).expect("the report as JSON");
    for id in [sealed, twin, mailbox.row] {
        assert!(
            !shown.contains(&id.to_hex()),
            "the re-derive's report names a row: {shown}",
        );
    }
}

/// A sealed CLAIM whose only evidence is gone and that no current CLAIM
/// restates is kept: it stays open, sealed and counted. The re-derive
/// writes no fact from nothing and never unseals.
#[test]
fn rederive_keeps_a_sealed_claim_whose_evidence_is_gone() {
    let mailbox = mailbox();
    let sealed = sealed_claim(&mailbox, "the fact");
    let report = mailbox
        .vault
        .rederive_sealed_rows(&owner_proof(&mailbox))
        .expect("the owner's re-derive");
    assert_eq!(
        (report.sealed, report.superseded, report.owed, report.kept),
        (1, 0, 0, 1),
        "the re-derive keeps the sealed CLAIM it cannot write again",
    );
    assert_eq!(
        lifecycle(&mailbox.vault, sealed),
        ClaimLifecycleStatus::Active,
        "the kept CLAIM stays open",
    );
    assert!(
        !reads(&mailbox.vault, sealed, &[mailbox.owner]).expect("the owner's read"),
        "LEAK: the re-derive unsealed a CLAIM it kept",
    );
    assert_eq!(
        hidden(&mailbox.vault),
        1,
        "doctor still counts the kept CLAIM",
    );
}

/// The re-derive is an owner act: a live person who does not own the vault
/// is refused, and nothing is closed.
#[test]
fn rederive_is_refused_to_a_person_who_does_not_own_the_vault() {
    let mailbox = mailbox();
    let sealed = sealed_claim(&mailbox, "the fact");
    claim_born_with(&mailbox, &[mailbox.row], MadeByInputRole::Input, "the fact");
    let person = EntityId::now();
    mailbox
        .vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("FIXTURE: a live person");
    let proof = mailbox
        .vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: a person's proof");
    assert!(
        mailbox.vault.rederive_sealed_rows(&proof).is_err(),
        "a person who does not own the vault ran the owner's re-derive",
    );
    assert_eq!(
        lifecycle(&mailbox.vault, sealed),
        ClaimLifecycleStatus::Active,
        "a refused re-derive closed the sealed CLAIM",
    );
}
