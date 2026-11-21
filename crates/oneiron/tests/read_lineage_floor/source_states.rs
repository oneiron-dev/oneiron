//! Fable design pass 31: a row's readers are computed from its sources'
//! states. A row stores the inputs whose floor it has not taken yet; a fold
//! moves an input's floor onto the rows waiting on it once that input is
//! bound and whole, and every door that writes a link judges it (L-S6: the
//! floor holds what the walk finds, whichever door wrote the link).
//!
//! #10315 review 1 (oracle cases 70 to 73): a support that becomes a
//! required input waits as one; an input whose stored floor names the seal
//! reads sealed, so the migration's heal leaves it alone; an old build's mark
//! on a support is a support's entry; and an erase at the end of a chain
//! longer than one judgement's depth seals the chain's first fact.
//!
//! Leg ls8-order-map (step L-S8's door map): the owner's delete of an old
//! fact judges it from its links before they go, and the same bytes
//! uploaded again after their release land their ASSET as itself.

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::deletion::TombstoneReason;
use oneiron::provenance::made_by::MadeByInputRole;
use oneiron::test_doors::claim_refinement_erase::apply_replayed_tombstone;
use oneiron::test_doors::read_lineage_floor::{
    asset_id_of, backfill_first_page, floor_of, floor_sealed, floor_waits, forget_floor_state,
    mark_raised, mark_waiting_on, register_dependency_source, store_floor_seal, walked_policies_of,
};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, WriteActor};

use super::erased_sources::{assert_no_stranger_or_reader_reads, erase, housekeeping_pass};
use super::{
    Mailbox, claim_born_before_floors, claim_born_from, claim_of_predicate_born_with, mailbox,
    owners_mailbox,
};

/// Sections 1.5 and 2: `fact` waits on `middle`, which waits on `late`, a
/// row not here yet. `late` lands bound to the mailbox: `middle` takes its
/// floor, and the fold goes on to `fact`, which takes `middle`'s in the same
/// write. The owner then erases `middle`: `fact` took its floor before, so
/// the erase seals nothing, and `fact` reads to the mailbox's reader and to
/// no stranger, after a housekeeping pass too.
#[test]
fn a_landed_floor_folds_down_a_chain_and_outlives_the_erase_of_the_middle_row() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let middle = claim_born_from(&mailbox, &[late], "learnt from a row on its way");
    let fact = claim_born_from(&mailbox, &[middle], "learnt from middle");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact born from a waiting row waits too",
    );
    let policy = bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
        .expect("late lands, bound to the mailbox");
    assert!(
        !floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "the landing of late left fact waiting on middle, whose floor is whole now",
    );
    assert!(
        floor_of(&mailbox.vault, fact)
            .expect("the floor")
            .contains(&policy),
        "the fold did not carry late's policy down to fact",
    );
    erase(&mailbox, middle);
    housekeeping_pass(&mailbox);
    assert!(
        !floor_sealed(&mailbox.vault, fact).expect("the floor's state"),
        "the erase of middle sealed a fact that had taken its floor",
    );
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader does not read a fact whose floor is whole",
    );
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads a fact learnt from the mailbox",
    );
}

/// L-S6, the commit path (`batch/builder/commit.rs`, which judged no link
/// before pass 31): a `DerivedFrom` edge a batch commit writes from a
/// CLAIM learnt from the mailbox gives the deriving row that CLAIM's floor,
/// so its floor holds every policy the walk meets, and no stranger reads it.
#[test]
fn a_link_the_batch_commit_path_writes_is_judged() {
    let mailbox = mailbox();
    let learnt = claim_born_from(&mailbox, &[mailbox.row], "learnt from the mailbox");
    let derived = claim_born_from(&mailbox, &[], "derived through the commit path");
    mailbox
        .vault
        .batch()
        .edge(&derived, EdgeKind::DerivedFrom, &learnt, 1.0)
        .commit()
        .expect("FIXTURE: the commit path writes the edge");
    let floor = floor_of(&mailbox.vault, derived).expect("the floor");
    assert!(
        floor.contains(&mailbox.policy),
        "the commit path wrote a link it did not judge: the floor misses the mailbox's policy",
    );
    let walked = walked_policies_of(&mailbox.vault, derived, &[mailbox.reader]).expect("the walk");
    assert!(
        walked.is_subset(&floor),
        "the floor {floor:?} misses a policy the walk meets {walked:?}",
    );
    assert!(
        !reads(&mailbox.vault, derived, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads a row derived from a mailbox fact",
    );
}

/// A CLAIM under `predicate` with no input of its own.
fn claim_of(mailbox: &Mailbox, predicate: &str, value: &str) -> EntityId {
    claim_of_predicate_born_with(mailbox, &[], MadeByInputRole::Input, predicate, value)
}

/// `support` supports `claim`, by an edge.
fn supports(mailbox: &Mailbox, support: EntityId, claim: EntityId) {
    mailbox
        .vault
        .put_edge(&support, EdgeKind::Supports, &claim, 1.0)
        .expect("FIXTURE: the support supports the claim");
}

/// #10315 review 1 P1-1 (oracle case 70): `claim` waits on its one support,
/// `support`, whose own floor waits for a row not here yet. `support` is
/// then registered as a source `claim` is derived from: a support that
/// becomes a required input is a new link, judged as one, so `claim` waits
/// on it as on any required input. A free support then frees the supports
/// and nothing else, so the mailbox's reader does not read `claim` while
/// `support` waits. Before the fix the write judged the links by id alone,
/// the entry stayed a support's, and the free support freed it.
#[test]
fn a_support_registered_as_a_required_source_is_not_freed_by_a_free_support() {
    let mailbox = mailbox();
    let late = EntityId::now();
    let support = claim_of_predicate_born_with(
        &mailbox,
        &[late],
        MadeByInputRole::Input,
        "fact.support_waiting",
        "learnt from a row on its way",
    );
    let claim = claim_of(&mailbox, "fact.supported", "held by its supports");
    supports(&mailbox, support, claim);
    housekeeping_pass(&mailbox);
    assert!(
        floor_waits(&mailbox.vault, claim).expect("the floor's state"),
        "precondition: a claim whose one support waits waits too",
    );
    register_dependency_source(&mailbox.vault, claim, support)
        .expect("FIXTURE: the support is registered as a source of the claim");
    let free = claim_of(&mailbox, "fact.support_free", "a free support");
    supports(&mailbox, free, claim);
    assert!(
        floor_waits(&mailbox.vault, claim).expect("the floor's state"),
        "a free support freed a claim whose required source still waits",
    );
    assert!(
        !reads(&mailbox.vault, claim, &[mailbox.reader]).expect("the reader's read"),
        "LEAK: the mailbox's reader reads a claim whose required source still waits",
    );
}

/// #10315 review 1 P1-2 (oracle case 71): an older build raised `fact`,
/// born from `input`, while `input` was whole and bound to no source, so
/// `fact`'s floor is empty. `input` then stored the seal (an older build's
/// seal at a tear). The migration visits `input` first, then heals `fact`:
/// an input whose floor names the seal reads sealed, and the heal leaves a
/// sealed input alone (section 5, M2, limit 3), so `fact` keeps its floor
/// and reads to the mailbox's reader, as a read before the pass found it.
/// Before the fix the visited input read bound with the seal on its floor,
/// and the heal stored the seal on `fact` for good.
#[test]
fn the_heal_leaves_alone_an_input_whose_stored_floor_names_the_seal() {
    let mailbox = owners_mailbox();
    let input = claim_born_from(&mailbox, &[], "whole, bound to no source");
    let fact = claim_born_from(&mailbox, &[input], "learnt from input");
    forget_floor_state(&mailbox.vault).expect("FIXTURE: the vault reads as written before floors");
    mark_raised(&mailbox.vault, input).expect("FIXTURE: an older build raised input");
    mark_raised(&mailbox.vault, fact).expect("FIXTURE: an older build raised fact");
    store_floor_seal(&mailbox.vault, input).expect("FIXTURE: input stores the seal");
    assert!(
        !floor_sealed(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a read before the migration leaves a sealed input alone",
    );
    housekeeping_pass(&mailbox);
    assert!(
        !floor_sealed(&mailbox.vault, fact).expect("the floor's state"),
        "SEALED: the heal stored the seal of an input it leaves alone",
    );
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader does not read a fact whose floor is whole",
    );
}

/// #10315 review 1 P1-3 (oracle case 72): an older build left `claim`
/// waiting on its one support, `support`, which waits for a row not here
/// yet. M1 makes each mark an entry, and a mark on a link that is a support
/// only is a support's entry. A free support then frees `claim`, whether it
/// comes after M1 or before it (`free_first`): the mailbox's reader reads
/// `claim`, after a housekeeping pass too. Before the fix M1 made the mark an
/// ordinary entry, and the free support freed nothing.
fn an_old_mark_on_a_support_is_freed_by_a_free_support(free_first: bool) {
    let mailbox = mailbox();
    let late = EntityId::now();
    let support = claim_of_predicate_born_with(
        &mailbox,
        &[late],
        MadeByInputRole::Input,
        "fact.support_waiting",
        "learnt from a row on its way",
    );
    let claim = claim_of(&mailbox, "fact.supported", "held by its supports");
    supports(&mailbox, support, claim);
    forget_floor_state(&mailbox.vault).expect("FIXTURE: the vault reads as written before floors");
    mark_waiting_on(&mailbox.vault, support, late).expect("FIXTURE: support waits for late");
    mark_waiting_on(&mailbox.vault, claim, support).expect("FIXTURE: claim waits on its support");
    assert!(
        floor_waits(&mailbox.vault, claim).expect("the floor's state"),
        "precondition: an older build's mark keeps the claim waiting on its support",
    );
    let free_support = || {
        let free = claim_of(&mailbox, "fact.support_free", "a free support");
        supports(&mailbox, free, claim);
    };
    if free_first {
        free_support();
        assert!(
            reads(&mailbox.vault, claim, &[mailbox.reader]).expect("the reader's read"),
            "STUCK: an old build's mark on a support outlived a free support at a read",
        );
        backfill_first_page(&mailbox.vault).expect("FIXTURE: M1 converts the marks");
    } else {
        backfill_first_page(&mailbox.vault).expect("FIXTURE: M1 converts the marks");
        free_support();
    }
    assert!(
        reads(&mailbox.vault, claim, &[mailbox.reader]).expect("the reader's read"),
        "STUCK: a free support did not free a claim an older build left waiting on a support",
    );
    housekeeping_pass(&mailbox);
    assert!(
        reads(&mailbox.vault, claim, &[mailbox.reader]).expect("the reader's read"),
        "STUCK: the migration left a claim a free support freed waiting on its support",
    );
}

#[test]
fn an_old_mark_on_a_support_is_freed_by_a_free_support_after_the_marks_become_entries() {
    an_old_mark_on_a_support_is_freed_by_a_free_support(false);
}

#[test]
fn an_old_mark_on_a_support_is_freed_by_a_free_support_before_the_marks_become_entries() {
    an_old_mark_on_a_support_is_freed_by_a_free_support(true);
}

/// #10315 review 1 P1-4 (oracle case 73): a chain of facts, each born from
/// the next and the last from `late`, a row not here yet, longer than the
/// depth one judgement recurses (8). A peer's tombstone of `late` replays
/// here: what `late` would have added can no longer be known, so the whole
/// chain is sealed, its first fact included, and the owner reads none of
/// it, after a housekeeping pass too. Before the fix a read stopped at the
/// depth bound and read the rest of the chain as pending, so the first fact
/// waited and the owner read it.
#[test]
fn a_tombstone_at_the_end_of_a_chain_longer_than_the_depth_bound_seals_its_first_fact() {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let mut first = late;
    for link in 0..12 {
        first = claim_of_predicate_born_with(
            &mailbox,
            &[first],
            MadeByInputRole::Input,
            &format!("fact.chain_{link}"),
            "learnt down a chain",
        );
    }
    assert!(
        floor_waits(&mailbox.vault, first).expect("the floor's state"),
        "precondition: the chain's first fact waits for late",
    );
    apply_replayed_tombstone(
        &mailbox.vault,
        &late,
        TombstoneReason::UserHardDelete,
        super::AT,
    )
    .expect("the peer's tombstone replays");
    assert!(
        floor_sealed(&mailbox.vault, first).expect("the floor's state"),
        "the erase at the end of a long chain left its first fact unsealed",
    );
    assert!(
        !reads(&mailbox.vault, first, &[mailbox.owner]).expect("the owner's read"),
        "the owner reads a fact at the head of a chain whose last input was erased",
    );
    housekeeping_pass(&mailbox);
    assert!(
        floor_sealed(&mailbox.vault, first).expect("the floor's state"),
        "a housekeeping pass unsealed the chain's first fact",
    );
}

/// Section 2, the owner's delete (leg ls8-order-map): `old` is a fact held
/// before floors, learnt from `late`, and the migration has not judged it
/// yet; `fact`, born from `old`, waits on it. The owner deletes `old`: the
/// delete judges `old` from its birth before the birth goes, so `fact`
/// takes `late`'s policy if `late` landed bound, and is sealed if `late`
/// never landed. Before the fix the delete dropped `old`'s birth first and
/// then judged it with no link: `old` read bound with an empty floor,
/// `fact` took that, and a stranger read it.
fn a_fact_learnt_from_an_old_fact_the_owner_deletes_before_the_migration_judged_it(
    late_lands: bool,
) {
    let mailbox = owners_mailbox();
    let late = EntityId::now();
    let old = claim_born_before_floors(&mailbox, &[late], "fact.old_from_late");
    forget_floor_state(&mailbox.vault).expect("FIXTURE: a vault written before floors");
    let fact = claim_born_from(&mailbox, &[old], "learnt from the old fact");
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact born from an old fact that waits on a row not here waits too",
    );
    if late_lands {
        bound_row_read_by(&mailbox.vault, late, &[mailbox.owner, mailbox.reader])
            .expect("late lands, bound to a policy the mailbox's reader reads");
        assert!(
            reads(&mailbox.vault, fact, &[mailbox.reader]).expect("the reader's read"),
            "precondition: the reader of late's policy reads a fact learnt from it",
        );
        assert!(
            !reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
            "precondition: no stranger reads a fact learnt from late",
        );
    }
    erase(&mailbox, old);
    for when in [
        "once the owner deleted the old fact",
        "after a housekeeping pass",
    ] {
        assert!(
            !reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
            "LEAK: a stranger reads a fact learnt from an old fact {when}: the delete judged \
             the old fact after its birth went",
        );
        if late_lands {
            assert!(
                reads(&mailbox.vault, fact, &[mailbox.reader]).expect("the reader's read"),
                "the reader of late's policy does not read the fact {when}",
            );
        } else {
            assert_no_stranger_or_reader_reads(&mailbox, fact, when);
        }
        housekeeping_pass(&mailbox);
    }
}

#[test]
fn a_fact_learnt_from_an_old_fact_the_owner_deletes_after_its_source_landed_keeps_that_source() {
    a_fact_learnt_from_an_old_fact_the_owner_deletes_before_the_migration_judged_it(true);
}

#[test]
fn a_fact_learnt_from_an_old_fact_the_owner_deletes_while_it_waits_is_sealed() {
    a_fact_learnt_from_an_old_fact_the_owner_deletes_before_the_migration_judged_it(false);
}

/// A new blob artifact of the mailbox's owner.
fn blob_artifact(mailbox: &Mailbox) -> EntityId {
    let id = EntityId::now();
    mailbox
        .vault
        .put_blob_artifact(
            &id,
            &BlobArtifactBody::new("read_lineage_floor.bin", "application/octet-stream"),
            TimeRange {
                start: super::AT,
                end: super::AT,
            },
            super::AT,
        )
        .expect("FIXTURE: a blob artifact");
    id
}

/// The owner uploads `bytes` as a version of `artifact`; the id of the
/// ASSET that holds them.
fn upload(mailbox: &Mailbox, artifact: EntityId, bytes: &[u8]) -> EntityId {
    let version = mailbox
        .vault
        .append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(mailbox.owner, EdgeActorClass::Human),
            TimeRange {
                start: super::AT,
                end: super::AT,
            },
            super::AT,
        )
        .expect("the owner uploads the bytes");
    asset_id_of(&version.content_hash).expect("the ASSET's id")
}

/// Section 2, readmission (case 52; leg ls8-order-map): the bytes of an
/// ASSET are released when the last artifact holding them goes, and a fact
/// learnt from the mailbox and from that ASSET is born after the release,
/// so it waits on the ASSET. The owner uploads the same bytes again: the
/// ASSET lands as itself, and the fact takes its floor. Before the fix the
/// upload read the release fence as an erased row's and sealed the fact,
/// so even the mailbox's reader lost it.
#[test]
fn a_fact_waiting_on_released_bytes_takes_their_floor_when_the_same_bytes_are_uploaded_again() {
    let mailbox = owners_mailbox();
    let bytes = b"read_lineage_floor: bytes released and uploaded again";
    let first = blob_artifact(&mailbox);
    let asset = upload(&mailbox, first, bytes);
    mailbox
        .vault
        .batch()
        .delete(&first)
        .commit()
        .expect("the last artifact holding the bytes goes");
    assert!(
        mailbox.vault.get_raw(&asset).expect("the read").is_none(),
        "precondition: the release took the ASSET with its bytes",
    );
    let fact = claim_born_from(
        &mailbox,
        &[mailbox.row, asset],
        "learnt from the mailbox and the released bytes",
    );
    assert!(
        floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "precondition: a fact born from released bytes waits until they return",
    );
    let again = blob_artifact(&mailbox);
    assert_eq!(
        upload(&mailbox, again, bytes),
        asset,
        "precondition: the same bytes land at the same ASSET",
    );
    assert!(
        mailbox.vault.get_raw(&asset).expect("the read").is_some(),
        "precondition: the upload landed the ASSET again",
    );
    assert!(
        !floor_sealed(&mailbox.vault, fact).expect("the floor's state"),
        "SEALED: the upload of the same bytes sealed a fact that waited on them",
    );
    assert!(
        !floor_waits(&mailbox.vault, fact).expect("the floor's state"),
        "the fact still waits on an ASSET whose bytes landed again",
    );
    assert!(
        reads(&mailbox.vault, fact, &[mailbox.reader]).expect("the reader's read"),
        "the mailbox's reader does not read a fact whose sources are all here",
    );
    assert!(
        !reads(&mailbox.vault, fact, &[mailbox.stranger]).expect("the stranger's read"),
        "LEAK: a stranger reads a fact learnt from the mailbox",
    );
}
