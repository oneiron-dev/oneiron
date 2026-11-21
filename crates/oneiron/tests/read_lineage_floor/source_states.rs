//! Fable design pass 31: a row's readers are computed from its sources'
//! states. A row stores the inputs whose floor it has not taken yet; a fold
//! moves an input's floor onto the rows waiting on it once that input is
//! bound and whole, and every door that writes a link judges it (L-S6: the
//! floor holds what the walk finds, whichever door wrote the link).

use oneiron::EdgeKind;
use oneiron::EntityId;
use oneiron::test_doors::read_lineage_floor::{
    floor_of, floor_sealed, floor_waits, walked_policies_of,
};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};

use super::erased_sources::{erase, housekeeping_pass};
use super::{claim_born_from, mailbox, owners_mailbox};

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
