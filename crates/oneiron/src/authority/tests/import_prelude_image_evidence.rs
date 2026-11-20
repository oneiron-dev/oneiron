//! REVIEW-9572 round 2 (FIX KIT-RESTORE-CHECKPOINT-EVIDENCE-TEST-ABSENT): a
//! signed-history import whose prelude adopts a checkpoint image in the
//! import's own write transaction, as a sealed kit restore does, rolls that
//! adoption back when it is refused. A handoff only that image covers is then
//! none this vault held, so the refusal's OF-166 evidence never names it.
//! The image is the source's own build taken as verified with no attestation
//! (`unattested_for_door`), so this module compiles only under
//! `--cfg oneiron_test_support`.
use super::history_transfer::{re_root_entry, store};
use super::support::*;
use super::*;
use crate::authority::checkpoint_adopt::VerifiedAuthorityCheckpoint;
use crate::error::{Error, RecordError};
use crate::vault::{OpenOptions, VaultStorageId};
use crate::{Vault, VaultConfig};

/// A fresh install of the source's vault imports the source's history and a
/// device enrolment the retired root signed after its handoff, with a prelude
/// that adopts the source's image of that history. The import is refused at
/// the enrolment, and the evidence names no handoff: the image that covered
/// the handoff rolled back with the import, and no row was resident. Red when
/// the held test reads the image the prelude staged (before bae7429f).
#[test]
fn a_refused_import_names_no_handoff_only_its_prelude_image_covers() {
    let source_dir = tempfile::tempdir().unwrap();
    let source = Vault::open(source_dir.path(), VaultConfig::default()).unwrap();
    let old = ed_key(183);
    let genesis = genesis_entry(183, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    store(&source, &genesis);
    let handoff = re_root_entry(id, &genesis, &old, 1, &ed_key(184));
    source.apply_signed_re_root(&handoff).unwrap();
    let handoff_hash = authority_entry_hash(&handoff).unwrap();
    let image = VerifiedAuthorityCheckpoint::unattested_for_door(
        source.build_authority_checkpoint_v2().unwrap(),
    )
    .unwrap();
    assert!(
        image.image().rows.contains_key(&handoff_hash),
        "FIXTURE: the source's image covers the handoff"
    );
    let refused = enroll_entry(id, &handoff, &old, 185, 2, 3);
    let refused_hash = authority_entry_hash(&refused).unwrap();
    let mut bodies = source.export_signed_authority_history().unwrap();
    bodies.push(encode_authority_log_entry_body(&refused).unwrap());

    let fresh_dir = tempfile::tempdir().unwrap();
    let fresh = Vault::open_owned_with(
        fresh_dir.path(),
        VaultConfig::default(),
        OpenOptions::default().adopt_storage_id(VaultStorageId::from_verified_pin(image.pin())),
    )
    .unwrap();
    let mut adopted = false;
    let error = fresh
        .import_signed_authority_history_judged(
            &bodies,
            |txn| {
                let expected = fresh.authority_checkpoint_expectation_in_txn(txn)?;
                fresh.adopt_authority_checkpoint_in_txn(txn, &image, &expected)?;
                adopted = true;
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap_err();
    assert!(adopted, "FIXTURE: the prelude adopted the image");
    assert!(
        matches!(
            &error,
            Error::Record(RecordError::InvalidAuthorityLogBody(reason))
                if *reason == "authority history standing on a key a handoff retired"
        ),
        "FIXTURE: the import is refused at the retired root's enrolment: {error:?}"
    );
    assert_eq!(
        fresh.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: authority_key_from_ed(&old),
            handoffs: BTreeSet::new(),
            refused: refused_hash,
        }],
        "LEAK: the evidence names a handoff only the image the refused import's prelude adopted covers"
    );
}
