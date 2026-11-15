//! Each on-record stretch of an off-record session is a conversation of its
//! own (FIX 22388). Flipping back off record cleared the saver but kept the
//! continuation shell, so the next on-record stretch's turns joined the
//! previous stretch's BASE conversation.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test off_record_continuation_shell`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::off_record::OffRecordBackendClass;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::off_record_shell::on_record_continuation_shell;
use oneiron::{Vault, VaultConfig};

#[test]
fn continuation_shell_is_fresh_after_flip_back() {
    let directory = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let session = vault
        .off_record_session_vault()
        .enter("sess-shell-flip-back", OffRecordBackendClass::Local)
        .expect("enter");

    session.flip_on_record_as(&proof).expect("flip on record");
    let first = on_record_continuation_shell(&session).expect("the first stretch's shell");
    assert_eq!(
        on_record_continuation_shell(&session).expect("read it again"),
        first,
        "FIXTURE: one stretch keeps one shell"
    );
    session.flip_off_record().expect("flip off record");
    session
        .flip_on_record_as(&proof)
        .expect("flip on record again");
    let second = on_record_continuation_shell(&session).expect("the second stretch's shell");

    assert_ne!(
        first, second,
        "the second on-record stretch reused the first stretch's continuation shell"
    );
}
