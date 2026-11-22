//! FIX [OWNER-RESERVE-CROSS-INSTALL-CARRY]: past its owner reserve, an
//! install lands only the owner's work (`authority/log_budget.rs`
//! `owner_work`): a row a slip issuer signs or cosigns, a row an anchor this
//! install takes as its own signs, and the owner's will this install
//! carries, which it reads by its own install key. An owner act install A
//! carries reaches install B of the same vault signed by A's install key, so
//! at B it is not B's will. Since row CARRIER-OWNER-PROOF, A signs a machine
//! answer and a policy-setting act with the proof of an owner key it holds
//! beside its own signature, and that cosign is a live owner's: B lands the
//! act past its reserve. An act A carries with no owner key held waits at
//! B, as any row that is not the owner's work.
//!
//! Each test takes A's history to a second install B (its own directory and
//! keystore, so its own install key), sets B's memory floor, and floods B
//! with an admitted machine's rows until B's door holds one at the reserve.
//! A then acts, and B imports what A wrote.
//!
//! Red at the head with the owner key's proof dropped from both writers
//! (`machine_answers.rs` `append_owner_answer_ending_keys_in_txn` and
//! `carried_act.rs` `append_carried_act_in_txn` sign with no proof): B's
//! import of A's removal refuses with `AuthorityLogFull`, and A's setting act
//! either is not counted at A or waits at B. The second test passes there too:
//! it shows the act A carries unproven waits at B.
//!
//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS: thirteen more carried ops
//! refused any cosign, at shape or in their own fold, so no proof could
//! land them past B's reserve. One rule now takes one cosign on each, judged
//! once at the merge as a live owner key's proof. The last three tests: a
//! proven world edit A carries lands and counts at B (red on main c8e2f038:
//! the world edit's fold refused the cosign), a stranger's cosign counts at
//! neither install (passes on main too), and the shape takes one cosign on
//! a carried cancel or install join, never two (red on main: refused).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_carry`.

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, MachineOwnership, MachineRole, OwnerAct, OwnerActKind, WorldPrivacy,
    WorldPrivacyEdit, authority_entry_hash, authority_transcript, decode_authority_log_entry_body,
};
use oneiron::settings::undo_send::UndoSendSetting;
use oneiron::test_doors::adopted_owner_work::this_install_machine_key;
use oneiron::test_doors::host_root_row_signature::cosign_authority_row_as_host_root;
use oneiron::{EntityId, ErrorKind};
use oneiron_authority::authority::{
    FrontierJoin, FrontierJoinFamily, FrontierJoinScope, OwnerWorkCancel,
};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Rooted, admit_flooder, heads_of_a, hold_owner_key, removes, rooted,
    second_install_at_its_reserve, stored_history, the_row_a_wrote,
};

/// The owner removes the flooding machine on A, where A holds an owner key.
/// A signs the removal under its install key with the owner key's proof
/// beside it, and B, past its owner reserve, lands it: the flooder reads
/// removed at B too, and B's fold stays under its floor.
#[test]
fn the_owners_removal_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            flooder.machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the flooding machine on A")
        .into_standing()
        .expect("the owner's removal stands at A");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| removes(op, flooder.machine));
    second
        .vault
        .import_signed_authority_history(&rows)
        .expect("B lands the removal A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the removal"
    );
    assert!(
        fold.machine(flooder.machine).is_some_and(|machine| machine
            .chains()
            .any(|(_, head)| head.entry == hash && head.removed)),
        "B reads the flooding machine removed by A's removal"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the removal with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
}

/// The same removal from an A that holds no owner key: A carries it under
/// its install key alone, so at B it is neither an issuer's row nor B's own
/// will, and it waits at B's door (`AuthorityLogFull`, retryable). The
/// flooder stays admitted at B until the owner proves the act or raises
/// B's floor.
#[test]
fn the_owners_removal_another_install_carries_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            flooder.machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the flooding machine on A")
        .into_standing()
        .expect("the owner's removal stands at A");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| removes(op, flooder.machine));
    assert!(
        entry.cosigns.is_empty(),
        "A holds no owner key, so it carries the removal unproven"
    );
    let import = second.vault.import_signed_authority_history(&rows);
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven removal at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
    assert!(
        fold.machine(flooder.machine)
            .is_some_and(|machine| !machine.chains().any(|(_, head)| head.removed)),
        "the flooding machine stays admitted at B"
    );
}

/// A policy-setting act A carries for the owner, with the proof of the owner
/// key A holds: the other writer that attaches the proof
/// (`carried_act.rs`). B, past its owner reserve, lands it, and the act is
/// in force there, not waiting for the owner.
#[test]
fn the_owners_setting_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let here = rooted
        .vault
        .local_machine()
        .expect("install A")
        .expect("install A's machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            here,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner marks install A yours")
        .into_standing()
        .expect("the owner's answer stands");
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    rooted
        .vault
        .set_undo_send(
            &rooted.proof,
            Some(ActSurface::ThisInstall),
            &UndoSendSetting {
                all_channels_secs: 30,
                channels: Vec::new(),
            },
        )
        .expect("the owner sets the undo-send window on A");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| {
        matches!(op, AuthorityOp::PolicySettingSet(_))
    });
    second
        .vault
        .import_signed_authority_history(&rows)
        .expect("B lands the setting act A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the setting act"
    );
    assert!(
        !fold.waiting_owner_choices().contains(&hash),
        "the setting act is in force at B, not waiting for the owner"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the setting act with one owner key's proof beside its install key"
    );
}

/// The cosign a test puts beside A's install key on a row A carries.
enum Cosign {
    /// The owner key A holds: the test host root.
    OwnerKey,
    /// A key no roster holds.
    Stranger(SigningKey),
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// A world edit install A carries for the owner under its install key, on
/// the heads of A's history, at the next sequence of that key there, cosigned as
/// `cosign` says: a row of the carried ops whose own fold reads no owner
/// proof (row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS). The test signs it,
/// as A's world edit door signs one, since that door attaches no proof yet.
fn world_edit_a_carries(rooted: &Rooted, cosign: Cosign) -> AuthorityLogEntry {
    let install = this_install_machine_key(&rooted.vault).expect("A's install key");
    let machine = rooted
        .vault
        .local_machine()
        .expect("install A")
        .expect("install A's machine")
        .id;
    let key = AuthorityKey::Ed25519(install.verifying_key().to_bytes());
    let seq = stored_history(&rooted.vault)
        .iter()
        .map(|body| decode_authority_log_entry_body(body).expect("a stored row"))
        .filter(|row| *row.signer_key() == key)
        .map(|row| row.seq)
        .max()
        .unwrap_or(0)
        + 1;
    let world = EntityId::now();
    let op = AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
        world,
        act: OwnerAct::by_owner(
            rooted.owner,
            OwnerActKind::WorldPrivacy,
            world,
            ActSurface::ThisInstall,
            [0; 32],
        ),
        machine,
        settings: WorldPrivacy::default(),
    });
    let cosigner = match &cosign {
        Cosign::OwnerKey => oneiron::test_support::test_host_issuer().public_key(),
        Cosign::Stranger(signing) => AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
    };
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: heads_of_a(rooted),
        op,
        overlay_seed,
        signer: signature_slot(key),
        cosigns: vec![signature_slot(cosigner)],
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = install.sign(&transcript).to_bytes().to_vec();
    match cosign {
        Cosign::OwnerKey => cosign_authority_row_as_host_root(
            &oneiron::test_support::test_host_issuer(),
            &mut entry,
        )
        .expect("the owner key's proof"),
        Cosign::Stranger(signing) => {
            entry.cosigns[0].signature = signing.sign(&transcript).to_bytes().to_vec();
        }
    }
    entry
}

/// Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS: a world edit A carries
/// with the proof of the owner key it holds lands past B's owner reserve and
/// B's fold counts it. The merge judges the one cosign once, at the edit's
/// parent state, as a live owner key's proof. Red on main c8e2f038: the
/// world edit's own transition refuses any cosign, so B does not count it.
#[test]
fn a_world_edit_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let edit = world_edit_a_carries(&rooted, Cosign::OwnerKey);
    let hash = authority_entry_hash(&edit).expect("hash");
    second
        .vault
        .put_authority_log_entry(&edit, AT, 1)
        .expect("B lands the world edit A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the proven world edit"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// The control: a cosign by a key no roster holds is no proof. Past B's
/// reserve the edit is not the owner's work, so it waits at B's door; at A,
/// with no reserve in play, the fold refuses it as a forged proof. Passes
/// on main too.
#[test]
fn a_world_edit_cosigned_by_no_owner_key_counts_at_neither_install() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let stranger = SigningKey::from_bytes(&[0x5C; 32]);
    let edit = world_edit_a_carries(&rooted, Cosign::Stranger(stranger));
    let hash = authority_entry_hash(&edit).expect("hash");
    let at_b = second.vault.put_authority_log_entry(&edit, AT, 1);
    assert!(
        at_b.as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the edit a stranger cosigned at its reserve: {at_b:?}"
    );
    assert!(
        !second
            .vault
            .authority_fold()
            .expect("B's fold")
            .valid_entries
            .contains(&hash),
        "B does not count it"
    );
    let at_a = rooted.vault.put_authority_log_entry(&edit, AT, 1);
    assert!(
        !rooted
            .vault
            .authority_fold()
            .expect("A's fold")
            .valid_entries
            .contains(&hash),
        "A's fold refuses the edit a stranger cosigned ({at_a:?})"
    );
}

/// A carried entry of an op whose shape refused any cosign, an owner work
/// cancel or an install's frontier join, now takes its carrier's install
/// key beside one cosign, which the fold judges; never two. An anchor's
/// join stays signed alone. Red on main c8e2f038 for the one-cosign shapes:
/// owner work and frontier joins refused any cosign at shape.
#[test]
fn a_carried_cancel_or_install_join_takes_one_cosign_by_shape() {
    let carrier = SigningKey::from_bytes(&[0xA1; 32]);
    let first = SigningKey::from_bytes(&[0xA2; 32]);
    let second = SigningKey::from_bytes(&[0xA3; 32]);
    let machine = EntityId::now();
    let request = [0x11; 32];
    let cancel = AuthorityOp::OwnerWorkCancel(OwnerWorkCancel {
        carrier: machine,
        act: OwnerAct::by_owner(
            EntityId::now(),
            OwnerActKind::RootRequest,
            machine,
            ActSurface::ThisInstall,
            OwnerWorkCancel::seen_for(request),
        ),
        request,
    });
    let join = |family| {
        AuthorityOp::FrontierJoin(FrontierJoin {
            family,
            scope: FrontierJoinScope::Main,
        })
    };
    let entry = |op: AuthorityOp, cosigners: &[&SigningKey]| {
        let mut keys: Vec<AuthorityKey> = cosigners
            .iter()
            .map(|cosigner| AuthorityKey::Ed25519(cosigner.verifying_key().to_bytes()))
            .collect();
        keys.sort();
        let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
            .expect("authority overlay seed");
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some([0x7A; 32]),
            seq: 1,
            parent_hashes: vec![[0x01; 32], [0x02; 32]],
            op,
            overlay_seed,
            signer: signature_slot(AuthorityKey::Ed25519(carrier.verifying_key().to_bytes())),
            cosigns: keys.into_iter().map(signature_slot).collect(),
            ts: 1,
        };
        let transcript = authority_transcript(&row).expect("transcript");
        row.signer.signature = carrier.sign(&transcript).to_bytes().to_vec();
        for cosign in &mut row.cosigns {
            let signing = [&first, &second]
                .into_iter()
                .find(|key| {
                    AuthorityKey::Ed25519(key.verifying_key().to_bytes()) == cosign.public_key
                })
                .expect("a cosigner");
            cosign.signature = signing.sign(&transcript).to_bytes().to_vec();
        }
        row
    };
    for (name, op) in [
        ("an owner work cancel", cancel),
        (
            "an install's frontier join",
            join(FrontierJoinFamily::Install(machine)),
        ),
    ] {
        assert!(
            entry(op.clone(), &[]).validate_shape().is_ok(),
            "{name} signed alone keeps its shape"
        );
        assert!(
            entry(op.clone(), &[&first]).validate_shape().is_ok(),
            "{name} takes one cosign beside its carrier"
        );
        assert!(
            entry(op, &[&first, &second]).validate_shape().is_err(),
            "{name} never takes two"
        );
    }
    assert!(
        entry(join(FrontierJoinFamily::Anchor), &[&first])
            .validate_shape()
            .is_err(),
        "an anchor's join stays signed alone"
    );
}
