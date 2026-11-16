//! [AUDIT-READ-POWER] (RULING AUDIT-READ-POWER-LIST = B, the lead 15 Nov
//! 21:1x; Engine RULINGs AUDITREAD-GRANT-HOME = A and AUDITREAD-DOOR-LIST = A,
//! 15 Nov 22:00): PR 2 group 1, the receipt and shared-act doors.
//!
//! - `vault.receipts.context` and `vault.receipts.craft_reply_manifest`: the
//!   receipt's own actor, the live owner or a live audit_read holder reads;
//!   anything else reads as none.
//! - `vault.mesh.path_receipts`: the owner or a live holder reads the newest
//!   path receipts; anyone else is refused.
//! - `vault.consent.bypassed_effect_receipts`: the owner or a live holder
//!   reads one bypass grant's Gate receipts; anyone else is refused. Shown by
//!   a grant that names nothing (not-found, not FORBIDDEN, after the grant):
//!   real bypassed effects need a heavy catastrophe fixture.
//! - `vault.notes.history_purge_receipts`: the owner or a live holder reads a
//!   NOTE's purge receipts, with no purged text in the answer.
//! - `vault.shared.receipt`: a told reader reads the receipt, or a live holder
//!   reads any receipt, told or not. Shown by an id that names nothing:
//!   real shared-act receipts need a shared vault, an invitation, an ask and
//!   an apply.
//!
//! Every call goes through the generated verb dispatch
//! (`task_verb::sdk::invoke`), JSON in and out, as a transport calls it.
//! Records are made through public paths or the owner's own verbs. Public
//! paths only.
//!
//! `cargo test --locked -p oneiron --all-features --test audit_read_receipt_doors`

mod audit_read_support;

use audit_read_support::*;
use oneiron::EntityId;
use oneiron::attempt_queue::{ManifestEntry, ManifestKind};
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::note::{NoteProgramEdit, TakeTarget};
use oneiron::receipt::ContextReceiptFields;
#[cfg(feature = "sync")]
use oneiron::sync::mesh_path::{MeshPathDirection, MeshPathOutcome, MeshPathReceipt};
use serde_json::{Value, json};

/// A CONVERSATION for a context or craft reply's receipt.
fn conversation(fixture: &Fixture) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    fixture.vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_CONVERSATION,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"a conversation",
    )?;
    Ok(id)
}

fn context_fields() -> ContextReceiptFields {
    ContextReceiptFields {
        persona_compile_stamp: "test:stamp".to_owned(),
        activated_memory_ids: Vec::new(),
        board_state_ref: "board-ref".to_owned(),
        substrate_ref: None,
        model: None,
        reasoning_effort: None,
        prompt_input_ref: None,
        disclosure_stamp: None,
    }
}

/// One context reply of the owner's own, as the host records it.
fn owner_context_receipt(fixture: &Fixture) -> Result<String, Box<dyn std::error::Error>> {
    let conv = conversation(fixture)?;
    Ok(owner(fixture).record_context_reply(
        conv,
        &context_fields(),
        "ab".repeat(32),
        "cd".repeat(32),
    )?)
}

/// One craft reply of the owner's own, as the host records it.
fn owner_craft_receipt(fixture: &Fixture) -> Result<String, Box<dyn std::error::Error>> {
    let conv = conversation(fixture)?;
    let message = EntityId::now();
    let manifest = vec![ManifestEntry::new(
        ManifestKind::Skill,
        "skill-id",
        "1",
        fixture.start,
    )];
    Ok(owner(fixture).record_craft_reply(
        conv,
        message,
        &manifest,
        "ab".repeat(32),
        "cd".repeat(32),
    )?)
}

/// `vault.receipts.context`: the frozen context reads for its own actor, the
/// owner and a live audit_read holder; to anyone else it reads as none.
#[test]
fn the_context_emit_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let receipt_ref = owner_context_receipt(&fixture)?;
    let input = json!({ "receipt_ref": receipt_ref });

    let own = call(&owner(&fixture), "vault.receipts.context", input.clone());
    assert_eq!(own["receipt_ref"], json!(receipt_ref), "the owner reads it");
    assert_eq!(
        call(&as_holder, "vault.receipts.context", input.clone()),
        Value::Null,
        "before any grant the receipt reads as none"
    );

    grant(&fixture, holder, None);
    let read = call(&as_holder, "vault.receipts.context", input.clone());
    assert_eq!(
        read["receipt_ref"],
        json!(receipt_ref),
        "the holder reads the owner's receipt: {read}"
    );
    assert_eq!(read["actor"], json!(fixture.owner.to_hex()));
    assert_eq!(
        call(&as_stranger, "vault.receipts.context", input.clone()),
        Value::Null,
        "a person without the power reads none"
    );

    revoke(&fixture, holder);
    assert_eq!(
        call(&as_holder, "vault.receipts.context", input),
        Value::Null,
        "after the revoke the receipt reads as none at the next read"
    );
    Ok(())
}

/// `vault.receipts.craft_reply_manifest`: the craft manifest reads for its own
/// actor, the owner and a live audit_read holder; to anyone else as none.
#[test]
fn the_craft_reply_manifest_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let receipt_ref = owner_craft_receipt(&fixture)?;
    let input = json!({ "receipt_ref": receipt_ref });

    let own = call(
        &owner(&fixture),
        "vault.receipts.craft_reply_manifest",
        input.clone(),
    );
    assert_eq!(own[0]["reference"], json!("skill-id"), "the owner reads it");
    assert_eq!(
        call(
            &as_holder,
            "vault.receipts.craft_reply_manifest",
            input.clone()
        ),
        Value::Null,
        "before any grant the manifest reads as none"
    );

    grant(&fixture, holder, None);
    let read = call(
        &as_holder,
        "vault.receipts.craft_reply_manifest",
        input.clone(),
    );
    assert_eq!(
        read[0]["reference"],
        json!("skill-id"),
        "the holder reads the owner's manifest: {read}"
    );
    assert_eq!(
        call(
            &as_stranger,
            "vault.receipts.craft_reply_manifest",
            input.clone()
        ),
        Value::Null,
        "a person without the power reads none"
    );

    revoke(&fixture, holder);
    assert_eq!(
        call(&as_holder, "vault.receipts.craft_reply_manifest", input),
        Value::Null,
        "after the revoke the manifest reads as none at the next read"
    );
    Ok(())
}

/// `vault.mesh.path_receipts`: the newest path receipts read for the owner
/// and a live audit_read holder, and for no one else.
#[cfg(feature = "sync")]
#[test]
fn the_mesh_path_receipts_read_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let id = fixture
        .vault
        .record_mesh_path_receipt(&MeshPathReceipt::new(
            MeshPathDirection::Outbound,
            MeshPathOutcome::Admitted,
            b"oneiron/sync/1",
        ))?;

    assert_forbidden(
        &refused(&as_holder, "vault.mesh.path_receipts", json!({})),
        "the receipts before any grant",
    );

    grant(&fixture, holder, None);
    let list = call(&as_holder, "vault.mesh.path_receipts", json!({}));
    assert!(
        list.as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["id"] == json!(id))),
        "the holder reads the receipt: {list}"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.mesh.path_receipts", json!({})),
        "the receipts for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.mesh.path_receipts", json!({})),
        "the receipts at the next read after the revoke",
    );
    Ok(())
}

/// `vault.consent.bypassed_effect_receipts`: a grant that names nothing shows
/// admission. The holder is refused before the grant and after the revoke,
/// and reads past the gate (no grant there) while the power is live.
#[test]
fn the_bypassed_effect_receipts_read_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = "00".repeat(32);
    let input = json!({ "grant": missing });

    assert_forbidden(
        &refused(
            &as_holder,
            "vault.consent.bypassed_effect_receipts",
            input.clone(),
        ),
        "the receipts before any grant",
    );

    grant(&fixture, holder, None);
    let past = refused(
        &as_holder,
        "vault.consent.bypassed_effect_receipts",
        input.clone(),
    );
    assert_eq!(
        past.code, MEMORY_CODE_BAD_REQUEST,
        "after the grant the missing grant reads past the gate, to its not-found refusal: {past:?}"
    );
    assert_forbidden(
        &refused(
            &as_stranger,
            "vault.consent.bypassed_effect_receipts",
            input.clone(),
        ),
        "the receipts for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.consent.bypassed_effect_receipts", input),
        "the receipts at the next read after the revoke",
    );
    Ok(())
}

/// `vault.notes.history_purge_receipts`: a NOTE's purge receipts read for the
/// owner and a live audit_read holder, and for no one else, with no purged
/// text in the holder's answer.
#[test]
fn the_history_purge_receipts_read_for_a_live_audit_read_holder_without_purged_text() -> TestResult
{
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let as_owner = owner(&fixture);
    let purged = "purged-secret-alpha-seven-seven";
    let live = "live-text-beta-seven-seven";

    let take = as_owner.author_take(TakeTarget::Subject(fixture.owner), purged)?;
    let note_ref = take.id_hex.clone();
    as_owner.edit_note(
        &note_ref,
        &NoteProgramEdit::Rewrite {
            text: live.to_owned(),
        },
    )?;
    let outcome = call(
        &as_owner,
        "vault.notes.history_purge",
        json!({ "note_ref": note_ref }),
    );
    assert_eq!(
        outcome["state"],
        json!("erased"),
        "one owner purges at once: {outcome}"
    );
    let input = json!({ "note_ref": note_ref });

    assert_forbidden(
        &refused(
            &as_holder,
            "vault.notes.history_purge_receipts",
            input.clone(),
        ),
        "the receipts before any grant",
    );

    grant(&fixture, holder, None);
    let answer = call(
        &as_holder,
        "vault.notes.history_purge_receipts",
        input.clone(),
    );
    assert!(
        answer.as_array().is_some_and(|rows| !rows.is_empty()),
        "the holder reads a receipt: {answer}"
    );
    let serialized = serde_json::to_string(&answer)?;
    assert!(
        !serialized.contains(purged),
        "no purged text leaves in the holder's answer: {serialized}"
    );
    assert_forbidden(
        &refused(
            &as_stranger,
            "vault.notes.history_purge_receipts",
            input.clone(),
        ),
        "the receipts for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.notes.history_purge_receipts", input),
        "the receipts at the next read after the revoke",
    );
    Ok(())
}

/// `vault.shared.receipt`: an id that names nothing shows admission. The
/// holder is refused before the grant and after the revoke, and reads past
/// the gate (no receipt there) while the power is live.
#[test]
fn the_shared_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let missing = EntityId::now().to_hex();
    let input = json!({ "receipt_id": missing });

    assert_forbidden(
        &refused(&as_holder, "vault.shared.receipt", input.clone()),
        "the receipt before any grant",
    );

    grant(&fixture, holder, None);
    let past = refused(&as_holder, "vault.shared.receipt", input.clone());
    assert_eq!(
        past.code, MEMORY_CODE_BAD_REQUEST,
        "after the grant the missing id reads past the gate, to its invalid-act refusal: {past:?}"
    );
    assert_forbidden(
        &refused(&as_stranger, "vault.shared.receipt", input.clone()),
        "the receipt for a person without the power",
    );

    revoke(&fixture, holder);
    assert_forbidden(
        &refused(&as_holder, "vault.shared.receipt", input),
        "the receipt at the next read after the revoke",
    );
    Ok(())
}
