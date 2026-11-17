//! The shared one-way confirm: every one-way verb meets one preview.
//!
//! An owner previews a one-way act with `vault.owner_confirm.preview`,
//! shows what it takes, and passes its confirm back; without that live
//! confirm the verb door refuses with `OWNER_CONFIRM_REQUIRED`. A confirm
//! of one state does not land another, a confirm of one record does not
//! erase another, and a record confirm past its ten-minute row is refused
//! while a hold confirm lands with one press. A history purge that erases
//! at once (one Owner) takes the confirm; with two Owners its start takes
//! none and its execute does. Each history confirm binds the NOTE and the
//! frontier its erase runs through, so an edit after the preview refuses the
//! old confirm. A preview of an act that lands over a damaged clock floor
//! classifies as that act does, and the record-erase previews an old build
//! kept go with their caller's erase and at the next preview.
//!
//! Every door is reached by its verb name and every answer is read as JSON,
//! so this file builds on main too. Red on main: `vault.owner_confirm.preview`
//! is an unknown verb there, `vault.records.erase_confirm` takes
//! `preview_digest`, `vault.legal_holds.lift_and_erase` takes `shown_state`,
//! and the other one-way verbs land with no confirm, so each gated call below
//! lands or answers another code.
//!
//! The vault is rooted, keyed and owned, as an embedded host opens it: an
//! erase signs its receipt with this install's key, and the owner's verbs by
//! name need the writer lease.
//!
//! `cargo test --locked -p oneiron --all-features --test one_way_confirm`
//!
//! The old-row test needs the doors and runs only under them:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test one_way_confirm`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::check_in::{ActClass, VerbActClass};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::MemoryError;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::revoke_lands::restriction_only_call;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::verb_names::VERB_ACT_CLASSES;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;
/// The code a one-way call without its live confirm is refused with.
const OWNER_CONFIRM_REQUIRED: &str = "OWNER_CONFIRM_REQUIRED";
/// The shared vault's id in the two-Owner test.
const SHARED: u64 = 43;
/// Base64 of `record A holds only these bytes`.
const BYTES_A_B64: &str = "cmVjb3JkIEEgaG9sZHMgb25seSB0aGVzZSBieXRlcw==";
/// Base64 of `shared bytes for B and C`.
const BYTES_B_B64: &str = "c2hhcmVkIGJ5dGVzIGZvciBCIGFuZCBD";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    clock: Arc<ManualClock>,
    // Dropped after the vault.
    _dir: tempfile::TempDir,
}

/// A device vault this process owns (the writer lease), on a manual clock,
/// rooted under the test host with this install's keys, and its embedded
/// owner bound as the human owner.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("a temporary vault directory");
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(dir.path(), config).expect("an owned vault");
    let issuer = provision_engine_machines(&vault);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("this install's signing keys");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    Fixture {
        vault,
        owner,
        clock,
        _dir: dir,
    }
}

impl Fixture {
    /// The embedded owner calls `verb` by name.
    fn call(&self, verb: &str, input: Value) -> Result<Value, MemoryError> {
        invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            verb,
            input,
        )
    }

    /// The embedded owner calls `verb`, which must be refused.
    fn refused(&self, verb: &str, input: Value) -> MemoryError {
        match self.call(verb, input) {
            Ok(out) => panic!("{verb} landed without a live confirm: {out}"),
            Err(error) => error,
        }
    }

    /// `person`'s own proof, with no credential.
    fn proof(&self, person: EntityId) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("a person proof")
    }

    /// A blob artifact holding the bytes `content_b64` names; its hex id.
    fn put_record(&self, name: &str, content_b64: &str) -> String {
        let put = self
            .call(
                "vault.artifacts.put",
                json!({ "name": name, "media_type": "text/plain", "occurred_at": NOW }),
            )
            .expect("the owner registers the artifact");
        let id = put
            .get("id_hex")
            .and_then(Value::as_str)
            .expect("the put names its id")
            .to_owned();
        let appended = self
            .call(
                "vault.artifacts.append",
                json!({ "artifact_ref": id.clone(), "content_base64": content_b64, "occurred_at": NOW }),
            )
            .expect("the owner appends the bytes");
        assert!(
            appended.get("landed").is_some(),
            "the append lands; got {appended}"
        );
        id
    }

    /// A NOTE with `markdown`, edited once so it has history; its hex id.
    fn put_note_with_history(&self, markdown: &str) -> String {
        let out = self
            .call(
                "vault.notes.create",
                json!({ "kind": "research", "markdown": markdown }),
            )
            .expect("the owner creates the note");
        let note = out
            .get("id_hex")
            .and_then(Value::as_str)
            .expect("the create names its id")
            .to_owned();
        self.edit_note(&note, &format!("{markdown}, edited once"));
        note
    }

    /// The owner replaces `note`'s whole text with `text`.
    fn edit_note(&self, note: &str, text: &str) {
        self.call(
            "vault.notes.edit",
            json!({
                "note_ref": note,
                "edit": {
                    "kind": "whole_text",
                    "text": text,
                    "timeout_ms": 100,
                    "base": null,
                },
            }),
        )
        .expect("the owner edits the note");
    }

    /// How many purge receipts `note` holds.
    fn purge_receipts(&self, note: &str) -> usize {
        self.call(
            "vault.notes.history_purge_receipts",
            json!({ "note_ref": note }),
        )
        .expect("the owner reads the note's purge receipts")
        .as_array()
        .expect("the receipts are a list")
        .len()
    }

    /// The owner founds a shared vault with a second live Owner, so a
    /// history purge waits on the `erase` veto window.
    fn share_with_a_co_owner(&self) {
        let co_owner = EntityId::now();
        self.vault
            .put_entity(
                &co_owner,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                b"co-owner",
            )
            .expect("a live person");
        let founder = |member_ref| InitialSharedMember {
            member_ref,
            role: Some(FederationGrantRole::Owner),
        };
        self.vault
            .initialize_shared_vault(
                &self.proof(self.owner),
                SHARED,
                None,
                &[founder(self.owner), founder(co_owner)],
                NOW,
            )
            .expect("a shared vault with two founding Owners");
        let co_proof = self.proof(co_owner);
        let invitation = self
            .vault
            .shared_invitations(&co_proof, SHARED)
            .expect("the co-owner's invitations")
            .into_iter()
            .find(|open| open.role == FederationGrantRole::Owner)
            .expect("the co-owner's founding invitation");
        self.vault
            .accept_shared_invitation(&co_proof, SHARED, &invitation.id)
            .expect("the co-owner accepts");
    }

    /// The owner's shared preview of `verb` with `input`.
    fn preview(&self, verb: &str, input: Value) -> Value {
        self.call(
            "vault.owner_confirm.preview",
            json!({ "verb": verb, "input": input }),
        )
        .expect("the owner previews the act")
    }

    /// Whether `vault.get` still answers a row for `entity`.
    fn is_live(&self, entity: &str) -> bool {
        self.call("vault.get", json!({ "entity_ref": entity }))
            .is_ok_and(|out| out.get("value").is_some_and(|value| !value.is_null()))
    }
}

fn confirm_of(preview: &Value) -> String {
    preview
        .get("confirm")
        .and_then(Value::as_str)
        .expect("the preview names its confirm")
        .to_owned()
}

fn takes_of(preview: &Value) -> Value {
    preview
        .get("takes")
        .cloned()
        .expect("the preview names what it takes")
}

fn assert_confirm_refused(error: &MemoryError, what: &str) {
    assert_eq!(
        error.code, OWNER_CONFIRM_REQUIRED,
        "{what} names the shared confirm; got {}: {}",
        error.code, error.message
    );
}

/// The outbound erase without its confirm is refused at the verb door.
/// Red on main: the call lands, `{"erased": false}` for a missing row.
#[test]
fn a_one_way_verb_without_its_confirm_is_refused_at_the_verb_door() {
    let fx = fixture();
    let error = fx.refused(
        "vault.outbound_calls.request.erase",
        json!({ "attempt": EntityId::now().to_hex(), "call_seq": 0 }),
    );
    assert_confirm_refused(&error, "the outbound erase without its confirm");
}

/// The shared preview confirms once, and a changed state is refused.
/// Red on main: the preview verb is unknown there.
#[test]
fn the_shared_preview_confirms_once_and_a_changed_state_is_refused() {
    let fx = fixture();
    let verb = "vault.records.erase_confirm";
    let a = fx.put_record("owen.bin", BYTES_A_B64);
    let first = fx.preview(verb, json!({ "record": a.clone() }));
    fx.call(
        verb,
        json!({ "record": a.clone(), "confirm": confirm_of(&first) }),
    )
    .expect("the shown preview confirms");
    assert!(!fx.is_live(&a), "the confirmed record is gone");

    let b = fx.put_record("yuki-b.bin", BYTES_B_B64);
    let shown = fx.preview(verb, json!({ "record": b.clone() }));
    // A third record with B's bytes joins what erasing B would take.
    let c = fx.put_record("yuki-c.bin", BYTES_B_B64);
    let reshown = fx.preview(verb, json!({ "record": b.clone() }));
    let takes_after = takes_of(&reshown);
    assert_ne!(
        takes_of(&shown),
        takes_after,
        "the third record moves what the preview shows"
    );
    let same_bytes = takes_after
        .get("same_bytes")
        .and_then(Value::as_array)
        .expect("the preview names the same-bytes records");
    assert!(
        same_bytes
            .iter()
            .any(|row| row.as_str() == Some(c.as_str())),
        "the new holder joins same_bytes; got {takes_after}"
    );
    let error = fx.refused(
        verb,
        json!({ "record": b.clone(), "confirm": confirm_of(&shown) }),
    );
    assert_confirm_refused(&error, "the confirm of the old state");
    assert!(fx.is_live(&b), "the refused record stays");
}

/// Every one-way verb meets the shared confirm, and no other row joins it.
/// Red on main: `vault.legal_holds.lift_and_erase` asks its `shown_state`
/// there, and `vault.notes.history_purge` is no erase row.
#[test]
fn every_one_way_verb_meets_the_shared_confirm() {
    let fx = fixture();
    let note = fx.put_note_with_history("a note the census purges");
    let mut inputs: BTreeMap<&str, Value> = BTreeMap::new();
    inputs.insert("vault.legal_holds.lift_and_erase", json!({ "records": [] }));
    // One Owner: the purge takes its erase-now branch, which is gated.
    inputs.insert("vault.notes.history_purge", json!({ "note_ref": note }));
    inputs.insert(
        "vault.notes.history_purge_execute",
        json!({ "act_id": EntityId::now().to_hex() }),
    );
    inputs.insert(
        "vault.outbound_calls.request.erase",
        json!({ "attempt": EntityId::now().to_hex(), "call_seq": 0 }),
    );
    inputs.insert(
        "vault.records.erase_confirm",
        json!({ "record": EntityId::now().to_hex() }),
    );
    inputs.insert("vault.shared.propose_delete", json!({ "vault_id": "1" }));
    let census: BTreeSet<&str> = inputs.keys().copied().collect();
    for (verb, input) in inputs {
        let error = fx.refused(verb, input);
        assert_confirm_refused(&error, verb);
    }
    let mut one_way: BTreeSet<&str> = BTreeSet::new();
    for row in &VERB_ACT_CLASSES {
        if matches!(
            row.1,
            VerbActClass::Act(ActClass::Erase | ActClass::VaultDelete)
        ) {
            one_way.insert(row.0);
        }
    }
    assert_eq!(census, one_way, "the census names every one-way verb");
}

/// A preview of one record does not confirm another.
/// Red on main: the preview verb is unknown there.
#[test]
fn a_preview_of_one_record_does_not_confirm_another() {
    let fx = fixture();
    let verb = "vault.records.erase_confirm";
    let a = fx.put_record("owen.bin", BYTES_A_B64);
    let b = fx.put_record("yuki.bin", BYTES_B_B64);
    let shown = fx.preview(verb, json!({ "record": a.clone() }));
    let error = fx.refused(
        verb,
        json!({ "record": b.clone(), "confirm": confirm_of(&shown) }),
    );
    assert_confirm_refused(&error, "another record's confirm");
    assert!(fx.is_live(&a), "the previewed record stays");
    assert!(fx.is_live(&b), "the other record stays");
}

/// A signer's own sign is not gated by the shared confirm (L8-49-SIGN = A):
/// it keeps its own preview. Green on main and on the head.
#[test]
fn a_signers_own_sign_is_not_gated() {
    let fx = fixture();
    let out = fx.call(
        "vault.esign.signing.act",
        json!({ "token": "no-such-token", "action": { "action": "load" } }),
    );
    if let Err(error) = out {
        assert_ne!(
            error.code, OWNER_CONFIRM_REQUIRED,
            "the sign is not the shared confirm's; got {}",
            error.message
        );
    }
}

/// A one-Owner purge erases at once, so it needs the confirm and erases
/// with it (PURGE-START, Engine 11:34).
/// Red on main: the purge erases with no confirm.
#[test]
fn a_one_owner_purge_needs_the_confirm_and_erases_with_it() {
    let fx = fixture();
    let verb = "vault.notes.history_purge";
    let note = fx.put_note_with_history("a note with history");
    let error = fx.refused(verb, json!({ "note_ref": note.clone() }));
    assert_confirm_refused(&error, "the purge without its confirm");
    let shown = fx.preview(verb, json!({ "note_ref": note.clone() }));
    let out = fx
        .call(
            verb,
            json!({ "note_ref": note, "confirm": confirm_of(&shown) }),
        )
        .expect("the shown purge erases");
    assert_eq!(
        out.get("state").and_then(Value::as_str),
        Some("erased"),
        "the purge erases at once; got {out}"
    );
}

/// A two-Owner purge opens a veto window, which is not yet one-way: its
/// start takes no confirm, and its execute does (PURGE-START, Engine 11:34).
/// Red on main: the execute answers its open window, not the confirm.
#[test]
fn a_two_owner_purge_starts_without_a_confirm_and_its_execute_needs_one() {
    let fx = fixture();
    fx.share_with_a_co_owner();
    let note = fx.put_note_with_history("a shared note with history");
    let started = fx
        .call("vault.notes.history_purge", json!({ "note_ref": note }))
        .expect("the two-Owner purge starts without a confirm");
    assert_eq!(
        started.get("state").and_then(Value::as_str),
        Some("waiting"),
        "the purge waits on its veto window; got {started}"
    );
    let act = started
        .get("act_id")
        .and_then(Value::as_str)
        .expect("the start names its act")
        .to_owned();
    let error = fx.refused(
        "vault.notes.history_purge_execute",
        json!({ "act_id": act }),
    );
    assert_confirm_refused(&error, "the execute without its confirm");
}

/// A purge confirm binds the NOTE and the frontier the purge runs through:
/// after two edits the old confirm is refused and erases nothing, and a new
/// preview's confirm erases through exactly the frontier it shows (review P1
/// on #7861).
/// Red at a2a2d0622a06: the purge preview binds no range there, so the old
/// confirm lands and erases the history the edits added after it.
#[test]
fn a_purge_confirm_of_the_old_history_does_not_erase_the_new() {
    let fx = fixture();
    let verb = "vault.notes.history_purge";
    let note = fx.put_note_with_history("a note the owner keeps editing");
    let old = fx.preview(verb, json!({ "note_ref": note.clone() }));
    fx.edit_note(&note, "a note the owner keeps editing, edited twice");
    fx.edit_note(&note, "a note the owner keeps editing, edited three times");
    let error = fx.refused(
        verb,
        json!({ "note_ref": note.clone(), "confirm": confirm_of(&old) }),
    );
    assert_confirm_refused(&error, "the confirm of the history before the edits");
    assert_eq!(
        fx.purge_receipts(&note),
        0,
        "the refused purge erases nothing"
    );

    let shown = fx.preview(verb, json!({ "note_ref": note.clone() }));
    let takes = takes_of(&shown);
    assert_eq!(
        takes.get("history").and_then(Value::as_str),
        Some(note.as_str()),
        "the preview names the NOTE; got {takes}"
    );
    let through = takes
        .get("through")
        .cloned()
        .expect("the preview names the frontier the purge runs through");
    assert_ne!(
        Some(&through),
        takes_of(&old).get("through"),
        "the edits move the frontier the preview shows"
    );
    let out = fx
        .call(
            verb,
            json!({ "note_ref": note.clone(), "confirm": confirm_of(&shown) }),
        )
        .expect("the confirm of the history as it stands erases");
    assert_eq!(
        out.get("receipt")
            .and_then(|receipt| receipt.get("applied")),
        Some(&through),
        "the purge runs through the frontier its preview shows; got {out}"
    );
    assert_eq!(
        fx.purge_receipts(&note),
        1,
        "the confirmed purge erases once"
    );
}

/// An execute confirm binds the history its act erases and the frontier it
/// runs through: after an edit the old confirm is refused, and a new
/// preview's confirm is admitted, so the act answers its open window.
/// Red at a2a2d0622a06: the execute preview binds no range there, so the old
/// confirm is admitted and the call answers the open window, not the confirm.
#[test]
fn an_execute_confirm_of_the_old_history_is_refused() {
    let fx = fixture();
    fx.share_with_a_co_owner();
    let note = fx.put_note_with_history("a shared note the owner keeps editing");
    let started = fx
        .call(
            "vault.notes.history_purge",
            json!({ "note_ref": note.clone() }),
        )
        .expect("the two-Owner purge starts without a confirm");
    let act = started
        .get("act_id")
        .and_then(Value::as_str)
        .expect("the start names its act")
        .to_owned();
    let verb = "vault.notes.history_purge_execute";
    let old = fx.preview(verb, json!({ "act_id": act.clone() }));
    fx.edit_note(&note, "a shared note the owner keeps editing, edited twice");
    let error = fx.refused(
        verb,
        json!({ "act_id": act.clone(), "confirm": confirm_of(&old) }),
    );
    assert_confirm_refused(&error, "the execute confirm of the history before the edit");

    let shown = fx.preview(verb, json!({ "act_id": act.clone() }));
    assert_eq!(
        takes_of(&shown).get("history").and_then(Value::as_str),
        Some(note.as_str()),
        "the execute preview names the act's NOTE; got {shown}"
    );
    let error = fx.refused(
        verb,
        json!({ "act_id": act, "confirm": confirm_of(&shown) }),
    );
    assert_eq!(
        error.code, "INVALID_STATE",
        "the confirm of the history as it stands is admitted, and the act answers its open window; got {}: {}",
        error.code, error.message
    );
    assert_eq!(
        fx.purge_receipts(&note),
        0,
        "the waiting act erases nothing"
    );
}

/// A hold confirm older than the ten-minute row still lands with one press:
/// its row never expires (FIX 1462, Engine 11:34).
/// Red on main: the preview verb is unknown there.
#[test]
fn a_legal_hold_confirm_older_than_the_ttl_still_lands_with_one_press() {
    let fx = fixture();
    let verb = "vault.legal_holds.lift_and_erase";
    let record = fx.put_record("owen.bin", BYTES_A_B64);
    let placed = fx
        .call(
            "vault.legal_holds.place",
            json!({ "targets": [{ "record": record.clone() }] }),
        )
        .expect("the owner places the hold");
    let hold = placed
        .get("hold_id")
        .and_then(Value::as_str)
        .expect("the place names its hold")
        .to_owned();
    let shown = fx.preview(verb, json!({ "records": [record.clone()] }));
    fx.clock.set(NOW + 601);
    let out = fx
        .call(
            verb,
            json!({ "records": [record], "confirm": confirm_of(&shown) }),
        )
        .expect("the hold confirm lands past ten minutes");
    let holds = out
        .get("holds")
        .and_then(Value::as_array)
        .expect("the lift names its holds");
    assert!(
        holds.iter().any(|row| row.as_str() == Some(hold.as_str())),
        "the answer names the hold as lifted; got {out}"
    );
}

/// A record erase confirm older than its ten-minute row is refused.
/// Red on main: the preview verb is unknown there.
#[test]
fn a_record_erase_confirm_older_than_the_ttl_is_refused() {
    let fx = fixture();
    let verb = "vault.records.erase_confirm";
    let a = fx.put_record("owen.bin", BYTES_A_B64);
    let shown = fx.preview(verb, json!({ "record": a.clone() }));
    fx.clock.set(NOW + 601);
    let error = fx.refused(
        verb,
        json!({ "record": a.clone(), "confirm": confirm_of(&shown) }),
    );
    assert_confirm_refused(&error, "the confirm past its row");
    assert!(fx.is_live(&a), "the refused record stays");
}

/// A preview of a one-way act that is restriction-only is restriction-only
/// too, so over a damaged clock floor every transport takes it under the
/// restriction-only clock, as it takes the act: the act's door admits only a
/// confirm the caller's own preview kept (review F1 on #7861). A preview of a
/// gated act that is no erase or revoke, of a verb the confirm does not gate,
/// or of the preview itself is not.
/// Red on the head before the fix: no preview is restriction-only.
#[test]
fn a_preview_of_a_restriction_only_act_is_restriction_only() {
    let fx = fixture();
    let id = EntityId::now().to_hex();
    let classifies = |verb: &str, input: &Value| {
        restriction_only_call(&fx.vault, verb, input).expect("the call classifies")
    };
    let preview_of = |verb: &str, input: &Value| json!({ "verb": verb, "input": input });
    for (verb, input) in [
        (
            "vault.legal_holds.lift_and_erase",
            json!({ "records": [id] }),
        ),
        ("vault.notes.history_purge", json!({ "note_ref": id })),
        ("vault.notes.history_purge_execute", json!({ "act_id": id })),
        ("vault.records.erase_confirm", json!({ "record": id })),
    ] {
        assert!(classifies(verb, &input), "{verb} is restriction-only");
        assert!(
            classifies("vault.owner_confirm.preview", &preview_of(verb, &input)),
            "the preview of {verb} is restriction-only"
        );
    }
    for (verb, input) in [
        (
            "vault.outbound_calls.request.erase",
            json!({ "attempt": id, "call_seq": 0 }),
        ),
        ("vault.shared.propose_delete", json!({ "vault_id": "1" })),
        ("vault.claims.retract", json!({ "claim_ref": id })),
        (
            "vault.owner_confirm.preview",
            preview_of("vault.records.erase_confirm", &json!({ "record": id })),
        ),
    ] {
        assert!(
            !classifies("vault.owner_confirm.preview", &preview_of(verb, &input)),
            "the preview of {verb} is not restriction-only"
        );
    }
}

/// A record-erase preview the build before the shared preview kept
/// (`erase:preview:v1:`) names its caller. An actor erase takes the erased
/// caller's rows, and the next preview takes every other, since none can
/// confirm again (review F2 on #7861).
/// Red on the head before the fix: no declared table owns the prefix, so the
/// erased caller's row survives the erase.
#[cfg(oneiron_test_support)]
#[test]
fn the_retired_erase_previews_go_with_their_caller_and_at_the_next_preview() {
    use oneiron::DeleteReason;
    use oneiron::test_doors::erase_preview_rows::{
        plant_retired_erase_preview, retired_erase_previews,
    };

    let fx = fixture();
    let former = EntityId::now();
    fx.vault
        .put_entity(
            &former,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"a former caller",
        )
        .expect("a live person");
    let other = EntityId::now();
    let record = EntityId::now();
    for caller in [&former, &other] {
        plant_retired_erase_preview(&fx.vault, caller, &record, NOW)
            .expect("an old erase preview row");
    }
    assert_eq!(
        retired_erase_previews(&fx.vault)
            .expect("the old rows")
            .len(),
        2,
        "both old rows are stored"
    );
    fx.vault
        .delete_entity_with_reason(&former, DeleteReason::UserHardDelete)
        .expect("hard erase");
    assert_eq!(
        retired_erase_previews(&fx.vault).expect("the old rows"),
        vec![(other, record)],
        "the erase takes the erased caller's old row and only that"
    );
    let a = fx.put_record("owen.bin", BYTES_A_B64);
    fx.preview("vault.records.erase_confirm", json!({ "record": a }));
    assert!(
        retired_erase_previews(&fx.vault)
            .expect("the old rows")
            .is_empty(),
        "the next preview takes every old row"
    );
}
