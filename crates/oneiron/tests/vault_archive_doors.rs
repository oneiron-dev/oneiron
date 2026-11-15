//! Public-door promise tests for the `vault.archive` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 5).
//!
//! Every case calls the four verbs by name through the generated verb
//! dispatcher (`task_verb::sdk::invoke`), as the owner on the embedded
//! owner's handle or as an agent on its own: `vault.archive.delete.preview`,
//! `vault.archive.delete.confirm`, `vault.archive.attempt.delete.preview`
//! and `vault.archive.attempt.delete.confirm`. Records reach the archive by
//! the vault's own cleanup run (a husk PERSON under the automatic posture; a
//! completed attempt past its retention under propose-first, accepted).
//! Each case owns its vault. No sleeps, no models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`):
//! - emptying the archive removes the records from the vault at once
//!   (`oneiron/agents/oneiron-arch-0073-vault-auto-cleanup-v1.md:94`);
//! - an agent empties the archive only under a Grant that names delete
//!   (same file `:96`); a completed attempt has no disclosure position, so
//!   no agent Grant reaches it (`vault_cleanup/attempt_delete_authority.rs:1-2`);
//! - archive is the trash can and restores, delete is full
//!   (`oneiron/core/oneiron-arch-0038-deletion-redaction-canonical-snapshot-v1.md:231`):
//!   a record the archive does not hold is never emptied as archive, and a
//!   restore beats a delete previewed before it.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test vault_archive_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryError};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::vault_cleanup::{
    CleanupPosture, accept_cleanup_proposal, run_vault_cleanup, set_cleanup_posture,
};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const PREVIEW: &str = "vault.archive.delete.preview";
const CONFIRM: &str = "vault.archive.delete.confirm";
const ATTEMPT_PREVIEW: &str = "vault.archive.attempt.delete.preview";
const ATTEMPT_CONFIRM: &str = "vault.archive.attempt.delete.confirm";

/// The age past which a completed attempt is archived here, in days.
const RETENTION_DAYS: u32 = 90;
const DAY: u64 = 86_400;

/// A served personal vault on a clock the test moves: its owner, two
/// enabled agents (`granted` holds a Grant naming `read` and `delete`,
/// `read_only` one naming `read` alone), a subject PERSON, and one
/// completed attempt the cleanup has not archived yet.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    t0: u64,
    owner: EntityId,
    granted: EntityId,
    read_only: EntityId,
    subject: EntityId,
    attempt: AttemptId,
}

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after the epoch")
        .as_secs()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let t0 = wall_now();
    let clock = ManualClock::new(t0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The attempt first: the queue holds nothing else to claim yet.
    let attempt = completed_attempt(&vault, t0);
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a subject the owner writes about",
        )
        .expect("a live subject PERSON");
    let granted = agent_with_grant(
        &vault,
        &owner_proof,
        "archive_delete_granted_agent",
        &["read", "delete"],
    );
    let read_only = agent_with_grant(&vault, &owner_proof, "archive_read_only_agent", &["read"]);
    Fixture {
        _dir: dir,
        vault,
        clock,
        t0,
        owner,
        granted,
        read_only,
        subject,
        attempt,
    }
}

/// One attempt enqueued, claimed and completed at `now`.
fn completed_attempt(vault: &Vault, now: u64) -> AttemptId {
    let queue = AttemptQueue::new(vault);
    queue
        .enqueue(EnqueueAttempt {
            kind: "test.retained".into(),
            payload: vec![1, 2, 3],
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue the attempt");
    let ClaimOutcome::Claimed(record) = queue
        .claim(ClaimAttempt {
            lease_owner: "doors-custody".into(),
            now,
        })
        .expect("claim the attempt")
    else {
        panic!("the attempt is claimed");
    };
    queue
        .complete(CompleteAttempt {
            id: record.id,
            lease_owner: "doors-custody".into(),
            attempt_count: record.attempt_count,
            now,
        })
        .expect("complete the attempt");
    record.id
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`.
fn agent_with_grant(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
    verbs: &[&str],
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Archive delete door test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: std::collections::BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    agent
}

fn attempt_hex(attempt: AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl Fixture {
    /// `actor` calls `verb` with `input` on its own handle.
    fn call(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        verb: &str,
        input: Value,
    ) -> Result<Value, MemoryError> {
        invoke(&self.vault.memory(actor, class), verb, input)
    }

    fn owner_call(&self, verb: &str, input: Value) -> Value {
        self.call(self.owner, EdgeActorClass::Human, verb, input)
            .unwrap_or_else(|error| panic!("the owner's {verb}: {error:?}"))
    }

    fn agent_call(&self, agent: EntityId, verb: &str, input: Value) -> Result<Value, MemoryError> {
        self.call(agent, EdgeActorClass::Agent, verb, input)
    }

    /// The owner's own fresh proof, on the vault's current clock.
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// The owner calls an attempt verb with his proof attached, as the
    /// served owner door attaches it.
    fn owner_attempt_call(&self, verb: &str, input: Value) -> Result<Value, MemoryError> {
        let proof = self.owner_proof();
        invoke(
            &self
                .vault
                .memory(self.owner, EdgeActorClass::Human)
                .with_owner_authorship(&proof),
            verb,
            input,
        )
    }

    /// A PERSON an extraction minted and never learned a fact about, which
    /// the vault's automatic cleanup run archives: its 32-hex id.
    fn archived_husk(&self) -> String {
        let husk = EntityId::now();
        assert!(
            self.vault
                .put_extraction_minted_person(
                    &husk,
                    ClaimSource::Generated,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"a person nobody mentions again",
                )
                .expect("mint the husk")
        );
        let report = run_vault_cleanup(&self.vault, &AttemptId::now()).expect("cleanup run");
        assert!(
            report.archived.contains(&Some(husk)),
            "the cleanup run archives the husk: {:?}",
            report.archived
        );
        assert!(self.archived(&husk.to_hex()), "the husk is in the archive");
        husk.to_hex()
    }

    /// The fixture's completed attempt, archived: the clock moves past its
    /// retention, and the owner accepts the propose-first run's proposal.
    fn archive_the_attempt(&self) {
        self.clock
            .set(self.t0 + (u64::from(RETENTION_DAYS) + 1) * DAY);
        self.vault
            .set_task_retention_days(Some(RETENTION_DAYS))
            .expect("completed attempt retention");
        set_cleanup_posture(&self.vault, CleanupPosture::ProposeFirst).expect("propose first");
        let report = run_vault_cleanup(&self.vault, &AttemptId::now()).expect("cleanup run");
        let proposal = report
            .proposal
            .expect("a propose-first run with a candidate proposes");
        accept_cleanup_proposal(&self.vault, &proposal).expect("accept the proposal");
        assert!(
            self.attempt_listed().is_none(),
            "the archived attempt leaves the live queue"
        );
        assert!(self.attempt_stored(), "the archive keeps the attempt's row");
    }

    fn archived(&self, id: &str) -> bool {
        self.vault
            .archived_entity(&EntityId::from_hex(id).expect("record id"))
            .expect("archive read")
            .is_some()
    }

    fn stored(&self, id: &str) -> bool {
        self.vault
            .get_raw(&EntityId::from_hex(id).expect("record id"))
            .expect("raw read")
            .is_some()
    }

    fn shell(&self, id: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(id).expect("record id"))
            .expect("shell read")
    }

    fn attempt_stored(&self) -> bool {
        AttemptQueue::new(&self.vault)
            .get(self.attempt)
            .expect("attempt read")
            .is_some()
    }

    fn attempt_listed(&self) -> Option<AttemptId> {
        AttemptQueue::new(&self.vault)
            .list()
            .expect("attempt list")
            .into_iter()
            .map(|record| record.id)
            .find(|id| *id == self.attempt)
    }
}

/// The single entry of a preview or confirm answer, for `id`.
fn entry<'a>(answer: &'a Value, id: &str) -> &'a Value {
    let entries = answer["entries"]
        .as_array()
        .expect("the answer lists entries");
    assert_eq!(entries.len(), 1, "one entry per distinct target: {answer}");
    assert_eq!(entries[0]["entity"], id, "{answer}");
    &entries[0]["result"]
}

/// A refused entry's error code.
fn refused_code(result: &Value) -> &str {
    assert_eq!(result["outcome"], "refused", "{result}");
    result["error"]["code"]
        .as_str()
        .expect("a refusal names its code")
}

/// The owner empties one archived record: the preview binds its bytes and
/// marker, a confirm bound to other bytes is refused and keeps it, and the
/// matching confirm deletes it at once and for good: no stored row, no
/// restore, nothing left to preview.
#[test]
fn the_owner_empties_an_archived_record_at_once() {
    let fx = fixture();
    let husk = fx.archived_husk();

    let preview = fx.owner_call(PREVIEW, json!({ "targets": [husk] }));
    let row = entry(&preview, &husk);
    assert_eq!(row["outcome"], "previewed", "{preview}");
    assert!(
        row["record_bytes"].as_u64().expect("record bytes") > 0,
        "{preview}"
    );
    let expected = row["expected"].clone();
    let hash = expected["record_hash"].as_str().expect("record hash");
    assert!(is_hex(hash, 64), "{preview}");

    // A confirm bound to bytes the preview did not read is refused alone.
    let mut other = hash.to_owned();
    let flipped = if other.starts_with('0') { "1" } else { "0" };
    other.replace_range(0..1, flipped);
    let tampered = json!({ "record_hash": other, "archive_marker": expected["archive_marker"] });
    let refused = fx.owner_call(
        CONFIRM,
        json!({ "items": [{ "entity": husk, "expected": tampered }] }),
    );
    assert_eq!(
        refused_code(entry(&refused, &husk)),
        "BAD_REQUEST",
        "{refused}"
    );
    assert!(fx.archived(&husk), "a refused confirm keeps the archive");
    assert!(fx.stored(&husk), "a refused confirm keeps the record");

    let confirmed = fx.owner_call(
        CONFIRM,
        json!({ "items": [{ "entity": husk, "expected": expected }] }),
    );
    let receipt = entry(&confirmed, &husk);
    assert_eq!(receipt["outcome"], "deleted", "{confirmed}");
    assert_eq!(receipt["existed"], true, "{confirmed}");
    assert_eq!(receipt["reason"], "user_hard_delete", "{confirmed}");
    assert_eq!(receipt["role"], "owner", "{confirmed}");
    assert!(receipt.get("grant_ref").is_none(), "{confirmed}");
    assert!(
        receipt["receipt_ref"]
            .as_str()
            .is_some_and(|text| text.starts_with("redaction:")),
        "the delete keeps its redaction receipt: {confirmed}"
    );

    assert!(
        !fx.stored(&husk),
        "the record is gone from the vault at once"
    );
    assert!(
        fx.vault
            .restore_archived(&EntityId::from_hex(&husk).expect("husk id"))
            .is_err(),
        "a deleted record never restores"
    );
    let again = fx.owner_call(PREVIEW, json!({ "targets": [husk] }));
    assert_eq!(
        entry(&again, &husk)["outcome"],
        "refused",
        "nothing is left to empty: {again}"
    );
}

/// The archive door empties only what the archive holds: a live NOTE the
/// owner wrote previews and confirms as refused, and stays live.
#[test]
fn a_live_record_is_never_emptied_as_archive() {
    let fx = fixture();
    let note = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(fx.subject), "a take the owner keeps")
        .expect("the owner writes a NOTE")
        .id_hex;
    assert!(!fx.archived(&note), "the NOTE is live");

    let preview = fx.owner_call(PREVIEW, json!({ "targets": [note] }));
    assert_eq!(
        refused_code(entry(&preview, &note)),
        "BAD_REQUEST",
        "{preview}"
    );
    let confirmed = fx.owner_call(CONFIRM, json!({ "items": [{ "entity": note }] }));
    assert_eq!(
        refused_code(entry(&confirmed, &note)),
        "BAD_REQUEST",
        "{confirmed}"
    );
    assert!(fx.stored(&note), "the NOTE is kept");
    assert!(!fx.shell(&note), "the NOTE is still live");
}

/// An agent whose Grant names `read` alone neither previews nor empties the
/// archive; the record stays in the archive, and the owner still restores
/// it.
#[test]
fn an_agent_without_a_delete_grant_cannot_empty_the_archive() {
    let fx = fixture();
    let husk = fx.archived_husk();

    let preview = fx
        .agent_call(fx.read_only, PREVIEW, json!({ "targets": [husk] }))
        .expect("the preview answers per record");
    let result = entry(&preview, &husk);
    assert_eq!(refused_code(result), MEMORY_CODE_FORBIDDEN, "{preview}");
    assert!(
        result["error"]["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("no_delete_grant:")),
        "the refusal names its reason: {preview}"
    );
    let confirmed = fx
        .agent_call(
            fx.read_only,
            CONFIRM,
            json!({ "items": [{ "entity": husk }] }),
        )
        .expect("the confirm answers per record");
    assert_eq!(
        refused_code(entry(&confirmed, &husk)),
        MEMORY_CODE_FORBIDDEN,
        "{confirmed}"
    );
    assert!(fx.archived(&husk), "the record stays in the archive");
    assert!(fx.stored(&husk), "the record is kept");

    fx.vault
        .restore_archived(&EntityId::from_hex(&husk).expect("husk id"))
        .expect("the owner restores what the agent could not delete");
    assert!(!fx.shell(&husk), "the restored record is live again");
}

/// An agent whose Grant names `delete` empties the archive: its receipt
/// names the agent's role and the Grant that admitted it, and the record is
/// gone at once.
#[test]
fn an_agent_with_a_delete_grant_empties_the_archive() {
    let fx = fixture();
    let husk = fx.archived_husk();

    let preview = fx
        .agent_call(fx.granted, PREVIEW, json!({ "targets": [husk] }))
        .expect("the agent previews");
    let row = entry(&preview, &husk);
    assert_eq!(row["outcome"], "previewed", "{preview}");
    let expected = row["expected"].clone();

    let confirmed = fx
        .agent_call(
            fx.granted,
            CONFIRM,
            json!({ "items": [{ "entity": husk, "expected": expected }] }),
        )
        .expect("the agent confirms");
    let receipt = entry(&confirmed, &husk);
    assert_eq!(receipt["outcome"], "deleted", "{confirmed}");
    assert_eq!(receipt["existed"], true, "{confirmed}");
    assert_eq!(receipt["reason"], "user_hard_delete", "{confirmed}");
    assert_eq!(receipt["role"], "agent", "{confirmed}");
    assert!(
        receipt["grant_ref"]
            .as_str()
            .is_some_and(|grant| !grant.is_empty()),
        "the receipt names the Grant that admitted the delete: {confirmed}"
    );
    assert!(
        receipt["receipt_ref"]
            .as_str()
            .is_some_and(|text| text.starts_with("redaction:")),
        "{confirmed}"
    );
    assert!(
        !fx.stored(&husk),
        "the record is gone from the vault at once"
    );
}

/// The archive is the trash can: a restore after a preview beats that
/// preview's confirm, and the record stays live.
#[test]
fn a_restore_beats_an_earlier_preview() {
    let fx = fixture();
    let husk = fx.archived_husk();

    let preview = fx.owner_call(PREVIEW, json!({ "targets": [husk] }));
    let row = entry(&preview, &husk);
    assert_eq!(row["outcome"], "previewed", "{preview}");
    let expected = row["expected"].clone();

    fx.vault
        .restore_archived(&EntityId::from_hex(&husk).expect("husk id"))
        .expect("the owner restores from the archive");
    assert!(
        !fx.archived(&husk),
        "the restore takes the record out of the archive"
    );

    let confirmed = fx.owner_call(
        CONFIRM,
        json!({ "items": [{ "entity": husk, "expected": expected }] }),
    );
    assert_eq!(
        refused_code(entry(&confirmed, &husk)),
        "BAD_REQUEST",
        "{confirmed}"
    );
    assert!(fx.stored(&husk), "the restored record is kept");
    assert!(!fx.shell(&husk), "the restored record stays live");
}

/// The owner empties an archived completed attempt: the confirm deletes
/// its row at once and stamps the receipt; nothing is left to preview.
#[test]
fn the_owner_empties_an_archived_attempt_at_once() {
    let fx = fixture();
    fx.archive_the_attempt();
    let attempt = attempt_hex(fx.attempt);

    let preview = fx
        .owner_attempt_call(ATTEMPT_PREVIEW, json!({ "attempt": attempt }))
        .expect("the owner previews the archived attempt");
    assert_eq!(preview["attempt"], attempt, "{preview}");
    assert!(
        preview["record_bytes"].as_u64().expect("record bytes") > 0,
        "{preview}"
    );
    let expected = preview["expected"].clone();

    let receipt = fx
        .owner_attempt_call(
            ATTEMPT_CONFIRM,
            json!({ "attempt": attempt, "expected": expected }),
        )
        .expect("the owner empties the archived attempt");
    assert_eq!(receipt["attempt"], attempt, "{receipt}");
    assert_eq!(receipt["role"], "owner", "{receipt}");
    assert_eq!(receipt["deleted_by"], fx.owner.to_hex(), "{receipt}");
    assert!(
        receipt["receipt_ref"]
            .as_str()
            .is_some_and(|text| text.starts_with("attempt_delete:")),
        "{receipt}"
    );

    assert!(!fx.attempt_stored(), "the attempt's row is gone at once");
    let again = fx
        .owner_attempt_call(ATTEMPT_PREVIEW, json!({ "attempt": attempt }))
        .expect_err("nothing is left to empty");
    assert_eq!(again.code, MEMORY_CODE_INVALID_STATE, "{again:?}");
}

/// No agent empties an archived attempt, its delete Grant included: the
/// attempt has no disclosure position, so the act is the owner's (or a
/// shared vault's Admin's). The row stays archived.
#[test]
fn an_agent_never_empties_an_archived_attempt() {
    let fx = fixture();
    fx.archive_the_attempt();
    let attempt = attempt_hex(fx.attempt);
    let expected = fx
        .owner_attempt_call(ATTEMPT_PREVIEW, json!({ "attempt": attempt }))
        .expect("the owner previews the archived attempt")["expected"]
        .clone();

    let preview = fx
        .agent_call(fx.granted, ATTEMPT_PREVIEW, json!({ "attempt": attempt }))
        .expect_err("an agent never previews an attempt delete");
    assert_eq!(preview.code, MEMORY_CODE_FORBIDDEN, "{preview:?}");
    assert_eq!(preview.message, "attempt_delete_no_standing", "{preview:?}");
    let confirmed = fx
        .agent_call(
            fx.granted,
            ATTEMPT_CONFIRM,
            json!({ "attempt": attempt, "expected": expected }),
        )
        .expect_err("an agent never empties an archived attempt");
    assert_eq!(confirmed.code, MEMORY_CODE_FORBIDDEN, "{confirmed:?}");

    assert!(fx.attempt_stored(), "the archived attempt's row is kept");
    assert!(fx.attempt_listed().is_none(), "the attempt stays archived");
    let still = fx
        .owner_attempt_call(ATTEMPT_PREVIEW, json!({ "attempt": attempt }))
        .expect("the owner still previews the archived attempt");
    assert_eq!(still["expected"], expected, "the archive is unchanged");
}
