//! A declared scope summary (ARCH-0006a) as the Dreamer composes it: only
//! from what its own read admits, bound to every MESSAGE its words came from,
//! settled whatever the post-call re-read finds, and composed once for an
//! unchanged declaration (review repros, #1353).
use super::witnessed_turns::{
    RecordingBackend, admit, delete_message, grant_messages, guard, message, open_clocked_vault,
    witness,
};
use super::*;
use crate::conversation_dag::fixtures::{body, input, time};
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::edge::EdgeKind;
use crate::memory::{WitnessAuthor, WitnessMessage};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY};
use crate::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};

const SECRET: &str = "the gate code is 4417";

/// Never reached: every attempt these tests run is a declared summary.
struct NoInner;

impl DreamerAttemptExecutor for NoInner {
    async fn execute(
        &mut self,
        _: &DreamerAdmittedAttempt,
        _: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        panic!("only declared summaries run here")
    }
}

/// Revokes the Dreamer's MESSAGE grant while the model writes.
struct RevokingBackend<'v> {
    vault: &'v Vault,
    grant: EntityId,
    inner: ScriptedBackend,
}

impl LlmBackend for RevokingBackend<'_> {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.vault
            .revoke_access_grant(&self.grant, 2)
            .expect("revoke the grant mid-call");
        self.inner.generate(request, lease)
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

fn canonical(conversation: EntityId) -> ScopeSelector {
    ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: false,
    }
}

/// Declares a canonical summary of `conversation`, landed as a header and
/// reply on `land_on` when one is named.
fn declare(
    vault: &Vault,
    requester: EntityId,
    conversation: EntityId,
    land_on: Option<EntityId>,
) -> Result<()> {
    vault.request_scope_summary(&ScopeSummaryRequest {
        target: ScopeSummaryTarget::Scope {
            scope: canonical(conversation),
            land_on,
            as_record: land_on.is_some(),
        },
        requester: WriteActor::new(requester, EdgeActorClass::Human),
    })?;
    Ok(())
}

/// Admits the queued declaration and runs it through the Dreamer's arm.
fn compose(vault: &Vault, backend: &dyn LlmBackend) -> Result<DreamerAttemptExecution> {
    run(vault, &admit(vault)?, backend)
}

/// Runs an admitted declaration through the Dreamer's arm.
fn run(
    vault: &Vault,
    admitted: &DreamerAdmittedAttempt,
    backend: &dyn LlmBackend,
) -> Result<DreamerAttemptExecution> {
    let guard = guard();
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = ScopeSummaryExecutor::new(
        NoInner,
        backend,
        &guard,
        vault.dreamer_authority()?,
        crate::ModelId::new("test/model@r1").expect("test model"),
        test_inference_host(),
        Some("Summarize these records."),
    );
    block_on_ready(executor.execute(
        admitted,
        &mut WakeAttemptContext {
            vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
            prepared_wake: None,
            prepared_attempt: None,
        },
    ))
}

fn summaries(vault: &Vault) -> Vec<EntityId> {
    vault
        .entities_by_type(ENTITY_TYPE_SUMMARY)
        .expect("summaries")
}

/// The witness PERSON `witness` minted for `seed`, allowed to land headers.
fn requester(vault: &Vault, seed: u8) -> Result<EntityId> {
    let person = EntityId::from_bytes([seed; 16])?;
    crate::conversation_dag::test_support::put_dag_test_policy(
        vault,
        WriteActor::new(person, EdgeActorClass::Human),
        true,
    )?;
    Ok(person)
}

/// An author allowed to append to, and land on, a fresh DAG conversation.
fn dag_conversation(vault: &Vault) -> Result<(WriteActor, EntityId)> {
    let author = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    vault.put_entity(
        &author.entity_ref(),
        ENTITY_TYPE_PERSON,
        time(1),
        1,
        &body("author"),
    )?;
    crate::conversation_dag::test_support::put_dag_test_policy(vault, author, true)?;
    let conversation = EntityId::now();
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_CONVERSATION,
        time(1),
        1,
        &body("conversation"),
    )?;
    Ok((author, conversation))
}

/// Finding 2: inline TURN text reaches the model only through the Dreamer's
/// own read. The owner withdraws that read before the pass runs, and the
/// TURN's words never enter a prompt.
#[test]
fn inline_turn_text_outside_the_dreamers_read_never_reaches_the_model() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (author, conversation) = dag_conversation(&vault)?;
    vault.append_dag_record(&crate::conversation_dag::AppendRecord {
        body: turn_body("user", SECRET, None),
        ..input(conversation, None, true, author)
    })?;
    declare(&vault, author.entity_ref(), conversation, None)?;
    let admitted = admit(&vault)?;
    crate::test_util::withhold_dreamer_read(&vault)?;
    let backend = RecordingBackend::new(vec![Ok(text_response(SECRET.to_owned()))]);
    let outcome = run(&vault, &admitted, &backend);
    let requests = backend.requests.lock().expect("request log");
    assert!(
        !requests.iter().any(|request| {
            request
                .messages
                .iter()
                .flat_map(|message| &message.content)
                .any(|part| matches!(part, ContentPart::Text { text } if text.contains(SECRET)))
        }),
        "the withheld TURN's words reached the model"
    );
    assert!(outcome.is_err(), "{outcome:?}");
    assert!(summaries(&vault).is_empty());
    Ok(())
}

/// Greptile #1353: a record in the scope with no text to read is not among
/// the summary's covers; `covers` are exactly what the model read.
#[test]
fn a_record_without_text_is_not_covered() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (author, conversation) = dag_conversation(&vault)?;
    let said = vault.append_dag_record(&crate::conversation_dag::AppendRecord {
        body: turn_body("user", "the first words", None),
        ..input(conversation, None, true, author)
    })?;
    let mut silent = Vec::new();
    rmpv::encode::write_value(
        &mut silent,
        &Value::Map(vec![(Value::from("spkr"), Value::from("user"))]),
    )
    .expect("text-less turn body");
    vault.append_dag_record(&crate::conversation_dag::AppendRecord {
        body: silent,
        ..input(conversation, Some(said.id), true, author)
    })?;
    declare(&vault, author.entity_ref(), conversation, None)?;
    let backend = RecordingBackend::new(vec![Ok(text_response("a summary".to_owned()))]);
    let outcome = compose(&vault, &backend)?;
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "{outcome:?}"
    );
    let [summary] = summaries(&vault)[..] else {
        panic!("one summary")
    };
    assert_eq!(vault.scope_summary_covers(&summary)?, [said.id]);
    Ok(())
}

/// Finding 3: summarise a witnessed TURN, then erase the MESSAGE whose words
/// the body holds. The summary and the reply copied from it are invalidated
/// in the erasing transaction and never served again.
#[test]
fn erasing_a_message_retires_the_summary_and_reply_written_from_it() -> Result<()> {
    let (_dir, vault) = open_vault();
    let said = message(0, WitnessAuthor::User, SECRET, true);
    let (turn, conversation) = witness(&vault, 0x6A, vec![said]);
    let person = requester(&vault, 0x6A)?;
    declare(&vault, person, conversation, Some(turn))?;
    let backend = RecordingBackend::new(vec![Ok(text_response(format!("They said {SECRET}.")))]);
    let outcome = compose(&vault, &backend)?;
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "{outcome:?}"
    );
    let [summary] = summaries(&vault)[..] else {
        panic!("one summary")
    };
    let reply = vault
        .resolve_dag_scope(&canonical(conversation))?
        .records
        .into_iter()
        .find(|record| *record != turn)
        .expect("the summary's reply");
    let [said] = vault.sources(&turn, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))?[..] else {
        panic!("one MESSAGE")
    };
    let reader = super::super::turn_text::dreamer_read(&vault)?;
    assert!(reader.is_entity_readable(&summary)? && reader.is_entity_readable(&reply)?);
    assert_eq!(vault.scope_summary_covers(&summary)?, [turn]);

    delete_message(&vault, said)?;

    assert!(vault.scope_summary_covers(&summary).is_err());
    assert!(
        !reader.is_entity_readable(&summary)?,
        "the summary is served"
    );
    assert!(!reader.is_entity_readable(&reply)?, "the reply is served");
    assert!(
        vault
            .land_header(
                &summary,
                &turn,
                WriteActor::new(person, EdgeActorClass::Human),
                false
            )
            .is_err()
    );
    Ok(())
}

/// Human readers each granted `core:read` over one set of entity types, in
/// one test policy.
fn granted_readers<'v>(
    vault: &'v Vault,
    grants: &[&[u8]],
) -> Result<Vec<crate::claim::ScopedRead<'v>>> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let mut read = crate::federation::Scope::top();
    read.verbs = crate::federation::ScopeAxis::Some(["read".to_owned()].into());
    let mut readers = Vec::new();
    let mut rows = Vec::new();
    for types in grants {
        let reader = EntityId::now();
        vault.put_entity(&reader, ENTITY_TYPE_PERSON, time(1), 1, &body("reader"))?;
        rows.push(serde_json::json!({
            "actor_ref": reader.to_hex(),
            "effector": "core:read",
            "scope": serde_json::to_value(&read).expect("scope json"),
            "selectors": {"entity_types": types},
            "receipt_required": false,
        }));
        let key = crate::claim::ScopedReadActorKey::with_actor_class(reader.to_hex(), "human")
            .expect("reader key");
        readers.push(vault.scoped_read(key));
    }
    crate::conversation_dag::test_support::put_test_policy_manifest(
        vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        EntityId::now(),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "summary-readers", "pack_version": "1",
            "min_engine_version": "0.0.0", "defaults": {}, "rules": [], "actor_ceilings": [],
            "scoped_grants": rows,
        }),
    )?;
    Ok(readers)
}

/// Finding 3, the reader's half (Astra re-check): a reader whose grant reads
/// SUMMARYs and TURNs but no MESSAGE reads neither the summary nor the reply
/// written from one; a reader who may read the MESSAGE reads both.
#[test]
fn a_reader_who_may_not_read_the_message_reads_no_summary_of_it() -> Result<()> {
    let (_dir, vault) = open_vault();
    let said = message(0, WitnessAuthor::User, SECRET, true);
    let (turn, conversation) = witness(&vault, 0x6E, vec![said]);
    let person = requester(&vault, 0x6E)?;
    declare(&vault, person, conversation, Some(turn))?;
    let backend = RecordingBackend::new(vec![Ok(text_response(format!("They said {SECRET}.")))]);
    let outcome = compose(&vault, &backend)?;
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "{outcome:?}"
    );
    let [summary] = summaries(&vault)[..] else {
        panic!("one summary")
    };
    let reply = vault
        .resolve_dag_scope(&canonical(conversation))?
        .records
        .into_iter()
        .find(|record| *record != turn)
        .expect("the summary's reply");
    let readers = granted_readers(
        &vault,
        &[
            &[ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN, ENTITY_TYPE_MESSAGE],
            &[ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN],
        ],
    )?;
    let [full, narrow] = &readers[..] else {
        panic!("two readers")
    };
    assert!(
        full.is_entity_readable(&summary)?,
        "the control reads the summary"
    );
    assert!(
        full.is_entity_readable(&reply)?,
        "the control reads the reply"
    );
    assert!(
        !narrow.is_entity_readable(&summary)?,
        "the summary is served"
    );
    assert!(!narrow.is_entity_readable(&reply)?, "the reply is served");
    // The same association under a longer string encoding of its key,
    // written through the raw put door, is still a reply to the summary.
    let mut copy = vec![0x82];
    rmpv::encode::write_value(&mut copy, &Value::from("txt")).expect("key");
    rmpv::encode::write_value(&mut copy, &Value::from(format!("They said {SECRET}.")))
        .expect("text");
    copy.extend_from_slice(b"\xd9\x07summary");
    rmpv::encode::write_value(&mut copy, &Value::from(summary.to_hex())).expect("ref");
    let forged = EntityId::now();
    vault.put_entity(&forged, ENTITY_TYPE_TURN, time(30), 30, &copy)?;
    assert!(
        !narrow.is_entity_readable(&forged)?,
        "a str8 key serves the copy"
    );
    Ok(())
}

/// Finding 5: the Dreamer's MESSAGE grant is revoked while the model writes.
/// The re-read refuses, and the paid call still settles on the wake budget.
#[test]
fn a_grant_revoked_during_the_call_still_charges_the_wake() -> Result<()> {
    let (_dir, vault, _clock) = open_clocked_vault();
    let space = EntityId::now();
    let (_, conversation) = witness(
        &vault,
        0x6B,
        vec![WitnessMessage {
            metadata: Some(serde_json::json!({"rel": space.to_hex()})),
            ..message(0, WitnessAuthor::User, SECRET, true)
        }],
    );
    let grant = grant_messages(&vault, space, u64::MAX)?;
    let person = requester(&vault, 0x6B)?;
    declare(&vault, person, conversation, None)?;
    let backend = RevokingBackend {
        vault: &vault,
        grant,
        inner: ScriptedBackend::new(vec![Ok(text_response("a summary".to_owned()))]),
    };
    let outcome = compose(&vault, &backend)?;
    // text_response bills 40 input and 10 output units.
    assert!(
        matches!(
            outcome,
            DreamerAttemptExecution::ParkWithSpend {
                completed_units: 50,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(summaries(&vault).is_empty());
    Ok(())
}

/// Finding 6: the same declaration twice over unchanged sources makes one
/// model call and one SUMMARY.
#[test]
fn an_unchanged_declaration_composes_once() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_, conversation) = witness(
        &vault,
        0x6C,
        vec![message(0, WitnessAuthor::User, SECRET, true)],
    );
    let person = requester(&vault, 0x6C)?;
    let backend = RecordingBackend::new(vec![
        Ok(text_response("a summary".to_owned())),
        Ok(text_response("a second summary".to_owned())),
    ]);
    for _ in 0..2 {
        declare(&vault, person, conversation, None)?;
        let admitted = admit(&vault)?;
        let outcome = run(&vault, &admitted, &backend)?;
        assert!(
            matches!(outcome, DreamerAttemptExecution::Completed { .. }),
            "{outcome:?}"
        );
        // The first declaration is settled before the second arrives, so the
        // second is a fresh attempt, not a coalesced one.
        DreamerRunnerStore::new(&vault).complete(
            crate::dreamer_runner::CompleteDreamerAttempt {
                id: admitted.status.attempt.id,
                lease_owner: "witness-worker".to_owned(),
                attempt_count: admitted.status.attempt.attempt_count,
                now: 22,
            },
        )?;
    }
    assert_eq!(backend.requests.lock().expect("request log").len(), 1);
    assert_eq!(summaries(&vault).len(), 1);
    Ok(())
}
