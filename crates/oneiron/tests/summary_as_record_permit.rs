//! The owner's summary-as-record lands on a default vault (Engine ruling
//! SUMMARY-AS-RECORD-PERMIT-SHAPE = A).
//!
//! A scope summary's merge header and its trunk reply TURN hold words the
//! Dreamer composed, so both are generated (ARCH-0040). Written under the
//! requester's actor, both pended on `gate.pending.source_trust` on a default
//! vault, and the owner's `as_record` summary was refused. Both now land
//! under the derived scope summary landing MACHINE, which two
//! default-manifest rows trust, each keyed to that one writer: a `system`
//! ceiling of auto, and a `generated` permit at the unstamped band,
//! receipted and warned. The requester stays the reply's read lane and holds
//! its receipts.
//!
//! The REST summary door (`POST /v1/conversations/{id}/summaries` with
//! `as_record`) only queues the request: the words come from a Dreamer
//! attempt, which needs a model. So this test mints the summary as the
//! Dreamer through a test door and lands it through `Vault::land_header`,
//! which runs the same `land_in_txn` the Dreamer's completion runs. The vault
//! is rooted and its engine writers provisioned, as the server does on open,
//! because a MACHINE's header claim carries the engine's signature.
//!
//! Controls: the owner's own generated claim still pends on source trust,
//! and a caller that names the landing writer is refused, on the DAG append
//! door and on the claim batch.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test summary_as_record_permit`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::error::{GateError, RecordError};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::test_doors::scope_summary::{
    apply_raw_landing_reply, apply_raw_landing_reply_edges, mint_scope_summary,
};
use oneiron::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The gate's reason for a write whose source needs a permit it lacks.
const PENDING_SOURCE_TRUST: &str = "gate.pending.source_trust";

/// The shipped default policy pack, whose manifest a read grant is added to.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// The landing writer's derivation domain, the engine's
/// `derived_domains::SCOPE_SUMMARY_LANDING_ACTOR`, spelled out so the test
/// also builds on the head before the fix (its red run) and pins the id.
const SCOPE_SUMMARY_LANDING_ACTOR: &[u8] = b"oneiron.scope-summary.landing.actor.v1";

/// The landing writer's refusal of an append that is not a landing's reply.
const NOT_A_LANDING: &str = "only a scope summary landing writes as its landing writer";

/// The landing reply rule's refusal contains this.
const LANDING_REPLY_REFUSAL: &str = "landing reply";

/// The pin refusal of an exact local re-put.
const APPEND_ONLY_REFUSAL: &str = "DAG records are append-only";

/// A rooted default vault, its owner and a two-record trunk the owner wrote.
/// The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    conversation: EntityId,
    trunk: [EntityId; 2],
    _dir: tempfile::TempDir,
}

/// The landing writer's id, derived from its domain as the engine derives it.
fn landing_writer() -> TestResult<EntityId> {
    Ok(EntityId::derive(SCOPE_SUMMARY_LANDING_ACTOR, &[])?)
}

/// Opens the vault. `writer_reads` first lets the landing writer read the
/// vault's conversations, so a caller's append under it reaches the append
/// door's checks instead of the reference check.
fn open(writer_reads: bool) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    if writer_reads {
        permit_conversation_reads(&vault, landing_writer()?)?;
    }
    // The server roots its vault and provisions the engine's MACHINE writers
    // on every open.
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let (conversation, trunk) = {
        let host = vault.memory(owner, EdgeActorClass::Human);
        let receipt = host.conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
        let conversation = EntityId::from_hex(&receipt.id)?;
        let first =
            host.conversations_records_append(&trunk_record(conversation, None, "the plan"))?;
        let second = host.conversations_records_append(&trunk_record(
            conversation,
            Some(&first.id),
            "the first step",
        ))?;
        (
            conversation,
            [
                EntityId::from_hex(&first.id)?,
                EntityId::from_hex(&second.id)?,
            ],
        )
    };
    Ok(Fixture {
        vault,
        owner,
        conversation,
        trunk,
        _dir: dir,
    })
}

/// One trunk record that advances HEAD from `parent`.
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

/// Lets `actor` read the vault's conversations: one actor-bound `core:read`
/// row added to the shipped policy manifest, its other rows and its
/// source-trust table kept as they are.
fn permit_conversation_reads(vault: &Vault, actor: EntityId) -> TestResult {
    let mut shipped = None;
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let Some(bytes) = vault.get(&id)? else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) = shipped.ok_or("the vault holds no shipped policy manifest")?;
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    manifest["scoped_grants"]
        .as_array_mut()
        .ok_or("the shipped policy manifest has no scoped grants")?
        .push(json!({
            "actor_ref": actor.to_hex(),
            "effector": "core:read",
            "scope": read,
            "receipt_required": false,
            "selectors": {"entity_types": [ENTITY_TYPE_CONVERSATION]},
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    Ok(())
}

/// The whole canonical trunk of `conversation`.
fn canonical(conversation: EntityId) -> ScopeSelector {
    ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: false,
    }
}

/// The writer a claim's write envelope stamped into its evidence.
fn claim_writer(evidence: Option<&Value>) -> Option<EntityId> {
    let Some(Value::Map(entries)) = evidence else {
        return None;
    };
    let (_, Value::Binary(bytes)) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY))?
    else {
        return None;
    };
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}

/// A `generated` claim about the owner under `actor`, asking for auto.
fn generated_claim(fixture: &Fixture, actor: WriteActor) -> TestResult<(EntityId, Error)> {
    let vault = &fixture.vault;
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    let refusal = vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(fixture.owner),
                Value::from("Ada"),
                1.0,
            ),
            &WriteEnvelope::new(
                actor,
                ClaimSource::Generated,
                WriteProvenance::new(Value::from("summary-as-record control"))?,
                ClaimApprovalStatus::Auto,
            ),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .commit()
        .err()
        .ok_or("the generated claim was written")?;
    Ok((id, refusal))
}

/// A TURN body as its map entries, with no trailing bytes.
fn body_entries(body: &[u8]) -> TestResult<Vec<(Value, Value)>> {
    let mut cursor = body;
    let Value::Map(entries) =
        rmpv::decode::read_value(&mut cursor).map_err(|err| format!("invalid TURN body: {err}"))?
    else {
        return Err("TURN body is not a map".into());
    };
    if !cursor.is_empty() {
        return Err("trailing TURN body bytes".into());
    }
    Ok(entries)
}

/// Map entries encoded as a TURN body.
fn encode_entries(entries: Vec<(Value, Value)>) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .map_err(|err| format!("TURN body encode failed: {err}"))?;
    Ok(bytes)
}

/// Copies `body` with its `txt` replaced by `text`.
fn body_with_text(body: &[u8], text: &str) -> TestResult<Vec<u8>> {
    let mut entries = body_entries(body)?;
    let mut replaced = false;
    for (key, value) in &mut entries {
        if key.as_str() == Some("txt") {
            *value = Value::from(text);
            replaced = true;
        }
    }
    if !replaced {
        return Err("TURN body has no txt".into());
    }
    encode_entries(entries)
}

/// Copies `body` with its `reply_to` pointer answering `target` at
/// `revision`. Other pointer fields stay as they are.
fn body_with_reply_to(body: &[u8], target: EntityId, revision: &str) -> TestResult<Vec<u8>> {
    let mut entries = body_entries(body)?;
    let mut replaced = false;
    for (key, value) in &mut entries {
        if key.as_str() == Some("reply_to") {
            let Value::Map(pointer) = value else {
                return Err("reply pointer is not a map".into());
            };
            let mut saw_record = false;
            let mut saw_revision = false;
            for (pkey, pvalue) in pointer.iter_mut() {
                if pkey.as_str() == Some("record") {
                    *pvalue = Value::from(target.to_hex());
                    saw_record = true;
                } else if pkey.as_str() == Some("revision") {
                    *pvalue = Value::from(revision);
                    saw_revision = true;
                }
            }
            if !saw_record || !saw_revision {
                return Err("reply pointer lacks record or revision".into());
            }
            replaced = true;
        }
    }
    if !replaced {
        return Err("TURN body has no reply_to".into());
    }
    encode_entries(entries)
}

/// The revision a reply captures of `turn`: the blake3 of its body.
fn turn_revision(vault: &Vault, turn: &EntityId) -> TestResult<String> {
    let body = vault.get(turn)?.ok_or("the reply target is stored")?;
    Ok(blake3::hash(&body).to_hex().to_string())
}

/// Asserts `err` is a DAG refusal whose message contains `needle`.
fn assert_dag_refusal(err: Error, needle: &str) -> TestResult {
    match &err {
        Error::Record(RecordError::InvalidConversationDag(msg)) if msg.contains(needle) => Ok(()),
        _ => Err(
            format!("expected InvalidConversationDag containing {needle:?}, got {err:?}").into(),
        ),
    }
}

#[test]
fn the_owners_summary_as_record_lands_its_header_and_reply_under_the_landing_writer() -> TestResult
{
    let fixture = open(false)?;
    let vault = &fixture.vault;
    let [asking, last] = fixture.trunk;
    let summary = mint_scope_summary(
        vault,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;

    let landed = vault
        .land_header(
            &summary,
            &asking,
            WriteActor::new(fixture.owner, EdgeActorClass::Human),
            true,
        )
        .expect("the owner's summary-as-record lands on the landing writer's permit");
    let writer = landing_writer()?;

    // The header: generated, and the landing writer's.
    let header = vault
        .get_claim(&landed.claim)?
        .ok_or("the header claim is stored")?;
    assert_eq!(header.predicate, "merge.summary");
    assert_eq!(header.subject, ClaimSubject::Entity(asking));
    assert_eq!(header.source, Some(ClaimSource::Generated));
    assert_eq!(claim_writer(header.evidence.as_ref()), Some(writer));

    // The reply: the trunk's new HEAD, the landing writer's, replying to the
    // turn the summary landed on.
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    let body: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&reply)?.ok_or("the reply is stored")?)?;
    assert_eq!(body["actor"], writer.to_hex());
    assert_eq!(body["summary"], summary.to_hex());
    assert_eq!(body["reply_to"]["record"], asking.to_hex());
    assert_ne!(reply, last);
    Ok(())
}

/// The permit is the landing writer's alone: the owner's own generated
/// claim reads the class as having no row and keeps pending.
#[test]
fn the_owners_other_generated_claim_still_pends_on_source_trust() -> TestResult {
    let fixture = open(false)?;
    let (id, refusal) = generated_claim(
        &fixture,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
    )?;
    assert!(
        matches!(
            &refusal,
            Error::Gate(GateError::GateWriteRejected { outcome, reason_codes })
                if *outcome == "pending" && reason_codes.contains(&PENDING_SOURCE_TRUST)
        ),
        "the owner's generated claim pends on source trust: {refusal:?}"
    );
    assert!(fixture.vault.get_claim(&id)?.is_none(), "nothing landed");
    Ok(())
}

/// A served door cannot name the landing writer: it binds the credential's
/// principal. The in-process API can, and both of its doors refuse it.
#[test]
fn a_caller_that_names_the_landing_writer_is_refused() -> TestResult {
    let fixture = open(true)?;
    let vault = &fixture.vault;
    let writer = landing_writer()?;
    let [_, last] = fixture.trunk;

    // The DAG append door: the writer reads the conversation, so only the
    // landing check stands between this append and the writer's permit.
    let mut append = trunk_record(fixture.conversation, None, "not a summary's reply");
    append.advance = false;
    let refusal = vault
        .memory(writer, EdgeActorClass::System)
        .conversations_records_append(&append)
        .expect_err("an append under the landing writer is not a landing's reply");
    assert!(
        refusal.message.contains(NOT_A_LANDING),
        "refused by the landing check: {refusal:?}"
    );
    assert_eq!(vault.head(&fixture.conversation)?, Some(last));

    // The claim batch: a MACHINE's claim needs the engine's signature, which
    // the host-provisioned signer gives only to the engine's own writes.
    // `generated_claim` fails the test if the claim lands.
    let (id, _refusal) =
        generated_claim(&fixture, WriteActor::new(writer, EdgeActorClass::System))?;
    assert!(vault.get_claim(&id)?.is_none(), "nothing landed");
    Ok(())
}

/// A copied landing reply with other words is not its landing's reply.
#[test]
fn a_copied_landing_reply_with_other_text_is_refused() -> TestResult {
    let fixture = open(false)?;
    let vault = &fixture.vault;
    let [asking, _last] = fixture.trunk;
    let summary = mint_scope_summary(
        vault,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = vault.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    let original_body = vault.get(&reply)?.ok_or("the reply is stored")?;
    let forged_body = body_with_text(&original_body, "forged words")?;
    let forged = EntityId::now();
    let refusal = apply_raw_landing_reply(
        vault,
        &reply,
        &forged,
        &forged_body,
        fixture.conversation,
        Some(reply),
        Some(asking),
    )
    .err()
    .ok_or("a copied landing reply with other text lands")?;
    assert_dag_refusal(refusal, LANDING_REPLY_REFUSAL)?;
    assert!(vault.get(&forged)?.is_none(), "nothing landed");
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    let body: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&reply)?.ok_or("the reply is stored")?)?;
    assert_eq!(body["txt"].as_str(), Some("The plan, and its first step."));
    Ok(())
}

/// A copied landing reply in another room is not its landing's reply.
#[test]
fn a_copied_landing_reply_in_another_room_is_refused() -> TestResult {
    let fixture = open(false)?;
    let vault = &fixture.vault;
    let [asking, _last] = fixture.trunk;
    let other_conversation = {
        let host = vault.memory(fixture.owner, EdgeActorClass::Human);
        let receipt = host.conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
        let conversation = EntityId::from_hex(&receipt.id)?;
        let first =
            host.conversations_records_append(&trunk_record(conversation, None, "other plan"))?;
        let _second = host.conversations_records_append(&trunk_record(
            conversation,
            Some(&first.id),
            "other step",
        ))?;
        conversation
    };
    let other_head = vault
        .head(&other_conversation)?
        .ok_or("the other room has a head")?;
    let summary = mint_scope_summary(
        vault,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = vault.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    // Room mismatch alone: the unchanged body still answers its landing's turn.
    let original_body = vault.get(&reply)?.ok_or("the reply is stored")?;
    let forged = EntityId::now();
    let refusal = apply_raw_landing_reply(
        vault,
        &reply,
        &forged,
        &original_body,
        other_conversation,
        Some(other_head),
        Some(asking),
    )
    .err()
    .ok_or("a copied landing reply in another room lands")?;
    assert_dag_refusal(refusal, LANDING_REPLY_REFUSAL)?;
    assert!(vault.get(&forged)?.is_none(), "nothing landed");
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    assert_eq!(vault.head(&other_conversation)?, Some(other_head));
    let body: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&reply)?.ok_or("the reply is stored")?)?;
    assert_eq!(body["summary"], summary.to_hex());
    Ok(())
}

/// A copied landing reply to another turn is not its landing's reply.
#[test]
fn a_copied_landing_reply_to_another_turn_is_refused() -> TestResult {
    let fixture = open(false)?;
    let vault = &fixture.vault;
    let [asking, last] = fixture.trunk;
    let summary = mint_scope_summary(
        vault,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = vault.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    // Primary: unchanged real body, wrong RepliesTo edge.
    let original_body = vault.get(&reply)?.ok_or("the reply is stored")?;
    let forged = EntityId::now();
    let refusal = apply_raw_landing_reply(
        vault,
        &reply,
        &forged,
        &original_body,
        fixture.conversation,
        Some(reply),
        Some(last),
    )
    .err()
    .ok_or("a copied landing reply to another turn lands")?;
    assert_dag_refusal(refusal, LANDING_REPLY_REFUSAL)?;
    assert!(vault.get(&forged)?.is_none(), "nothing landed");
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    // Coherent retarget: body's reply_to matches its malicious edge, so
    // admission must check the signed landing target, not coherence.
    let revision = turn_revision(vault, &last)?;
    let forged_body = body_with_reply_to(&original_body, last, &revision)?;
    let retargeted_reply = EntityId::now();
    let retarget_refusal = apply_raw_landing_reply(
        vault,
        &reply,
        &retargeted_reply,
        &forged_body,
        fixture.conversation,
        Some(reply),
        Some(last),
    )
    .err()
    .ok_or("a coherent retarget to another turn lands")?;
    assert_dag_refusal(retarget_refusal, LANDING_REPLY_REFUSAL)?;
    assert!(vault.get(&retargeted_reply)?.is_none(), "nothing landed");
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    // Edge-only: the real landing reply gains no second RepliesTo.
    let edge_refusal =
        apply_raw_landing_reply_edges(vault, &reply, fixture.conversation, None, Some(last))
            .err()
            .ok_or("a landing reply gains a second RepliesTo")?;
    assert_dag_refusal(edge_refusal, LANDING_REPLY_REFUSAL)?;
    assert!(
        !vault.edge_exists(&reply, EdgeKind::RepliesTo, &last)?,
        "no second RepliesTo landed"
    );
    assert!(
        vault.edge_exists(&reply, EdgeKind::RepliesTo, &asking)?,
        "the landing RepliesTo stands"
    );
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    Ok(())
}

/// The real landing reply still lands, and its exact re-put still pins.
#[test]
fn the_real_landing_reply_still_lands_and_reapplies() -> TestResult {
    let fixture = open(false)?;
    let vault = &fixture.vault;
    let [asking, last] = fixture.trunk;
    let summary = mint_scope_summary(
        vault,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = vault.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    let writer = landing_writer()?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    let body: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&reply)?.ok_or("the reply is stored")?)?;
    assert_eq!(body["actor"], writer.to_hex());
    assert_eq!(body["summary"], summary.to_hex());
    assert_eq!(body["reply_to"]["record"], asking.to_hex());
    // Its exact re-put refuses as append-only, as before, changing nothing.
    let original_body = vault.get(&reply)?.ok_or("the reply is stored")?;
    let refusal = apply_raw_landing_reply(
        vault,
        &reply,
        &reply,
        &original_body,
        fixture.conversation,
        Some(last),
        Some(asking),
    )
    .err()
    .ok_or("an exact re-put lands")?;
    assert_dag_refusal(refusal, APPEND_ONLY_REFUSAL)?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    let again: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&reply)?.ok_or("the reply is stored")?)?;
    assert_eq!(again["summary"], summary.to_hex());
    assert_eq!(again["txt"].as_str(), Some("The plan, and its first step."));
    Ok(())
}

/// A reply under a header signed by an unbound key is refused: the provisional row's key
/// proves nothing about the landing writer, so neither a coherent copied TURN nor an
/// independently staged one gains its ChildOf/RepliesTo.
#[cfg(feature = "sync")]
#[test]
fn a_reply_under_a_header_signed_by_an_unbound_key_is_refused() -> TestResult {
    let fixture = open(false)?;
    let vault = &fixture.vault;
    let [asking, last] = fixture.trunk;
    let summary = mint_scope_summary(
        vault,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = vault.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    // A second header naming (last, summary) by the writer, signed with a fresh key the
    // fold does not bind, through the replicated put path.
    let forged_header =
        oneiron::test_doors::scope_summary::put_unbound_landing_header(vault, &summary, &last)?;
    // The door returns only after its replicated put commits; the ClaimOf in the same
    // batch proves the header row landed. No claim/history/raw-readable read here: H2 is
    // deliberately provisional.
    assert!(
        vault.edge_exists(&forged_header, EdgeKind::ClaimOf, &last)?,
        "the forged ClaimOf is stored"
    );
    // Coherent retarget: body's reply_to matches its edge, so admission must check the
    // fold-bound landing target, not coherence.
    let original_body = vault.get(&reply)?.ok_or("the reply is stored")?;
    let revision = turn_revision(vault, &last)?;
    let forged_body = body_with_reply_to(&original_body, last, &revision)?;
    let forged = EntityId::now();
    let refusal = apply_raw_landing_reply(
        vault,
        &reply,
        &forged,
        &forged_body,
        fixture.conversation,
        Some(reply),
        Some(last),
    )
    .err()
    .ok_or("a reply under an unbound key lands")?;
    assert_dag_refusal(refusal, LANDING_REPLY_REFUSAL)?;
    assert!(vault.get(&forged)?.is_none(), "nothing landed");
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    // Edge-only: an independently staged TURN gains no ChildOf/RepliesTo under the
    // unbound header either.
    let staged = EntityId::now();
    let now = vault.now_recorded_at();
    vault
        .batch()
        .put(
            &staged,
            oneiron::registry::ENTITY_TYPE_TURN,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &forged_body,
        )
        .commit()?;
    assert!(vault.get(&staged)?.is_some(), "the staged body is stored");
    let edge_refusal = apply_raw_landing_reply_edges(
        vault,
        &staged,
        fixture.conversation,
        Some(reply),
        Some(last),
    )
    .err()
    .ok_or("a staged reply gains edges under an unbound key")?;
    assert_dag_refusal(edge_refusal, LANDING_REPLY_REFUSAL)?;
    assert!(
        !vault.edge_exists(&staged, EdgeKind::ChildOf, &fixture.conversation)?,
        "no ChildOf landed"
    );
    assert!(
        !vault.edge_exists(&staged, EdgeKind::RepliesTo, &last)?,
        "no RepliesTo landed"
    );
    assert_eq!(vault.head(&fixture.conversation)?, Some(reply));
    assert!(
        vault.edge_exists(&reply, EdgeKind::RepliesTo, &asking)?,
        "the landing RepliesTo stands"
    );
    Ok(())
}

/// A reply whose ChildOf/RepliesTo replay before its landing's ClaimOf still lands
/// after it in the same page: the edge pass defers the early edges with their replay
/// marker and retries them once the landing arrives, whatever the map's key order.
#[cfg(feature = "sync")]
#[test]
fn a_reply_placed_before_its_landing_edge_lands_after_it() -> TestResult {
    let fixture = open(false)?;
    let source = &fixture.vault;
    let [asking, _last] = fixture.trunk;
    let summary = mint_scope_summary(
        source,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = source.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let header = landed.claim;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    // A receiving vault sharing the source's authority, so the header's vault-bound
    // signature verifies there as it does here.
    let receiver_dir = tempfile::tempdir()?;
    let receiver = Vault::open_owned(receiver_dir.path(), VaultConfig::default())?;
    receiver.import_signed_authority_history(
        &source.export_signed_authority_history()?,
        &std::collections::BTreeMap::new(),
    )?;
    // One window, R's edges before H's ClaimOf.
    let (window, _count) = oneiron::test_doors::scope_summary::replay_landing_edges_in_order(
        source,
        &receiver,
        &reply,
        &[fixture.conversation, asking, summary, header, reply],
        &[
            (reply, EdgeKind::ChildOf, fixture.conversation),
            (reply, EdgeKind::RepliesTo, asking),
            (asking, EdgeKind::ChildOf, fixture.conversation),
            (header, EdgeKind::ClaimOf, asking),
        ],
    )?;
    assert!(!window.is_empty(), "a window key is returned");
    // The reply is in the receiver's room under T, not merely stored.
    let body: serde_json::Value =
        rmp_serde::from_slice(&receiver.get(&reply)?.ok_or("the reply replayed")?)?;
    assert_eq!(body["summary"], summary.to_hex());
    assert_eq!(body["reply_to"]["record"], asking.to_hex());
    assert!(
        receiver.edge_exists(&reply, EdgeKind::ChildOf, &fixture.conversation)?,
        "R's ChildOf is placed"
    );
    assert!(
        receiver.edge_exists(&reply, EdgeKind::RepliesTo, &asking)?,
        "R's RepliesTo is placed under T"
    );
    assert!(
        receiver.edge_exists(&header, EdgeKind::ClaimOf, &asking)?,
        "H's ClaimOf is placed"
    );
    let quarantined = oneiron::sync::quarantined_records(&receiver)?;
    assert!(
        quarantined.is_empty(),
        "R's edges were not quarantined: {quarantined:?}"
    );
    Ok(())
}

/// A reply whose landing has not arrived yet waits: it is neither admitted nor
/// terminally refused. Its edges keep the source's replay marker, and after H and its
/// ClaimOf replay and the window is walked again the reply is placed.
#[cfg(feature = "sync")]
#[test]
fn a_reply_whose_landing_has_not_arrived_waits() -> TestResult {
    let fixture = open(false)?;
    let source = &fixture.vault;
    let [asking, _last] = fixture.trunk;
    let summary = mint_scope_summary(
        source,
        &canonical(fixture.conversation),
        "The plan, and its first step.",
    )?;
    let landed = source.land_header(
        &summary,
        &asking,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        true,
    )?;
    let header = landed.claim;
    let reply = landed.record.ok_or("as_record lands a reply TURN")?;
    let receiver_dir = tempfile::tempdir()?;
    let receiver = Vault::open_owned(receiver_dir.path(), VaultConfig::default())?;
    receiver.import_signed_authority_history(
        &source.export_signed_authority_history()?,
        &std::collections::BTreeMap::new(),
    )?;
    // First walk: R and its edges, no header H at all.
    let (window, _first) = oneiron::test_doors::scope_summary::replay_landing_edges_in_order(
        source,
        &receiver,
        &reply,
        &[fixture.conversation, asking, summary, reply],
        &[
            (reply, EdgeKind::ChildOf, fixture.conversation),
            (reply, EdgeKind::RepliesTo, asking),
            (asking, EdgeKind::ChildOf, fixture.conversation),
        ],
    )?;
    assert!(
        receiver.get(&reply)?.is_some(),
        "R's body is stored by the entity pass"
    );
    assert!(
        !receiver.edge_exists(&reply, EdgeKind::ChildOf, &fixture.conversation)?,
        "R's ChildOf waits, not placed"
    );
    assert!(
        !receiver.edge_exists(&reply, EdgeKind::RepliesTo, &asking)?,
        "R's RepliesTo waits, not placed"
    );
    let quarantined = oneiron::sync::quarantined_records(&receiver)?;
    assert!(
        quarantined.is_empty(),
        "waiting edges are not quarantined: {quarantined:?}"
    );
    let marker = format!("rm:w:{window}:{}", reply.to_hex());
    assert!(
        receiver.sync_state_get(&marker)?.is_some(),
        "the source keeps its replay marker"
    );
    // Second walk: H and its ClaimOf arrive, the window is walked again, the reply lands.
    let (_window2, _second) = oneiron::test_doors::scope_summary::replay_landing_edges_in_order(
        source,
        &receiver,
        &reply,
        &[fixture.conversation, asking, summary, header, reply],
        &[
            (header, EdgeKind::ClaimOf, asking),
            (reply, EdgeKind::ChildOf, fixture.conversation),
            (reply, EdgeKind::RepliesTo, asking),
            (asking, EdgeKind::ChildOf, fixture.conversation),
        ],
    )?;
    assert!(
        receiver.edge_exists(&reply, EdgeKind::ChildOf, &fixture.conversation)?,
        "R's ChildOf is placed after its landing"
    );
    assert!(
        receiver.edge_exists(&reply, EdgeKind::RepliesTo, &asking)?,
        "R's RepliesTo is placed under T after its landing"
    );
    let quarantined = oneiron::sync::quarantined_records(&receiver)?;
    assert!(
        quarantined.is_empty(),
        "still not quarantined: {quarantined:?}"
    );
    Ok(())
}
