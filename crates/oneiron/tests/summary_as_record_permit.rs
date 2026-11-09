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
use oneiron::error::GateError;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::test_doors::scope_summary::mint_scope_summary;
use oneiron::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    Error, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
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
