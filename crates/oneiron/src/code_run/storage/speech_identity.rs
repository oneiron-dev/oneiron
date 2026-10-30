//! Deterministic conversation, turn and message ids derived from a run's identity.

use sha2::{Digest, Sha256};

use crate::code_run::dispatcher::HostSelfDispatcher;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::SelfDispatchOutcome;
use crate::lens::RecordRef;
use crate::memory::{CommitReceipt, MessageResultAttachment, WitnessAssertions, WitnessReceipt};
use crate::off_record::ExecutorUtterance;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::task_verb::{TaskCreateReceipt, sdk::AgentVerb};
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// A result MESSAGE's typed attachment (FIX 365), and the rows its run's
/// answers were served from, which its hold on the body keeps.
#[derive(Clone, Copy)]
pub(crate) struct ResultSpeech<'a> {
    pub(crate) attachment: &'a MessageResultAttachment,
    pub(crate) served_rows: Option<&'a [EntityId]>,
}

impl ResultSpeech<'_> {
    /// The MESSAGE metadata that carries the attachment.
    pub(crate) fn metadata(&self) -> Result<serde_json::Value> {
        self.attachment.to_metadata()
    }
}

/// The committed-write refs a run's next speech bubble asserts (FIX 11456).
/// `cited` stays empty: served/read rows are never citations.
#[derive(Default)]
pub(crate) struct RunAssertionCollector {
    created: Vec<RecordRef>,
}

impl RunAssertionCollector {
    fn note(&mut self, reference: RecordRef) {
        if !self.created.contains(&reference) {
            self.created.push(reference);
        }
    }

    fn take(&mut self) -> WitnessAssertions {
        WitnessAssertions {
            cited: Vec::new(),
            created: std::mem::take(&mut self.created),
        }
    }

    fn restore(&mut self, assertions: WitnessAssertions) {
        let pending = std::mem::take(&mut self.created);
        for reference in assertions.created.into_iter().chain(pending) {
            self.note(reference);
        }
    }
}

impl HostSelfDispatcher<'_> {
    /// Notes created records from a successful committed write. Typed DTOs
    /// only: no prose extraction and no served/read rows.
    pub(crate) fn note_created_from_outcome(
        &self,
        verb: Option<AgentVerb>,
        outcome: &SelfDispatchOutcome,
    ) {
        match outcome {
            SelfDispatchOutcome::MemoryWrite(result) => {
                self.note_created_ref(RecordRef::from_id(ENTITY_TYPE_CLAIM, &result.id, None));
            }
            SelfDispatchOutcome::MemoryEdgeWrite(result) => {
                for id in [result.src, result.tgt] {
                    if let Some(reference) = self.record_ref_for(id) {
                        self.note_created_ref(reference);
                    }
                }
            }
            SelfDispatchOutcome::AgentVerb(answer) => match verb {
                Some(AgentVerb::TasksCreate) => {
                    if let Ok(receipt) =
                        serde_json::from_value::<TaskCreateReceipt>(answer.output.clone())
                    {
                        self.note_created_refs([receipt.task_record, receipt.proposal_record]);
                    }
                }
                Some(AgentVerb::VaultClaimsUpsert | AgentVerb::VaultOffRecordClaimsUpsert) => {
                    if let Ok(receipt) =
                        serde_json::from_value::<CommitReceipt>(answer.output.clone())
                    {
                        let claim = receipt.claim.or_else(|| {
                            receipt
                                .receipt_ref
                                .strip_prefix("claim:")
                                .and_then(|hex| EntityId::from_hex(hex).ok())
                                .map(|id| RecordRef::from_id(ENTITY_TYPE_CLAIM, &id, None))
                        });
                        self.note_created_refs([claim, receipt.superseded]);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn note_created_refs(&self, refs: impl IntoIterator<Item = Option<RecordRef>>) {
        for reference in refs.into_iter().flatten() {
            self.note_created_ref(reference);
        }
    }

    fn note_created_ref(&self, reference: RecordRef) {
        self.assertions_created.borrow_mut().note(reference);
    }

    fn record_ref_for(&self, id: EntityId) -> Option<RecordRef> {
        let kind = match &self.storage {
            ExecutorStorage::Canonical(vault) => {
                let txn = vault.store.env.read_txn().ok()?;
                Self::entity_type_of(&vault.store, &txn, &id).ok()?
            }
            ExecutorStorage::Session(binding) => binding
                .session
                .read_composed(|view, txn| Self::entity_type_of(view, txn, &id))
                .ok()?,
        }?;
        Some(RecordRef::from_id(kind, &id, None))
    }

    fn entity_type_of(
        dbs: &impl crate::store::ManifestDbs,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<u8>> {
        use crate::ports::EntityStoreRead;
        let Some(raw) = dbs.port_entity_raw(txn, id)? else {
            return Ok(None);
        };
        Ok(Some(
            crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("entity metadata"))?
                .entity_type,
        ))
    }

    /// Takes the refs for one witness attempt. On error the caller restores
    /// them, so a retry asserts the same set.
    pub(crate) fn take_run_assertions(&self) -> WitnessAssertions {
        self.assertions_created.borrow_mut().take()
    }

    /// Restores a failed witness attempt's refs ahead of any later writes.
    pub(crate) fn restore_run_assertions(&self, assertions: WitnessAssertions) {
        self.assertions_created.borrow_mut().restore(assertions);
    }
}

/// Domain tags for a canonical run's speech identities (ONE-1686).
///
/// Executor-owned transcript identity is DERIVED, never minted. A durable
/// executor passes both the host-bound run ref and `EngineExecutorConfig.run_id`,
/// so two replay records cannot share transcript rows merely because their
/// dispatchers reused a ref. The optional run id preserves the original
/// run-ref-only identity for standalone dispatcher and witness APIs that have no
/// durable executor config.
const EXECUTOR_SPEECH_CONVERSATION_DOMAIN: &[u8] = b"oneiron:executor-speech-conversation:v1";

const EXECUTOR_SPEECH_TURN_DOMAIN: &[u8] = b"oneiron:executor-speech-turn:v1";

const EXECUTOR_SPEECH_MESSAGE_DOMAIN: &[u8] = b"oneiron:executor-speech-message:v1";
/// Domain tag for a run's compaction session.
const EXECUTOR_COMPACTION_SESSION_DOMAIN: &[u8] = b"oneiron:executor-compaction-session:v1";

/// Derives one deterministic entity id from a domain tag and length-prefixed
/// material, re-salting past a reserved sentinel rather than truncating into
/// one.
pub(in crate::code_run) fn derived_executor_id(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0..=u8::MAX {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([salt]);
        for part in parts {
            let len = u64::try_from(part.len())
                .map_err(|_| Error::ArithmeticOverflow("executor speech id material"))?;
            hasher.update(len.to_le_bytes());
            hasher.update(part);
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "executor speech id derivation failed",
    ))
}

/// The legacy standalone conversation identity. Runtime executor paths use
/// [`canonical_speech_conversation_id_for_run`] with their durable run id.
#[cfg(test)]
pub(in crate::code_run) fn canonical_speech_conversation_id(run_ref: &str) -> Result<EntityId> {
    canonical_speech_conversation_id_for_run(run_ref, None)
}

/// The conversation a CANONICAL run's speech lands in: one shell per durable
/// run, create-or-get through the ordinary witness door.
pub(crate) fn canonical_speech_conversation_id_for_run(
    run_ref: &str,
    run_id: Option<EntityId>,
) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_CONVERSATION_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_CONVERSATION_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The turn one run's speech appends to.
///
/// ONE turn per run, not one per utterance: a TURN is the maximal consecutive
/// run of ONE speaker, and every bubble a run emits is the same Companion. The
/// bubbles' own `order` values carry the interleaving.
pub(in crate::code_run) fn executor_speech_turn_id(
    run_ref: &str,
    run_id: Option<EntityId>,
) -> Result<EntityId> {
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_TURN_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes()],
        ),
        None => derived_executor_id(EXECUTOR_SPEECH_TURN_DOMAIN, &[run_ref.as_bytes()]),
    }
}

/// The legacy standalone MESSAGE identity. Runtime executor paths also fold in
/// their durable run id through [`executor_speech_message_id_for_run`].
#[cfg(test)]
pub(crate) fn executor_speech_message_id(run_ref: &str, order: u32) -> Result<EntityId> {
    executor_speech_message_id_for_run(run_ref, None, order)
}

/// The MESSAGE id for one executor bubble: the run identity plus the bubble's
/// host-owned position.
///
/// `order` is the bridge ordering the host stamped (or, for the trailing
/// fallback, the run's next bridge position), so it is unique within the run
/// and reproducible from the persisted replay state. That is what makes a
/// re-emission a re-PUT of the same row rather than a second bubble.
pub(super) fn executor_speech_message_id_for_run(
    run_ref: &str,
    run_id: Option<EntityId>,
    order: u32,
) -> Result<EntityId> {
    let order_bytes = order.to_le_bytes();
    match run_id {
        Some(run_id) => derived_executor_id(
            EXECUTOR_SPEECH_MESSAGE_DOMAIN,
            &[run_ref.as_bytes(), run_id.as_bytes(), &order_bytes],
        ),
        None => derived_executor_id(
            EXECUTOR_SPEECH_MESSAGE_DOMAIN,
            &[run_ref.as_bytes(), &order_bytes],
        ),
    }
}

/// Records ONE canonical-run executor turn through ONE-1728's facade witness
/// door (ONE-1686).
///
/// A CALL SITE, not a transcript surface — the same standing the session arm
/// has. Conversation identity, container resolution, role tags, the approval
/// ceiling, the `AuthoredBy` edge and the BM25 posting are all the door's; what
/// this adds is the run-scoped shell and turn a canonical run has no session to
/// hand it, both derived from the durable run identity so they are the same on
/// every attempt but distinct from another run that reused the dispatcher ref.
///
/// `turn_ref` IS supplied here, unlike on the session arm. The typed refusal
/// there guards GUEST-named turns inside a room; this id is host-derived from
/// the run identity, and naming it is exactly what makes a retried step append
/// to the turn it already opened instead of opening another.
///
/// # Errors
///
/// Propagates the witness door's refusals, including the ONE-1686 approval
/// ceiling — preserved as the typed gate denial so the dispatcher records a
/// `Denied` bridge row rather than an opaque failure.
///
/// A `result` MESSAGE carries its attachment as metadata, and its hold on
/// the body lands in the same transaction as the MESSAGE (FIX 365).
#[expect(
    clippy::too_many_arguments,
    reason = "every parameter is a distinct axis the witness envelope binds; folding them into a \
              struct would hide which ones the host owns"
)]
pub(super) fn canonical_witness_executor_turn_sourced(
    vault: &Vault,
    run_ref: &str,
    run_id: Option<EntityId>,
    kind: ExecutorUtterance,
    text: &str,
    result: Option<ResultSpeech<'_>>,
    occurred_at: u64,
    order: u32,
    message_id: EntityId,
    actor: WriteActor,
    assertions: WitnessAssertions,
) -> Result<WitnessReceipt> {
    let conversation_id = canonical_speech_conversation_id_for_run(run_ref, run_id)?;
    let turn_id = executor_speech_turn_id(run_ref, run_id)?;
    vault
        .memory(actor.entity_ref(), actor.actor_class())
        .witness_host_executor(
            &crate::memory::WitnessTurn {
                conversation_ref: conversation_id.to_hex(),
                turn_ref: Some(turn_id.to_hex()),
                thread_audience: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: Some(message_id.to_hex()),
                    author: crate::memory::WitnessAuthor::Companion,
                    message_type: kind.as_message_type().to_owned(),
                    content: text.to_owned(),
                    metadata: result.map(|result| result.metadata()).transpose()?,
                    is_visible: kind.is_visible(),
                    order,
                    quote: None,
                }],
                occurred_at,
                assertions,
            },
            None,
            |wtxn| {
                if let Some(result) = result {
                    vault.retain_message_result_in_txn(
                        wtxn,
                        message_id,
                        result.attachment,
                        result.served_rows.map(<[EntityId]>::to_vec),
                    )?;
                }
                Ok(())
            },
        )
        .map_err(|error| {
            error
                .gate_denial_error()
                .unwrap_or(Error::InvariantViolation(
                    "executor witness door rejected the canonical turn",
                ))
        })
}

/// The compaction session of one durable run (agent-runtime-v1 §d7).
///
/// A run's REPL window is its own session: one log, one epoch lineage, its
/// steps as the turns. The ref is derived, never minted, so a resumed run
/// (same run ref, same credential scope) re-enters its lineage and no other
/// run can address it.
pub(crate) fn executor_compaction_session_id(run_ref: &str, run_id: EntityId) -> Result<EntityId> {
    derived_executor_id(
        EXECUTOR_COMPACTION_SESSION_DOMAIN,
        &[run_ref.as_bytes(), run_id.as_bytes()],
    )
}

/// The speech TURN of a canonical durable run, whether or not it spoke yet.
pub(crate) fn executor_speech_turn_id_for_run(run_ref: &str, run_id: EntityId) -> Result<EntityId> {
    executor_speech_turn_id(run_ref, Some(run_id))
}

/// The MESSAGE id a canonical durable run's speech takes at bridge position
/// `order`, whether or not it spoke there.
pub(crate) fn executor_speech_message_id_in_run(
    run_ref: &str,
    run_id: EntityId,
    order: u32,
) -> Result<EntityId> {
    executor_speech_message_id_for_run(run_ref, Some(run_id), order)
}
