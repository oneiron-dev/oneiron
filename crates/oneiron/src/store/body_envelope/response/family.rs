//! Each family of row-held responses, by the rows it recognizes: what a
//! checkpoint carries of a row, who owns the row's response, and what a
//! retired copy keeps.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::super::opaque_response::{
    ResponseOwners, ResponseScan, is_opaque_erased, stamp_opaque_erased,
};
use super::{ResponseCarriage, ResponseDb, Rows};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::self_heal::blocked_reports::blocked_capture_owners_in_txn;
use crate::side_table::{self, SideTableDbs};
use crate::store::{MediaKey, Store, StoreAttemptOperations, StoreVoiceBankResponse};

/// A family of row-held responses (KS-2B1; KS-2B2 adds the host's HTTP
/// idempotency entries and media jobs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseFamily {
    /// A turn program's STEP row: a send's kept body (FIX 5719).
    ProgramStep,
    /// An LLM step's device-local progression row: its response payload.
    StepState,
    /// A terminal `dreamer.step` claim: its inline response.
    StepClaim,
    /// A code run's replay record: its bridge outcomes and output previews.
    Replay,
    /// An HTTP idempotency cache entry: its request, headers, target and
    /// response (KS-2B2).
    Http,
    /// A durable invocation intent or its settled JSON outcome (FIX 11889).
    InvocationClaim,
    /// A media job's row: its request and its end (KS-2B2).
    MediaJob,
    /// One of a media job's clips, in a row of its own beside the job's.
    MediaPart,
    /// A blocked report's captured request: a receipt row or a durable
    /// step's row of the replay-source table (FIX 6708), carried whole.
    BlockedCapture,
    /// The reply a parked run was delivered (FIX 6588).
    WaitDelivery,
    /// A wait's settled reply, shared by every holder of the wait (FIX
    /// 6588): only the index's settled rows, never its waiters.
    WaitSettled,
    /// A Dreamer agent dispatch's attempt row: its target's instructions,
    /// briefing and direct spawn receipt (FIX 7115).
    AttemptPayload,
    /// A public model-step submission: its request and its result, kept
    /// beside the receipt's metadata (FIX 9929).
    ModelStepSubmission,
    /// A saved query's verdict memo: its judge's explanation, owned by the
    /// query, the candidate and every row its evidence came from; a retired
    /// memo leaves nothing (FIX 10089).
    SavedQueryMemo,
    /// The reply assertions a MESSAGE born whole kept (FIX 10260), carried
    /// whole: an owner's erase retires the row.
    MessageReplyAssertions,
    /// A row of the voice reference bank (FIX 8972): a pack, an identity,
    /// its incarnation, a target pointer, the current render decision, a
    /// recorded render event or an owner index entry, carried whole and
    /// erased with the bank's subject or creator.
    VoiceBank,
    /// A centroid verdict's evidence snapshot (FIX 10094): the candidate's
    /// and labels' copied vectors and the retrieval run, carried whole and
    /// owned by every source it copied; a retired snapshot keeps its erased
    /// marker (FIX 10822).
    CentroidEvidence,
    /// A report cluster (FIX 9856): its member ISSUEs' copied vectors and
    /// their centroid, carried whole and owned by every member; a retired
    /// cluster leaves nothing.
    ReportCluster,
    /// A typed question's copies of one judgment answer (FIX 9918, 11236,
    /// 11237), carried whole. At bind time, decoded labels and windows
    /// join their answer's claim, unit and receipt principal; opaque or
    /// orphan copies keep their claim alone. Existing unchanged bindings
    /// keep their prior owners. A retired copy leaves nothing.
    TypedQuestion,
    /// A conversation summary's check material (FIX 5040): its sealed gate
    /// request, the backend's whole reply and the gate policy, carried whole
    /// and owned by the SUMMARY and every source of its window. A retired
    /// copy keeps its erased form, which holds the refs and digest only.
    CompactionCheckMaterial,
}

impl ResponseFamily {
    /// The family of the canonical row `key` of `db`, holding `value`.
    pub(crate) fn of_row(db: ResponseDb, key: &[u8], value: &[u8]) -> Option<Self> {
        match db {
            // Recognized by key, so a retired stub is too.
            ResponseDb::VaultMeta => [
                (&side_table::DREAMER_TURN_PROGRAM_STEP, Self::ProgramStep),
                (&side_table::DREAMER_STEP_STATE, Self::StepState),
                (&side_table::CODE_RUN_REPLAY, Self::Replay),
                (&side_table::COACH_BLOCKED_SOURCE, Self::BlockedCapture),
                (&side_table::CODE_RUN_WAIT_DELIVERY, Self::WaitDelivery),
                (
                    &side_table::MODEL_STEP_SUBMISSION,
                    Self::ModelStepSubmission,
                ),
                (&side_table::SAVED_QUERY_MEMO, Self::SavedQueryMemo),
                (
                    &side_table::SELF_HEAL_CENTROID_EVIDENCE,
                    Self::CentroidEvidence,
                ),
                (
                    &side_table::MESSAGE_REPLY_ASSERTIONS,
                    Self::MessageReplyAssertions,
                ),
                (&side_table::FEEDBACK_REPORT_CLUSTER, Self::ReportCluster),
                (&side_table::TYPED_QUESTION, Self::TypedQuestion),
                (
                    &side_table::COMPACTION_CHECK_MATERIAL,
                    Self::CompactionCheckMaterial,
                ),
            ]
            .into_iter()
            .find(|(decl, _)| key.starts_with(decl.prefix))
            .map(|(_, family)| family)
            .or_else(|| {
                crate::store::executor_wait_delivery::settled_wait_key(key)
                    .then_some(Self::WaitSettled)
            })
            .or_else(|| {
                crate::store::voice_bank_response::voice_bank_row(key).then_some(Self::VoiceBank)
            }),
            ResponseDb::Entities => EntityMetadataHeader::parse(value)
                .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
                .map(|_| Self::StepClaim),
            ResponseDb::SyncState => {
                if key.starts_with(side_table::HTTP_IDEMPOTENCY_REPLY.prefix) {
                    return Some(Self::Http);
                }
                if key.starts_with(side_table::INVOCATION_CLAIM.prefix) {
                    return Some(Self::InvocationClaim);
                }
                crate::store::media_key(key).map(|media| match media {
                    MediaKey::Job => Self::MediaJob,
                    MediaKey::Part { .. } => Self::MediaPart,
                })
            }
            ResponseDb::Attempts => {
                crate::store::attempt_payload_route::attempt_payload_family(key, value)
                    .then_some(Self::AttemptPayload)
            }
        }
    }

    /// The database the family's rows rest in.
    pub(crate) const fn database(self) -> ResponseDb {
        match self {
            Self::StepClaim => ResponseDb::Entities,
            Self::Http | Self::InvocationClaim | Self::MediaJob | Self::MediaPart => {
                ResponseDb::SyncState
            }
            Self::AttemptPayload => ResponseDb::Attempts,
            Self::ProgramStep
            | Self::StepState
            | Self::Replay
            | Self::BlockedCapture
            | Self::WaitDelivery
            | Self::WaitSettled
            | Self::ModelStepSubmission
            | Self::SavedQueryMemo
            | Self::MessageReplyAssertions
            | Self::VoiceBank
            | Self::CentroidEvidence
            | Self::ReportCluster
            | Self::TypedQuestion
            | Self::CompactionCheckMaterial => ResponseDb::VaultMeta,
        }
    }

    /// Whether the family's response is shared by every holder its
    /// obligations name, so one holder's erase owes its retirement to the
    /// final holder's release (FIX 6588).
    pub(crate) fn shared(self) -> bool {
        self == Self::WaitSettled
    }

    /// What a checkpoint carries of the row `key`, the one scanner every
    /// census, binding, stale and retire path reads it through: no response
    /// (a bodyless step, a state with no payload, a claim whose response
    /// rests in an artifact, an erased reply or marker, a dispatch with no
    /// text), a decoded one, or, for a row its family recognizes that does
    /// not decode or whose stub does not encode, an opaque one (FIX 6227,
    /// 9390). A clip's raw bytes always carry: it bears no marker.
    pub(crate) fn scan(
        self,
        operations: &dyn StoreAttemptOperations,
        voice: &dyn StoreVoiceBankResponse,
        key: &[u8],
        value: &[u8],
    ) -> ResponseScan {
        // An opaque response's erased form holds nothing.
        if self != Self::MediaPart && is_opaque_erased(value) {
            return ResponseScan::NotResponse;
        }
        match self {
            Self::ProgramStep => crate::dreamer_runner::program_step_carriage(value),
            Self::StepState => crate::llm::step_state_carriage(value),
            Self::StepClaim => {
                crate::store::model_step_response_carriage::step_claim_carriage(value)
            }
            Self::Replay => crate::code_run::replay_carriage(value),
            Self::Http => crate::store::http_scan(value),
            Self::InvocationClaim => crate::store::invocation_claim_scan(value),
            Self::MediaJob => crate::store::media_job_scan(value),
            Self::MediaPart => ResponseScan::decoded(
                crate::store::media_part_carriage(value).map(ResponseCarriage::whole),
            ),
            // The whole row; nothing stays once retired: the row goes.
            Self::BlockedCapture => {
                crate::self_heal::blocked_reports::blocked_capture_scan(key, value)
            }
            Self::WaitDelivery | Self::WaitSettled => {
                crate::store::executor_wait_delivery::wait_reply_scan(value)
            }
            Self::AttemptPayload => {
                crate::store::attempt_payload_response::attempt_payload_scan(operations, key, value)
            }
            Self::ModelStepSubmission => crate::llm::submission_carriage(value),
            Self::SavedQueryMemo => crate::store::query_memos::memo_carriage(value),
            Self::CentroidEvidence => {
                crate::store::centroid_evidence::centroid_evidence_carriage(value)
            }
            Self::MessageReplyAssertions => crate::memory::reply_assertions_scan(value),
            Self::ReportCluster => crate::feedback::intake::report_cluster_carriage(value),
            Self::VoiceBank => voice.voice_bank_scan(key, value),
            Self::TypedQuestion => {
                crate::llm::decision::questions::typed_question_carriage(key, value)
            }
            Self::CompactionCheckMaterial => crate::compaction::check_material_carriage(value),
        }
    }

    /// Whether a mixed attempt/wait row carries a response for checkpoint payload
    /// placement (FIX 9179): a queue row or a wait index row the response client
    /// takes, by the same family and scan the census reads (a response, the erased
    /// marker, a wait's erased reply). Any other family is not a mixed family.
    pub(crate) fn mixed_response_placed_as_response(
        operations: &dyn StoreAttemptOperations,
        db: ResponseDb,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        match Self::of_row(db, key, value) {
            Some(ResponseFamily::AttemptPayload) => {
                is_opaque_erased(value)
                    || crate::store::attempt_payload_response::attempt_payload_scan(
                        operations, key, value,
                    ) != ResponseScan::NotResponse
            }
            Some(ResponseFamily::WaitDelivery | ResponseFamily::WaitSettled) => {
                is_opaque_erased(value)
                    || crate::store::executor_wait_delivery::wait_reply_scan(value)
                        != ResponseScan::NotResponse
                    || crate::store::executor_wait_delivery::wait_reply_erased(value)
            }
            _ => false,
        }
    }

    /// Who owns the opaque response in the row `key`, as far as its key
    /// proves (FIX 6227): a claim's is its own id; a STEP row's its run and
    /// step, a replay record's its run and the actor a program's run runs
    /// as, the rest of what their rows stamp unknown; a step-state row's
    /// none.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn opaque_owners(
        self,
        store: &Store,
        txn: &RoTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<ResponseOwners> {
        if self == Self::Replay {
            let Some(run) = key
                .strip_prefix(side_table::CODE_RUN_REPLAY.prefix)
                .and_then(|raw| <[u8; 16]>::try_from(raw).ok())
                .and_then(|raw| EntityId::from_bytes(raw).ok())
            else {
                return Ok(ResponseOwners::Unknown);
            };
            let mut owners = vec![run];
            owners.extend(crate::dreamer_runner::program_run_actor_in_txn(
                store, txn, &run,
            )?);
            return Ok(ResponseOwners::Partial(owners));
        }
        if self == Self::VoiceBank {
            return store
                .voice_bank_response
                .voice_bank_owners(store, txn, key, value);
        }
        if self == Self::MessageReplyAssertions {
            return Ok(crate::memory::reply_assertions_opaque_owners(key, value));
        }
        let owners = self.owners(store, txn, key, value)?;
        Ok(match self {
            Self::StepClaim => ResponseOwners::Known(owners),
            _ if owners.is_empty() => ResponseOwners::Unknown,
            _ => ResponseOwners::Partial(owners),
        })
    }

    /// Who owns the row's response, by the stamps written with it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn owners(
        self,
        store: &Store,
        txn: &RoTxn<'_>,
        key: &[u8],
        value: &[u8],
    ) -> Result<Vec<EntityId>> {
        match self {
            Self::ProgramStep => crate::dreamer_runner::program_step_owners(store, txn, key, value),
            Self::StepState => Ok(crate::llm::step_state_owners(value)),
            Self::StepClaim => Ok(vec![EntityId::from_bytes(
                key.try_into()
                    .map_err(|_| Error::CorruptedIndex("entity key"))?,
            )?]),
            Self::Replay => crate::code_run::replay_owners(store, txn, value),
            Self::Http => Ok(crate::store::http_owners(value)),
            Self::InvocationClaim => Ok(crate::store::invocation_claim_owners(value)),
            Self::MediaJob => Ok(crate::store::media_job_owners(value)),
            Self::BlockedCapture => blocked_capture_owners_in_txn(store, txn, key, value),
            Self::WaitDelivery => crate::code_run::wait_delivery_owners(store, txn, key),
            Self::WaitSettled => {
                crate::store::executor_wait_delivery::wait_settled_owners(store, txn, key)
            }
            Self::AttemptPayload => Ok(
                crate::store::attempt_payload_response::attempt_payload_owners(
                    store.attempt_operations,
                    key,
                    value,
                ),
            ),
            Self::ModelStepSubmission => Ok(crate::llm::submission_owners(value)),
            Self::SavedQueryMemo => Ok(crate::store::query_memos::memo_owners(value)),
            Self::CentroidEvidence => Ok(
                crate::store::centroid_evidence::centroid_evidence_owners(value),
            ),
            Self::MessageReplyAssertions => Ok(crate::memory::reply_assertions_owners(value)),
            Self::ReportCluster => Ok(crate::feedback::intake::report_cluster_owners(value)),
            // A bank row's are its subject's or creator's, as far as the
            // bank's own rows prove them; the rest are reported.
            Self::VoiceBank => {
                let owners = store
                    .voice_bank_response
                    .voice_bank_owners(store, txn, key, value)?;
                if !owners.proved() {
                    tracing::warn!(
                        "a voice bank row is bound under the owners the bank proves; the rest \
                         are not known"
                    );
                }
                Ok(owners.into_ids())
            }
            // A clip's owners are its job's, as the job's row stamps them.
            Self::MediaPart => {
                let Some(MediaKey::Part { job }) = crate::store::media_key(key) else {
                    return Ok(Vec::new());
                };
                Ok(store
                    .side_sync_state()?
                    .get(txn, sync_state_key(&key[..job])?)?
                    .map(|row| crate::store::media_job_owners(&row))
                    .unwrap_or_default())
            }
            Self::TypedQuestion => {
                crate::llm::decision::questions::typed_question_copy_owners_in_txn(
                    store, txn, key, value,
                )
            }
            Self::CompactionCheckMaterial => {
                Ok(crate::compaction::check_material_owners(key, value))
            }
        }
    }

    /// What the erased disposition of the retired row `key` takes beside the
    /// row itself, in raw image rows: a claim's step-index rows and its
    /// projection rows go, and its soft-delete marker and fence are left, as
    /// an erase leaves them (FIX 6661); a retired clip's row goes, and so
    /// does a retired captured request's (FIX 6708).
    ///
    /// # Errors
    ///
    /// A row that does not decode.
    pub(crate) fn retire_in_rows(
        self,
        databases: &mut BTreeMap<String, Rows>,
        key: &[u8],
    ) -> Result<()> {
        match self {
            Self::StepClaim => crate::llm::retire_step_claim_in_rows(databases, key),
            // A retired clip's row goes: its job keeps its erased form.
            Self::MediaPart => {
                drop_row(databases, ResponseDb::SyncState, key);
                Ok(())
            }
            // A retired bank row goes, as the bank's erase deletes it live.
            Self::BlockedCapture | Self::MessageReplyAssertions | Self::VoiceBank => {
                drop_row(databases, ResponseDb::VaultMeta, key);
                Ok(())
            }
            // A retired memo's row goes; the next evaluation derives anew. A
            // retired cluster's row goes, as its member's erase remakes it
            // live without that member. A retired answer copy's row goes, as
            // the owner's erase deletes it live (FIX 9918, 11236).
            Self::SavedQueryMemo | Self::ReportCluster | Self::TypedQuestion => {
                drop_row(databases, ResponseDb::VaultMeta, key);
                Ok(())
            }
            // A retired centroid snapshot's row keeps its stub, the erased
            // marker, as its source's erase leaves it live (FIX 10822).
            Self::CentroidEvidence => Ok(()),
            Self::ProgramStep
            | Self::StepState
            | Self::Replay
            | Self::Http
            | Self::InvocationClaim
            | Self::MediaJob
            | Self::WaitDelivery
            | Self::WaitSettled
            | Self::AttemptPayload
            | Self::ModelStepSubmission
            | Self::CompactionCheckMaterial => Ok(()),
        }
    }

    /// Leaves the live row `key` its erased disposition in `wtxn`, as
    /// `carriage` names it: an activation's prune of a row whose instance
    /// its source retired. A `vault_meta` row takes its stub as far as the
    /// disposition keeps it (an opaque one's, its erased marker, stamped
    /// with the time it retired, FIX 10710); a claim, the erase's shell
    /// beside its markers.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn retire_in_txn(
        self,
        write: &crate::secret_custody::CustodyWrite<'_>,
        wtxn: &mut RwTxn<'_>,
        key: &[u8],
        carriage: &ResponseCarriage,
    ) -> Result<()> {
        let store = write.store;
        let kept = || {
            carriage
                .stub
                .get(..carriage.retired)
                .map(stamp_opaque_erased)
                .ok_or(Error::InvariantViolation(
                    "a response stub shorter than it keeps",
                ))
        };
        match self {
            Self::StepClaim => crate::llm::retire_step_claim_in_txn(write, wtxn, key),
            Self::ProgramStep
            | Self::StepState
            | Self::Replay
            | Self::WaitDelivery
            | Self::WaitSettled
            | Self::ModelStepSubmission
            | Self::CentroidEvidence
            | Self::CompactionCheckMaterial => store.side_vault_meta().put(wtxn, key, &kept()?),
            Self::BlockedCapture | Self::MessageReplyAssertions | Self::VoiceBank => {
                store.side_vault_meta().delete(wtxn, key)?;
                Ok(())
            }
            Self::SavedQueryMemo | Self::ReportCluster | Self::TypedQuestion => {
                store.side_vault_meta().delete(wtxn, key)?;
                Ok(())
            }
            Self::AttemptPayload => {
                crate::store::attempt_payload_retire::retire_attempt_payload_in_txn(
                    store,
                    wtxn,
                    key,
                    &kept()?,
                )
            }
            Self::Http | Self::InvocationClaim | Self::MediaJob => {
                store
                    .side_sync_state()?
                    .put(wtxn, sync_state_key(key)?, &kept()?)
            }
            Self::MediaPart => {
                store
                    .side_sync_state()?
                    .delete(wtxn, sync_state_key(key)?)?;
                Ok(())
            }
        }
    }
}

/// Takes the row `key` out of `db`'s raw image rows.
fn drop_row(databases: &mut BTreeMap<String, Rows>, db: ResponseDb, key: &[u8]) {
    if let Some(rows) = databases.get_mut(db.name()) {
        rows.retain(|(row, _)| row.as_slice() != key);
    }
}

/// The `sync_state` row key `key` as the text such a key is.
fn sync_state_key(key: &[u8]) -> Result<&str> {
    std::str::from_utf8(key).map_err(|_| Error::CorruptedIndex("sync_state row key"))
}
