mod scoped_settlement;

use super::encoding::{
    DEDUPE_DOMAIN_V1, DEDUPE_INDEX_KEY_LEN, decode_ready_key, dedupe_index_key,
    dedupe_index_key_v2, encode_record, legacy_dedupe_index_key, ready_at, ready_key,
};
use super::engine::{
    ERR_RETRY_CHAIN_CYCLE, ERR_RETRY_CHAIN_MISMATCH, ERR_RETRY_CHAIN_MISSING_ROW,
    RETRY_CHAIN_DEPTH_LIMIT, RETRY_REASON_UNSPECIFIED,
};
use super::telemetry::emit_attempt_queue_cleanup_span;
use super::types::MAX_ATTEMPT_EVENTS_PER_RECORD;
use super::validate::{
    CancelReceiptDraft, ERR_ABANDONED_WITHOUT_REASON, ERR_ABANDONED_WITHOUT_RESULT,
    ERR_CANCEL_ACTOR_IS_RUNTIME, ERR_CANCEL_NO_STANDING, ERR_CANCEL_RECEIPT_FIELD_FORBIDDEN,
    ERR_CANCEL_RECEIPT_MISSING_GROUNDS, ERR_CANCEL_RECEIPT_MISSING_REASON,
    ERR_CANCEL_RECEIPT_MISSING_REQUEST_REF, ERR_CANCEL_RECEIPT_MISSING_RESUME_POINT,
    ERR_CANCEL_RECEIPT_MISSING_TRIGGER, ERR_CANCEL_RECEIPT_RESERVE_UNITS, ERR_CANCEL_RECEIPTS_FULL,
    ERR_DEDUPE_ACTOR_WITHOUT_KEY, ERR_FAILURE_REASON_EMPTY, ERR_HANDOFF_WITHOUT_RESUME_POINT,
    ERR_LANDING_RECORD_MISPLACED, ERR_LANDING_WITHOUT_LEASE, ERR_LEASE_TIMEOUT_ZERO,
    ERR_MANIFEST_FULL, ERR_MANIFEST_REFERENCE_EMPTY, ERR_MANIFEST_REFERENCE_HAS_AT,
    ERR_MANIFEST_REFERENCE_TOO_LONG, ERR_MANIFEST_VERSION_EMPTY, ERR_MANIFEST_VERSION_TOO_LONG,
    ERR_RESULT_REF_REBOUND, ERR_RUN_ID_TOO_LONG, MAX_FAILURE_REASON_LEN,
    MAX_MANIFEST_REFERENCE_LEN, MAX_MANIFEST_VERSION_LEN, MAX_RESULT_REF_LEN, MAX_RUN_ID_LEN,
    append_cancel_receipt,
};
use super::*;
use crate::error::{Error, Result};
use crate::{Vault, VaultConfig};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

mod abandon_result;
mod actor_task_run;
mod claim_transitions;
mod cleanup_decode;
mod enqueue_pause_cancel;
mod landing_core;
mod landing_reserve_settle;
mod manifest_pack_compat;
mod retry_chains;
mod support;

use support::*;
