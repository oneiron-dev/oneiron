//! Remote-backed NativeClient SDK seam with its stamped-turn input.

use napi_derive::napi;

use super::boundary::{boundary_error, facade_error};
use super::convert::{
    commit_receipt_from_engine, gate_receipt_from_engine, memory_pack_from_engine,
    recall_scope_to_engine, witness_receipt_from_engine, witness_turn_to_engine,
};
use super::dtos::{
    NapiClaimInput, NapiCommitReceipt, NapiGateReceipt, NapiMemoryPack, NapiRecallScope,
    NapiWitnessMessage, NapiWitnessReceipt, NapiWitnessTurn,
};
use super::input_error::witness_input_error;
use super::numeric::{claim_input_to_engine, dimensions_to_engine, limit_to_engine};

// ── ONE-1441 WIRE-P1: the shared-backend client behind the `oneiron` npm
//    package ───────────────────────────────────────────────────────────────
//
// `VaultBridge`/`ActorScopedVault` above stay exactly as they are for existing
// direct native consumers. `NativeClient` is the SDK seam: it holds one
// `oneiron_remote::OneironClient`, so the embedded and remote backends differ
// by a constructor and nothing else, and neither this file nor the TypeScript
// wrapper contains an endpoint, a timeout, or a route table.
//
// It is PRIVATE to the npm package. `packages/oneiron` re-exports `Oneiron` and
// `OneironError` only; this class is an implementation detail the wrapper
// holds and never hands out.

/// One turn to witness, with an OPTIONAL timestamp (ONE-1441 I14).
///
/// The only difference from [`NapiWitnessTurn`] is that `occurredAt` may be
/// omitted, which is the §HEAD-CONTRACT surface. Omission is stamped with
/// current wall-clock Unix seconds by `oneiron_remote::stamp_occurred_at` —
/// the same function the Python binding calls — so the stamping rule has one
/// implementation rather than one per language.
#[napi(object)]
pub struct NapiWitnessTurnInput {
    /// CONVERSATION ref (32-hex create-or-get, or existing short ref).
    pub conversation_ref: String,
    /// TURN ref (create-or-get); omitted ⇒ a fresh TURN.
    pub turn_ref: Option<String>,
    /// Messages, attributed to the bound actor unless `system`.
    pub messages: Vec<NapiWitnessMessage>,
    /// Unix seconds; omitted ⇒ stamped at the call boundary.
    pub occurred_at: Option<f64>,
}

/// The private native handle behind `packages/oneiron`.
#[napi]
pub struct NativeClient {
    inner: oneiron_remote::OneironClient,
}

#[napi]
impl NativeClient {
    /// Opens an embedded vault; `path` omitted ⇒ `~/.oneiron/default`.
    #[napi(factory)]
    pub fn open(path: Option<String>, dimensions: Option<f64>) -> napi::Result<Self> {
        let options = oneiron_remote::OpenOptions {
            dimensions: dimensions
                .map(dimensions_to_engine)
                .transpose()
                .map_err(facade_error)?,
        };
        let path = path.map(std::path::PathBuf::from);
        let inner =
            oneiron_remote::OneironClient::open(path.as_deref(), &options).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Binds a remote `oneiron-server` with a minted slip, passed verbatim.
    #[napi(factory)]
    pub fn connect(url: String, key: String) -> napi::Result<Self> {
        let inner = oneiron_remote::OneironClient::connect(&url, &key).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Returns a NEW handle bound to another actor; refuses when connected.
    #[napi]
    pub fn as_actor(&self, actor_key: String) -> napi::Result<Self> {
        let inner = self.inner.as_actor(&actor_key).map_err(facade_error)?;
        Ok(Self { inner })
    }

    /// Witnesses one conversational turn.
    #[napi]
    pub fn witness(&self, turn: NapiWitnessTurnInput) -> napi::Result<NapiWitnessReceipt> {
        let stamped = oneiron_remote::stamp_occurred_at(turn.occurred_at).map_err(facade_error)?;
        // Caller numbers are already validated; narrowing failure here is
        // an internal invariant failure, not bad input.
        let occurred_at = i64::try_from(stamped)
            .map_err(|_| boundary_error("occurred_at is out of range".to_owned()))?;
        let turn = NapiWitnessTurn {
            conversation_ref: turn.conversation_ref,
            turn_ref: turn.turn_ref,
            messages: turn.messages,
            occurred_at,
        };
        let engine_turn = witness_turn_to_engine(&turn).map_err(witness_input_error)?;
        let receipt = self.inner.witness(&engine_turn).map_err(facade_error)?;
        Ok(witness_receipt_from_engine(receipt))
    }

    /// Upserts one claim through the gated claim-candidate path.
    #[napi]
    pub fn claim_upsert(&self, claim: NapiClaimInput) -> napi::Result<NapiCommitReceipt> {
        let engine_claim = claim_input_to_engine(&claim).map_err(facade_error)?;
        let receipt = self
            .inner
            .claim_upsert(&engine_claim)
            .map_err(facade_error)?;
        Ok(commit_receipt_from_engine(receipt))
    }

    /// Effort-dialed retrieval into a memory pack.
    #[napi]
    pub fn recall(
        &self,
        query: String,
        effort: Option<String>,
        scope: Option<NapiRecallScope>,
        limit: Option<f64>,
        format: Option<String>,
    ) -> napi::Result<NapiMemoryPack> {
        let effort = oneiron_remote::parse_effort(effort.as_deref().unwrap_or("standard"))
            .map_err(facade_error)?;
        let scope = recall_scope_to_engine(scope);
        let limit = limit
            .map(limit_to_engine)
            .transpose()
            .map_err(facade_error)?
            .unwrap_or(oneiron_remote::DEFAULT_RECALL_LIMIT);
        let pack = self
            .inner
            .recall(&query, effort, &scope, limit, format.as_deref())
            .map_err(facade_error)?;
        memory_pack_from_engine(pack).map_err(boundary_error)
    }

    /// Gate decision receipts, newest first.
    #[napi]
    pub fn receipts(&self, limit: Option<f64>) -> napi::Result<Vec<NapiGateReceipt>> {
        let limit = limit
            .map(limit_to_engine)
            .transpose()
            .map_err(facade_error)?
            .unwrap_or(oneiron_remote::DEFAULT_RECEIPTS_LIMIT);
        let records = self.inner.receipts(limit).map_err(facade_error)?;
        records
            .into_iter()
            .map(|record| gate_receipt_from_engine(record).map_err(boundary_error))
            .collect()
    }
}
