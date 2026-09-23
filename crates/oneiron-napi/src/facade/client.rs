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

impl NapiWitnessTurnInput {
    fn into_engine(self) -> napi::Result<oneiron::memory::WitnessTurn> {
        let stamped = oneiron_remote::stamp_occurred_at(self.occurred_at).map_err(facade_error)?;
        // Caller numbers are already validated; narrowing failure here is
        // an internal invariant failure, not bad input.
        let occurred_at = i64::try_from(stamped)
            .map_err(|_| boundary_error("occurred_at is out of range".to_owned()))?;
        witness_turn_to_engine(&NapiWitnessTurn {
            conversation_ref: self.conversation_ref,
            turn_ref: self.turn_ref,
            messages: self.messages,
            occurred_at,
        })
        .map_err(witness_input_error)
    }
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
}

mod agent_verbs;
