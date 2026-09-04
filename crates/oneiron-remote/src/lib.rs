//! `oneiron-remote` — the shared Rust SDK backend behind the `oneiron` npm and
//! PyPI packages (ONE-1441 WIRE-P1).
//!
//! # What this crate is
//!
//! One [`OneironClient`] with two backends and ONE semantic switch between
//! them. `open` binds an embedded vault; `connect` binds a remote
//! `oneiron-server`. Every public verb below enters through the same
//! dispatcher, so the N-API and PyO3 layers convert language values into
//! engine DTOs, call this client, and convert the result back. Neither of them
//! branches on backend, holds a route table, or contains an HTTP client.
//!
//! # The verb catalog is DECLARED, not implied
//!
//! [`FACADE_VERB_CATALOG`] is the ordered, authoritative list of verbs this
//! SDK ships, and it is the same list the server's `/v1/core/facade` nest
//! routes and the same list both language export censuses assert against. It
//! holds the four calls of the canonical quickstart — `witness`,
//! `claim_upsert`, `recall`, `receipts` — matching the projection L1 landed.
//!
//! The remaining §HEAD-CONTRACT verbs are ABSENT rather than stubbed, for the
//! reason `oneiron-server`'s `api/facade.rs` header already gives: a `501` stub
//! is still a registered row. It enters the route census, a client's catalog
//! test counts it as shipped, and the only thing it proves is that somebody
//! meant to write the verb. Extending the catalog means adding a server
//! handler, a client row, and both language bindings together — which is a
//! sequenced follow-on, not a silent partial row here.
//!
//! # What this crate never does
//!
//! It does not mint, split, parse, or validate authority. The `OF-452` slip
//! crosses verbatim and every authority decision is the server's. It does not
//! emulate a facade verb out of lower-level storage routes. It does not mint
//! or simulate a retrieval lease, so `Effort::Deep` returns the engine's own
//! `LEASE_REQUIRED`.

#![forbid(unsafe_code)]

mod caps;
mod embedded;
mod error;
mod remote;

use std::fmt;
use std::path::Path;

use oneiron::memory::{
    ClaimInput, CommitReceipt, Effort, MEMORY_CODE_INTERNAL, MemoryError, MemoryPack,
    MemoryReceipt, RecallScope, WitnessReceipt, WitnessTurn,
};
use serde::Serialize;

pub use crate::caps::{
    MAX_BATCH_ENTITIES, MAX_BLOB_BASE64_LEN, MAX_BLOB_CONTENT_BYTES, MAX_CODEBASE_FILES,
    MAX_DIMENSIONS, MAX_ENTITY_PAYLOAD_BYTES, MAX_QUERY_BYTES, MAX_REMOTE_REQUEST_BYTES,
    MAX_REMOTE_RESPONSE_BYTES, MAX_SEARCH_LIMIT, check_batch_len, check_dimensions, check_limit,
    check_payload_bytes, check_query, check_unix_seconds,
};
use crate::embedded::EmbeddedClient;
pub use crate::embedded::store_open_count;
use crate::error::forbidden;
use crate::remote::RemoteClient;

/// `recall`'s default result count, per §HEAD-CONTRACT.
pub const DEFAULT_RECALL_LIMIT: usize = 10;

/// `receipts`'s default row count, per §HEAD-CONTRACT.
pub const DEFAULT_RECEIPTS_LIMIT: usize = 100;

/// The ordered public verb catalog this SDK ships.
///
/// Load-bearing as an ORDER and as a SET: the server route census, the npm
/// export census, and the Python stub census are all compared against this
/// exact slice, so a verb cannot appear in one surface and be forgotten in
/// another. Every entry is also the wire path segment, which is why the
/// spelling is the engine's snake_case verb name and not the JavaScript one.
pub const FACADE_VERB_CATALOG: [&str; 4] = ["witness", "claim_upsert", "recall", "receipts"];

/// Options an embedded open accepts (§HEAD-CONTRACT `OpenOptions`).
///
/// `PartialEq` is not decoration: I9 compares a reopen's options against the
/// registered ones and refuses a divergent pair, so equality IS the
/// same-vault test.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Embedding vector dimensions; `None` takes the engine default.
    pub dimensions: Option<usize>,
}

/// Current wall-clock time, in whole Unix seconds.
///
/// The SDK's own clock read, because the engine's is crate-private. This is
/// the value an omitted `occurredAt`/`occurred_at` is stamped with, and it is
/// read at the CALL boundary so a long-lived handle does not stamp writes with
/// the time it was constructed.
#[must_use]
pub fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Resolves an optional caller timestamp into engine Unix seconds (I14).
///
/// `None` means the caller omitted the field and gets [`unix_seconds_now`].
/// `Some` is validated — non-negative, whole, finite, safe — and passed
/// through with NO unit conversion. The SDK never guesses that a large number
/// was milliseconds: a caller who sends milliseconds gets a date in the year
/// 56000 and a bug they can see, not a value silently divided by a thousand.
pub fn stamp_occurred_at(supplied: Option<f64>) -> Result<u64, MemoryError> {
    match supplied {
        None => Ok(unix_seconds_now()),
        Some(value) => check_unix_seconds("occurred_at", value),
    }
}

/// Parses the `effort` token, which is the engine's own vocabulary.
pub fn parse_effort(value: &str) -> Result<Effort, MemoryError> {
    Effort::parse(value).ok_or_else(|| {
        crate::error::bad_request(
            format!("unknown recall effort {value:?}"),
            &["Use one of: minimal, standard, deep."],
        )
    })
}

/// The one client both language bindings call.
pub struct OneironClient {
    backend: Backend,
}

/// Embedded or remote, decided once at construction.
enum Backend {
    Embedded(EmbeddedClient),
    Remote(RemoteClient),
}

/// Prints the backend KIND and nothing else.
///
/// `Debug` is required rather than decorative: the contract tests assert a
/// refusal with `expect_err` on a `Result<Self, _>`, and that panic message
/// formats the `Ok` type. It is HAND-WRITTEN because a derive would walk into
/// the backend and print what a handle holds — a remote handle holds the
/// bearer slip verbatim, and a credential must not reach a panic message, a
/// test log, or a caller's crash report. The kind is the only thing a
/// diagnostic needs to know about a handle.
impl fmt::Debug for OneironClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = match self.backend {
            Backend::Embedded(_) => "Embedded",
            Backend::Remote(_) => "Remote",
        };
        write!(formatter, "OneironClient {{ backend: {backend} }}")
    }
}

/// `recall`'s wire request, matching the server handler's body exactly.
#[derive(Serialize)]
struct RecallRequest<'a> {
    query: &'a str,
    effort: Effort,
    scope: &'a RecallScope,
    limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'a str>,
}

/// `receipts`'s wire request.
#[derive(Serialize)]
struct ReceiptsRequest {
    limit: usize,
}

impl OneironClient {
    /// Opens an embedded vault and returns an actor-bound handle.
    ///
    /// `path` of `None` resolves to `~/.oneiron/default` against the current
    /// process home. The handle is usable immediately: the constructor binds
    /// the generic embedded owner actor through the core bootstrap seam, so
    /// there is no actor ceremony between `open()` and the first verb.
    pub fn open(path: Option<&Path>, options: &OpenOptions) -> Result<Self, MemoryError> {
        Ok(Self {
            backend: Backend::Embedded(EmbeddedClient::open(path, options)?),
        })
    }

    /// Binds a remote `oneiron-server` through the facade projection.
    ///
    /// Validates URL configuration and nothing else. Authority arrives with
    /// the slip and is decided server-side from the MAC-verified
    /// `principal_ref` and `actor_class` claims; this call neither claims it
    /// nor mints an actor locally.
    pub fn connect(url: &str, key: &str) -> Result<Self, MemoryError> {
        Ok(Self {
            backend: Backend::Remote(RemoteClient::connect(url, key)?),
        })
    }

    /// Rebinds to another actor, or refuses.
    ///
    /// Embedded handles resolve the pinned `human:|agent:|system:<ref>`
    /// grammar through core and return a NEW handle over the same vault.
    ///
    /// Connected handles fail typed `FORBIDDEN` (I10). The verb is present so
    /// the two backends have the same public method census — a caller writing
    /// against the handle type should not discover a missing method — but a
    /// remote principal cannot widen or replace the actor its slip bound. That
    /// is the whole point of binding it server-side.
    pub fn as_actor(&self, actor_key: &str) -> Result<Self, MemoryError> {
        match &self.backend {
            Backend::Embedded(embedded) => Ok(Self {
                backend: Backend::Embedded(embedded.as_actor(actor_key)?),
            }),
            Backend::Remote(_) => Err(forbidden(
                "a connected handle cannot rebind its actor",
                &[
                    "Reconnect with a slip minted for the actor you want to act as.",
                    "The slip's principal_ref and actor_class bind write identity server-side.",
                ],
            )),
        }
    }

    /// Whether this handle talks to a remote server.
    #[must_use]
    pub fn is_remote(&self) -> bool {
        matches!(self.backend, Backend::Remote(_))
    }

    /// The origin a connected handle talks to; `None` when embedded.
    #[must_use]
    pub fn base_url(&self) -> Option<&str> {
        match &self.backend {
            Backend::Embedded(_) => None,
            Backend::Remote(remote) => Some(remote.base_url()),
        }
    }

    /// The 32-hex id of the actor an embedded handle writes as; `None` when
    /// remote.
    ///
    /// `None` for a connected handle is the contract, not an omission: a
    /// remote handle's write identity lives in the server-verified slip and
    /// is never something the client can report.
    #[must_use]
    pub fn actor_ref(&self) -> Option<String> {
        match &self.backend {
            Backend::Embedded(embedded) => Some(embedded.actor_hex()),
            Backend::Remote(_) => None,
        }
    }

    /// The PID holding this vault's writer lease; `None` when remote.
    #[must_use]
    pub fn lease_pid(&self) -> Option<u32> {
        match &self.backend {
            Backend::Embedded(embedded) => Some(embedded.lease_pid()),
            Backend::Remote(_) => None,
        }
    }

    /// The single-writer gate every embedded verb passes first (I8).
    ///
    /// A no-op for remote handles: the server owns its own vault's lease, and
    /// this process holds nothing to be wrong about.
    fn ensure_dispatch_pid(&self) -> Result<(), MemoryError> {
        match &self.backend {
            Backend::Embedded(embedded) => embedded.ensure_dispatch_pid(),
            Backend::Remote(_) => Ok(()),
        }
    }

    /// Pointer identity of the shared native vault, for contract tests (T3).
    ///
    /// `None` for remote handles, which share nothing local.
    #[must_use]
    pub fn shared_vault_addr(&self) -> Option<usize> {
        match &self.backend {
            Backend::Embedded(embedded) => {
                Some(std::sync::Arc::as_ptr(embedded.shared()).cast::<()>() as usize)
            }
            Backend::Remote(_) => None,
        }
    }

    // ── the declared catalog ────────────────────────────────────────────
    //
    // One method per FACADE_VERB_CATALOG entry, in catalog order. Each one
    // gates the PID, validates its own caps, and then makes exactly one
    // dispatch: an engine facade call or one HTTP round trip to the verb of
    // the same name. There is no composition and no second code path.

    /// Witnesses one conversational turn.
    ///
    /// `turn.occurred_at` is already stamped by the caller through
    /// [`stamp_occurred_at`], because the engine DTO's field is required and a
    /// backend cannot tell an omitted `0` from a deliberate one.
    pub fn witness(&self, turn: &WitnessTurn) -> Result<WitnessReceipt, MemoryError> {
        self.ensure_dispatch_pid()?;
        check_batch_len("messages", turn.messages.len())?;
        for message in &turn.messages {
            check_payload_bytes("message content", message.content.len())?;
        }
        match &self.backend {
            Backend::Embedded(embedded) => embedded.memory().witness(turn),
            Backend::Remote(remote) => remote.call("witness", turn),
        }
    }

    /// Upserts one claim through the gated claim-candidate path.
    pub fn claim_upsert(&self, claim: &ClaimInput) -> Result<CommitReceipt, MemoryError> {
        self.ensure_dispatch_pid()?;
        check_claim_input(claim)?;
        match &self.backend {
            Backend::Embedded(embedded) => embedded.memory().claim_upsert(claim),
            Backend::Remote(remote) => remote.call("claim_upsert", claim),
        }
    }

    /// Recalls a memory pack.
    ///
    /// The lease argument the engine takes is `None` and is NOT a client
    /// input: no lease issuer exists, and a bearer slip is not one. An
    /// `Effort::Deep` call therefore returns the engine's `LEASE_REQUIRED`
    /// through both backends, spelled identically.
    pub fn recall(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
    ) -> Result<MemoryPack, MemoryError> {
        self.ensure_dispatch_pid()?;
        check_query(query)?;
        check_limit(limit)?;
        match &self.backend {
            Backend::Embedded(embedded) => embedded
                .memory()
                .recall(query, effort, scope, limit, format, None),
            Backend::Remote(remote) => remote.call(
                "recall",
                &RecallRequest {
                    query,
                    effort,
                    scope,
                    limit,
                    format,
                },
            ),
        }
    }

    /// Lists governance receipts, newest first.
    pub fn receipts(&self, limit: usize) -> Result<Vec<MemoryReceipt>, MemoryError> {
        self.ensure_dispatch_pid()?;
        check_limit(limit)?;
        match &self.backend {
            Backend::Embedded(embedded) => embedded.memory().receipts(limit),
            Backend::Remote(remote) => remote.call("receipts", &ReceiptsRequest { limit }),
        }
    }
}

/// Validates a claim's boundary-checkable fields before dispatch.
///
/// `confidence` and `salience` are already `f32` on the engine DTO, so the
/// non-finite refusal for them happens in the binding layers where the host's
/// `f64` narrows. What remains checkable here is the serialized value size.
fn check_claim_input(claim: &ClaimInput) -> Result<(), MemoryError> {
    if !claim.confidence.is_finite() {
        return Err(crate::error::bad_request(
            "confidence must be a finite number",
            &["NaN and infinity are not confidences; send a value in [0, 1]."],
        ));
    }
    if claim.salience.is_some_and(|value| !value.is_finite()) {
        return Err(crate::error::bad_request(
            "salience must be a finite number",
            &["NaN and infinity are not salience values; send a value in [0, 1]."],
        ));
    }
    let encoded = serde_json::to_vec(&claim.value).map_err(|error| {
        crate::error::sdk_error(
            MEMORY_CODE_INTERNAL,
            format!("claim value could not be serialized: {error}"),
            &["Send a JSON-representable claim value."],
        )
    })?;
    check_payload_bytes("claim value", encoded.len())
}
