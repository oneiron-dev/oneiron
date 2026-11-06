//! FIX 6424 (Engine 10-20 20:4x): an e-sign act called with no retry key is
//! keyed on its own call. An owner's one-time press approves exactly one
//! prepared send, and that send's logical ref (`esign:<verb>:<document>:<key>`)
//! is part of what it approves, so two separate calls stay two sends: two
//! keys, two intent refs, two gate decisions, each with its own press.
//!
//! A call whose transport named its invocation (`x-oneiron-invocation`, MCP
//! `_meta`, a code-mode step) derives its key from that id, so a true retry
//! of the call, naming it again, prepares the same send and spends the same
//! press. A call that names none mints a fresh nonce, as every no-key call
//! did before; its view's `intent_ref` ends in that key, and its retry passes
//! the key as `idempotency_key`. No key is stored and no ledger row is read,
//! so a damaged earlier row never blocks a new call (CALLS `FIX 6424 e-sign
//! no-key key chain`).

use crate::verb_invocation::InvocationId;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// The BLAKE3 domain of a no-key act's key derived from its invocation.
pub const NO_KEY_CALL_DOMAIN: &[u8] = b"oneiron.esign.dispatch.no_key.call.v1";
/// How many bytes of that digest the key keeps, as lower hex: a fresh
/// nonce's length.
pub const NO_KEY_CALL_KEY_BYTES: usize = 16;
