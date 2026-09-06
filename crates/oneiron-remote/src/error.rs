//! The SDK's half of the typed error contract (ONE-1441 §Typed error contract,
//! I7).
//!
//! There is exactly one error type on this surface and it is the ENGINE's:
//! [`MemoryError`], the `{code, message, suggestions}` triple. Embedded
//! failures are that value already and cross byte-for-byte. Remote failures
//! are rebuilt from the server's `{error:{code,message,requestId,suggestions}}`
//! envelope with the code string carried verbatim, so an engine code this SDK
//! has never heard of still reaches user code spelled the way the engine
//! spelled it.
//!
//! `MemoryError`'s own constructors are crate-private to `oneiron`, so this
//! module builds the struct literally. Every field is `pub`, and the two
//! diagnostic tails (`successor_short_id`, `gate_denial`) are `None` on
//! SDK-minted refusals: they are engine facts, and the SDK is not in a
//! position to invent either one.

use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MemoryError,
};

/// Builds an SDK-minted refusal carrying `code` verbatim.
///
/// `suggestions` is never empty on this path by construction: every caller
/// below passes at least one, and the contract says a caller is always told
/// what to do next.
pub(crate) fn sdk_error(
    code: &str,
    message: impl Into<String>,
    suggestions: &[&str],
) -> MemoryError {
    MemoryError {
        code: code.to_owned(),
        message: message.into(),
        suggestions: suggestions.iter().map(|s| (*s).to_owned()).collect(),
        successor_short_id: None,
        gate_denial: None,
    }
}

/// Malformed public input, refused before core entry.
pub(crate) fn bad_request(message: impl Into<String>, suggestions: &[&str]) -> MemoryError {
    sdk_error(MEMORY_CODE_BAD_REQUEST, message, suggestions)
}

/// A refusal the caller cannot retry their way out of with the same identity.
pub(crate) fn forbidden(message: impl Into<String>, suggestions: &[&str]) -> MemoryError {
    sdk_error(MEMORY_CODE_FORBIDDEN, message, suggestions)
}

/// Transport and other failures the caller did not cause.
///
/// Used for every connection, TLS, timeout, truncated-body and
/// non-Oneiron-response failure. A foreign response body NEVER reaches this
/// value: proxies and load balancers emit HTML that would become executable
/// text in a caller's log or UI, and the only honest thing to say about it is
/// that the endpoint did not answer as Oneiron.
pub(crate) fn transport_error(message: impl Into<String>) -> MemoryError {
    sdk_error(
        MEMORY_CODE_INTERNAL,
        message,
        &[
            "Check that the Oneiron URL points at a running oneiron-server.",
            "Check server health and network reachability, then retry.",
        ],
    )
}

/// The single-writer refusal (I8).
///
/// Minted at exactly three places: the embedded constructor, when the lease
/// acquire refused with `Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD)`;
/// the `open_shared` registry join, when a post-`fork` child would otherwise
/// be handed the parent's live entry; and the per-verb PID gate, which catches
/// that same child dispatching on an inherited handle. All three are "somebody
/// else owns this directory's write side", which is what the code says.
///
/// The first suggestion names `connect` on purpose: the single-writer rule is
/// not a wall, it is a redirection, and the process that owns the vault is
/// exactly the one a second process should be talking to.
pub(crate) fn vault_locked() -> MemoryError {
    sdk_error(
        MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER,
        "this vault directory is already owned by another embedded process",
        &[
            "Connect to the process that owns this vault with Oneiron.connect(url, key).",
            "Stop the owning process before reopening this path in embedded mode.",
        ],
    )
}
