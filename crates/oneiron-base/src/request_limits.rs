//! Request boundary limits and pure validators.

use oneiron_contracts::memory::MemoryError;

/// Maximum query string, in bytes: 8 KiB.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;

/// The 1,000-row candidate floor a narrowed read fetches.
pub const MAX_SEARCH_LIMIT: usize = 1_000;

/// How many candidates a read that narrows its rows after ranking fetches
/// for `requested`: `requested` over the [`MAX_SEARCH_LIMIT`] floor, never
/// the index's population, so its cost follows the caller's page and not
/// the vault. Zero stays zero. The page is short when the window holds
/// fewer rows the narrowing keeps.
pub fn narrowed_candidate_window(requested: usize) -> usize {
    if requested == 0 {
        0
    } else {
        requested.max(MAX_SEARCH_LIMIT)
    }
}

/// Maximum serialized body of one entity, claim, or message: 64 KiB.
pub const MAX_ENTITY_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum entities or claims in one batched call: 10,000.
pub const MAX_BATCH_ENTITIES: usize = 10_000;

/// Maximum files in one legacy codebase-snapshot call: 100,000.
pub const MAX_CODEBASE_FILES: usize = 100_000;

/// Maximum remote REQUEST body, in bytes: 64 MiB.
///
/// Matches the `DefaultBodyLimit` the server's facade nest applies, so a body
/// this client agrees to send is a body that router agrees to read.
pub const MAX_REMOTE_REQUEST_BYTES: usize = 64 * 1024 * 1024;

/// A remote success body, in bytes: 64 MiB. The SDK client no longer reads
/// its replies under it: it decodes each from the wire whatever its length
/// (ABC transport row T19). A device's own sync reads (renewal, removal
/// delivery) and the residence row read still take it as their bound.
pub const MAX_REMOTE_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Rejects an over-long query before it reaches retrieval.
pub fn check_query(query: &str) -> Result<(), MemoryError> {
    if query.len() > MAX_QUERY_BYTES {
        return Err(MemoryError::bad_request_with(
            format!("query exceeds the {MAX_QUERY_BYTES}-byte ceiling"),
            &["Shorten the query; retrieval scores intent, not transcript length."],
        ));
    }
    Ok(())
}

/// Longest recall deadline a request or a vault may name, in milliseconds:
/// one minute. Past it a deadline stops being a cut and becomes a wait.
pub const MAX_RECALL_DEADLINE_MS: u64 = 60_000;

/// Refuses a recall deadline outside 1 to [`MAX_RECALL_DEADLINE_MS`].
pub fn check_deadline_ms(deadline_ms: Option<u64>) -> Result<(), MemoryError> {
    if deadline_ms.is_some_and(|ms| ms == 0 || ms > MAX_RECALL_DEADLINE_MS) {
        return Err(deadline_out_of_range());
    }
    Ok(())
}

/// A binding's `deadline_ms` number as engine milliseconds. JavaScript has
/// no integer type, so a fractional, non-finite or out-of-range value is
/// refused here, before it narrows.
pub fn check_deadline_ms_number(value: f64) -> Result<u64, MemoryError> {
    // MAX_RECALL_DEADLINE_MS is far below 2^53, so the cast is exact.
    let max = MAX_RECALL_DEADLINE_MS as f64;
    if !value.is_finite() || value.fract() != 0.0 || !(1.0..=max).contains(&value) {
        return Err(deadline_out_of_range());
    }
    // Proven finite, whole and within 1..=MAX_RECALL_DEADLINE_MS above.
    Ok(value as u64)
}

fn deadline_out_of_range() -> MemoryError {
    MemoryError::bad_request_with(
        format!("deadline_ms must be a whole number between 1 and {MAX_RECALL_DEADLINE_MS}"),
        &["Send the milliseconds the caller can wait, or omit deadline_ms for no deadline."],
    )
}

/// Latest reference time a recall may name: 9999-12-31T23:59:59Z.
pub const MAX_AS_OF_SECONDS: u64 = oneiron_contracts::temporal::TEMPORAL_MAX_REFERENCE_SECS;

/// Rejects a reference time past the calendar the temporal parser resolves.
pub fn check_as_of(as_of: Option<u64>) -> Result<(), MemoryError> {
    if as_of.is_some_and(|as_of| as_of > MAX_AS_OF_SECONDS) {
        return Err(MemoryError::bad_request_with(
            format!("as_of must be Unix seconds no later than {MAX_AS_OF_SECONDS}"),
            &["Send the conversation's time in Unix seconds, or omit as_of for now."],
        ));
    }
    Ok(())
}

/// Rejects a zero row count.
///
/// Zero is refused rather than silently defaulted: a caller who asks for no
/// rows has a bug the SDK must not paper over by inventing a page size.
pub fn check_limit_nonzero(limit: usize) -> Result<(), MemoryError> {
    if limit == 0 {
        return Err(MemoryError::bad_request_with(
            "limit must be at least 1",
            &["Request at least one row."],
        ));
    }
    Ok(())
}

/// Rejects an over-large entity/claim/message body.
///
/// `label` names the field in the caller's own vocabulary so the message is
/// actionable without the caller reading this source.
pub fn check_payload_bytes(label: &str, len: usize) -> Result<(), MemoryError> {
    if len > MAX_ENTITY_PAYLOAD_BYTES {
        return Err(MemoryError::bad_request_with(
            format!("{label} exceeds the {MAX_ENTITY_PAYLOAD_BYTES}-byte payload ceiling"),
            &["Split the payload, or store the bulk as a blob artifact and claim its ref."],
        ));
    }
    Ok(())
}

/// Rejects an over-large batch.
pub fn check_batch_len(label: &str, len: usize) -> Result<(), MemoryError> {
    if len > MAX_BATCH_ENTITIES {
        return Err(MemoryError::bad_request_with(
            format!("{label} exceeds the {MAX_BATCH_ENTITIES}-element batch ceiling"),
            &["Send the work in smaller batches."],
        ));
    }
    Ok(())
}

/// Rejects an unusable embedding dimension count.
pub fn check_dimensions(dimensions: usize) -> Result<(), MemoryError> {
    if dimensions == 0 {
        return Err(MemoryError::bad_request_with(
            "dimensions must be at least 1",
            &["Open the vault with the dimension count its embedding model produces."],
        ));
    }
    Ok(())
}

/// Reads a rendering token budget a binding passed as its host language's
/// number (FIX 9962): a non-negative whole number, 0 rendering uncut. Like
/// [`check_unix_seconds`], it proves the number narrows exactly.
pub fn check_token_budget_number(value: f64) -> Result<u64, MemoryError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > 9_007_199_254_740_991.0
    {
        return Err(MemoryError::bad_request(
            "token_budget must be a non-negative whole number of tokens",
        ));
    }
    // Proven finite, non-negative, whole and below 2^53 above.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

/// Rejects a timestamp that is not a usable Unix-seconds value (I14).
///
/// The public bindings take timestamps as the host language's number type —
/// JavaScript has no integer type at all — so "non-negative" and "safe
/// integer" are properties this boundary must PROVE rather than assume. A
/// negative or fractional value fails here, before any `f64`-to-integer
/// narrowing could silently truncate it into a plausible-looking date.
pub fn check_unix_seconds(label: &str, value: f64) -> Result<u64, MemoryError> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
        return Err(MemoryError::bad_request_with(
            format!("{label} must be a non-negative whole number of Unix seconds"),
            &[
                "Pass a whole number of Unix seconds (not milliseconds, not a fraction); the SDK performs no unit conversion.",
            ],
        ));
    }
    // JavaScript's MAX_SAFE_INTEGER is 2^53 - 1. Although 2^53 itself is
    // representable, its next integer rounds to the same f64 and is not safe.
    if value > 9_007_199_254_740_991.0 {
        return Err(MemoryError::bad_request_with(
            format!("{label} is not a safe integer"),
            &["Unix seconds fit comfortably in a safe integer; check for a milliseconds value."],
        ));
    }
    // Proven finite, non-negative, whole and below 2^53 above.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

/// The longest ref `vault.refs.resolve` reads, in bytes.
pub const RECORD_REF_MAX_BYTES: usize = 256;

/// Call mode's deadline unless a vault sets its own. ARCH-0042
/// #call-mode-budget holds call-mode recall at p95 ≤ 100 ms server-side at
/// 10k records (≤ 150 ms at 100k), a starting bar the perf pass drives
/// lower. It is the default of `VaultConfig::call_mode_deadline`,
/// and a request's own `deadline_ms` overrides that.
pub const DEFAULT_CALL_MODE_DEADLINE: std::time::Duration = std::time::Duration::from_millis(100);
