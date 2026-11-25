//! Moved from `crates/oneiron/src/receipt/call.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
pub use oneiron_verb_wire::receipt::call::CallAttemptRef;
pub use oneiron_verb_wire::receipt::call::CallOutcome;
pub use oneiron_verb_wire::receipt::call::CallReceiptRequest;
pub use oneiron_verb_wire::receipt::call::CallTransport;

/// The domain an action digest is taken in, so it never equals another
/// digest of the same bytes.
pub const ACTION_DIGEST_DOMAIN: &str = "oneiron.action_digest.v1";

/// BLAKE3 of `value` serialized canonically (object keys sorted at every
/// depth), lowercase hex: the digest a receipt states for a JSON input or
/// result, stable however the caller ordered its keys.
#[must_use]
pub fn call_json_digest(value: &serde_json::Value) -> String {
    let mut hasher = blake3::Hasher::new();
    write_canonical(&mut hasher, value);
    hasher.finalize().to_hex().to_string()
}

/// Writes `value` canonically (object keys sorted at every depth) into
/// `hasher`: the bytes [`call_json_digest`] hashes.
pub fn write_canonical(hasher: &mut blake3::Hasher, value: &serde_json::Value) {
    write_canonical_to_sink(
        &mut |bytes: &[u8]| {
            hasher.update(bytes);
        },
        value,
    );
}

/// Hands the canonical bytes of `value` (object keys sorted at every depth)
/// to `sink`, in order, one piece at a time: the bytes [`write_canonical`]
/// writes into a BLAKE3 hasher, for a digest kept by another writer (the
/// fingerprint door's `LegacyDigest`).
pub fn write_canonical_to_sink(sink: &mut impl FnMut(&[u8]), value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            sink(b"{");
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    sink(b",");
                }
                write_canonical_to_sink(sink, &serde_json::Value::String(key.clone()));
                sink(b":");
                if let Some(item) = map.get(key) {
                    write_canonical_to_sink(sink, item);
                }
            }
            sink(b"}");
        }
        serde_json::Value::Array(items) => {
            sink(b"[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    sink(b",");
                }
                write_canonical_to_sink(sink, item);
            }
            sink(b"]");
        }
        scalar => {
            // A scalar's JSON text is already canonical.
            sink(scalar.to_string().as_bytes());
        }
    }
}
