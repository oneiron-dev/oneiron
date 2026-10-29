//! A media call's replay key (FIX 465, FIX 2962): the name a repeat of one
//! call shares with the first, so the repeat answers from what the first
//! was given, its answer or its job's ticket, and is not paid for or
//! rendered again. A durable step keys its call by its attempt, as
//! `call_as_step` keys a model call; a caller keys its own by the
//! idempotency key it sends, inside its own partition. Every key binds the
//! request's canonical hash, so one key on another request names another
//! call, which goes out as any call does. A call with no key is never
//! replayed.
use super::MediaRequest;

/// What a media call's repeat is known by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaReplayKey {
    /// A durable step's call: its attempt (hex) and the request's hash.
    Step {
        attempt: String,
        request_hash: String,
    },
    /// A caller's own key for the call, inside `partition`, the caller it
    /// is kept for: no other caller's key reaches its answer.
    Caller {
        partition: String,
        key: String,
        request_hash: String,
    },
}

impl MediaReplayKey {
    /// The key of the call `request` makes in attempt `attempt` (hex).
    ///
    /// # Errors
    ///
    /// A request whose canonical bytes do not encode.
    pub fn step(attempt: String, request: &MediaRequest) -> Result<Self, serde_json::Error> {
        Ok(Self::Step {
            attempt,
            request_hash: request.canonical_hash_hex()?,
        })
    }

    /// The key a caller in `partition` sent as `key` for `request`.
    ///
    /// # Errors
    ///
    /// A request whose canonical bytes do not encode.
    pub fn caller(
        partition: String,
        key: String,
        request: &MediaRequest,
    ) -> Result<Self, serde_json::Error> {
        Ok(Self::Caller {
            partition,
            key,
            request_hash: request.canonical_hash_hex()?,
        })
    }

    /// The id its answer is kept under: a digest of its kind and each of its
    /// parts, each part length-prefixed, so two keys never share one.
    #[must_use]
    pub fn memo_id(&self) -> String {
        let parts: [&str; 4] = match self {
            Self::Step {
                attempt,
                request_hash,
            } => ["step", attempt, "", request_hash],
            Self::Caller {
                partition,
                key,
                request_hash,
            } => ["caller", partition, key, request_hash],
        };
        let mut digest = blake3::Hasher::new();
        for part in parts {
            digest.update(&(part.len() as u64).to_le_bytes());
            digest.update(part.as_bytes());
        }
        digest.finalize().to_hex()[..MEMO_ID_HEX].to_owned()
    }
}

/// The hex digits of a memo id: 128 bits.
const MEMO_ID_HEX: usize = 32;
