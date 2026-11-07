//! Canonical MESSAGE body vocabulary, encoding, and structural validation.

use rmpv::Value;

use crate::gate_reason::GateReasonCode;
use crate::source_audience_obligation::{
    SOURCE_AUDIENCE_REQUIRED_KEY, encode_source_audience_required,
};
use oneiron_base::error::{Error, RecordError, Result};
use oneiron_contracts::limit_ask::{EngineLimit, LimitWatch};

/// The vault owner's own words.
pub const WITNESS_AUTHOR_USER: &str = "user";
/// The companion persona's words.
pub const WITNESS_AUTHOR_COMPANION: &str = "companion";
/// Tooling/engine rows. These carry NO `AuthoredBy` edge, which is exactly why
/// the bucket needs authority the other two do not: an unattributed row reads
/// downstream as the engine's own voice.
pub const WITNESS_AUTHOR_SYSTEM: &str = "system";

/// The canonical MESSAGE body keys, in canonical order.
const BODY_KEY_AUTHOR: &str = "author";
const BODY_KEY_TYPE: &str = "type";
const BODY_KEY_CONTENT: &str = "content";
const BODY_KEY_PARTS: &str = "parts";
const BODY_KEY_METADATA: &str = "metadata";
const BODY_KEY_IS_VISIBLE: &str = "is_visible";
const BODY_KEY_ORDER: &str = "order";

/// The TURN-level grouping key (`memory::witness`'s `speaker` stamp). Listed
/// with the MESSAGE body keys below because metadata that restates it is the
/// same side channel one level up.
const TURN_KEY_SPEAKER: &str = "speaker";

/// Envelope-axis names metadata may not restate, at ANY depth. Metadata is
/// opaque passenger data; a key that shadows an axis the door authorizes is a
/// second, ungated copy of that axis riding inside the first. The engine's
/// source-audience obligation is one of them: only the top-level key of a
/// source-bound row carries it (fix list row 16256).
const RESERVED_METADATA_KEYS: [&str; 8] = [
    BODY_KEY_AUTHOR,
    BODY_KEY_TYPE,
    BODY_KEY_CONTENT,
    BODY_KEY_METADATA,
    BODY_KEY_IS_VISIBLE,
    BODY_KEY_ORDER,
    TURN_KEY_SPEAKER,
    SOURCE_AUDIENCE_REQUIRED_KEY,
];

/// Metadata nesting bound, the root map at depth 0: the decoder's own floor
/// (ABC row 52), distinct from a raw JSON parser's depth. A value nested
/// deeper fails closed; the size of a metadata map is measured instead
/// ([`witness_metadata_measure`]), never refused.
const MAX_WITNESS_METADATA_DEPTH: usize = 128;

/// The metadata key an import's provenance rides under: the transcript
/// importer's and an archive import's (ARCH-0027, FIX 7777).
pub const METADATA_KEY_IMPORT: &str = "import";

/// The key inside an archive import's provenance that carries the value the
/// source row's own metadata kept under `import` (FIX 7777).
pub const IMPORT_KEY_SOURCE_IMPORT: &str = "source_import";

/// One durable ordered MESSAGE part. Custody references carry no part bytes;
/// revealing one still requires the existing secret entry grant.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum StoredMessagePart {
    Inline(oneiron_model::llm::ContentPart),
    Custody { custody: String },
}

/// One MESSAGE envelope, exactly as the write door will encode it.
///
/// `metadata` is the rmpv value the body carries (the engine converts JSON to
/// MessagePack before it reaches the door), never the caller's JSON: the door
/// authorizes what will be written.
#[derive(Debug, Clone, PartialEq)]
pub struct WitnessMessageEnvelope<'a> {
    /// `user` | `companion` | `system`; anything else fails closed.
    pub author: &'a str,
    /// App-closed type token.
    pub message_type: &'a str,
    /// Text content, BM25-indexed by the caller when non-empty.
    pub content: &'a str,
    /// Ordered terminal parts owned by the MESSAGE, never its editable text.
    pub parts: Option<Vec<StoredMessagePart>>,
    /// Opaque passenger data, or `None`.
    pub metadata: Option<Value>,
    /// Whether the row is part of the visible transcript.
    pub is_visible: bool,
    /// Position within the turn.
    pub order: u32,
}

impl WitnessMessageEnvelope<'_> {
    /// The CANONICAL MESSAGE body bytes for this envelope.
    ///
    /// This is the only MESSAGE body encoder in the engine: `memory::witness`
    /// delegates here, and the door below re-runs it to prove the staged bytes
    /// are the authorized ones. Key order is part of the encoding, not an
    /// accident of construction.
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        let mut entries = vec![
            (Value::from(BODY_KEY_AUTHOR), Value::from(self.author)),
            (Value::from(BODY_KEY_TYPE), Value::from(self.message_type)),
            (Value::from(BODY_KEY_CONTENT), Value::from(self.content)),
        ];
        if let Some(parts) = &self.parts {
            let encoded = rmp_serde::to_vec_named(parts)
                .map_err(|_| Error::InvalidClaimBody("witness message parts are not encodable"))?;
            let value = rmpv::decode::read_value(&mut encoded.as_slice())
                .map_err(|_| Error::InvalidClaimBody("witness message parts are not encodable"))?;
            entries.push((Value::from(BODY_KEY_PARTS), value));
        }
        if let Some(metadata) = &self.metadata {
            entries.push((Value::from(BODY_KEY_METADATA), metadata.clone()));
        }
        entries.push((
            Value::from(BODY_KEY_IS_VISIBLE),
            Value::Boolean(self.is_visible),
        ));
        entries.push((
            Value::from(BODY_KEY_ORDER),
            Value::from(u64::from(self.order)),
        ));
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries))
            .map_err(|_| Error::InvalidClaimBody("witness message body is not encodable"))?;
        Ok(out)
    }

    /// The canonical body of a SOURCE-BOUND MESSAGE (fix list row 16256):
    /// [`Self::encode_body`] with the engine's source-audience obligation
    /// appended last. Only the source landing's proof-bearing door stages
    /// these bytes; every other door binds [`Self::encode_body`] and so
    /// refuses them.
    ///
    /// # Errors
    ///
    /// As [`Self::encode_body`].
    pub fn encode_source_bound_body(&self) -> Result<Vec<u8>> {
        encode_source_audience_required(&self.encode_body()?)
    }
}

/// Envelope shape, vocabulary and coherence. Unknown or malformed values fail
/// closed; there is no "pass it through and let the app decide" arm, because
/// the app is exactly who this door does not trust.
pub fn witness_message_envelope_denial(
    envelope: &WitnessMessageEnvelope<'_>,
    body: &[u8],
) -> Option<GateReasonCode> {
    let malformed = Some(GateReasonCode::DenyWitnessMessageMalformedEnvelope);

    if !matches!(
        envelope.author,
        WITNESS_AUTHOR_USER | WITNESS_AUTHOR_COMPANION | WITNESS_AUTHOR_SYSTEM
    ) {
        return malformed;
    }
    if !valid_message_type(envelope.message_type) {
        return malformed;
    }
    // A user's own words are never invisible. `companion`/`system` rows may be
    // hidden (an executor's kept-to-itself reasoning is a real, gated shape);
    // an invisible row attributed to the owner is a forgery with no reader.
    if envelope.author == WITNESS_AUTHOR_USER && !envelope.is_visible {
        return malformed;
    }
    if let Some(metadata) = &envelope.metadata
        && !valid_metadata_map(metadata)
    {
        return malformed;
    }

    // The BIND. Everything above authorized the AXES; this proves the bytes the
    // caller is about to write are those axes and nothing else — no extra key,
    // no reordered map, no second copy of an axis appended after the encode.
    match envelope.encode_body() {
        Ok(canonical) if canonical == body => None,
        _ => malformed,
    }
}

/// [`witness_message_envelope_denial`] for a SOURCE-BOUND MESSAGE (fix list
/// row 16256): every axis check over the envelope's plain encoding, then the
/// bind of `body` to [`WitnessMessageEnvelope::encode_source_bound_body`],
/// so the one extra key is the obligation, last, as `true`, and nothing else.
#[must_use]
pub fn source_bound_witness_message_envelope_denial(
    envelope: &WitnessMessageEnvelope<'_>,
    body: &[u8],
) -> Option<GateReasonCode> {
    let malformed = Some(GateReasonCode::DenyWitnessMessageMalformedEnvelope);
    let Ok(plain) = envelope.encode_body() else {
        return malformed;
    };
    if let Some(reason_code) = witness_message_envelope_denial(envelope, &plain) {
        return Some(reason_code);
    }
    match envelope.encode_source_bound_body() {
        Ok(stamped) if stamped == body => None,
        _ => malformed,
    }
}

/// The canonical-envelope verdict for one MESSAGE body, at the storage
/// materialization chokepoint (ONE-1686).
///
/// [`validate_canonical_witness_message_body`] answers with the row's AUTHOR
/// bucket, because that is the axis a door with no actor still has to rule on:
/// a `system` row carries no `AuthoredBy` edge, so nothing downstream can tell
/// it from the engine's own voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessMessageBodyAuthor {
    User,
    Companion,
    System,
}

/// Proves MESSAGE bytes are the canonical envelope this module encodes, and
/// returns the author bucket they claim.
///
/// This is the SAME encoder and the SAME envelope floor
/// [`check_witness_message_ceiling`] runs — decoded here rather than supplied,
/// so a door that holds bytes but no actor (a raw put, a replicated carry) can
/// still refuse anything that is not a well-formed transcript row. It is NOT a
/// second authorization path: it answers "are these bytes an envelope", never
/// "may somebody write it", and every local write still passes the ceiling
/// door before it stages.
///
/// # Errors
///
/// [`RecordError::InvalidWitnessMessageBody`](crate::error::RecordError::InvalidWitnessMessageBody) when the bytes are not decodable, are
/// not the canonical key set in canonical order, carry an unknown author or
/// type token, hide a `user` row, carry malformed
/// metadata, or do not re-encode byte-identically.
///
/// A source-bound row (fix list row 16256) carries one more key, the
/// engine's source-audience obligation, LAST and only as `true`; its bytes
/// must re-encode as [`WitnessMessageEnvelope::encode_source_bound_body`].
/// Accepting it here is format, not authority: every door that writes
/// MESSAGE rows binds its own encoding, and only the source landing's
/// carries it.
pub fn validate_canonical_witness_message_body(body: &[u8]) -> Result<WitnessMessageBodyAuthor> {
    let malformed = || {
        Error::Record(RecordError::InvalidWitnessMessageBody(
            "MESSAGE body is not a canonical envelope",
        ))
    };
    let mut cursor = body;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(malformed());
    };
    if !cursor.is_empty() {
        return Err(malformed());
    }
    let mut author: Option<&str> = None;
    let mut message_type: Option<&str> = None;
    let mut content: Option<&str> = None;
    let mut parts: Option<Vec<StoredMessagePart>> = None;
    let mut metadata: Option<Value> = None;
    let mut is_visible: Option<bool> = None;
    let mut order: Option<u32> = None;
    let mut source_bound = false;
    for (position, (key, value)) in entries.iter().enumerate() {
        let Some(key) = key.as_str() else {
            return Err(malformed());
        };
        // Duplicate keys are a second copy of an axis; the canonical encoder
        // emits each exactly once, so a repeat cannot round-trip anyway. It is
        // rejected by name so the failure names the reason.
        let duplicated = match key {
            BODY_KEY_AUTHOR => {
                author = value.as_str();
                author.is_none()
            }
            BODY_KEY_TYPE => {
                message_type = value.as_str();
                message_type.is_none()
            }
            BODY_KEY_CONTENT => {
                content = value.as_str();
                content.is_none()
            }
            BODY_KEY_PARTS => {
                if parts.is_some() {
                    return Err(malformed());
                }
                let mut encoded = Vec::new();
                rmpv::encode::write_value(&mut encoded, value).map_err(|_| malformed())?;
                parts = Some(rmp_serde::from_slice(&encoded).map_err(|_| malformed())?);
                false
            }
            BODY_KEY_METADATA => {
                if metadata.is_some() {
                    return Err(malformed());
                }
                metadata = Some(value.clone());
                false
            }
            BODY_KEY_IS_VISIBLE => {
                is_visible = value.as_bool();
                is_visible.is_none()
            }
            BODY_KEY_ORDER => {
                order = value.as_u64().and_then(|value| u32::try_from(value).ok());
                order.is_none()
            }
            // The obligation is the last key, once, as `true`.
            SOURCE_AUDIENCE_REQUIRED_KEY => {
                if position + 1 != entries.len() || value.as_bool() != Some(true) {
                    return Err(malformed());
                }
                source_bound = true;
                false
            }
            _ => return Err(malformed()),
        };
        if duplicated {
            return Err(malformed());
        }
    }
    let (Some(author), Some(message_type), Some(content), Some(is_visible), Some(order)) =
        (author, message_type, content, is_visible, order)
    else {
        return Err(malformed());
    };
    let envelope = WitnessMessageEnvelope {
        author,
        message_type,
        content,
        parts,
        metadata,
        is_visible,
        order,
    };
    // The SAME floor the ceiling door runs, including the canonical-bytes bind
    // (`encode_body() == body`, or its source-bound twin), which is what makes
    // key ORDER and the absence of any extra byte part of the answer rather
    // than of the parse.
    let denial = if source_bound {
        source_bound_witness_message_envelope_denial(&envelope, body)
    } else {
        witness_message_envelope_denial(&envelope, body)
    };
    if denial.is_some() {
        return Err(malformed());
    }
    Ok(match envelope.author {
        WITNESS_AUTHOR_USER => WitnessMessageBodyAuthor::User,
        WITNESS_AUTHOR_COMPANION => WitnessMessageBodyAuthor::Companion,
        // The floor above already refused every other value.
        _ => WitnessMessageBodyAuthor::System,
    })
}

/// Message types are a closed set APP-side and opaque here, so the door pins
/// the SHAPE rather than the vocabulary: a printable, punctuation-only token
/// (`dialogue`, `executor.speak`, `tool_result`) of any length: ASCII
/// alphanumerics plus the separators existing types use. No whitespace, no
/// control bytes, no empty token. Anything else is an unknown value and fails
/// closed.
fn valid_message_type(message_type: &str) -> bool {
    !message_type.is_empty()
        && message_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '+'))
}

/// What one MESSAGE's metadata measures against its `[limits]` rows (ABC
/// rows 53 and 56): the most nodes, keys and values together, and the most
/// canonical MessagePack bytes, any one of its three parts holds (the
/// entries other than `import`, an import's provenance, and the source row's
/// own `import` it carries, FIX 7777).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WitnessMetadataMeasure {
    /// Keys and values, recursively, of the largest part.
    pub nodes: u64,
    /// Canonical MessagePack bytes of the largest part.
    pub bytes: u64,
}

impl WitnessMetadataMeasure {
    /// Tells `watch` what this metadata measured: past the
    /// `witness_metadata_nodes` or `witness_metadata_bytes` row it asks
    /// whether everything is okay, and the metadata is kept whole.
    pub fn report(self, watch: &LimitWatch) {
        watch.measure(EngineLimit::WitnessMetadataNodes, self.nodes);
        watch.measure(EngineLimit::WitnessMetadataBytes, self.bytes);
    }
}

/// The metadata of canonical MESSAGE `body`, measured, when the body carries
/// metadata that is a well-formed map; `None` for a body without metadata or
/// one that does not decode. Run where a put stores the row, after its
/// envelope is proven, so a crossing asks once per stored row.
pub fn witness_metadata_measure(body: &[u8]) -> Option<WitnessMetadataMeasure> {
    let mut cursor = body;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    let metadata = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(BODY_KEY_METADATA))
        .map(|(_, value)| value)?;
    measure_metadata_map(metadata)
}

/// Measures every part of `metadata` and keeps the largest, or `None` when it
/// is not a well-formed metadata map.
fn measure_metadata_map(metadata: &Value) -> Option<WitnessMetadataMeasure> {
    let parts = metadata_parts(metadata)?;
    let mut measure = WitnessMetadataMeasure::default();
    for (index, part) in parts.iter().enumerate() {
        let mut walk = MetadataWalk::default();
        if !walk.part(part, index == IMPORT_PART) {
            return None;
        }
        measure.nodes = measure.nodes.max(walk.nodes);
        measure.bytes = measure.bytes.max(walk.bytes);
    }
    Some(measure)
}

/// Whether `metadata` is a well-formed metadata map: string keys only, no
/// reserved envelope-axis name at any depth, no opaque value kind, nesting
/// within [`MAX_WITNESS_METADATA_DEPTH`]. Its size is measured, never refused
/// ([`witness_metadata_measure`]).
fn valid_metadata_map(metadata: &Value) -> bool {
    measure_metadata_map(metadata).is_some()
}

/// Where the `import` part sits in [`metadata_parts`].
const IMPORT_PART: usize = 1;

/// The three parts of `metadata` that are measured each on its own (FIX
/// 7777): the entries other than `import`; the `import` entry, an import's
/// provenance, without its `source_import`; and that `source_import` value,
/// measured as the `import` entry it was in the source row. An archive import
/// adds its provenance to a source row whose own metadata, its own `import`
/// value included, may already be large, and none of the three counts toward
/// another. `None` when `metadata` is not a map.
fn metadata_parts(metadata: &Value) -> Option<[Vec<(&Value, &Value)>; 3]> {
    let Value::Map(entries) = metadata else {
        return None;
    };
    let mut rest = Vec::new();
    let mut import = Vec::new();
    let mut carried = Vec::new();
    for (key, value) in entries {
        if key.as_str() != Some(METADATA_KEY_IMPORT) {
            rest.push((key, value));
            continue;
        }
        let Value::Map(provenance) = value else {
            import.push((key, value));
            continue;
        };
        import.push((key, value));
        for (name, source) in provenance {
            if name.as_str() == Some(IMPORT_KEY_SOURCE_IMPORT) {
                carried.push((key, source));
            }
        }
    }
    Some([rest, import, carried])
}

/// One part's walk: well-formedness, and its nodes and canonical encoded
/// bytes counted as it goes, with checked sums and no encoding allocated.
#[derive(Default)]
struct MetadataWalk {
    nodes: u64,
    bytes: u64,
}

impl MetadataWalk {
    /// Walks one part, a map of `entries`. In the `import` part
    /// (`provenance`), an `import` entry holding a provenance map is walked
    /// without its `source_import`, which is its own part.
    fn part(&mut self, entries: &[(&Value, &Value)], provenance: bool) -> bool {
        self.count_node();
        self.add(map_header_len(entries.len()));
        entries.iter().all(|(key, value)| {
            let Some(name) = key.as_str() else {
                return false;
            };
            if !self.key(name) {
                return false;
            }
            match value {
                Value::Map(import) if provenance && name == METADATA_KEY_IMPORT => {
                    self.count_node();
                    let own: Vec<_> = import
                        .iter()
                        .filter(|(inner, _)| inner.as_str() != Some(IMPORT_KEY_SOURCE_IMPORT))
                        .collect();
                    self.add(map_header_len(own.len()));
                    own.iter().all(|(inner, entry)| {
                        inner.as_str().is_some_and(|inner| self.key(inner)) && self.value(entry, 2)
                    })
                }
                _ => self.value(value, 1),
            }
        })
    }

    /// One map key: nonempty, no control character, no reserved axis name;
    /// counted as a node and its string encoding.
    fn key(&mut self, key: &str) -> bool {
        if key.is_empty()
            || key.chars().any(char::is_control)
            || RESERVED_METADATA_KEYS.contains(&key)
        {
            return false;
        }
        self.count_node();
        self.add(str_len(key.len()));
        true
    }

    /// One value at `depth` (the part's root map is depth 0).
    fn value(&mut self, value: &Value, depth: usize) -> bool {
        if depth > MAX_WITNESS_METADATA_DEPTH {
            return false;
        }
        self.count_node();
        match value {
            Value::Nil | Value::Boolean(_) => {
                self.add(1);
                true
            }
            Value::Integer(integer) => {
                self.add(integer_len(integer));
                true
            }
            Value::F32(_) => {
                self.add(5);
                true
            }
            Value::F64(_) => {
                self.add(9);
                true
            }
            Value::String(text) => text.as_str().is_some_and(|text| {
                self.add(str_len(text.len()));
                true
            }),
            // Binary and Ext are byte channels no JSON-shaped metadata can
            // produce; accepting them would reopen the side channel one layer
            // down.
            Value::Binary(_) | Value::Ext(_, _) => false,
            Value::Array(items) => {
                self.add(array_header_len(items.len()));
                items.iter().all(|item| self.value(item, depth + 1))
            }
            Value::Map(entries) => {
                self.add(map_header_len(entries.len()));
                entries.iter().all(|(key, entry)| {
                    key.as_str().is_some_and(|key| self.key(key)) && self.value(entry, depth + 1)
                })
            }
        }
    }

    fn count_node(&mut self) {
        self.nodes = self.nodes.saturating_add(1);
    }

    fn add(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// Encoded bytes of a MessagePack string of `len` bytes, as `rmp` writes it:
/// fixstr, str8, str16 or str32 header, then the bytes.
fn str_len(len: usize) -> u64 {
    let header = match len {
        0..32 => 1,
        32..256 => 2,
        256..65_536 => 3,
        _ => 5,
    };
    header + len as u64
}

/// Encoded bytes of a MessagePack array header for `len` items.
fn array_header_len(len: usize) -> u64 {
    match len {
        0..16 => 1,
        16..65_536 => 3,
        _ => 5,
    }
}

/// Encoded bytes of a MessagePack map header for `len` entries.
fn map_header_len(len: usize) -> u64 {
    array_header_len(len)
}

/// Encoded bytes of `integer` in the smallest form `rmp` writes it in.
fn integer_len(integer: &rmpv::Integer) -> u64 {
    if let Some(value) = integer.as_u64() {
        return match value {
            0..128 => 1,
            128..256 => 2,
            256..65_536 => 3,
            65_536..4_294_967_296 => 5,
            _ => 9,
        };
    }
    match integer.as_i64().unwrap_or(i64::MIN) {
        -32..0 => 1,
        -128..-32 => 2,
        -32_768..-128 => 3,
        -2_147_483_648..-32_768 => 5,
        _ => 9,
    }
}

/// The REPLICATED MESSAGE door (ONE-1686): CLOSED, on the evidence.
///
/// # What the replicated door actually carries
///
/// A MESSAGE that arrives over sync reaches `batch::apply_put` with
/// `replicated = true`, a `write_envelope` of `None`, a `WindowKey` that is a
/// calendar month (`YYYY-MM`), and a CRDT map key that is the entity id. The
/// body itself is the six-axis transcript envelope and carries no signature,
/// no signer key and no actor ref. `crate::write_envelope::WriteEnvelope` —
/// the type that carries `WriteActor` provenance into a write — appears
/// nowhere in `crate::sync`, and nothing on the replay path reads the row's
/// `AuthoredBy` edge (edges materialize in a LATER pass than entities, so it
/// is not even present when the body lands).
///
/// The kinds that DO admit remote rows carry their own proof inside the body:
/// an AUTHORITY_LOG entry names its signer and is folded against this vault's
/// roster; a REDACTION_AUDIT receipt carries an Ed25519 attestation bound to a
/// mirrored lease. A MESSAGE envelope has no such half. There is no verified
/// source actor or peer at this door to bind remote authorship to.
///
/// # Why that means closed, not narrowed
///
/// `check_witness_message_ceiling` is the ONLY authorization for a MESSAGE
/// row, and its subject is an ACTOR: which actor may author which bucket,
/// against the policy snapshot the write commits under. With no actor there is
/// no ceiling to run, and admitting the row anyway would make sync a second,
/// weaker MESSAGE authorization path — a peer (including a foreign vault whose
/// blob `sync::selector::admit_federated_entity_blob` copies through verbatim,
/// MESSAGE having no pinned admission arm there) could mint transcript rows in
/// this vault's own voice. Every author bucket therefore fails closed, with the
/// bucket named so the quarantine row says which forgery was attempted:
///
/// * `system` — the ENGINE'S own voice, carrying no `AuthoredBy` edge at all;
///   permitted locally only by an owner-authored, actor-bound `auto` ceiling
///   that no replicated envelope can present.
/// * `user`/`companion` — attributed rows whose local counterpart is bound to
///   a store-verified actor entity by an `AuthoredBy` edge the writing door
///   mints in the same transaction. Replicated, there is no actor to bind and
///   nothing downstream could tell an honest row from a forged one.
///
/// This narrows exactly ONE entity kind's remote door. Every other kind
/// converges unchanged, and a local MESSAGE row already in LMDB is skipped by
/// the byte-identical short-circuit in `sync::window::forward_rematerialize`
/// before it ever reaches this door, so a healthy vault replaying its own
/// mirror is untouched.
///
/// A row whose put carries an own-device lane that vouches for it meets
/// the gate's `validate_own_device_witness_message_body` instead (FIX 9600). This door
/// stays every other replay's: federated, recovered, or from no proven sender.
///
/// # Errors
///
/// [`RecordError::InvalidWitnessMessageBody`](crate::error::RecordError::InvalidWitnessMessageBody), always. `sync::quarantine` classifies
/// the kind as a remote-op rejection, so the row is quarantined with its
/// payload and the window continues; nothing partial is written, because the
/// refusal precedes every store mutation in `apply_put`.
pub fn validate_replicated_witness_message_body(body: &[u8]) -> Result<()> {
    // The envelope floor runs FIRST even though the verdict is refusal either
    // way: the quarantine row keeps the rejection reason, and "a peer shipped
    // bytes that are not a transcript row at all" is a different operational
    // fact from "a peer shipped a well-formed row it has no authority to
    // author". It also keeps the floor where it belongs if a future protocol
    // revision ever does carry a verified source actor here.
    Err(match validate_canonical_witness_message_body(body)? {
        WitnessMessageBodyAuthor::System => Error::Record(RecordError::InvalidWitnessMessageBody(
            "a replicated MESSAGE may not claim the unattributed system author",
        )),
        WitnessMessageBodyAuthor::User | WitnessMessageBodyAuthor::Companion => {
            Error::Record(RecordError::InvalidWitnessMessageBody(
                "a replicated MESSAGE carries no local actor binding for its author",
            ))
        }
    })
}
