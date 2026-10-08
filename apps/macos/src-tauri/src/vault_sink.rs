//! Landing a segment in the embedded vault.
//!
//! Two writes, in this order: the audio as an ASSET entity, then one
//! `voice.segment` claim whose subject is that entity. The claim is what makes
//! the bytes legible — span, channel count, echo-cancellation mode, device —
//! and the engine's claim door is what makes it honest. The app spells the
//! value; it does not get to decide whether the value is acceptable.

use std::sync::Arc;

use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::voice_segment::{PREDICATE_VOICE_SEGMENT, VOICE_SEGMENT_VALUE_KEYS};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
};
use rmpv::Value;

use crate::capture::{Result, SegmentMeta, SegmentSink};

/// The pinned key set, read off the engine constant rather than retyped: a
/// rename over there becomes a compile error here instead of a silently stale
/// key on new segments.
const KEY_SPAN_START: &str = VOICE_SEGMENT_VALUE_KEYS[0];
const KEY_SPAN_END: &str = VOICE_SEGMENT_VALUE_KEYS[1];
const KEY_CHANNELS: &str = VOICE_SEGMENT_VALUE_KEYS[2];
const KEY_AEC_MODE: &str = VOICE_SEGMENT_VALUE_KEYS[3];
const KEY_DEVICE: &str = VOICE_SEGMENT_VALUE_KEYS[4];

/// A segment sink that writes into a local vault.
pub struct VaultSegmentSink {
    vault: Arc<Vault>,
}

impl VaultSegmentSink {
    /// A sink over `vault`.
    #[must_use]
    pub const fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }
}

impl SegmentSink for VaultSegmentSink {
    fn commit_segment(&self, audio: &[u8], meta: SegmentMeta) -> Result<EntityId> {
        let span = TimeRange {
            start: meta.started_at,
            end: meta.span_end()?,
        };
        let asset = EntityId::now();
        self.vault
            .put_entity(&asset, ENTITY_TYPE_ASSET, span, meta.started_at, audio)?;
        self.vault.put_claim(
            &EntityId::now(),
            &segment_claim(asset, &meta, span.end)?,
            span,
            meta.started_at,
        )?;
        Ok(asset)
    }
}

fn segment_claim(asset: EntityId, meta: &SegmentMeta, span_end: u64) -> oneiron::Result<ClaimBody> {
    ClaimBody::new(
        PREDICATE_VOICE_SEGMENT,
        ClaimSubject::Entity(asset),
        Value::Map(vec![
            (Value::from(KEY_SPAN_START), Value::from(meta.started_at)),
            (Value::from(KEY_SPAN_END), Value::from(span_end)),
            (
                Value::from(KEY_CHANNELS),
                Value::from(u64::from(meta.channels)),
            ),
            (
                Value::from(KEY_AEC_MODE),
                Value::from(meta.aec.claim_mode()),
            ),
            (Value::from(KEY_DEVICE), Value::from(meta.device.as_str())),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}
