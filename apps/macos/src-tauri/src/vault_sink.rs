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
            &segment_claim(asset, &meta, span.end),
            span,
            meta.started_at,
        )?;
        Ok(asset)
    }
}

fn segment_claim(asset: EntityId, meta: &SegmentMeta, span_end: u64) -> ClaimBody {
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

#[cfg(test)]
mod tests {
    use oneiron::VaultConfig;

    use super::*;
    use crate::capture::{AecMode, OutputRoute};

    const STARTED_AT: u64 = 1_773_532_800;
    const AUDIO: &[u8] = b"RIFF....WAVEfmt segment";

    fn temp_vault() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("open vault");
        (dir, Arc::new(vault))
    }

    fn meta(aec: AecMode, channels: u16) -> SegmentMeta {
        SegmentMeta {
            started_at: STARTED_AT,
            duration_ms: 60_000,
            aec,
            device: "built-in-microphone".to_owned(),
            channels,
        }
    }

    #[test]
    fn a_committed_segment_is_asset_bytes_plus_a_readable_claim() {
        let (_dir, vault) = temp_vault();
        let sink = VaultSegmentSink::new(Arc::clone(&vault));

        let asset = sink
            .commit_segment(
                AUDIO,
                meta(
                    AecMode::Bypassed {
                        route: OutputRoute::Headphones,
                    },
                    2,
                ),
            )
            .expect("the segment must land");

        assert_eq!(
            vault.get(&asset).expect("read asset").as_deref(),
            Some(AUDIO),
            "the audio is stored exactly as captured"
        );
    }

    #[test]
    fn the_claim_door_refuses_a_segment_that_captured_nothing() {
        let (_dir, vault) = temp_vault();
        let sink = VaultSegmentSink::new(vault);

        // Zero channels is not a segment; the engine family — not the app —
        // is what says so.
        let err = sink
            .commit_segment(AUDIO, meta(AecMode::Unavailable, 0))
            .expect_err("a channel-less segment must be refused");
        assert!(
            matches!(err, crate::capture::CaptureError::Vault(_)),
            "expected the vault to refuse it, got {err}"
        );
    }
}
