// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! The recorder's engine contract (VOX-08).
//!
//! A capture device commits one segment as ASSET bytes plus a `voice.segment`
//! claim describing them, and syncs it to the home node. Three properties are
//! load-bearing and all three live in the engine, not in the app:
//!
//! 1. the committed segment reaches a second vault BYTE-IDENTICALLY over the
//!    ordinary device-sync path — nothing about audio is special on the wire;
//! 2. the claim door refuses a segment claim that misdescribes the audio;
//! 3. a capture device that registers no candidacy never becomes the home
//!    node, and alone it elects nothing — the vault stays device-local.
//!
//! The two-vault half rides the shared `tests/it_sync/sync_harness` and needs
//! the `sync` feature; the claim-door and election halves are featureless.

use oneiron::dreamer_runner::{DreamerHomeNodeCandidate, DreamerHomeNodeClass, DreamerRunnerStore};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::voice_segment::{
    AEC_MODE_ACTIVE, AEC_MODE_BYPASSED_HEADPHONES, PREDICATE_VOICE_SEGMENT,
    VOICE_SEGMENT_VALUE_KEYS,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Error, TimeRange,
    Vault, VaultConfig,
};
use rmpv::Value;

/// 2026-03-15 00:00 UTC — inside the sync harness's shared window.
const SPAN_START: u64 = 1_773_532_800;
/// One 60-second segment, the recorder's segment length.
const SPAN_END: u64 = SPAN_START + 60;
const DEVICE: &str = "built-in-microphone";
/// Stand-in for the segment's WAV bytes. Their content is irrelevant; that
/// they cross the wire unchanged is the point.
const SEGMENT_AUDIO: &[u8] = b"RIFF\x24\x00\x00\x00WAVEfmt segment-bytes";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn span() -> TimeRange {
    TimeRange {
        start: SPAN_START,
        end: SPAN_END,
    }
}

/// The exact wire object, spelled literally — no engine encoder in sight.
fn segment_value(channels: u64, aec_mode: &str) -> Value {
    Value::Map(vec![
        (Value::from("span_start"), Value::from(SPAN_START)),
        (Value::from("span_end"), Value::from(SPAN_END)),
        (Value::from("channels"), Value::from(channels)),
        (Value::from("aec_mode"), Value::from(aec_mode)),
        (Value::from("device"), Value::from(DEVICE)),
    ])
}

fn segment_claim(asset: EntityId, value: Value) -> ClaimBody {
    ClaimBody::new(
        PREDICATE_VOICE_SEGMENT,
        ClaimSubject::Entity(asset),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}

/// What the recorder's vault sink does: audio bytes as an ASSET entity, then
/// one claim saying what those bytes are. Only the two-vault half commits a
/// whole segment; the claim-door and election halves talk to the door directly.
#[cfg(feature = "sync")]
fn commit_segment(
    vault: &Vault,
    asset: &EntityId,
    claim_id: &EntityId,
    value: Value,
) -> Result<(), Error> {
    vault.put_entity(asset, ENTITY_TYPE_ASSET, span(), SPAN_START, SEGMENT_AUDIO)?;
    vault.put_claim(claim_id, &segment_claim(*asset, value), span(), SPAN_START)
}

/// The pinned key set, restated literally: a silent rename here is a wire
/// break for every already-committed segment.
#[test]
fn segment_value_keys_are_pinned() {
    assert_eq!(
        VOICE_SEGMENT_VALUE_KEYS,
        ["span_start", "span_end", "channels", "aec_mode", "device"]
    );
}

/// The claim door — not the app — is what refuses a dishonest segment.
#[test]
fn malformed_segment_claim_is_rejected_by_the_claim_door() {
    let (_dir, vault) = temp_vault();
    let asset = EntityId::now();
    vault
        .put_entity(&asset, ENTITY_TYPE_ASSET, span(), SPAN_START, SEGMENT_AUDIO)
        .expect("asset bytes");

    // Zero channels: nothing was captured, so there is no segment to describe.
    let err = vault
        .put_claim(
            &EntityId::now(),
            &segment_claim(asset, segment_value(0, AEC_MODE_ACTIVE)),
            span(),
            SPAN_START,
        )
        .expect_err("a zero-channel segment must be refused");
    assert!(
        matches!(err, Error::InvalidClaimBody(_)),
        "expected a claim-body rejection, got {err:?}"
    );

    // An unpinned mode would let a segment claim cancellation nobody ran.
    let err = vault
        .put_claim(
            &EntityId::now(),
            &segment_claim(asset, segment_value(2, "probably_cancelled")),
            span(),
            SPAN_START,
        )
        .expect_err("an unknown aec_mode must be refused");
    assert!(
        matches!(err, Error::InvalidClaimBody(_)),
        "expected a claim-body rejection, got {err:?}"
    );

    // The same door accepts the honest body.
    vault
        .put_claim(
            &EntityId::now(),
            &segment_claim(asset, segment_value(2, AEC_MODE_BYPASSED_HEADPHONES)),
            span(),
            SPAN_START,
        )
        .expect("a well-formed segment claim must land");
}

/// The recorder is a laptop. It registers no home-node candidacy at all, so
/// its candidate carries no designation class: beside an always-on node it
/// loses, and alone it elects nothing rather than electing itself.
#[test]
fn recorder_never_becomes_the_home_node() {
    const RECORDER_NODE: u64 = 806;
    const ALWAYS_ON_NODE: u64 = 42;

    let (_dir, vault) = temp_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let recorder = DreamerHomeNodeCandidate {
        node_id: RECORDER_NODE,
        cloud: false,
        attached: false,
        always_on_local: false,
        primary_device: false,
    };
    let always_on = DreamerHomeNodeCandidate::always_on_local(ALWAYS_ON_NODE);

    let elected = runner
        .elect_home_node(&[recorder, always_on], SPAN_START)
        .expect("election")
        .expect("an always-on node must be elected");
    assert_eq!(elected.node_id, ALWAYS_ON_NODE);
    assert_eq!(elected.class, DreamerHomeNodeClass::AlwaysOnLocal);

    assert!(
        runner
            .elect_home_node(&[recorder], SPAN_START + 1)
            .expect("election")
            .is_none(),
        "a lone recorder must elect no home node — the vault stays device-local"
    );
}

#[cfg(feature = "sync")]
#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

#[cfg(feature = "sync")]
mod device_sync {
    use oneiron::sync::types::WindowKey;
    use oneiron::sync::window;
    use oneiron::{EntityId, voice_segment::AEC_MODE_BYPASSED_HEADPHONES};

    use crate::sync_harness::{WINDOW, assert_converged, exchange, vault_pair};
    use crate::{PREDICATE_VOICE_SEGMENT, commit_segment, segment_value};

    /// The done-means: a committed segment lands on the second vault
    /// byte-identically over the ordinary device-sync path.
    #[test]
    fn committed_segment_round_trips_byte_identically() {
        let (a, b) = vault_pair();
        let asset = EntityId::now();
        let claim_id = EntityId::now();
        commit_segment(
            &a.vault,
            &asset,
            &claim_id,
            segment_value(2, AEC_MODE_BYPASSED_HEADPHONES),
        )
        .expect("commit segment on node A");

        let audio_a = a
            .vault
            .get_raw(&asset)
            .unwrap()
            .expect("segment asset on node A");
        let claim_a = a
            .vault
            .get_raw(&claim_id)
            .unwrap()
            .expect("segment claim on node A");

        // Node A's LMDB → its live window doc → the wire.
        let key = WindowKey::new(WINDOW);
        window::reverse_rematerialize(&a.vault, a.doc(WINDOW), &key).unwrap();
        exchange(&a, &b, WINDOW);

        assert_eq!(
            b.vault.get_raw(&asset).unwrap().as_deref(),
            Some(audio_a.as_slice()),
            "segment audio must arrive on node B byte-identically"
        );
        assert_eq!(
            b.vault.get_raw(&claim_id).unwrap().as_deref(),
            Some(claim_a.as_slice()),
            "the voice.segment claim must arrive on node B byte-identically"
        );

        // …and it is readable as the claim it was written as: the replay door
        // ran the family validator and kept it.
        let replicated = b
            .vault
            .get_claim(&claim_id)
            .unwrap()
            .expect("replicated segment claim must read back");
        assert_eq!(replicated.predicate, PREDICATE_VOICE_SEGMENT);
        assert_eq!(
            replicated.value,
            segment_value(2, AEC_MODE_BYPASSED_HEADPHONES)
        );

        assert_converged(&a, &b, WINDOW);
    }
}
