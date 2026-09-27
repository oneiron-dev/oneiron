use oneiron::error::Result;
use oneiron::voice_identity::ref_bank::*;
use oneiron::{EntityId, Vault, VaultConfig};

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("create vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn pack(id: &str, voice_id: &str, owner: EntityId, origin: VoiceRefOrigin) -> VoiceRefPack {
    VoiceRefPack {
        version: 1,
        id: id.into(),
        voice_id: voice_id.into(),
        owner,
        origin,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1, 2, 3],
            transcript: "reference".into(),
        }],
    }
}

#[test]
fn designed_captured_and_generated_packs_belong_to_a_vault_identity() -> Result<()> {
    let (_dir, vault) = open();
    let (_other_dir, other) = open();
    let owner = EntityId::now();
    let designed = pack(
        "design",
        "voice-1",
        owner,
        VoiceRefOrigin::Designed {
            vendor: "design-tool".into(),
        },
    );
    let captured = pack("capture", "voice-2", owner, VoiceRefOrigin::Captured);
    let generated = pack("generated", "voice-1", owner, VoiceRefOrigin::Generated);
    assert!(vault.store_voice_ref_pack(&generated).is_err());
    assert!(vault.voice_identity("voice-1")?.is_none());
    vault.store_voice_ref_pack(&designed)?;
    vault.store_voice_ref_pack(&captured)?;
    vault.store_voice_ref_pack(&generated)?;
    vault.store_voice_ref_pack(&generated)?; // idempotent retry
    assert_eq!(
        vault.voice_identity("voice-1")?.unwrap().pack_ids,
        vec!["design", "generated"]
    );
    assert_eq!(
        vault.voice_identity("voice-2")?.unwrap().pack_ids,
        vec!["capture"]
    );
    assert_eq!(
        vault.voice_ref_pack("generated")?.unwrap().origin,
        VoiceRefOrigin::Generated
    );
    assert!(other.voice_identity("voice-1")?.is_none());
    let mut changed = generated;
    changed.clips[0].audio.push(4);
    assert!(vault.store_voice_ref_pack(&changed).is_err());
    changed.id = "another".into();
    changed.owner = EntityId::now();
    assert!(vault.store_voice_ref_pack(&changed).is_err());
    Ok(())
}

#[test]
fn clones_select_refs_and_cache_target_ids_only_until_change_or_eviction() -> Result<()> {
    let (_dir, vault) = open();
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&pack(
        "source",
        "our-voice",
        owner,
        VoiceRefOrigin::Captured,
    ))?;
    assert!(vault.voice_identity("vendor-only-id")?.is_none());
    assert!(
        vault
            .prepare_voice_clone("vendor-only-id", "host", false)
            .is_err()
    );
    let source = vault.prepare_voice_clone("our-voice", "host", false)?;
    assert_eq!(source.source_packs, vec!["source"]);
    assert!(
        vault
            .voice_target_clone("our-voice", "host", false)?
            .is_none()
    );
    let first = vault.record_voice_target_clone(&source, "vendor-only-id", 42)?;
    assert_eq!(first.vendor_voice_id, "vendor-only-id");
    let duplicate = vault.record_voice_target_clone(&source, "unnecessary-reclone", 43)?;
    assert_eq!(duplicate, first); // A current pointer cannot be replaced.
    assert_eq!(first.cloned_at, 42);
    assert_eq!(
        vault
            .voice_target_clone("our-voice", "host", false)?
            .as_ref(),
        Some(&first)
    );
    let second = vault.prepare_voice_clone("our-voice", "local", false)?;
    vault.record_voice_target_clone(&second, "local-pointer", 43)?;
    vault.store_voice_ref_pack(&pack("ai", "our-voice", owner, VoiceRefOrigin::Generated))?;
    assert!(
        vault
            .voice_target_clone("our-voice", "host", true)?
            .is_none()
    );
    // The source-only selection is still valid after AI refs are added.
    assert_eq!(
        vault.record_voice_target_clone(&source, "source-only", 44)?,
        first
    );
    assert!(
        vault
            .voice_target_clone("our-voice", "host", false)?
            .is_some()
    );
    let with_ai = vault.prepare_voice_clone("our-voice", "host", true)?;
    assert_eq!(with_ai.source_packs, vec!["source", "ai"]);
    assert_eq!(with_ai.clips.len(), 2);
    vault.store_voice_ref_pack(&pack("ai-2", "our-voice", owner, VoiceRefOrigin::Generated))?;
    assert!(
        vault
            .record_voice_target_clone(&with_ai, "stale", 45)
            .is_err()
    );
    let with_ai = vault.prepare_voice_clone("our-voice", "host", true)?;
    let refreshed = vault.record_voice_target_clone(&with_ai, "new-host-pointer", 46)?;
    assert_eq!(
        vault.voice_target_clone("our-voice", "host", true)?,
        Some(refreshed)
    );
    assert!(
        vault
            .voice_target_clone("our-voice", "host", false)?
            .is_none()
    );
    // Adding a new source pack invalidates even the source-only selection.
    vault.store_voice_ref_pack(&pack(
        "source-2",
        "our-voice",
        owner,
        VoiceRefOrigin::Captured,
    ))?;
    assert!(
        vault
            .voice_target_clone("our-voice", "local", false)?
            .is_none()
    );
    assert!(
        vault
            .record_voice_target_clone(&second, "old-refs", 47)
            .is_err()
    );
    let new_local = vault.prepare_voice_clone("our-voice", "local", false)?;
    let updated = vault.record_voice_target_clone(&new_local, "new-local-pointer", 48)?;
    assert_eq!(
        vault.voice_target_clone("our-voice", "local", false)?,
        Some(updated)
    );
    vault.evict_voice_target("our-voice", "host")?;
    assert!(
        vault
            .voice_target_clone("our-voice", "host", true)?
            .is_none()
    );
    assert!(vault.voice_identity("our-voice")?.is_some());
    assert!(
        vault
            .voice_target_clone("our-voice", "local", false)?
            .is_some()
    );
    Ok(())
}

#[test]
fn withdrawing_owner_deletes_identity_packs_and_target_pointers() -> Result<()> {
    let (_dir, vault) = open();
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&pack("source", "voice", owner, VoiceRefOrigin::Captured))?;
    let request = vault.prepare_voice_clone("voice", "host", false)?;
    vault.record_voice_target_clone(&request, "provider-id", 1)?;
    vault.withdraw_voice_consent(&oneiron::voice_identity::VoiceWithdrawalRequest {
        event_id: "withdraw-owner".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![oneiron::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: oneiron::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    assert!(vault.voice_identity("voice")?.is_none());
    assert!(vault.voice_ref_pack("source")?.is_none());
    assert!(vault.voice_target_clone("voice", "host", false)?.is_none());
    Ok(())
}
