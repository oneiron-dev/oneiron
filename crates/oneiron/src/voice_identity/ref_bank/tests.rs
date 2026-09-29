use super::*;

#[test]
fn target_reader_and_writer_reject_the_same_corrupt_rows() -> Result<()> {
    let dir = tempfile::tempdir().expect("ref vault directory");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "source".into(),
        voice_id: "our-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1],
            transcript: String::new(),
        }],
    })?;
    let request = vault.prepare_voice_clone("our-voice", "host", false)?;
    let valid = vault.record_voice_target_clone(&request, "provider-id", 42)?;
    for (case, mut bad) in [valid.clone(), valid.clone(), valid]
        .into_iter()
        .enumerate()
    {
        match case {
            0 => bad.cloned_at = 0,
            1 => bad.vendor_voice_id = " ".into(),
            _ => bad.vendor_voice_id = "x".repeat(4_097),
        }
        // The writer must not silently replace corrupt persisted data either.
        let key = target_key("our-voice", "host")?;
        let mut txn = vault.store.env.write_txn()?;
        TARGETS.put(&vault.store, &mut txn, &key, &bad)?;
        txn.commit()?;
        assert!(matches!(
            vault.voice_target_clone("our-voice", "host", false),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            vault.record_voice_target_clone(&request, "replacement", 43),
            Err(Error::InvalidConfig(_))
        ));
    }
    Ok(())
}

#[test]
fn fence_follows_the_selected_source_refs() -> Result<()> {
    let dir = tempfile::tempdir().expect("ref vault directory");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let owner = EntityId::now();
    let pack = |id: &str, origin: VoiceRefOrigin| VoiceRefPack {
        version: 1,
        id: id.into(),
        voice_id: "our-voice".into(),
        owner,
        origin,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1],
            transcript: String::new(),
        }],
    };
    vault.store_voice_ref_pack(&pack("source", VoiceRefOrigin::Captured))?;
    let (_, fence) = vault.prepare_fenced_voice_clone("our-voice", "local", false)?;
    assert!(vault.voice_ref_fence_current_now("our-voice", "local", &fence)?);
    // A generated pack is outside a source-only selection; a new source pack is not.
    vault.store_voice_ref_pack(&pack("generated", VoiceRefOrigin::Generated))?;
    assert!(vault.voice_ref_fence_current_now("our-voice", "local", &fence)?);
    vault.store_voice_ref_pack(&pack("second", VoiceRefOrigin::Captured))?;
    assert!(!vault.voice_ref_fence_current_now("our-voice", "local", &fence)?);
    assert!(
        vault
            .with_fenced_voice_clone("our-voice", "local", &fence, |_| Ok(()))
            .is_err()
    );
    Ok(())
}

#[test]
fn identity_banked_before_incarnations_fences_until_rebirth() -> Result<()> {
    let dir = tempfile::tempdir().expect("ref vault directory");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let owner = EntityId::now();
    let pack = VoiceRefPack {
        version: 1,
        id: "source".into(),
        voice_id: "our-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1],
            transcript: String::new(),
        }],
    };
    vault.store_voice_ref_pack(&pack)?;
    // An identity banked before incarnations were minted has no row.
    let mut txn = vault.store.env.write_txn()?;
    INCARNATIONS.delete(&vault.store, &mut txn, &"our-voice".to_owned())?;
    txn.commit()?;
    let (_, legacy) = vault.prepare_fenced_voice_clone("our-voice", "local", false)?;
    assert_eq!(legacy.incarnation, None);
    assert!(vault.voice_ref_fence_current_now("our-voice", "local", &legacy)?);
    // Withdrawal deletes the identity; an identical rebank is a new incarnation.
    let mut txn = vault.store.env.write_txn()?;
    delete_owner_refs(&vault.store, &mut txn, &owner)?;
    txn.commit()?;
    vault.store_voice_ref_pack(&pack)?;
    assert!(!vault.voice_ref_fence_current_now("our-voice", "local", &legacy)?);
    Ok(())
}
