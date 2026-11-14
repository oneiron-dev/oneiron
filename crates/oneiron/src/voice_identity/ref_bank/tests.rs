use super::*;

/// The subject's render grant the captured refs are banked under, reaching
/// the targets these tests prepare; each captured pack cites its event.
fn grant_render(vault: &Vault, owner: EntityId) -> Result<()> {
    vault.record_voice_render_consent(&VoiceRenderDecision {
        event_id: "grant-our-voice".into(),
        voice_id: "our-voice".into(),
        subject: owner,
        subject_kind: VoiceRefSubjectKind::Person,
        recorded_by: owner,
        occurred_at: 1,
        reach: ModelLocality::OwnServer,
        basis: Some(VoiceConsentBasis::ConversationalNotice {
            notice: "render".into(),
        }),
        state: VoiceConsentState::Granted,
    })?;
    Ok(())
}

#[test]
fn target_reader_and_writer_reject_the_same_corrupt_rows() -> Result<()> {
    let dir = tempfile::tempdir().expect("ref vault directory");
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let owner = EntityId::now();
    grant_render(&vault, owner)?;
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "source".into(),
        voice_id: "our-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured {
            consent_event_ref: "grant-our-voice".into(),
        },
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![1],
            transcript: String::new(),
        }],
    })?;
    let request =
        vault.prepare_voice_clone("our-voice", "host", false, ModelLocality::OwnServer)?;
    let valid = vault.record_voice_target_clone(&request, "provider-id", 42, false)?;
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
            vault.voice_target_clone("our-voice", "host", false, ModelLocality::OwnServer),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            vault.record_voice_target_clone(&request, "replacement", 43, false),
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
    grant_render(&vault, owner)?;
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
    vault.store_voice_ref_pack(&pack(
        "source",
        VoiceRefOrigin::Captured {
            consent_event_ref: "grant-our-voice".into(),
        },
    ))?;
    let (_, fence) =
        vault.prepare_fenced_voice_clone("our-voice", "local", false, ModelLocality::OwnServer)?;
    assert!(vault.voice_ref_fence_current_now("our-voice", "local", &fence)?);
    // A generated pack is outside a source-only selection; a new source pack is not.
    vault.store_voice_ref_pack(&pack("generated", VoiceRefOrigin::Generated))?;
    assert!(vault.voice_ref_fence_current_now("our-voice", "local", &fence)?);
    vault.store_voice_ref_pack(&pack(
        "second",
        VoiceRefOrigin::Captured {
            consent_event_ref: "grant-our-voice".into(),
        },
    ))?;
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
    grant_render(&vault, owner)?;
    let pack = VoiceRefPack {
        version: 1,
        id: "source".into(),
        voice_id: "our-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured {
            consent_event_ref: "grant-our-voice".into(),
        },
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
    let (_, legacy) =
        vault.prepare_fenced_voice_clone("our-voice", "local", false, ModelLocality::OwnServer)?;
    assert_eq!(legacy.incarnation, None);
    assert!(vault.voice_ref_fence_current_now("our-voice", "local", &legacy)?);
    // Withdrawal deletes the identity; an identical rebank is a new incarnation.
    let mut txn = vault.store.env.write_txn()?;
    delete_owner_refs(&vault.store, &mut txn, &owner)?;
    txn.commit()?;
    // The erase took the subject's grant with the refs: grant again first.
    grant_render(&vault, owner)?;
    vault.store_voice_ref_pack(&pack)?;
    assert!(!vault.voice_ref_fence_current_now("our-voice", "local", &legacy)?);
    Ok(())
}
