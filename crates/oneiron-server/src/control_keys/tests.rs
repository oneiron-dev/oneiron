use super::*;

#[tokio::test]
async fn unique_digest_no_plaintext_per_call_scope_stamp_rotate_revoke_and_floor()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), oneiron::VaultConfig::server())?);
    let keys = ControlKeys::new(vault.clone(), Zeroizing::new(vec![7; 32]))?;
    let old = b"control-key-secret-never-persist-this-value";
    let new = b"replacement-secret-never-persist-this-value";
    let scopes = BTreeSet::from(["control:read".to_owned()]);
    let row = keys.insert(old, scopes.clone(), 10, Some(100))?;
    assert!(matches!(
        keys.insert(old, scopes.clone(), 10, None),
        Err(KeyError::Duplicate)
    ));
    for key in vault.sync_state_keys_with_prefix(PREFIX)? {
        let bytes = vault.sync_state_get(&key)?.unwrap();
        assert!(!bytes.windows(old.len()).any(|w| w == old));
    }
    assert_eq!(
        keys.verify(old, "control:read", 11).await?.last_used_at,
        Some(11)
    );
    assert_eq!(
        keys.verify(old, "control:read", 12).await?.last_used_at,
        Some(12)
    );
    let started = Instant::now();
    assert!(matches!(
        keys.verify(old, "control:write", 13).await,
        Err(KeyError::ScopeDenied)
    ));
    assert!(started.elapsed() >= FAILURE_FLOOR);
    assert_eq!(keys.record(&row.digest)?.unwrap().last_used_at, Some(12));
    assert!(matches!(
        keys.rotate(old, old, 14),
        Err(KeyError::Duplicate)
    ));
    keys.verify(old, "control:read", 14).await?;
    let rotated = keys.rotate(old, new, 15)?;
    for (key, now) in [
        (old.as_slice(), 16),
        (b"unknown".as_slice(), 16),
        (new.as_slice(), rotated.expires_at),
    ] {
        let started = Instant::now();
        assert!(matches!(
            keys.verify(key, "control:read", now).await,
            Err(KeyError::Rejected)
        ));
        assert!(started.elapsed() >= FAILURE_FLOOR);
    }
    keys.verify(new, "control:read", 17).await?;
    keys.revoke(new)?;
    assert!(keys.record(&rotated.digest)?.unwrap().revoked);
    assert!(matches!(
        keys.verify(new, "control:read", 18).await,
        Err(KeyError::Rejected)
    ));
    let sibling = b"a-third-control-key-to-demonstrate-no-cache";
    let third = keys.insert(sibling, scopes, 10, None)?;
    keys.verify(sibling, "control:read", 20).await?;
    vault.sync_state_delete(&format!("{PREFIX}{}", third.digest))?;
    assert!(matches!(
        keys.verify(sibling, "control:read", 21).await,
        Err(KeyError::Rejected)
    ));
    Ok(())
}
