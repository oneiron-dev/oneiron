//! Closing timestamps cannot precede the authored claim's occurred start.

use super::*;

#[test]
fn lifecycle_binding_rejects_before_start_despite_clamped_header() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    assert_current_actor(&vault, id, actor)?;
    let raw = vault.get_raw(&id)?.expect("authored claim");
    let digest = binding_digest(&vault, id)?;
    assert_eq!(digest, Some(row_digest(&raw).to_vec()));

    for lifecycle in [
        ClaimLifecycleStatus::Retracted,
        ClaimLifecycleStatus::Superseded,
    ] {
        let mut op = retract_op(&vault, id)?;
        let BatchOp::Put { occurred, data, .. } = &mut op else {
            unreachable!();
        };
        let mut body = decode_claim_body(data, false)?;
        body.lifecycle = lifecycle;
        body.valid_to = Some(9);
        *data = encode_claim_body(&body)?;
        // Match the public callers' current clamp: the header is a legal
        // point event, but the body still closes before the stored start.
        occurred.end = occurred.start;
        let error = vault
            .with_write_txn(|txn| ClaimMaterialization::lifecycle(&vault.store, txn, &op))
            .expect_err("a clamped header must not seal an early closing timestamp");
        assert!(
            matches!(error, Error::InvalidTimeRange { start: 10, end: 9 }),
            "{lifecycle:?}: {error:?}"
        );
        assert_eq!(vault.get_raw(&id)?.expect("unchanged claim"), raw);
        assert_eq!(binding_digest(&vault, id)?, digest);
        assert_current_actor(&vault, id, actor)?;
    }
    Ok(())
}

#[test]
fn retract_before_start_rejects_without_changing_claim_binding_or_edges() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    authored_local_claim(&vault, actor, id)?;
    assert_current_actor(&vault, id, actor)?;
    actor_only_policy(&vault, actor)?;
    let raw = vault.get_raw(&id)?.expect("authored claim");
    let digest = binding_digest(&vault, id)?;
    assert_eq!(digest, Some(row_digest(&raw).to_vec()));
    let decisions = vault.store.gate_decisions(128)?;
    let mut edges_before = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for db in [&vault.store.edges_out, &vault.store.edges_in] {
            let rows = db
                .iter(&txn)?
                .map(|entry| {
                    let (key, value) = entry?;
                    Ok((key.to_vec(), value.to_vec()))
                })
                .collect::<Result<Vec<_>>>()?;
            edges_before.push(rows);
        }
    }

    let error = vault
        .retract_claim(&id, 9)
        .expect_err("retraction cannot close a claim before its occurred start");
    assert!(
        matches!(error, Error::InvalidTimeRange { start: 10, end: 9 }),
        "{error:?}"
    );
    assert_eq!(vault.get_raw(&id)?.expect("unchanged claim"), raw);
    assert_eq!(binding_digest(&vault, id)?, digest);
    assert_current_actor(&vault, id, actor)?;
    assert_eq!(vault.store.gate_decisions(128)?, decisions);
    let txn = vault.store.env.read_txn()?;
    for (db, before) in [&vault.store.edges_out, &vault.store.edges_in]
        .into_iter()
        .zip(edges_before)
    {
        let after = db
            .iter(&txn)?
            .map(|entry| {
                let (key, value) = entry?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(after, before);
    }
    Ok(())
}

#[test]
fn supersede_before_start_rejects_without_changing_claims_bindings_or_edges() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let old = entity(0x64);
    let new = entity(0x65);
    let mut claims_before = Vec::new();
    for id in [old, new] {
        authored_local_claim(&vault, actor, id)?;
        assert_current_actor(&vault, id, actor)?;
        let raw = vault.get_raw(&id)?.expect("authored claim");
        let digest = binding_digest(&vault, id)?;
        assert_eq!(digest, Some(row_digest(&raw).to_vec()));
        claims_before.push((id, raw, digest));
    }
    actor_only_policy(&vault, actor)?;
    let decisions = vault.store.gate_decisions(128)?;
    let mut edges_before = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for db in [&vault.store.edges_out, &vault.store.edges_in] {
            let rows = db
                .iter(&txn)?
                .map(|entry| {
                    let (key, value) = entry?;
                    Ok((key.to_vec(), value.to_vec()))
                })
                .collect::<Result<Vec<_>>>()?;
            edges_before.push(rows);
        }
    }

    let error = vault
        .supersede_claim(&new, &old, 9)
        .expect_err("supersession cannot close a claim before its occurred start");
    assert!(
        matches!(error, Error::InvalidTimeRange { start: 10, end: 9 }),
        "{error:?}"
    );
    for (id, raw, digest) in claims_before {
        assert_eq!(vault.get_raw(&id)?.expect("unchanged claim"), raw);
        assert_eq!(binding_digest(&vault, id)?, digest);
        assert_current_actor(&vault, id, actor)?;
    }
    assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
    assert!(vault.sources(&old, EdgeKind::Supersedes, None)?.is_empty());
    assert_eq!(vault.store.gate_decisions(128)?, decisions);
    let txn = vault.store.env.read_txn()?;
    for (db, before) in [&vault.store.edges_out, &vault.store.edges_in]
        .into_iter()
        .zip(edges_before)
    {
        let after = db
            .iter(&txn)?
            .map(|entry| {
                let (key, value) = entry?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(after, before);
    }
    Ok(())
}

#[test]
fn lifecycle_at_or_after_start_preserves_actor_and_exact_timestamp() -> Result<()> {
    for now in [10, 11] {
        let (_dir, vault, actor) = fixture()?;
        let retracted = entity(0x64);
        let old = entity(0x65);
        let new = entity(0x66);
        for id in [retracted, old, new] {
            authored_local_claim(&vault, actor, id)?;
            assert_current_actor(&vault, id, actor)?;
        }
        actor_only_policy(&vault, actor)?;
        let new_raw = vault.get_raw(&new)?.expect("replacement claim");
        let new_digest = binding_digest(&vault, new)?;

        vault.retract_claim(&retracted, now)?;
        vault.supersede_claim(&new, &old, now)?;
        for (id, lifecycle) in [
            (retracted, ClaimLifecycleStatus::Retracted),
            (old, ClaimLifecycleStatus::Superseded),
        ] {
            let raw = vault.get_raw(&id)?.expect("closed claim");
            let header = EntityMetadataHeader::parse(&raw).expect("header");
            let body = vault.get_claim(&id)?.expect("closed body");
            assert_eq!(body.lifecycle, lifecycle);
            assert_eq!(body.valid_to, Some(now));
            assert_eq!(header.occurred_start, 10);
            assert_eq!(header.occurred_end, now);
            assert_eq!(header.learned_at, 10);
            assert_eq!(binding_digest(&vault, id)?, Some(row_digest(&raw).to_vec()));
            assert_current_actor(&vault, id, actor)?;
        }
        assert_eq!(vault.get_raw(&new)?.expect("unchanged replacement"), new_raw);
        assert_eq!(binding_digest(&vault, new)?, new_digest);
        assert_current_actor(&vault, new, actor)?;
        assert_eq!(vault.targets(&new, EdgeKind::Supersedes, None)?, vec![old]);
        assert_eq!(vault.sources(&old, EdgeKind::Supersedes, None)?, vec![new]);
        let edges = vault.edges_out(&new)?;
        let supersedes = edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::Supersedes && edge.target == old)
            .expect("supersedes edge");
        assert_eq!(supersedes.created_at, now);
    }
    Ok(())
}
