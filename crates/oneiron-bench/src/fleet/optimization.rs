//! Paired full recompute versus persisted depth-five resume, with identical output checks.
use oneiron::{EdgeKind, EntityId, ScoredEntity, TimeRange, Vault, VaultConfig};
use std::collections::BTreeMap;
use std::time::Instant;

use super::{
    Result,
    configuration::Plan,
    report::{Metric, Optimization},
};

pub(super) const AT: u64 = 1_772_000_000;

pub(super) fn id(domain: u8, index: usize) -> Result<EntityId> {
    let mut bytes = [0_u8; 16];
    bytes[0] = domain;
    bytes[8..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    Ok(EntityId::from_bytes(bytes)?)
}

pub(super) fn config(plan: &Plan) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.fast_dims = None;
    config.map_size = plan.map_size;
    config.max_readers = 128;
    config.embedding_model = Some("bench/fleet@v1".into());
    config
}

fn graph(vault: &Vault, nodes: usize) -> Result<()> {
    let mut batch = vault.batch();
    for i in 0..nodes {
        let source = id(0x51, i)?;
        batch = batch
            .put(
                &source,
                1,
                TimeRange { start: AT, end: AT },
                AT,
                b"fleet graph",
            )
            .edge_with_created_at(
                &source,
                EdgeKind::Supports,
                &id(0x51, (i + 1) % nodes)?,
                1.0,
                AT,
            )
            .edge_with_created_at(
                &source,
                EdgeKind::Supports,
                &id(0x51, (i + 7) % nodes)?,
                0.5,
                AT,
            );
    }
    batch.commit()?;
    Ok(())
}

fn query(vault: &Vault, seed: EntityId, depth: u32) -> Result<Vec<ScoredEntity>> {
    Ok(vault
        .query()
        .search_ppr(&[seed], depth)
        .with_temporal_now(AT)
        .limit(100)
        .run()?)
}

fn equivalent(left: &[ScoredEntity], right: &[ScoredEntity]) -> bool {
    left.len() == right.len()
        && !left.is_empty()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.id == b.id && a.score.to_bits() == b.score.to_bits())
}

pub(super) fn measure(plan: &Plan, metrics: &mut BTreeMap<String, Metric>) -> Result<Optimization> {
    let cold_dir = tempfile::tempdir_in(&plan.scratch)?;
    let resume_dir = tempfile::tempdir_in(&plan.scratch)?;
    let cold = Vault::open(cold_dir.path(), config(plan))?;
    let resume = Vault::open(resume_dir.path(), config(plan))?;
    graph(&cold, plan.ppr_nodes)?;
    graph(&resume, plan.ppr_nodes)?;
    let mut cold_ms = Vec::new();
    let mut resume_ms = Vec::new();
    let mut prep_ms = Vec::new();
    let mut digest = blake3::Hasher::new();
    for i in 0..plan.ppr_samples {
        let seed = id(0x51, i)?;
        // Each pair uses a distinct seed. No exact-depth cache hit can replace a walk.
        let prep = Instant::now();
        let _ = query(&resume, seed, 5)?;
        prep_ms.push(prep.elapsed().as_secs_f64() * 1000.0);
        // Prime the baseline's pages without creating a cache row. This public
        // diagnostic runs the same walk but explicitly bypasses PPR cache IO.
        let _ = cold
            .query()
            .search_ppr(&[seed], 5)
            .with_temporal_now(AT)
            .limit(100)
            .run_with_ppr_vad_evidence()?;
        // Alternate ordering to avoid always giving the second arm warm CPU state.
        let (full, continued) = if i % 2 == 0 {
            let full = timed(&cold, seed, &mut cold_ms)?;
            (full, timed(&resume, seed, &mut resume_ms)?)
        } else {
            let continued = timed(&resume, seed, &mut resume_ms)?;
            (timed(&cold, seed, &mut cold_ms)?, continued)
        };
        if !equivalent(&full, &continued) {
            return Err(format!("PPR cold/resume output differs at seed {i}").into());
        }
        for row in full {
            digest.update(row.id.as_bytes());
            digest.update(&row.score.to_bits().to_le_bytes());
        }
    }
    let cold_s = cold_ms.iter().sum::<f64>() / 1000.0;
    let resume_s = resume_ms.iter().sum::<f64>() / 1000.0;
    let prep_s = prep_ms.iter().sum::<f64>() / 1000.0;
    metrics.insert("ppr_full".into(), Metric::new(cold_ms, cold_s)?);
    metrics.insert("ppr_resume".into(), Metric::new(resume_ms, resume_s)?);
    metrics.insert("ppr_prepare".into(), Metric::new(prep_ms, prep_s)?);
    Ok(Optimization {
        route: "full-depth10-vs-depth5-resume-to10-v1".into(),
        equivalent_pairs: plan.ppr_samples,
        result_blake3: digest.finalize().to_hex().to_string(),
        incremental_speedup: cold_s / resume_s,
        preparation_seconds: prep_s,
        preparation_included_speedup: cold_s / (resume_s + prep_s),
    })
}

fn timed(vault: &Vault, seed: EntityId, samples: &mut Vec<f64>) -> Result<Vec<ScoredEntity>> {
    let start = Instant::now();
    let output = query(vault, seed, 10)?;
    samples.push(start.elapsed().as_secs_f64() * 1000.0);
    Ok(output)
}
