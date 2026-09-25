//! Query-derived occurred windows must not lose their eligible hit to learned-time candidates.

use oneiron::memory::Effort;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

#[test]
fn query_range_keeps_occurred_hit_ahead_of_recently_learned_old_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let eligible = EntityId::from_bytes([240; 16])?;
    vault.put_entity(
        &eligible,
        1,
        TimeRange {
            start: now - 3 * 86_400,
            end: now - 3 * 86_400,
        },
        now - 60 * 86_400,
        b"payload",
    )?;
    for seed in 241..=245 {
        vault.put_entity(
            &EntityId::from_bytes([seed; 16])?,
            1,
            TimeRange {
                start: now - 40 * 86_400,
                end: now - 40 * 86_400,
            },
            now - 3 * 86_400,
            b"payload",
        )?;
    }
    let results = vault
        .query()
        .search_text("last week", 1)
        .limit(1)
        .retrieval_effort(Effort::Medium, &[])
        .run()?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, eligible);
    Ok(())
}
