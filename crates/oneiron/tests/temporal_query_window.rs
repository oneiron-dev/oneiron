//! Query-derived occurred windows must not lose their eligible hit to learned-time candidates.
//!
//! On the testkit: each case opens its own copy of the empty fixture vault,
//! and "now" is the fake clock the copy's store reads (a query resolves "last
//! week" against the store clock), so the window is the same on every run.

use oneiron::memory::Effort;
use oneiron::{EntityId, TimeRange};
use oneiron_testkit::{FixtureVault, fixture_cache};

#[test]
fn query_range_keeps_occurred_hit_ahead_of_recently_learned_old_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureVault::empty(&fixture_cache!())?;
    let now = fixture.ended_at();
    // "Last week" starts at midnight UTC seven days before today, not
    // seven days before the current time of day.
    let range_start = now - now % 86_400 - 7 * 86_400;
    for (occurred, label) in [
        (now - 40 * 86_400, "40-day control"),
        (range_start - 86_400 - 60, "eight-day boundary"),
        (range_start - 60, "seven-day boundary"),
    ] {
        let copy = fixture.copy()?;
        let vault = copy.open()?;
        assert!(occurred < range_start, "{label}");
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
                    start: occurred,
                    end: occurred,
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
        assert_eq!(results.len(), 1, "{label} distractors displaced the hit");
        assert_eq!(results[0].id, eligible, "{label} distractors");
    }
    Ok(())
}
