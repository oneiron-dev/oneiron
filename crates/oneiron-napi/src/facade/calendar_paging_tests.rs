//! Regression tests for the actor-bound calendar paging surface.

use super::*;
use oneiron::calendar::door::CalendarEventCreateRequest;
use oneiron::{CalendarRangeDto, Vault, VaultConfig};

#[test]
fn calendar_search_pages_through_the_window_with_resume_from() {
    let dir = unique_vault_dir("calendar-search-pages");
    let path = dir.to_str().expect("utf8 path");
    {
        let actor = open_owner_scope(path);
        seed_events(
            &actor,
            &[
                ("planning", 1_700, 1_750),
                ("standup", 1_100, 1_150),
                ("outside", 2_100, 2_150),
                ("review", 1_400, 1_450),
            ],
        );

        let mut resume_from = None;
        let mut names = Vec::new();
        let mut starts = Vec::new();
        loop {
            let page = actor
                .calendar_search(search_request(1, None, resume_from))
                .expect("read search page");
            assert_eq!(page.value.len(), 1, "one distinct start per page");
            let event = &page.value[0];
            assert!(event.blocks_time, "native EVENTs are busy");
            names.push(event.name.clone().expect("EVENT name"));
            starts.push(event.start_utc.expect("EVENT start"));
            assert!(names.len() <= 3, "no duplicate or out-of-window EVENTs");

            if names.len() == 1 {
                assert_eq!(names[0], "standup");
                assert!(!page.complete, "the first page leaves later EVENTs");
                assert!(page.resume_from.is_some());
            }
            if page.complete {
                assert_eq!(page.resume_from, None, "the last page has no frontier");
                break;
            }
            let next = page.resume_from.expect("incomplete page has a frontier");
            assert!(next > resume_from.unwrap_or(1_000), "frontier advances");
            resume_from = Some(next);
        }
        assert_eq!(names, ["standup", "review", "planning"]);
        assert_eq!(starts, [1_100, 1_400, 1_700]);
    }
    std::fs::remove_dir_all(dir).expect("remove temp vault");
}

#[test]
fn calendar_search_forwards_the_deadline_and_the_resume_point() {
    let dir = unique_vault_dir("calendar-search-deadline");
    let path = dir.to_str().expect("utf8 path");
    {
        let actor = open_owner_scope(path);
        seed_events(
            &actor,
            &[
                ("planning", 1_700, 1_750),
                ("standup", 1_100, 1_150),
                ("review", 1_400, 1_450),
            ],
        );

        for deadline in [0, 60_001] {
            let error = actor
                .calendar_search(search_request(10, Some(deadline), None))
                .err()
                .expect("out-of-range deadline is refused");
            assert!(
                error
                    .reason
                    .contains("deadline_ms must be a whole number between 1 and 60000"),
                "{}",
                error.reason
            );
        }

        let mut request = search_request(10, None, Some(1_300));
        request.range = None;
        let error = actor
            .calendar_search(request)
            .err()
            .expect("resume_from needs a range");
        assert!(
            error
                .reason
                .contains("calendar search resume_from needs the range its pages read"),
            "{}",
            error.reason
        );

        // The window fits in the first slice, which always runs in full.
        let page = actor
            .calendar_search(search_request(10, Some(60_000), None))
            .expect("maximum valid deadline is accepted");
        let names: Vec<_> = page
            .value
            .iter()
            .map(|event| event.name.as_deref())
            .collect();
        assert_eq!(names, [Some("standup"), Some("review"), Some("planning")]);
        assert!(page.complete);
        assert_eq!(page.resume_from, None);
    }
    std::fs::remove_dir_all(dir).expect("remove temp vault");
}

#[test]
fn calendar_freebusy_reads_from_resume_from_and_forwards_the_deadline() {
    let dir = unique_vault_dir("calendar-freebusy-pages");
    let path = dir.to_str().expect("utf8 path");
    {
        let actor = open_owner_scope(path);
        seed_events(
            &actor,
            &[("review", 1_700, 1_750), ("standup", 1_100, 1_150)],
        );

        let page = actor
            .calendar_freebusy(None, window(), None, None)
            .expect("read whole-window freebusy");
        let intervals: Vec<_> = page
            .value
            .iter()
            .map(|interval| (interval.start_utc, interval.end_utc))
            .collect();
        // Engine EVENT ends are inclusive; busy interval ends are exclusive.
        assert_eq!(intervals, [(1_100, 1_151), (1_700, 1_751)]);
        assert!(page.complete);
        assert_eq!(page.resume_from, None);

        // page_frontier accepts a caller-chosen point anywhere inside W.
        let page = actor
            .calendar_freebusy(None, window(), None, Some(1_500))
            .expect("read freebusy after the resume point");
        let intervals: Vec<_> = page
            .value
            .iter()
            .map(|interval| (interval.start_utc, interval.end_utc))
            .collect();
        assert_eq!(intervals, [(1_700, 1_751)]);
        assert!(page.complete);
        assert_eq!(page.resume_from, None);

        let error = actor
            .calendar_freebusy(None, window(), Some(0), None)
            .err()
            .expect("zero deadline is refused");
        assert!(
            error
                .reason
                .contains("deadline_ms must be a whole number between 1 and 60000"),
            "{}",
            error.reason
        );
    }
    std::fs::remove_dir_all(dir).expect("remove temp vault");
}

fn open_owner_scope(path: &str) -> ActorScopedVault {
    let owner = {
        let vault =
            Vault::open(path, VaultConfig::device()).expect("open vault for owner bootstrap");
        vault.ensure_embedded_owner_actor().expect("owner actor")
    };
    let bridge = VaultBridge::open(path.to_owned(), None, None).expect("open vault bridge");
    bridge
        .as_actor(format!("human:{}", owner.to_hex()))
        .expect("bind owner human actor")
}

fn seed_events(actor: &ActorScopedVault, events: &[(&str, u64, u64)]) {
    let memory = actor.facade().expect("owner facade");
    for &(summary, start, end) in events {
        memory
            .calendar_create(&CalendarEventCreateRequest::Native {
                summary: summary.to_owned(),
                occurred_at: CalendarRangeDto { start, end },
            })
            .expect("seed native EVENT");
    }
}

fn window() -> NapiCalendarRange {
    NapiCalendarRange {
        start: 1_000,
        end: 2_000,
    }
}

fn search_request(
    limit: u32,
    deadline_ms: Option<u32>,
    resume_from: Option<i64>,
) -> NapiCalendarSearchRequest {
    NapiCalendarSearchRequest {
        calendars: None,
        range: Some(window()),
        text: None,
        limit,
        deadline_ms,
        resume_from,
    }
}

fn unique_vault_dir(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("oneiron-napi-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp vault dir");
    dir
}
