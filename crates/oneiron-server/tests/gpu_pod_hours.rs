//! A GPU pod with `hours` takes new batches only inside them, read in its
//! fixed UTC offset or in its IANA zone, which follows daylight saving; a pod
//! without `hours` takes them at any hour (CROSS-ARCH-0024 #my-network 07:
//! "Jobs go to machines by role and schedule ... Embeddings can run on the
//! GPU box at night"; census L10-15, FIX [JOB-ROUTING-BY-MACHINE-ROLE-UNBUILT]).
//!
//! Each pool polls a loopback fake pod that answers its health and readiness
//! probes, so every pod is healthy after the first poll. The registry reads
//! the wall clock, so each test picks the `utc_offset` that puts the pod's
//! local time at a chosen hour: any UTC time is within 12 hours of it.
#![allow(clippy::unwrap_used)]

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron_server::runtime::{GpuPool, GpuPoolConfig, GpuRegistryError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const MINUTES_PER_DAY: i64 = 24 * 60;

/// A loopback pod that answers every request with 200 and `{}`. Returns its
/// base URL, as `[[gpu.pods]] url` names it.
async fn fake_pod() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                          content-length: 2\r\nconnection: close\r\n\r\n{}",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    format!("http://{address}/v1")
}

/// The `utc_offset` under which the local time is now `hour`:00 (plus the
/// seconds of the current UTC minute).
fn offset_for_local_hour(hour: i64) -> String {
    let utc_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let utc_minute = i64::try_from(utc_seconds / 60).unwrap() % MINUTES_PER_DAY;
    let mut offset = (hour * 60 - utc_minute).rem_euclid(MINUTES_PER_DAY);
    if offset > MINUTES_PER_DAY / 2 {
        offset -= MINUTES_PER_DAY;
    }
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.abs();
    format!("{sign}{:02}:{:02}", offset / 60, offset % 60)
}

/// One `[[pods]]` table; `hours` is `(start, end, utc_offset)`.
fn pod(id: &str, url: &str, capacity: usize, hours: Option<(&str, &str, &str)>) -> String {
    let hours = hours.map_or_else(String::new, |(start, end, offset)| {
        format!("hours = {{ start = \"{start}\", end = \"{end}\", utc_offset = \"{offset}\" }}\n")
    });
    format!("[[pods]]\nid = \"{id}\"\nurl = \"{url}\"\ncapacity = {capacity}\n{hours}")
}

/// The `[gpu]` section with these pods, as `serve` reads it.
fn config(pods: &[String]) -> GpuPoolConfig {
    let text = format!("region = \"home\"\npoll_seconds = 3600\n{}", pods.concat());
    toml::from_str(&text).unwrap()
}

/// A pool over `pods`, after one health poll.
async fn polled_pool(pods: &[String]) -> GpuPool {
    let pool = GpuPool::new(config(pods)).unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    pool.poll_health(&client).await;
    pool
}

#[tokio::test]
async fn a_night_pod_takes_no_batch_by_day() {
    let url = fake_pod().await;
    let noon = offset_for_local_hour(12);
    let pool = polled_pool(&[pod("home-gpu", &url, 4, Some(("22:00", "07:00", &noon)))]).await;
    assert!(
        matches!(pool.acquire(), Err(GpuRegistryError::Unavailable)),
        "a pod whose hours are 22:00-07:00 took a batch at local noon"
    );
}

#[tokio::test]
async fn a_night_pod_takes_a_batch_on_both_sides_of_midnight() {
    let url = fake_pod().await;
    for hour in [23, 3] {
        let offset = offset_for_local_hour(hour);
        let pool =
            polled_pool(&[pod("home-gpu", &url, 4, Some(("22:00", "07:00", &offset)))]).await;
        let lease = pool.acquire();
        assert!(
            matches!(&lease, Ok(guard) if guard.lease().pod == "home-gpu"),
            "a pod whose hours are 22:00-07:00 took no batch at local {hour}:00"
        );
    }
}

#[tokio::test]
async fn a_day_window_closes_at_its_end() {
    let url = fake_pod().await;
    let hours = |offset: &str| pod("office-gpu", &url, 4, Some(("09:00", "18:00", offset)));
    let noon = polled_pool(&[hours(&offset_for_local_hour(12))]).await;
    assert!(
        matches!(noon.acquire(), Ok(guard) if guard.lease().pod == "office-gpu"),
        "a pod whose hours are 09:00-18:00 took no batch at local noon"
    );
    let evening = polled_pool(&[hours(&offset_for_local_hour(20))]).await;
    assert!(
        matches!(evening.acquire(), Err(GpuRegistryError::Unavailable)),
        "a pod whose hours are 09:00-18:00 took a batch at local 20:00"
    );
}

#[tokio::test]
async fn day_batches_go_to_the_pod_without_hours() {
    let url = fake_pod().await;
    let noon = offset_for_local_hour(12);
    let pool = polled_pool(&[
        pod("home-gpu", &url, 4, Some(("22:00", "07:00", &noon))),
        pod("pod-a", &url, 1, None),
    ])
    .await;
    let first = pool.acquire();
    assert!(
        matches!(&first, Ok(guard) if guard.lease().pod == "pod-a"),
        "the day batch did not go to the pod without hours"
    );
    assert!(
        matches!(pool.acquire(), Err(GpuRegistryError::Unavailable)),
        "with the pod without hours full, a day batch went to the night pod"
    );
    drop(first);
}

/// Green on main too: a pod configured without `hours` keeps today's
/// behaviour.
#[tokio::test]
async fn a_pod_without_hours_takes_a_batch_at_any_hour() {
    let url = fake_pod().await;
    let pool = polled_pool(&[pod("pod-a", &url, 1, None)]).await;
    assert!(
        matches!(pool.acquire(), Ok(guard) if guard.lease().pod == "pod-a"),
        "a pod without hours took no batch"
    );
}

#[tokio::test]
async fn serve_refuses_hours_that_name_no_time() {
    let url = "https://home-gpu.example:8000/v1";
    for (start, end, offset, expected) in [
        ("24:00", "07:00", "+09:00", "start must be a time of day"),
        ("22:00", "7:00", "+09:00", "end must be a time of day"),
        ("22:00", "22:00", "+09:00", "start and end must differ"),
        ("22:00", "07:00", "+15:00", "utc_offset must be"),
        ("22:00", "07:00", "09:00", "utc_offset must be"),
    ] {
        let config = config(&[pod("home-gpu", url, 2, Some((start, end, offset)))]);
        let error = format!("{:#}", GpuPool::new(config).unwrap_err());
        assert!(
            error.contains("gpu pod home-gpu hours") && error.contains(expected),
            "hours {start}-{end} {offset}: {error}"
        );
    }
}

/// One `[[pods]]` table whose `hours` take `clock`, the TOML of their clock
/// keys, verbatim.
fn pod_on_clock(clock: &str) -> String {
    format!(
        "[[pods]]\nid = \"home-gpu\"\nurl = \"https://home-gpu.example:8000/v1\"\n\
         capacity = 2\nhours = {{ start = \"22:00\", end = \"07:00\"{clock} }}\n"
    )
}

#[tokio::test]
async fn serve_refuses_hours_on_no_clock_two_clocks_or_an_unknown_zone() {
    for (clock, expected) in [
        ("", "hours need a utc_offset or an iana_timezone"),
        (
            ", utc_offset = \"+01:00\", iana_timezone = \"Europe/Berlin\"",
            "set utc_offset or iana_timezone, not both",
        ),
        (
            ", iana_timezone = \"Mars/Olympus_Mons\"",
            "iana_timezone must name",
        ),
        (
            ", iana_timezone = \"europe/berlin\"",
            "iana_timezone must name",
        ),
        (", iana_timezone = \"\"", "iana_timezone must name"),
    ] {
        let error = format!(
            "{:#}",
            GpuPool::new(config(&[pod_on_clock(clock)])).unwrap_err()
        );
        assert!(
            error.contains("gpu pod home-gpu hours") && error.contains(expected),
            "hours with clock `{clock}`: {error}"
        );
    }
}

/// UTC instants around Europe/Berlin's 2026 changes: summer time from
/// 29 Mar 01:00 UTC (02:00 CET to 03:00 CEST) to 25 Oct 01:00 UTC.
const MAR_28_0530_UTC: u64 = 1_774_675_800;
const MAR_29_0530_UTC: u64 = 1_774_762_200;
const JUL_15_2030_UTC: u64 = 1_784_147_400;
const OCT_24_0530_UTC: u64 = 1_792_819_800;
const OCT_25_0530_UTC: u64 = 1_792_906_200;

#[test]
fn pod_hours_in_a_named_zone_follow_daylight_saving() {
    let pool = config(&[
        pod_on_clock(", iana_timezone = \"Europe/Berlin\""),
        pod(
            "fixed-gpu",
            "https://fixed-gpu.example:8000/v1",
            2,
            Some(("22:00", "07:00", "+01:00")),
        ),
    ]);
    let night_hours = |index: usize| pool.pods[index].hours.as_ref().unwrap().hours().unwrap();
    let (zoned, fixed) = (night_hours(0), night_hours(1));
    for (at, local, zoned_in, fixed_in) in [
        (
            MAR_28_0530_UTC,
            "06:30 CET, the day before the change",
            true,
            true,
        ),
        (
            MAR_29_0530_UTC,
            "07:30 CEST, the morning of the change",
            false,
            true,
        ),
        (JUL_15_2030_UTC, "22:30 CEST, a summer evening", true, false),
        (
            OCT_24_0530_UTC,
            "07:30 CEST, the last summer morning",
            false,
            true,
        ),
        (
            OCT_25_0530_UTC,
            "06:30 CET, the morning back on winter time",
            true,
            true,
        ),
    ] {
        assert_eq!(
            zoned.contains(at),
            zoned_in,
            "22:00-07:00 in Europe/Berlin at {local} (unix {at})"
        );
        assert_eq!(
            fixed.contains(at),
            fixed_in,
            "22:00-07:00 at the fixed +01:00 when Berlin reads {local} (unix {at})"
        );
    }
}

/// The local hour in `zone` now, read in the engine's zone database.
fn local_hour_now(zone: &str) -> u8 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    oneiron::calendar::utc_to_wall(now, zone).unwrap().h
}

#[tokio::test]
async fn a_pod_in_a_named_zone_takes_batches_in_its_local_hours_only() {
    let url = fake_pod().await;
    let hour = i64::from(local_hour_now("Europe/Berlin"));
    let at = |offset: i64| format!("{:02}:00", (hour + offset).rem_euclid(24));
    let zoned = |start: &str, end: &str| {
        format!(
            "[[pods]]\nid = \"home-gpu\"\nurl = \"{url}\"\ncapacity = 2\n\
             hours = {{ start = \"{start}\", end = \"{end}\", iana_timezone = \"Europe/Berlin\" }}\n"
        )
    };
    let open = polled_pool(&[zoned(&at(-1), &at(2))]).await;
    assert!(
        matches!(open.acquire(), Ok(guard) if guard.lease().pod == "home-gpu"),
        "a pod whose Berlin hours hold the Berlin hour now took no batch"
    );
    let closed = polled_pool(&[zoned(&at(3), &at(5))]).await;
    assert!(
        matches!(closed.acquire(), Err(GpuRegistryError::Unavailable)),
        "a pod whose Berlin hours open later today took a batch now"
    );
}
