//! A GPU pod with `hours` takes new batches only inside them, read in its
//! fixed UTC offset; a pod without `hours` takes them at any hour
//! (CROSS-ARCH-0024 #my-network 07: "Jobs go to machines by role and
//! schedule ... Embeddings can run on the GPU box at night"; census L10-15).
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
    let missing_offset = "region = \"home\"\n[[pods]]\nid = \"home-gpu\"\n\
        url = \"https://home-gpu.example:8000/v1\"\ncapacity = 2\n\
        hours = { start = \"22:00\", end = \"07:00\" }\n";
    let error = toml::from_str::<GpuPoolConfig>(missing_offset)
        .unwrap_err()
        .to_string();
    assert!(error.contains("utc_offset"), "{error}");
}
