//! The path measurement of the first job's step 2 (pass 33,
//! `33-exec-node/DESIGN.md` section 12, "R6 in five steps"): samples and
//! byte counts of the control round trip and a result fetch, over the
//! engine's iroh transport on the direct path, between two keys only the two
//! measuring endpoints trust. Here both ends run on loopback in one process.
#![cfg(feature = "mesh")]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use oneiron_mesh_transport::{MeshMachineAddress, MeshPathDirection, MeshPathKind};
use oneiron_server::gpu_execution_node::path_measure::{
    MeasureError, MeasurePlan, MeasurerKey, PathReceiptLog, SampleKind, bind_measurer,
    measure_path, report_lines, serve_measurements, summarize,
};
use oneiron_server::gpu_execution_node::wire::FETCH_MAX_BYTES;
use tokio::time::Instant;

/// A loopback UDP address no socket holds now.
fn free_loopback() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("a free loopback port")
}

fn address(endpoint_key: [u8; 32], direct_addrs: Vec<SocketAddr>) -> MeshMachineAddress {
    MeshMachineAddress {
        endpoint_key,
        direct_addrs,
        relay_url: None,
    }
}

fn plan(control_samples: u32, fetch_samples: u32) -> MeasurePlan {
    MeasurePlan {
        control_samples,
        control_request_bytes: 256,
        control_answer_bytes: 4096,
        fetch_samples,
        fetch_bytes: FETCH_MAX_BYTES,
        call_timeout: Duration::from_secs(10),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_measurement_reports_each_round_trip_with_its_bytes_on_the_direct_path() {
    let (listener_key, dialer_key) = (MeasurerKey::generate(), MeasurerKey::generate());
    let at = free_loopback();
    let (listener, _) = bind_measurer(
        &listener_key,
        address(dialer_key.endpoint(), Vec::new()),
        at,
        Arc::default(),
    )
    .await
    .expect("the listener binds");
    let receipts = Arc::new(PathReceiptLog::default());
    let (dialer, peer) = bind_measurer(
        &dialer_key,
        address(listener_key.endpoint(), vec![at]),
        free_loopback(),
        Arc::clone(&receipts),
    )
    .await
    .expect("the dialer binds");
    let deadline = Instant::now() + Duration::from_secs(60);
    let serving = tokio::spawn(async move { serve_measurements(&listener, deadline, 1).await });

    let report = measure_path(&dialer, peer, &plan(5, 2))
        .await
        .expect("the measurement runs");

    assert_eq!(report.samples.len(), 7, "{report:?}");
    let indexes: Vec<u32> = report.samples.iter().map(|s| s.index).collect();
    assert_eq!(indexes, (0..7).collect::<Vec<u32>>());
    for sample in &report.samples {
        let asked = match sample.kind {
            SampleKind::Control => 4096,
            SampleKind::Fetch => FETCH_MAX_BYTES,
        };
        // The codec adds a few bytes of framing around the body it carries.
        assert!(
            (asked..asked + 64).contains(&sample.received_bytes),
            "{sample:?}"
        );
        assert!((256..256 + 64).contains(&sample.sent_bytes), "{sample:?}");
        assert!(sample.elapsed > Duration::ZERO, "{sample:?}");
    }
    let control = summarize(&report.samples, SampleKind::Control).expect("control samples");
    assert_eq!(control.count, 5);
    assert!(control.min <= control.p50 && control.p50 <= control.p95 && control.p95 <= control.max);
    let fetch = summarize(&report.samples, SampleKind::Fetch).expect("fetch samples");
    assert_eq!(fetch.count, 2);

    let tally = serving
        .await
        .expect("the listener task")
        .expect("the listener serves");
    assert_eq!(tally.connections, 1);
    assert_eq!(tally.answers, 7);
    let sent: u64 = report.samples.iter().map(|s| s.sent_bytes).sum();
    let received: u64 = report.samples.iter().map(|s| s.received_bytes).sum();
    assert_eq!(
        (tally.received_bytes, tally.sent_bytes),
        (sent, received),
        "both ends count the same message bytes"
    );

    let path = receipts
        .wait_closed(MeshPathDirection::Outbound, Duration::from_secs(5))
        .await
        .expect("the closed connection's path receipt");
    assert_eq!(path.paths, MeshPathKind::Direct, "{path:?}");
    assert!(path.used_direct && !path.used_relay, "{path:?}");
    let lines = report_lines(&report, Some(&path));
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("## SUMMARY kind=control n=5 ")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("## SUMMARY kind=fetch n=2 ")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("## PATH paths=direct used_direct=true used_relay=false")),
        "{lines:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_answers_no_key_but_the_one_dialer_it_was_given() {
    let (listener_key, dialer_key, stranger_key) = (
        MeasurerKey::generate(),
        MeasurerKey::generate(),
        MeasurerKey::generate(),
    );
    let at = free_loopback();
    let (listener, _) = bind_measurer(
        &listener_key,
        address(dialer_key.endpoint(), Vec::new()),
        at,
        Arc::default(),
    )
    .await
    .expect("the listener binds");
    let (stranger, peer) = bind_measurer(
        &stranger_key,
        address(listener_key.endpoint(), vec![at]),
        free_loopback(),
        Arc::default(),
    )
    .await
    .expect("the stranger binds");
    let deadline = Instant::now() + Duration::from_secs(8);
    let serving = tokio::spawn(async move { serve_measurements(&listener, deadline, 1).await });

    let mut short = plan(1, 0);
    short.call_timeout = Duration::from_secs(3);
    let refused = measure_path(&stranger, peer, &short).await;

    assert!(refused.is_err(), "a stranger was answered: {refused:?}");
    let tally = serving
        .await
        .expect("the listener task")
        .expect("the listener serves");
    assert_eq!(tally.answers, 0, "{tally:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plan_above_one_fetch_answer_is_refused_before_it_dials() {
    let (listener_key, dialer_key) = (MeasurerKey::generate(), MeasurerKey::generate());
    // Nothing listens here: a plan that dialed would time out, not refuse.
    let (dialer, peer) = bind_measurer(
        &dialer_key,
        address(listener_key.endpoint(), vec![free_loopback()]),
        free_loopback(),
        Arc::default(),
    )
    .await
    .expect("the dialer binds");
    let mut too_large = plan(0, 1);
    too_large.fetch_bytes = FETCH_MAX_BYTES + 1;

    let refused = measure_path(&dialer, peer, &too_large).await;

    assert!(
        matches!(refused, Err(MeasureError::TooLarge { most }) if most == FETCH_MAX_BYTES),
        "{refused:?}"
    );
}
