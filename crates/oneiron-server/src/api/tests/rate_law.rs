//! Rule five, checked at every row the code lists (`LimitRow::ALL`): crossed
//! by a burst on one credential, a row turns nobody away and asks whether
//! everything is okay (ARCH-0044 C5, OF-520). The match below has no
//! wildcard, so a row added without a driver does not compile.

use crate::admission::Crossing;
use crate::wire_telemetry::LimitRow;
use oneiron::limit_ask::EngineLimit;

/// Callers per row: enough to cross a bound of one several times over.
const CALLERS: usize = 8;

async fn cross(row: LimitRow) -> Crossing {
    match row {
        LimitRow::Connections => crate::http_listener::tests::cross_the_floor(CALLERS).await,
        LimitRow::GitExchanges => {
            crate::api::git_http::tests_lifetime::cross_the_exchanges(CALLERS).await
        }
        LimitRow::LfsTransfers | LimitRow::LfsQuota | LimitRow::LfsObjectSize => {
            crate::api::git_lfs::tests::cross_the_lfs_row(row, CALLERS).await
        }
        LimitRow::LfsMemoryBytes => crate::api::git_lfs::tests::cross_the_frames(CALLERS).await,
        LimitRow::CodeRuns => super::mcp_code_admission::cross_the_runs(CALLERS).await,
        LimitRow::CompactionPasses => {
            tokio::task::spawn_blocking(|| crate::ai_host::cross_the_passes(CALLERS))
                .await
                .unwrap()
        }
        LimitRow::EmbedderRequests => tokio::task::spawn_blocking(|| {
            crate::embedder::serve::tests::cross_the_requests(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::EmbedderBodyBytes => {
            tokio::task::spawn_blocking(|| crate::embedder::serve::tests::cross_the_bodies(CALLERS))
                .await
                .unwrap()
        }
        LimitRow::EmbedderAnswerBytes => tokio::task::spawn_blocking(|| {
            crate::embedder::serve::tests::cross_the_answers(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::WindowsPerConnection => {
            crate::handler::window_row_tests::cross_the_windows(CALLERS).await
        }
        LimitRow::LiveSessions => crate::livequery::rule5_tests::cross_the_sessions(CALLERS).await,
        LimitRow::LiveSubscriptions => {
            crate::livequery::rule5_tests::cross_the_subscriptions(CALLERS).await
        }
        LimitRow::MessageStreams => tokio::task::spawn_blocking(|| {
            crate::server::live_rows_tests::cross_the_streams(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::LiveDocuments => tokio::task::spawn_blocking(|| {
            crate::server::live_rows_tests::cross_the_documents(CALLERS)
        })
        .await
        .unwrap(),
        LimitRow::RetainedMemoryBytes => {
            crate::livequery::rule5_tests::cross_the_retained_bytes(CALLERS)
        }
        LimitRow::ResidenceIndexPages | LimitRow::ResidenceIndexBytes => {
            crate::livequery::rule5_tests::cross_the_index(row, CALLERS).await
        }
        LimitRow::BookingWindows => {
            tokio::task::spawn_blocking(|| crate::api::booking::cross_the_booking_windows(CALLERS))
                .await
                .unwrap()
        }
        LimitRow::Engine(EngineLimit::KeyedFilterJsonBytes) => {
            crate::api::facade::tests::cross_the_keyed_filters(CALLERS).await
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_limits_row_queues_its_burst_and_asks() {
    for row in LimitRow::ALL {
        assert_eq!(
            cross(row).await,
            Crossing {
                refused: 0,
                asked: true
            },
            "{}: past the row, work waits its turn and the row asks; nothing is refused",
            row.key()
        );
    }
}
