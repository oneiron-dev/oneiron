use super::*;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};
use crate::test_util::entity;
use std::io::Write;
use std::net::TcpListener;

#[test]
fn indexed_scores_reject_omissions_duplicates_nonfinite_and_overrun() {
    let response = |results| ScoreResponse {
        results,
        usage: Usage { total_tokens: 7 },
    };
    let row = |index, relevance_score| IndexedScore {
        index,
        relevance_score,
    };
    let good = validate_response(response(vec![row(1, 0.8), row(0, -0.4)]), 2, Some(7)).unwrap();
    assert_eq!(good.value, vec![-0.4, 0.8]);
    for rows in [
        vec![row(0, 1.0)],
        vec![row(0, 1.0), row(0, 0.0)],
        vec![row(0, 1.0), row(2, 0.0)],
        vec![row(0, 1.0), row(1, f32::NAN)],
    ] {
        let failure = validate_response(response(rows), 2, Some(7)).unwrap_err();
        assert!(matches!(failure.error, Error::InvalidConfig(_)));
        assert_eq!(failure.tokens_used, 7);
    }
    assert_eq!(
        validate_response(response(vec![row(0, 1.0)]), 1, Some(6))
            .unwrap_err()
            .tokens_used,
        7
    );
}

#[test]
fn local_service_prepares_nonblocking_snapshot_and_pipeline_ladder() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}/rerank", listener.local_addr()?);
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut wire = Vec::new();
        loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            wire.push(byte[0]);
            if wire.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8(wire).unwrap();
        let length = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|n| n.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["documents"].as_array().unwrap().len(), 2);
        assert_eq!(request["model"], "host/model@revision");
        let body = r#"{"results":[{"index":1,"relevance_score":40.0},{"index":0,"relevance_score":-10.0}],"usage":{"total_tokens":3}}"#;
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
    });
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::default());
    let a = entity(51);
    let b = entity(52);
    let range = crate::temporal::TimeRange { start: 1, end: 1 };
    vault
        .batch()
        .put(&a, 4, range, 1, b"a")
        .text(&a, &[("body", "launch decision")])
        .put(&b, 4, range, 1, b"b")
        .text(&b, &[("body", "launch decision decision")])
        .commit()?;
    let baseline = vault
        .query()
        .search_text("launch", 10)
        .with_temporal_now(100)
        .run()?;
    assert_eq!(baseline.len(), 2);
    let candidates: Vec<_> = baseline
        .iter()
        .enumerate()
        .map(|(index, hit)| RerankCandidate {
            id: hit.id,
            score: hit.score,
            rank: index as u32 + 1,
            claim: None,
        })
        .collect();
    let scorer = CrossEncoder::local(&endpoint, "host/model@revision", Duration::from_secs(5))?
        .with_documents(BTreeMap::from([
            (a, "launch decision".into()),
            (b, "launch decision decision".into()),
        ]));
    let lease = BudgetGuard::new("crossencoder", 100_000, BudgetExhaustionPolicy::Suspend)
        .admit()
        .unwrap()
        .lease;
    let prepared = scorer
        .prepare("launch", &candidates, Some(20), &lease)
        .map_err(|failure| failure.error)?;
    assert_eq!(prepared.tokens_used, 3);
    service.join().unwrap(); // service is now gone: rerank cannot perform a network hop.
    assert!(prepared.value.rerank("another query", &candidates).is_err());
    let hits = vault
        .query()
        .search_text("launch", 10)
        .with_temporal_now(100)
        .rerank(&prepared.value, super::super::RerankOptions::default())
        .run()?;
    assert_eq!(hits[0].id, baseline[1].id);
    assert_eq!(hits[1].id, baseline[0].id);
    assert_eq!(
        hits.iter().map(|hit| hit.score).collect::<Vec<_>>(),
        baseline.iter().map(|hit| hit.score).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn endpoint_policy_refuses_remote_cleartext_and_local_dns() {
    assert!(CrossEncoder::local("http://localhost/rerank", "m", Duration::from_secs(1)).is_err());
    assert!(CrossEncoder::local("http://192.0.2.1/rerank", "m", Duration::from_secs(1)).is_err());
    assert!(
        CrossEncoder::remote(
            "http://example.invalid/rerank",
            "m",
            "t".into(),
            Duration::from_secs(1)
        )
        .is_err()
    );
}
