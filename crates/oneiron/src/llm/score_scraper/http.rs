//! Bounded HTTPS JSON transport for configured score sources.
use super::{ScoreFetch, ScoreSourceConfig};
use crate::error::{Error, Result};
use std::{io::Read, time::Duration};

const MAX_SCORE_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
const SCORE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Host-neutral, credential-free HTTPS GET adapter. The host owns source URLs
/// and any upstream proxy; redirects are refused to keep the configured target
/// from silently changing. Responses must be JSON within the byte ceiling.
pub struct HttpScoreFetch {
    client: reqwest::blocking::Client,
}

impl HttpScoreFetch {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(SCORE_REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| transport_error("could not build benchmark HTTP client"))?;
        Ok(Self { client })
    }
}

fn transport_error(message: &str) -> Error {
    Error::Io(std::io::Error::other(message))
}

fn fetch_json(
    client: &reqwest::blocking::Client,
    url: &str,
    deadline: Duration,
) -> Result<serde_json::Value> {
    // Never include URL or peer-provided error bodies in errors: configured
    // URLs may carry secrets in query strings.
    let response = client
        .get(url)
        // The client timeout resets per blocking read in reqwest 0.12. A
        // request timeout also covers body completion while bytes trickle in.
        .timeout(deadline)
        .send()
        .map_err(|_| transport_error("benchmark GET failed"))?;
    if !response.status().is_success() {
        return Err(transport_error("benchmark GET returned non-success status"));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_SCORE_DOCUMENT_BYTES)
    {
        return Err(transport_error("benchmark response exceeds byte limit"));
    }
    let mut body = Vec::new();
    response
        .take(MAX_SCORE_DOCUMENT_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| transport_error("could not read benchmark response"))?;
    if body.len() as u64 > MAX_SCORE_DOCUMENT_BYTES {
        return Err(transport_error("benchmark response exceeds byte limit"));
    }
    serde_json::from_slice(&body)
        .map_err(|_| transport_error("benchmark response is not valid JSON"))
}

impl ScoreFetch for HttpScoreFetch {
    fn fetch(&mut self, source: &ScoreSourceConfig) -> Result<serde_json::Value> {
        let url = reqwest::Url::parse(&source.url)
            .map_err(|_| transport_error("invalid benchmark HTTPS URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(transport_error("invalid benchmark HTTPS URL"));
        }
        fetch_json(&self.client, url.as_str(), SCORE_REQUEST_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener, thread};

    fn local_response(body: &[u8], status: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes = body.to_vec();
        let status = status.to_owned();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .unwrap();
            stream.write_all(&bytes).unwrap();
        });
        format!("http://{addr}/scores")
    }

    /// Sends a valid JSON document a byte at a time. Every read can finish
    /// within the client timeout, but the complete response cannot finish
    /// within the shorter request deadline.
    fn trickle_response() -> (String, std::sync::mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            let body = format!("[{}]", " ".repeat(100));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            for (index, byte) in body.bytes().enumerate() {
                if stream.write_all(&[byte]).is_err() {
                    break; // The client met its deadline and closed the socket.
                }
                if index == 0 {
                    let _ = started_tx.send(());
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        (format!("http://{addr}/scores"), started_rx)
    }

    #[test]
    fn trickled_body_hits_whole_request_deadline_and_worker_drop_is_bounded() {
        use super::super::{ScoreScraper, ScoreScraperConfig};
        use std::{collections::BTreeMap, sync::Arc, time::Instant};

        const DEADLINE: Duration = Duration::from_millis(120);
        const SHUTDOWN_LIMIT: Duration = Duration::from_secs(2);
        struct LocalFetch {
            client: reqwest::blocking::Client,
            url: String,
        }
        impl ScoreFetch for LocalFetch {
            fn fetch(&mut self, _: &ScoreSourceConfig) -> Result<serde_json::Value> {
                fetch_json(&self.client, &self.url, DEADLINE)
            }
        }
        let client = HttpScoreFetch::new().unwrap().client;
        let (url, started) = trickle_response();
        let before = Instant::now();
        let result = fetch_json(&client, &url, DEADLINE);
        assert!(started.recv_timeout(Duration::from_secs(1)).is_ok());
        assert!(
            result.is_err(),
            "trickled response must time out, not parse"
        );
        assert!(before.elapsed() < SHUTDOWN_LIMIT);

        // The worker uses the same transport path. Destroy it while a source
        // still streams; join must finish at the request deadline, not EOF.
        let (url, started) = trickle_response();
        let config = ScoreScraperConfig {
            version: 1,
            fetch_interval_secs: 60,
            sources: vec![ScoreSourceConfig {
                id: "bench".into(),
                url: "https://example.invalid/scores".into(),
                rows_pointer: "/data".into(),
                model_pointer: "/model".into(),
                score_pointer: "/score".into(),
                benchmark: "quality".into(),
                model_bindings: BTreeMap::from([(
                    "external".into(),
                    super::super::ModelId::new("test/model@r1").unwrap(),
                )]),
            }],
        };
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let worker = ScoreScraper::new(config, LocalFetch { client, url })
            .unwrap()
            .start(Arc::new(vault));
        started.recv_timeout(Duration::from_secs(3)).unwrap();
        let before = Instant::now();
        drop(worker);
        assert!(
            before.elapsed() < SHUTDOWN_LIMIT,
            "worker joined beyond deadline"
        );
    }

    #[test]
    fn transport_accepts_json_and_refuses_status_and_oversize() {
        let client = HttpScoreFetch::new().unwrap().client;
        let url = local_response(br#"{"data":[{"model":"one","score":42}]}"#, "200 OK");
        assert_eq!(
            fetch_json(&client, &url, SCORE_REQUEST_TIMEOUT).unwrap()["data"][0]["score"],
            42
        );
        let url = local_response(b"not found", "404 Not Found");
        assert!(fetch_json(&client, &url, SCORE_REQUEST_TIMEOUT).is_err());
        let url = local_response(&vec![b' '; MAX_SCORE_DOCUMENT_BYTES as usize + 1], "200 OK");
        assert!(fetch_json(&client, &url, SCORE_REQUEST_TIMEOUT).is_err());
    }

    #[test]
    fn public_fetch_refuses_insecure_source() {
        let mut fetcher = HttpScoreFetch::new().unwrap();
        let source = ScoreSourceConfig {
            id: "bench".into(),
            url: "http://127.0.0.1/scores".into(),
            rows_pointer: "/data".into(),
            model_pointer: "/model".into(),
            score_pointer: "/score".into(),
            benchmark: "quality".into(),
            model_bindings: Default::default(),
        };
        assert!(fetcher.fetch(&source).is_err());
    }
}
