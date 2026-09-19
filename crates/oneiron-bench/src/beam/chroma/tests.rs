use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};
#[test]
fn chroma_wire_fixture_is_independent_and_cannot_read_gold() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let server = std::thread::spawn(move || {
        for response in [
            serde_json::json!({"id":"fixture-collection"}),
            serde_json::json!({}),
            serde_json::json!({"ids":[["turn-1"]],"distances":[[0.0]]}),
            serde_json::json!({}),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut start = String::new();
            reader.read_line(&mut start).unwrap();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" {
                    break;
                }
                if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            seen.lock().unwrap().push((
                start,
                if body.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&body).unwrap()
                },
            ));
            let body = response.to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
    });
    let record: super::super::report_model::RunContractRecord = serde_json::from_str(include_str!(
        "../../../fixtures/beam_128k_contract.run.jsonl"
    ))
    .unwrap();
    let config = ChromaConfig {
        endpoint: format!("http://{address}/api/v2"),
        retrieval_k: 1,
        card_id: "chroma-vanilla@v2".into(),
    };
    let arm = ChromaArm::ingest(&config, &record.corpus).unwrap();
    assert_eq!(
        arm.retrieve(&[1.0, 0.0, 0.0, 0.0]).unwrap(),
        format!("{}\n", record.corpus[0].text)
    );
    drop(arm);
    server.join().unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[1].1["ids"],
        serde_json::json!(["turn-1", "turn-2"])
    );
    assert!(requests.iter().all(|(_, body)| body.get("gold").is_none()));
    assert!(requests[2].0.contains("/query"));
}
