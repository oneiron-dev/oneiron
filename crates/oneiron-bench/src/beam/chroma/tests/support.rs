use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};
pub(in crate::beam) struct MockChroma {
    pub(in crate::beam) endpoint: String,
    requests: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    server: std::thread::JoinHandle<()>,
}
impl MockChroma {
    pub(in crate::beam) fn start(queries: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let server = std::thread::spawn(move || {
            let responses = [
                serde_json::json!({"id":"fixture-collection"}),
                serde_json::json!({}),
            ]
            .into_iter()
            .chain(
                (0..queries).map(|_| serde_json::json!({"ids":[["turn-1"]],"distances":[[0.0]]})),
            )
            .chain(std::iter::once(serde_json::json!({})));
            for response in responses {
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
        Self {
            endpoint: format!("http://{address}/api/v2"),
            requests,
            server,
        }
    }
    pub(in crate::beam) fn finish(self) -> Vec<(String, serde_json::Value)> {
        self.server.join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}
