//! `oneiron api call` through the shipped binary: a literal `--data` body and an
//! `@FILE` body reach an independent HTTP peer byte for byte, and nothing in
//! them is shell-evaluated.

#[test]
fn cli_literal_and_file_bodies_arrive_verbatim_without_shell_side_effects() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("shell-side-effect");
    let literal = format!(
        r#"{{"shell":"$(touch {}); `touch {}`; & | < > * ? $HOME"}}"#,
        sentinel.display(),
        sentinel.display()
    );
    let file_bytes = br#"{"from":"file","shell":"$(printf ignored); `printf ignored`"}"#;
    let body_path = dir.path().join("request.json");
    std::fs::write(&body_path, file_bytes).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let backlog = listener.try_clone().unwrap();
    let server = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let end = loop {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            assert!(headers.starts_with("post /v1/core/memory/verbs/board.append http/1.1"));
            let size: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            while bytes.len() < end + size {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            bodies.push(bytes[end..end + size].to_vec());
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        }
        bodies
    });
    let invoke = |data: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args([
                "api",
                "--base-url",
                &base,
                "call",
                "board.append",
                "--data",
                data,
            ])
            .env_remove("ONEIRON_SECRET")
            .env("NO_PROXY", "127.0.0.1")
            .env_remove("http_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("all_proxy")
            .env_remove("ALL_PROXY")
            .output()
            .unwrap()
    };
    for data in [&literal, &format!("@{}", body_path.display())] {
        let output = invoke(data);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"{}");
        assert!(!sentinel.exists());
    }
    let received = server.join().unwrap();
    assert_eq!(
        received,
        vec![literal.as_bytes().to_vec(), file_bytes.to_vec()]
    );
    let missing = invoke(&format!("@{}", dir.path().join("absent.json").display()));
    assert!(!missing.status.success());
    backlog.set_nonblocking(true).unwrap();
    assert!(matches!(backlog.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert!(!sentinel.exists());
}
