//! Servers sharing one models directory.
//!
//! Two servers on a fresh host, or a CPU and a GPU `embedder serve` started
//! together, fetch the same model into the same directory at the same moment.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;

use super::*;

/// A model file big enough to arrive in more than one read.
fn model_body() -> Vec<u8> {
    (0..1u32 << 20).map(|i| (i % 251) as u8).collect()
}

fn pinned(body: &[u8]) -> PinnedArtifact {
    PinnedArtifact {
        file: Cow::Borrowed("model.safetensors"),
        sha256: Box::leak(hex(&Sha256::digest(body)).into_boxed_str()),
        bytes: body.len() as u64,
    }
}

fn shared_models_dir(root: &Path) -> (LocalEmbedderConfig, PathBuf) {
    let config = LocalEmbedderConfig {
        models_dir: Some(root.to_path_buf()),
        ..LocalEmbedderConfig::default()
    };
    let dir = model_dir(&config).expect("a configured root");
    (config, dir)
}

/// A fake model source on loopback that answers `fetches` requests together.
///
/// It holds every answer until all of them have asked, then sends each the
/// first half of the body, waits, and sends the rest: every fetch is part way
/// through writing its file when the first one finishes. It answers nothing
/// else, so a fetch after these fails.
fn source_answering_together(
    fetches: usize,
    body: Vec<u8>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let source = std::thread::spawn(move || {
        let mut streams = Vec::new();
        for _ in 0..fetches {
            let (stream, _) = listener.accept().expect("a fetch connects");
            let mut request = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            while request.read_line(&mut line).expect("request head") > 2 {
                line.clear();
            }
            streams.push(stream);
        }
        let half = body.len() / 2;
        for stream in &mut streams {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("head");
            stream.write_all(&body[..half]).expect("first half");
        }
        std::thread::sleep(Duration::from_millis(500));
        for stream in &mut streams {
            stream.write_all(&body[half..]).expect("second half");
        }
    });
    (base, source)
}

/// Two servers fetching one file into one directory at once both succeed,
/// and both find the verified file in place afterwards. Each writes its own
/// temporary file, so neither truncates the other's bytes or renames them
/// away from under it (`No such file or directory` on mel, 2026-10-10).
#[test]
fn two_servers_fetching_one_model_into_one_directory_both_get_it() {
    let body = model_body();
    let artifact = pinned(&body);
    let (base, source) = source_answering_together(2, body.clone());
    let root = tempfile::tempdir().expect("models root");
    let (config, dir) = shared_models_dir(root.path());
    // Two managers are two servers: neither knows what the other verified.
    let servers = [
        ModelManager::with_base_url(&base),
        ModelManager::with_base_url(&base),
    ];

    std::thread::scope(|scope| {
        let fetches: Vec<_> = servers
            .iter()
            .map(|server| scope.spawn(|| server.ensure_one(&config, &dir, &artifact)))
            .collect();
        for fetch in fetches {
            let fetched = fetch
                .join()
                .expect("fetch thread")
                .expect("each concurrent fetch succeeds");
            assert!(fetched, "each server downloaded the file itself");
        }
    });
    source.join().expect("the source answered both");

    let path = dir.join(artifact.file.as_ref());
    assert_eq!(std::fs::read(&path).expect("the file in place"), body);
    for server in &servers {
        // The source has stopped answering, so only a file found in place and
        // verified lets this return.
        let fetched = server
            .ensure_one(&config, &dir, &artifact)
            .expect("each server finds the verified file in place");
        assert!(!fetched, "nothing is fetched a second time");
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .expect("model dir")
        .map(|entry| entry.expect("entry").file_name())
        .filter(|name| name.as_os_str() != artifact.file.as_ref())
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temporary file is left: {leftovers:?}"
    );
}

/// A temporary file a killed fetch left does not stay for good: the next
/// server to check that model file removes one nothing has written for longer
/// than a fetch may run, under this build's names and the earlier one, and
/// leaves a fresh one, which may be another server's fetch still running.
#[test]
fn a_killed_fetchs_leftover_is_removed_and_a_running_fetchs_file_is_kept() {
    let body = model_body();
    let artifact = pinned(&body);
    let root = tempfile::tempdir().expect("models root");
    let (config, dir) = shared_models_dir(root.path());
    std::fs::create_dir_all(&dir).expect("model dir");
    let path = dir.join(artifact.file.as_ref());
    std::fs::write(&path, &body).expect("the model in place");
    let killed = partial_path(&path);
    let earlier_build = path.with_extension("partial");
    let running = partial_path(&path);
    let long_ago = SystemTime::now() - STALE_PARTIAL - Duration::from_secs(60);
    for (leftover, modified) in [
        (&killed, Some(long_ago)),
        (&earlier_build, Some(long_ago)),
        (&running, None),
    ] {
        let file = std::fs::File::create(leftover).expect("a partial file");
        if let Some(modified) = modified {
            file.set_modified(modified).expect("age the partial file");
        }
    }

    // Nothing answers here: the file in place must be what satisfies this.
    let fetched = ModelManager::with_base_url("http://127.0.0.1:9")
        .ensure_one(&config, &dir, &artifact)
        .expect("the verified file in place");

    assert!(!fetched);
    assert!(!killed.exists(), "the killed fetch's file is removed");
    assert!(
        !earlier_build.exists(),
        "an earlier build's leftover is removed"
    );
    assert!(
        running.exists(),
        "a file a fetch may still be writing stays"
    );
}
