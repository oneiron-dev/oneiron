use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::Path;

use super::*;

fn private_runtime() -> tempfile::TempDir {
    let runtime = tempfile::tempdir().expect("runtime");
    // Do not rely on tempfile defaults or the test runner's process-wide umask.
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    let metadata = fs::metadata(runtime.path()).expect("runtime metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    runtime
}

#[test]
fn listener_is_0600_serves_real_bridge_and_owns_cleanup() {
    let runtime = private_runtime();
    let (_dir, vault) = vault();
    let mut guard = SocketGuard::bind(runtime.path(), OsStr::new("voice.sock")).expect("bind");
    let socket_path = guard.path().to_owned();
    let metadata = fs::symlink_metadata(&socket_path).expect("socket metadata");
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert!(guard.try_accept().expect("nonblocking accept").is_none());
    let client = UnixStream::connect(&socket_path).expect("connect");
    let connection = guard
        .try_accept()
        .expect("accept")
        .expect("connection queued");
    let mut peer = Peer::start(
        client,
        connection,
        guard.shutdown_signal(),
        Arc::clone(&vault),
        TestEnricher::stable(),
        BridgeLimits::default(),
    );
    let handle = peer.open();
    assert_eq!(
        peer.observe("partial", &handle, 1, "Tokyo")["decision"],
        "fired"
    );
    guard.shutdown().expect("shutdown listener");
    guard.shutdown().expect("idempotent shutdown");
    assert!(!socket_path.exists());
    assert!(guard.try_accept().expect("closed accept").is_none());
    let mut line = String::new();
    assert_eq!(peer.reader.read_line(&mut line).expect("worker EOF"), 0);
    assert_eq!(peer.finish(), ["Tokyo"]);
    assert_eq!(Arc::strong_count(&vault), 1);
}

#[test]
fn preexisting_regular_socket_and_symlink_entries_are_never_removed() {
    let runtime = private_runtime();
    let file = runtime.path().join("file");
    fs::write(&file, b"FOREIGN").expect("file");
    assert!(SocketGuard::bind(runtime.path(), OsStr::new("file")).is_err());
    assert_eq!(fs::read(&file).expect("foreign preserved"), b"FOREIGN");
    let socket = runtime.path().join("foreign.sock");
    let foreign = UnixListener::bind(&socket).expect("foreign listener");
    assert!(SocketGuard::bind(runtime.path(), OsStr::new("foreign.sock")).is_err());
    assert!(
        UnixStream::connect(&socket).is_ok(),
        "foreign socket still listens"
    );
    let link = runtime.path().join("link.sock");
    symlink(&socket, &link).expect("symlink");
    assert!(SocketGuard::bind(runtime.path(), OsStr::new("link.sock")).is_err());
    assert!(
        fs::symlink_metadata(&link)
            .expect("link preserved")
            .file_type()
            .is_symlink()
    );
    drop(foreign);
}

#[test]
fn rejects_names_traversal_and_nonprivate_runtime() {
    let runtime = private_runtime();
    for name in [
        "",
        ".",
        "..",
        "../escape.sock",
        "/tmp/escape.sock",
        "child/socket",
        "a/",
        "a\0b",
    ] {
        assert!(
            SocketGuard::bind(runtime.path(), OsStr::new(name)).is_err(),
            "{name:?}"
        );
    }
    assert!(SocketGuard::bind(runtime.path(), OsStr::new(&"x".repeat(49))).is_err());
    assert!(SocketGuard::bind(Path::new("relative"), OsStr::new("voice.sock")).is_err());
    assert!(
        SocketGuard::bind(&runtime.path().join("../missing"), OsStr::new("voice.sock")).is_err()
    );
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o755)).expect("public runtime");
    assert_eq!(
        SocketGuard::bind(runtime.path(), OsStr::new("voice.sock"))
            .err()
            .expect("public runtime rejected")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(!runtime.path().join("voice.sock").exists());
}

#[test]
fn runtime_and_ancestor_symlinks_cannot_escape_to_another_directory() {
    let parent = private_runtime();
    let outside = private_runtime();
    let link = parent.path().join("runtime");
    symlink(outside.path(), &link).expect("runtime symlink");
    assert!(SocketGuard::bind(&link, OsStr::new("voice.sock")).is_err());
    let child = outside.path().join("child");
    fs::create_dir(&child).expect("child");
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).expect("private child");
    assert!(SocketGuard::bind(&link.join("child"), OsStr::new("voice.sock")).is_err());
    assert!(!outside.path().join("voice.sock").exists());
    assert!(!outside.path().join("child/voice.sock").exists());
}

#[test]
fn cleanup_does_not_unlink_replacement_sockets_or_symlinks() {
    let runtime = private_runtime();
    let guard = SocketGuard::bind(runtime.path(), OsStr::new("voice.sock")).expect("bind");
    let path = guard.path().to_owned();
    let moved = runtime.path().join("saved.sock");
    fs::rename(&path, &moved).expect("preserve original inode");
    let foreign = UnixListener::bind(&path).expect("foreign replacement");
    drop(guard);
    assert!(UnixStream::connect(&path).is_ok());
    drop(foreign);
    fs::remove_file(&path).expect("test owns foreign replacement");
    let guard = SocketGuard::bind(runtime.path(), OsStr::new("voice.sock")).expect("bind again");
    fs::rename(&path, runtime.path().join("saved2.sock")).expect("preserve second inode");
    symlink(&moved, &path).expect("replacement link");
    drop(guard);
    assert!(
        fs::symlink_metadata(&path)
            .expect("foreign link preserved")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn directory_swap_cannot_redirect_cleanup_to_foreign_socket() {
    let parent = private_runtime();
    let runtime = parent.path().join("runtime");
    fs::create_dir(&runtime).expect("runtime");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("private runtime");
    let guard = SocketGuard::bind(&runtime, OsStr::new("voice.sock")).expect("bind");
    let moved = parent.path().join("moved");
    fs::rename(&runtime, &moved).expect("move runtime");
    let outside = private_runtime();
    let foreign_path = outside.path().join("voice.sock");
    let foreign = UnixListener::bind(&foreign_path).expect("foreign listener");
    symlink(outside.path(), &runtime).expect("swap runtime path");
    drop(guard);
    assert!(
        !moved.join("voice.sock").exists(),
        "original pinned socket removed"
    );
    assert!(
        UnixStream::connect(&foreign_path).is_ok(),
        "outside socket survives"
    );
    drop(foreign);
}

#[test]
fn completed_shutdown_disarms_cleanup_before_path_reuse() {
    let runtime = private_runtime();
    let mut guard = SocketGuard::bind(runtime.path(), OsStr::new("voice.sock")).expect("bind");
    let path = guard.path().to_owned();
    guard.shutdown().expect("shutdown");
    let foreign = UnixListener::bind(&path).expect("new listener after shutdown");
    guard.shutdown().expect("repeated shutdown");
    drop(guard);
    assert!(UnixStream::connect(&path).is_ok());
    drop(foreign);
}
