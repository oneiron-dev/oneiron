use super::*;
use std::io::{Read, Write};

#[test]
fn guest_socket_works_under_a_long_private_jail_path() -> Result<()> {
    let root = tempfile::tempdir().expect("test fixture");
    let jail = root.path().join("private-jail-".repeat(16));
    fs::create_dir(&jail).expect("test fixture");
    let metadata = fs::metadata(&jail).expect("test fixture");
    let (_directory, endpoint, listener) =
        bind_guest_listener(&jail, metadata.uid(), metadata.gid())?;
    let mut client = UnixStream::connect(endpoint).expect("descriptor-relative connect");
    client.write_all(b"hello").expect("fixture write");
    let (mut server, _) = listener.accept().expect("fixture accept");
    let mut bytes = [0; 5];
    server.read_exact(&mut bytes).expect("fixture read");
    assert_eq!(&bytes, b"hello");
    let socket = fs::metadata(jail.join("vsock.sock_52")).expect("socket stays in jail");
    assert_eq!(socket.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        (socket.uid(), socket.gid()),
        (metadata.uid(), metadata.gid())
    );
    Ok(())
}
