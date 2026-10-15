//! The managed wake ledger's push, through its real Unix-socket path: the
//! frame an independent peer receives pins the token as a hex string.

#[tokio::test]
async fn ledger_push_sends_pinned_token_string_to_independent_peer() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    const WIRE: &[u8] = b"{\"op\":\"ledger_update\",\"vault\":\"wire-peer\",\"token\":\"3031323334353637383961626364656630313233343536373839616263646566\",\"rev\":7,\"entries\":[]}\n";
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("peer.sock");
    let peer = tokio::net::UnixListener::bind(&socket).unwrap();
    let receiving = tokio::spawn(async move {
        let (stream, _) = peer.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut received = Vec::new();
        reader.read_until(b'\n', &mut received).await.unwrap();
        assert_eq!(received, WIRE);
        writer.write_all(b"{\"ok\":true}\n").await.unwrap();
        writer.flush().await.unwrap();
    });
    let vault = std::sync::Arc::new(
        oneiron::Vault::open(dir.path().join("vault"), oneiron::VaultConfig::device()).unwrap(),
    );
    let credentials = oneiron_vault_contract::Credentials {
        dek: [0x17; 32],
        token: *b"0123456789abcdef0123456789abcdef",
    };
    let ledger =
        oneiron_server::managed::WakeLedger::load(vault, "wire-peer".into(), socket, &credentials)
            .unwrap();
    ledger.push_once(7, &[]).await.unwrap();
    receiving.await.unwrap();
    // Independent ingress frame, not a serialize-then-deserialize round trip.
    let received: oneiron_vault_contract::LedgerUpdate = serde_json::from_slice(WIRE).unwrap();
    received.validate().unwrap();
    assert_eq!(
        received.token.expose(),
        "3031323334353637383961626364656630313233343536373839616263646566"
    );
}
