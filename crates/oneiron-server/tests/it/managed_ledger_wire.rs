//! The managed wake ledger's push, through its real Unix-socket path: the
//! frame an independent peer receives pins the token as a hex string.

#[tokio::test]
async fn ledger_push_sends_pinned_token_string_to_independent_peer() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    // The vault-contract v3 page (FIX 9549, #3940), authored by hand from the
    // contract: an empty report at revision 7 is one page; its digest is the
    // BLAKE3 derive-key hash `LedgerReportHead::of` documents ("oneiron
    // wake-ledger report v1" over the length-delimited vault, revision, entry
    // count, training setting and origin count), computed outside this crate.
    const WIRE: &str = concat!(
        r#"{"op":"ledger_update","vault":"wire-peer","#,
        r#""token":"3031323334353637383961626364656630313233343536373839616263646566","#,
        r#""page":{"rev":7,"#,
        r#""report_digest":"d2a4abae2b3d2df829ed4110948b664b2c5d4a7bfb6fc5ffa8b0ea3b2e414dc0","#,
        r#""total":0,"artifact_origins_total":0,"offset":0,"entries":[],"artifact_origins":[],"#,
        r#""training":{"on":false,"allow_opt_out":false,"#,
        r#""revision":"0000000000000000000000000000000000000000000000000000000000000000","#,
        r#""set_by":null}}}"#,
        "\n",
    );
    // The supervisor's receipt of the report's last page: it holds the report.
    const ACK: &str = concat!(
        r#"{"ok":true,"report":{"rev":7,"#,
        r#""report_digest":"d2a4abae2b3d2df829ed4110948b664b2c5d4a7bfb6fc5ffa8b0ea3b2e414dc0","#,
        r#""total":0,"artifact_origins_total":0},"offset":0,"committed":true}"#,
        "\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("peer.sock");
    let peer = tokio::net::UnixListener::bind(&socket).unwrap();
    let receiving = tokio::spawn(async move {
        let (stream, _) = peer.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut received = Vec::new();
        reader.read_until(b'\n', &mut received).await.unwrap();
        assert_eq!(received, WIRE.as_bytes());
        writer.write_all(ACK.as_bytes()).await.unwrap();
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
    let snapshot = oneiron_server::managed::LedgerSnapshot {
        entries: Vec::new(),
        training: oneiron_vault_contract::ManagedTrainingSetting {
            on: false,
            allow_opt_out: false,
            revision: "0".repeat(64),
            set_by: None,
        },
        artifact_origins: Vec::new(),
    };
    ledger.push_once(7, &snapshot).await.unwrap();
    receiving.await.unwrap();
    // Independent ingress frame, not a serialize-then-deserialize round trip.
    let received: oneiron_vault_contract::LedgerUpdate = serde_json::from_str(WIRE).unwrap();
    received.validate().unwrap();
    assert_eq!(
        received.token.expose(),
        "3031323334353637383961626364656630313233343536373839616263646566"
    );
}
