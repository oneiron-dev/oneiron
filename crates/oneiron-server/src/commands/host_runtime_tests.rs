use oneiron_vault_contract::{
    host::{Host, HostLimits},
    host_adapters::InProcessHost,
};
#[tokio::test]
async fn in_process_host_boots_vault_then_idles_without_exit_and_stops() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let (events, observed) = std::sync::mpsc::channel();
    let ready = events.clone();
    let mut host = InProcessHost::new(
        listener,
        HostLimits::unbounded(),
        move || {
            ready.send("ready")?;
            Ok(())
        },
        move || {
            events.send("stopped")?;
            Ok(())
        },
    );
    let mut vault = None;
    host.start(|_| {
        vault = Some(oneiron::Vault::open(
            dir.path(),
            oneiron::VaultConfig::default(),
        )?);
        Ok(())
    })?;
    assert_eq!(observed.recv()?, "ready");
    host.idle(Some(std::time::SystemTime::now())).await?;
    let vault = vault.expect("booted");
    let id = oneiron::EntityId::from_bytes([0x6D; 16])?;
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"after idle",
    )?;
    assert_eq!(vault.get(&id)?.as_deref(), Some(b"after idle".as_slice()));
    assert!(observed.try_recv().is_err());
    host.on_stop()?;
    assert_eq!(observed.recv()?, "stopped");
    Ok(())
}
