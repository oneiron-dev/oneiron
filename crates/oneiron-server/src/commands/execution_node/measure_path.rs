//! `oneiron execution-node measure-path` (pass 33 section 12, R6 step 2):
//! the control round trip and a result fetch between the issuer and a node,
//! over the engine's own transport and codec on the direct path, between two
//! keys only these processes trust ([`crate::gpu_execution_node::path_measure`]).

use crate::cli::{ExecutionNodeMeasurePathArgs, MeasurePathCommand};

/// Runs one `measure-path` command.
///
/// # Errors
///
/// A key file that could not be written or read, an endpoint key that is
/// not 64 hex digits, an endpoint that could not be bound, or a measurement
/// that stopped.
pub(super) fn measure_path(args: ExecutionNodeMeasurePathArgs) -> anyhow::Result<()> {
    match args.command {
        #[cfg(feature = "mesh")]
        MeasurePathCommand::Key(args) => mesh::write_key(&args.out),
        #[cfg(feature = "mesh")]
        MeasurePathCommand::Listen(args) => run_async(mesh::listen(args)),
        #[cfg(feature = "mesh")]
        MeasurePathCommand::Dial(args) => run_async(mesh::dial(args)),
        #[cfg(not(feature = "mesh"))]
        MeasurePathCommand::Key(_)
        | MeasurePathCommand::Listen(_)
        | MeasurePathCommand::Dial(_) => {
            anyhow::bail!("measure-path: this build has no mesh transport (the `mesh` feature)")
        }
    }
}

/// Runs `future` to its end from this synchronous command: on the binary's
/// multi-threaded runtime when there is one, else on a runtime of its own.
#[cfg(feature = "mesh")]
fn run_async<F>(future: F) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    use tokio::runtime::{Handle, RuntimeFlavor};

    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        Ok(_) => anyhow::bail!("measure-path needs a multi-threaded runtime"),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(future),
    }
}

#[cfg(feature = "mesh")]
mod mesh {
    use std::io::Write as _;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context as _;
    use oneiron_mesh_transport::{MeshMachineAddress, MeshPathDirection};
    use tokio::time::Instant;

    use crate::cli::{MeasurePathDialArgs, MeasurePathListenArgs};
    use crate::gpu_execution_node::path_measure::{
        MeasurePlan, MeasurerKey, PathReceiptLog, bind_measurer, measure_path, path_line,
        report_lines, serve_measurements,
    };

    /// How long a dialer waits for its closed connection's path receipt.
    const CLOSED_RECEIPT_WAIT: Duration = Duration::from_secs(3);

    /// `measure-path key`: a new measuring key in `out` (never over an
    /// existing file; mode 0600), and its endpoint key.
    pub(super) fn write_key(out: &Path) -> anyhow::Result<()> {
        let key = MeasurerKey::generate();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(out)
            .with_context(|| format!("measure-path key: create {}", out.display()))?;
        writeln!(file, "{}", oneiron_hex::encode(&key.seed()))
            .and_then(|()| file.sync_all())
            .with_context(|| format!("measure-path key: write {}", out.display()))?;
        println!(
            "## KEY endpoint={} file={}",
            oneiron_hex::encode(&key.endpoint()),
            out.display()
        );
        Ok(())
    }

    /// `measure-path listen`: serves the one dialer until the deadline.
    pub(super) async fn listen(args: MeasurePathListenArgs) -> anyhow::Result<()> {
        let peer = endpoint_key(&args.peer)?;
        let key = MeasurerKey::generate();
        let receipts = Arc::new(PathReceiptLog::default());
        let address = MeshMachineAddress {
            endpoint_key: peer,
            direct_addrs: Vec::new(),
            relay_url: None,
        };
        let (transport, _) = bind_measurer(&key, address, args.bind, Arc::clone(&receipts))
            .await
            .map_err(|error| anyhow::anyhow!("measure-path listen: bind {}: {error}", args.bind))?;
        println!(
            "## LISTEN endpoint={} bind={} peer={} max_secs={} connections={}",
            oneiron_hex::encode(&key.endpoint()),
            args.bind,
            args.peer,
            args.max_secs,
            args.connections
        );
        std::io::stdout().flush()?;
        let deadline = Instant::now() + Duration::from_secs(args.max_secs);
        let served = serve_measurements(&transport, deadline, args.connections).await;
        let path = receipts.closed(MeshPathDirection::Inbound);
        let _ = transport.shutdown().await;
        let tally = served.map_err(|error| anyhow::anyhow!("measure-path listen: {error}"))?;
        println!(
            "## SERVED connections={} answers={} received_bytes={} sent_bytes={}",
            tally.connections, tally.answers, tally.received_bytes, tally.sent_bytes
        );
        println!("{}", path_line(path.as_ref()));
        Ok(())
    }

    /// `measure-path dial`: takes the samples and prints the report.
    pub(super) async fn dial(args: MeasurePathDialArgs) -> anyhow::Result<()> {
        let key = MeasurerKey::from_seed(&read_seed(&args.key)?);
        let address = MeshMachineAddress {
            endpoint_key: endpoint_key(&args.peer)?,
            direct_addrs: vec![args.addr],
            relay_url: None,
        };
        let receipts = Arc::new(PathReceiptLog::default());
        let (transport, peer) = bind_measurer(&key, address, args.bind, Arc::clone(&receipts))
            .await
            .map_err(|error| anyhow::anyhow!("measure-path dial: bind {}: {error}", args.bind))?;
        let plan = MeasurePlan {
            control_samples: args.control_samples,
            control_request_bytes: args.control_request_bytes,
            control_answer_bytes: args.control_answer_bytes,
            fetch_samples: args.fetch_samples,
            fetch_bytes: args.fetch_bytes,
            call_timeout: Duration::from_secs(args.timeout_secs),
        };
        println!(
            "## PATH-MEASURE peer={} addr={} endpoint={} relay=none",
            args.peer,
            args.addr,
            oneiron_hex::encode(&key.endpoint())
        );
        let measured = measure_path(&transport, peer, &plan).await;
        let path = receipts
            .wait_closed(MeshPathDirection::Outbound, CLOSED_RECEIPT_WAIT)
            .await;
        let _ = transport.shutdown().await;
        let report = measured.map_err(|error| anyhow::anyhow!("measure-path dial: {error}"))?;
        for line in report_lines(&report, path.as_ref()) {
            println!("{line}");
        }
        Ok(())
    }

    /// A 32-byte endpoint key from its 64 hex digits.
    fn endpoint_key(text: &str) -> anyhow::Result<[u8; 32]> {
        oneiron_hex::decode_any_case::<32>(text.trim())
            .with_context(|| format!("measure-path: {text:?} is not 64 hex digits"))
    }

    /// The seed in a key file `key` wrote.
    fn read_seed(file: &Path) -> anyhow::Result<[u8; 32]> {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("measure-path dial: read {}", file.display()))?;
        oneiron_hex::decode_any_case::<32>(text.trim())
            .with_context(|| format!("measure-path dial: {} holds no key", file.display()))
    }
}
