fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if let Some(result) = oneiron_server::cli::worker_bootstrap_entry() {
        return result;
    }
    run()
}

#[tokio::main]
async fn run() -> anyhow::Result<()> {
    oneiron_server::cli::run().await
}
