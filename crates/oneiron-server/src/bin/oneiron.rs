#[tokio::main]
async fn main() -> anyhow::Result<()> {
    oneiron_server::cli::run().await
}
