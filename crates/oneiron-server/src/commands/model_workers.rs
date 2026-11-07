use crate::cli::ModelWorkersArgs;
use crate::config::models::worker_controller_config;

/// The non-vault process owns its configured model workers until operator stop.
pub async fn model_workers(args: ModelWorkersArgs) -> anyhow::Result<()> {
    let config = worker_controller_config(&args.config)?;
    super::init_tracing("info");
    let controller = crate::models::start_worker_controller(&config);
    super::stop_requested().await;
    controller.shutdown().await;
    Ok(())
}
