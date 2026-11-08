fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if let Some(result) = oneiron_server::cli::worker_bootstrap_entry() {
        return result;
    }
    run()
}

fn run() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .enable_all()
        .build()?
        .block_on(oneiron_server::cli::run())
}
