fn main() -> anyhow::Result<()> {
    // The job unit's own steps (pass 33, 7.6) run before any runtime starts:
    // `job-exec` becomes the workload, and no thread of the engine may exist
    // beside it.
    #[cfg(target_os = "linux")]
    {
        // Lossy, so an argument that is not UTF-8 never panics here; the
        // steps take ASCII arguments only, and every other command reads its
        // own arguments again.
        let args: Vec<String> = std::env::args_os()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        if let Some(status) =
            oneiron_server::gpu_execution_node::scope_systemd::run_unit_step(&args)
        {
            std::process::exit(status);
        }
    }
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
