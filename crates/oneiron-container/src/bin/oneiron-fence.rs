//! Engine-mounted Linux fence launcher, not a development runner.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut delimiter = 3;
    let mut read_only_paths = Vec::new();
    while args.get(delimiter).is_some_and(|arg| arg == "--read-only") {
        let path = args
            .get(delimiter + 1)
            .ok_or_else(|| std::io::Error::other("missing read-only path"))?;
        read_only_paths.push(std::path::PathBuf::from(path));
        delimiter += 2;
    }
    if args.len() <= delimiter + 1 || args[delimiter] != "--" {
        return Err(std::io::Error::other(
            "usage: oneiron-fence SOCKET GENERATION RECONNECT_MS [--read-only PATH]... -- COMMAND [ARGS]",
        ));
    }
    let millis = args[2]
        .to_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other("invalid reconnect window"))?;
    let status = oneiron_container::launch_fenced(
        std::path::Path::new(&args[0]),
        args[1].to_string_lossy().into_owned(),
        std::time::Duration::from_millis(millis),
        &read_only_paths,
        &args[delimiter + 1..],
    )?;
    std::process::exit(status);
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other("the container fence requires Linux"))
}
