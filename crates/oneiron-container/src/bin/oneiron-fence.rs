//! Engine-mounted Linux fence launcher, not a development runner.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() < 5 || args[3] != "--" {
        return Err(std::io::Error::other(
            "usage: oneiron-fence SOCKET GENERATION RECONNECT_MS -- COMMAND [ARGS]",
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
        &args[4..],
    )?;
    std::process::exit(status);
}
#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other("the container fence requires Linux"))
}
