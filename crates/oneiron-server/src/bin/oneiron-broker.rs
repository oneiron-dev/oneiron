//! `oneiron-broker serve`: the credential broker, run as its own OS user. It
//! calls only the broker library, so it runs no model and opens no vault.

fn main() -> std::process::ExitCode {
    // The broker relays provider requests; a panic message could quote one.
    oneiron_server::logging::install_panic_hook();
    oneiron_broker::cli::main()
}
