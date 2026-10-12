//! `oneiron-broker serve`: the credential broker, run as its own OS user. It
//! calls only the broker library, so it runs no model and opens no vault.

fn main() -> std::process::ExitCode {
    oneiron_broker::cli::main()
}
