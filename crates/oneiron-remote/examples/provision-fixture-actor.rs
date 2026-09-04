//! Provisions the wire fixture's owner actor on a PRE-SERVER vault.
//!
//! Used only by `scripts/wire-test-server.sh`. It opens the temporary vault
//! through the ordinary SDK constructor — which runs the core-owned
//! `ensure_embedded_owner_actor` bootstrap — and prints the resulting 32-hex
//! actor id. The fixture then mints a slip whose `principal_ref` names that
//! same actor, so the server's first witness succeeds because the PERSON it
//! writes as already exists.
//!
//! This deliberately reaches for the SDK constructor rather than a storage
//! primitive. Embedded construction-time ownership IS the authority (OF-452
//! D10), so the same seam that binds a local owner binds the fixture's, and
//! the fixture needs no privileged write path of its own.
//!
//! The writer lease is released when this process exits, which is why it must
//! run to completion BEFORE the server starts: two processes cannot own one
//! vault directory, and that rule has no fixture exemption.

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: provision-fixture-actor <vault-dir>");
        return std::process::ExitCode::FAILURE;
    };

    let options = oneiron_remote::OpenOptions::default();
    let client =
        match oneiron_remote::OneironClient::open(Some(std::path::Path::new(&path)), &options) {
            Ok(client) => client,
            Err(error) => {
                eprintln!(
                    "could not open the fixture vault: {} {}",
                    error.code, error.message
                );
                return std::process::ExitCode::FAILURE;
            }
        };

    let Some(actor) = client.actor_ref() else {
        eprintln!("an embedded open must produce a bound actor");
        return std::process::ExitCode::FAILURE;
    };
    println!("{actor}");
    std::process::ExitCode::SUCCESS
}
