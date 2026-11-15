//! `oneiron host recover-root`: moves a stopped self-host vault's root to a
//! new issuer seed after this install lost the old one and the vault's key
//! custody gives none back (L1-07; OF-570). The recovery kit's authority
//! key, enrolled before the loss (`recovery-kit enroll-authority`), signs one
//! ReRoot in-chain, so the vault keeps its genesis and its id, and the engine
//! carries its writers, its machines' standing and its MACHINE claim
//! histories as a re-root does (`Vault::recover_host_root_to_new_seed`).
//! Every credential a key the move retired minted stops working; this
//! command lists them.
//!
//! The kit is the whole proof: two pieces, or one and its passphrase. The
//! host secret is no key: it only admits this command and the next start, as
//! for every host command, so any value the owner sets now works. The move
//! retires the kit's key with every other key, so the report gives the
//! commands that enrol a new kit (L1-07-KIT-AFTER-MOVE = B).

use crate::cli::HostRecoverRootArgs;
use crate::config::resolve_serve_config;

use super::host_re_root::{print_root_move_report, root_move_steps};

pub fn host_recover_root(args: HostRecoverRootArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !args.serve.managed_by_hypnos,
        "a managed vault recovers its root through account sign-in; recover-root is self-host only"
    );
    anyhow::ensure!(
        args.serve.auth_secret.is_none(),
        "set ONEIRON_AUTH_SECRET or a protected config file; never pass the host secret in argv"
    );
    // A TOML error renders the line it failed on, and that line may hold a
    // host secret, so only the outermost message leaves this command.
    let config = resolve_serve_config(&args.serve).map_err(|error| {
        anyhow::anyhow!("{error} (detail withheld: the file may hold a secret)")
    })?;
    anyhow::ensure!(
        config.privacy_posture == oneiron::HostingPrivacyPosture::SelfHostLocal,
        "recover-root is self-host only: a relay keeps no host recovery path, and a managed vault recovers through account sign-in"
    );
    anyhow::ensure!(
        config.vault_path.join("data.mdb").is_file(),
        "vault {} does not exist",
        config.vault_path.display()
    );
    anyhow::ensure!(
        config
            .sync_server_config()
            .auth_secret
            .is_some_and(|secret| !secret.is_empty()),
        "set the host secret first (ONEIRON_AUTH_SECRET or the config's auth_secret): it admits host commands and the next `oneiron serve`, and any new value works"
    );
    let (vault, secret) = super::owner::open_kit_material(&config, &args.kit, &args.unlock)?;
    // The install gives the recovery its keystore. The recovery itself
    // takes back a seed the vault's custody still escrows for its live root
    // (FIX-LIST 10770) before it reads the slot, and refuses when that step
    // faults, so a root that is not lost is never moved by the kit.
    if vault.device_keystore_assurance().is_none() {
        config.keystore.install_on(&vault, &config.vault_path);
    }
    let moved = vault.recover_host_root_to_new_seed(secret)?;
    let mut steps = vec![
        "The vault's root moved to a new issuer seed kept in this install's keystore. Start `oneiron serve` with your host secret (ONEIRON_AUTH_SECRET or the config's auth_secret).".to_owned(),
    ];
    steps.extend(root_move_steps(&vault, &moved, "the lost root"));
    print_root_move_report(&moved, steps)
}
