use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct ModelWorkersArgs {
    /// Read the `[models]` section of this server config, without opening a vault.
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
}
