//! Flags for `oneiron secrets bind`, `unbind`, `pending` and
//! `import-supplement` (FIX 2620, 11158, 12068): the owner's bindings of a
//! secret to an effector, a restore's credentials pending on their source's
//! evidence, and the import of an export secret supplement. None reads a
//! value.

use clap::Args;

use crate::config::ServeArgs;

/// The secret, by exactly one of its handle or its custody name.
#[derive(Args, Clone, Debug)]
pub struct SecretRefArgs {
    /// The secret's handle, such as `sc12`, as a masked text or field holds it.
    #[arg(long, conflicts_with = "name", required_unless_present = "name")]
    pub handle: Option<String>,

    /// The secret's custody name.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct SecretBindArgs {
    #[command(flatten)]
    pub secret: SecretRefArgs,

    /// The effector that may use the secret, such as `connector:slack`. A
    /// binding it already holds is replaced.
    #[arg(long)]
    pub effector: String,

    /// The most exposed rung it may be used at: 0 doored (the default), 1
    /// leased, 2 local-registered.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=2))]
    pub rung: Option<u8>,

    /// What the binding grants; repeat for more. `read`, which lets the door
    /// hand the value over, when none is given.
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scopes: Vec<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct SecretUnbindArgs {
    #[command(flatten)]
    pub secret: SecretRefArgs,

    /// The effector whose binding is withdrawn; every other binding stays.
    #[arg(long)]
    pub effector: String,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct SecretPendingArgs {
    /// Keep every credential this restore batch (32 hex) holds pending on
    /// its source's evidence, as the backup carried it, with `--confirm
    /// keep_without_source`. Without it, the batches are listed.
    #[arg(long, value_name = "BATCH", requires = "confirm")]
    pub keep: Option<String>,

    /// The typed confirm a keep takes: `keep_without_source`, "the source is
    /// gone, keep these". It is your election, not a check of the source.
    #[arg(long, value_name = "WORD", requires = "keep")]
    pub confirm: Option<String>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

/// `oneiron secrets import-supplement` reads the supplement read's JSON
/// from stdin: no flag names the copy.
#[derive(Args, Clone, Debug)]
pub struct SecretImportSupplementArgs {
    #[command(flatten)]
    pub serve: ServeArgs,
}
