//! The crate-private verb export macro.
//!
//! The macro is deliberately crate-private (no `macro_export`): the closed
//! exported surface is a property of this crate, not something a consumer
//! extends. `scripts/sdk/generate.py` writes its one invocation into
//! `facade_generated.rs` from the verb table.

/// Emits the exported verb block plus the SDK-name and Rust-name ledgers.
///
/// Every arm is `"sdkName" => fn rust_name(&self, ..) -> Output = |client| {
/// body };`. The body runs with `client` bound to the handle's shared
/// `oneiron_remote::OneironClient` and returns `Result<Output, OneironError>`;
/// the generator writes it as lower, call the row's typed client method,
/// lift. The two ledgers come from the same invocation, so they name exactly
/// the methods it exports.
macro_rules! export_facade {
    ($(
        $sdk_name:literal =>
        fn $rust_name:ident(&self $(, $arg:ident: $arg_ty:ty)*) -> $output:ty
            = |$client:ident| $body:block;
    )+) => {
        /// The exported verb ledger in canonical SDK spelling, emitted from
        /// the same invocation that declares the exported methods.
        pub const EXPORTED_UNIFFI_VERBS: &[&str] = &[$($sdk_name),+];

        /// The exported Rust method names, positionally paired with
        /// [`EXPORTED_UNIFFI_VERBS`].
        pub const EXPORTED_UNIFFI_RUST_NAMES: &[&str] = &[
            $(stringify!($rust_name)),+
        ];

        #[uniffi::export]
        #[allow(
            clippy::too_many_arguments,
            reason = "a verb's typed arguments cross one by one, as its table row spells them"
        )]
        impl Oneiron {
            $(
                /// One verb of the SDK verb table, answered by the shared
                /// client's typed method for its row on the embedded or the
                /// remote backend.
                pub fn $rust_name(
                    &self,
                    $($arg: $arg_ty),*
                ) -> Result<$output, OneironError> {
                    let $client = &self.inner;
                    $body
                }
            )+
        }
    };
}
