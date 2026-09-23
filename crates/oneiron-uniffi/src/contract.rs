//! Head-contract pins and the crate-private verb export macro.
//!
//! The macro is deliberately crate-private (no `macro_export`): the closed
//! exported surface is a property of this crate, not something a consumer
//! extends.

/// Emits the exported verb block plus the SDK-name and Rust-name ledgers.
///
/// Every arm is `"sdkName" => fn rust_name(&self, ..) -> Output;`. The bodies
/// are definition-only by construction: there is no seam in this macro for a
/// caller to smuggle behaviour into the exported surface.
macro_rules! export_facade {
    ($(
        $sdk_name:literal =>
        fn $rust_name:ident(&self $(, $arg:ident: $arg_ty:ty)*) -> $output:ty;
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
        impl Oneiron {
            $(
                /// One pinned head-contract verb.
                ///
                /// Definition-only: the exported signature is authoritative,
                /// the body fails closed until the first consumer wires it
                /// through the core memory facade.
                pub fn $rust_name(
                    &self,
                    $($arg: $arg_ty),*
                ) -> Result<$output, OneironError> {
                    let _ = ($(&$arg,)*);
                    definition_only($sdk_name)
                }
            )+
        }
    };
}
