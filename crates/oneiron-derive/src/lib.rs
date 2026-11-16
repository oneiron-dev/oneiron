//! Proc-macro derives of the oneiron workspace, one module per derive. A derive's trait, and the
//! documentation of its rule, live in the crate that re-exports it; the code a derive writes
//! names that crate.
//!
//! - `SideKey` (module `side_key`): `oneiron_store::side_table::key::SideKey`, a stored
//!   side-table key that declares its parts once.

use proc_macro::TokenStream;

mod side_key;

/// Derives `oneiron_store::side_table::key::SideKey` for a struct whose fields are the key's
/// parts, in order, and `FixedSideKey` when every part is fixed width.
#[proc_macro_derive(SideKey, attributes(side_key))]
pub fn derive_side_key(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    side_key::expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
