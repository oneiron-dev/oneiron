//! Proc-macro derives of the oneiron workspace, one module per derive. A derive's trait, and the
//! documentation of its rule, live in the crate that re-exports it; the code a derive writes
//! names that crate.
//!
//! - `SideKey` (module `side_key`): `oneiron_store::side_table::key::SideKey`, a stored
//!   side-table key that declares its parts once.
//! - `Register` (module `register`): `oneiron_contracts::register::Register`, a closed list of
//!   names declared once.

use proc_macro::TokenStream;

mod register;
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

/// Derives `oneiron_contracts::register::Register` for an enum of unit variants, one row each,
/// and an inherent `const fn as_str(self)` at the enum's visibility. The enum states the
/// Register's name in `#[register("lower.dotted")]`; each row's name is the one serde writes.
///
/// ```
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// #[register("doc.example")]
/// enum Example {
///     First,
///     #[register(name = "second.row")]
///     Second,
/// }
///
/// assert_eq!(Example::NAME, "doc.example");
/// assert_eq!(Example::ROWS, &[Example::First, Example::Second]);
/// assert_eq!(Example::First.as_str(), "First");
/// assert_eq!(Example::named("second.row"), Some(Example::Second));
/// ```
///
/// It refuses, at compile time, a variant that carries data:
///
/// ```compile_fail
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// #[register("doc.example")]
/// enum Example {
///     First,
///     Second(u8),
/// }
/// ```
///
/// two rows with one name:
///
/// ```compile_fail
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// #[register("doc.example")]
/// enum Example {
///     First,
///     #[register(name = "First")]
///     Second,
/// }
/// ```
///
/// an empty name, or one with white space:
///
/// ```compile_fail
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// #[register("doc.example")]
/// enum Example {
///     First,
///     #[register(name = "")]
///     Second,
/// }
/// ```
///
/// ```compile_fail
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// #[register("doc.example")]
/// enum Example {
///     First,
///     #[register(name = "second row")]
///     Second,
/// }
/// ```
///
/// an enum with no `#[register("...")]` line:
///
/// ```compile_fail
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// enum Example {
///     First,
///     Second,
/// }
/// ```
///
/// and a Register name that is not lower case and dotted:
///
/// ```compile_fail
/// use oneiron_contracts::register::Register;
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq, Register)]
/// #[register("Doc Example")]
/// enum Example {
///     First,
///     Second,
/// }
/// ```
#[proc_macro_derive(Register, attributes(register))]
pub fn derive_register(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    register::expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
