//! `#[derive(SideKey)]` for `oneiron_store::side_table::key::SideKey`: a stored side-table key
//! declares its parts once, and both `encode_into` and `decode_key` follow from that declaration.
//!
//! `oneiron_store::side_table::key` re-exports this derive beside the trait and documents the rule
//! and its settings there, with examples that run as doc tests. The code written here names
//! `::oneiron_store::side_table::key`, so a crate that derives a key depends on `oneiron-store`.

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote, quote_spanned};
use syn::meta::ParseNestedMeta;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, Ident, Lit, LitByte, LitByteStr, Member, Type};

/// How a decode finds where a part ends.
enum Role {
    /// The part type's `FixedSideKey::WIDTH` bytes.
    Fixed,
    /// A big-endian count (a `LengthPrefix` type), then that many bytes.
    LengthPrefixed(Type),
    /// The bytes the other parts leave.
    Rest,
}

/// One field: one part of the key.
struct Part {
    member: Member,
    field_type: Type,
    /// The `with = ..` part type that spells the field, if any.
    spelling: Option<Type>,
    role: Role,
    span: Span,
}

impl Part {
    /// The type the key spells: the `with` part type, else the field's own type.
    fn part_type(&self) -> &Type {
        self.spelling.as_ref().unwrap_or(&self.field_type)
    }

    fn width(&self, key: &TokenStream2) -> TokenStream2 {
        let part_type = self.part_type();
        quote_spanned!(self.span=> <#part_type as #key::FixedSideKey>::WIDTH)
    }

    fn encode(&self, key: &TokenStream2) -> TokenStream2 {
        let member = &self.member;
        let field_type = &self.field_type;
        let write = match &self.spelling {
            Some(spelling) => quote! {
                <#spelling as #key::FieldSpelling<#field_type>>::encode_field(&self.#member, out);
            },
            None => quote!(<#field_type as #key::SideKey>::encode_into(&self.#member, out);),
        };
        match &self.role {
            Role::LengthPrefixed(count) => quote! {
                <#count as #key::LengthPrefix>::encode_prefixed(out, |out| { #write });
            },
            Role::Fixed | Role::Rest => write,
        }
    }

    /// Reads this part from exactly the bytes in `raw` into `binding`.
    fn decode(&self, binding: &Ident, raw: &Ident, key: &TokenStream2) -> TokenStream2 {
        let part_type = self.part_type();
        let decoded = quote!(<#part_type as #key::SideKey>::decode_key(#raw)?);
        match &self.spelling {
            Some(spelling) => {
                let field_type = &self.field_type;
                quote! {
                    let #binding = <#spelling as #key::FieldSpelling<#field_type>>::into_field(#decoded);
                }
            }
            None => quote!(let #binding = #decoded;),
        }
    }
}

/// The struct-level settings.
#[derive(Default)]
struct Layout {
    prefix: Option<LitByteStr>,
    separator: Option<LitByte>,
}

/// The `SideKey` impl (and the `FixedSideKey` impl, when every part is fixed width) for `input`.
pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "a derived side key has no generic parameters",
        ));
    }
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.ident.span(),
            "SideKey derives for a struct of key parts; an enum key keeps its own impl",
        ));
    };
    if data.fields.is_empty() {
        return Err(syn::Error::new(
            input.ident.span(),
            "a key with no parts is the singleton key `()`",
        ));
    }
    let layout = parse_layout(input)?;
    let parts = data
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| parse_part(index, field))
        .collect::<syn::Result<Vec<_>>>()?;
    let rest = rest_index(&parts)?;
    let key = quote!(::oneiron_store::side_table::key);
    let name = &input.ident;
    let encode = encode_body(&layout, &parts, &key);
    let decode = decode_body(&layout, &parts, rest, &key);
    let construct = construct(&data.fields, &parts);
    let fixed = fixed_impl(name, &layout, &parts, &key);
    Ok(quote! {
        impl #key::SideKey for #name {
            fn encode_into(&self, out: &mut ::std::vec::Vec<u8>) {
                #encode
            }

            fn decode_key(bytes: &[u8]) -> ::core::option::Option<Self> {
                #decode
                ::core::option::Option::Some(#construct)
            }
        }

        #fixed
    })
}

fn parse_layout(input: &DeriveInput) -> syn::Result<Layout> {
    let mut layout = Layout::default();
    for attr in input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("side_key"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("prefix") {
                let Lit::ByteStr(prefix) = meta.value()?.parse::<Lit>()? else {
                    return Err(meta.error("prefix is a byte string literal such as b\"row:\""));
                };
                set_once(&mut layout.prefix, prefix, &meta, "prefix is given twice")
            } else if meta.path.is_ident("sep") {
                let Lit::Byte(separator) = meta.value()?.parse::<Lit>()? else {
                    return Err(
                        meta.error("sep is one byte, written as a byte literal such as b':'")
                    );
                };
                set_once(
                    &mut layout.separator,
                    separator,
                    &meta,
                    "sep is given twice",
                )
            } else {
                Err(meta.error("a key takes prefix and sep; a part takes rest, len and with"))
            }
        })?;
    }
    Ok(layout)
}

fn parse_part(index: usize, field: &syn::Field) -> syn::Result<Part> {
    let mut role = None;
    let mut spelling = None;
    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("side_key"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rest") {
                set_once(
                    &mut role,
                    Role::Rest,
                    &meta,
                    "a part takes one of rest and len",
                )
            } else if meta.path.is_ident("len") {
                let count = meta.value()?.parse::<Type>()?;
                set_once(
                    &mut role,
                    Role::LengthPrefixed(count),
                    &meta,
                    "a part takes one of rest and len",
                )
            } else if meta.path.is_ident("with") {
                let part_type = meta.value()?.parse::<Type>()?;
                set_once(&mut spelling, part_type, &meta, "with is given twice")
            } else {
                Err(meta.error("a part takes rest, len and with; a key takes prefix and sep"))
            }
        })?;
    }
    let member = field
        .ident
        .clone()
        .map_or_else(|| Member::Unnamed(syn::Index::from(index)), Member::Named);
    Ok(Part {
        member,
        field_type: field.ty.clone(),
        spelling,
        role: role.unwrap_or(Role::Fixed),
        span: field.ty.span(),
    })
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    meta: &ParseNestedMeta<'_>,
    twice: &str,
) -> syn::Result<()> {
    if slot.is_some() {
        return Err(meta.error(twice));
    }
    *slot = Some(value);
    Ok(())
}

/// The index of the one rest part, after checking the rule: at most one rest part, and only
/// fixed-width parts after it, because those are read from the end of the key.
fn rest_index(parts: &[Part]) -> syn::Result<Option<usize>> {
    let mut rest = None;
    for (index, part) in parts.iter().enumerate() {
        match (&part.role, rest) {
            (Role::Rest, Some(_)) => {
                return Err(syn::Error::new(
                    part.span,
                    "a key has at most one rest part: give the other variable part a length prefix (len = u16)",
                ));
            }
            (Role::Rest, None) => rest = Some(index),
            (Role::LengthPrefixed(_), Some(_)) => {
                return Err(syn::Error::new(
                    part.span,
                    "a part after the rest part is read from the end of the key, so it is fixed width",
                ));
            }
            _ => {}
        }
    }
    Ok(rest)
}

/// The local names of part `index`: its value, and the bytes it is read from.
fn names(index: usize) -> (Ident, Ident) {
    (
        format_ident!("part_{}", index),
        format_ident!("part_{}_bytes", index),
    )
}

fn encode_body(layout: &Layout, parts: &[Part], key: &TokenStream2) -> TokenStream2 {
    let prefix = layout
        .prefix
        .as_ref()
        .map(|prefix| quote!(out.extend_from_slice(#prefix);));
    let writes = parts.iter().enumerate().map(|(index, part)| {
        let separator = layout
            .separator
            .as_ref()
            .filter(|_| index > 0)
            .map(|separator| quote!(out.push(#separator);));
        let write = part.encode(key);
        quote!(#separator #write)
    });
    quote!(#prefix #(#writes)*)
}

/// Reads the parts before the rest part from the front, the parts after it from the end, and
/// gives the rest part what is left. A key with no rest part refuses any byte left over.
fn decode_body(
    layout: &Layout,
    parts: &[Part],
    rest: Option<usize>,
    key: &TokenStream2,
) -> TokenStream2 {
    let mut steps = Vec::new();
    if let Some(prefix) = &layout.prefix {
        steps.push(quote!(let bytes = bytes.strip_prefix(#prefix)?;));
    }
    let separator = layout.separator.as_ref();
    for (index, part) in parts.iter().enumerate().take(rest.unwrap_or(parts.len())) {
        let (binding, raw) = names(index);
        steps.push(match &part.role {
            Role::LengthPrefixed(count) => quote! {
                let (#raw, bytes) = <#count as #key::LengthPrefix>::split_prefixed(bytes)?;
            },
            Role::Fixed | Role::Rest => {
                let width = part.width(key);
                quote!(let (#raw, bytes) = bytes.split_at_checked(#width)?;)
            }
        });
        steps.push(part.decode(&binding, &raw, key));
        if let Some(separator) = separator.filter(|_| index + 1 < parts.len()) {
            steps.push(quote!(let bytes = bytes.strip_prefix(&[#separator])?;));
        }
    }
    if let Some(rest) = rest {
        for (index, part) in parts.iter().enumerate().skip(rest + 1).rev() {
            let (binding, raw) = names(index);
            let width = part.width(key);
            steps.push(quote! {
                let (bytes, #raw) = bytes.split_at_checked(bytes.len().checked_sub(#width)?)?;
            });
            steps.push(part.decode(&binding, &raw, key));
            if let Some(separator) = separator {
                steps.push(quote!(let bytes = bytes.strip_suffix(&[#separator])?;));
            }
        }
        let (binding, _) = names(rest);
        steps.push(parts[rest].decode(&binding, &format_ident!("bytes"), key));
    } else {
        steps.push(quote! {
            if !bytes.is_empty() {
                return ::core::option::Option::None;
            }
        });
    }
    quote!(#(#steps)*)
}

fn construct(fields: &Fields, parts: &[Part]) -> TokenStream2 {
    let bindings = (0..parts.len()).map(|index| names(index).0);
    match fields {
        Fields::Named(_) => {
            let members = parts.iter().map(|part| &part.member);
            quote!(Self { #(#members: #bindings),* })
        }
        Fields::Unnamed(_) | Fields::Unit => quote!(Self(#(#bindings),*)),
    }
}

/// `FixedSideKey` when every part is fixed width: the prefix, the separators and the parts.
fn fixed_impl(
    name: &Ident,
    layout: &Layout,
    parts: &[Part],
    key: &TokenStream2,
) -> Option<TokenStream2> {
    if !parts.iter().all(|part| matches!(part.role, Role::Fixed)) {
        return None;
    }
    let prefix_width = layout
        .prefix
        .as_ref()
        .map_or(0, |prefix| prefix.value().len());
    let separator_width = if layout.separator.is_some() {
        parts.len() - 1
    } else {
        0
    };
    let widths = parts.iter().map(|part| part.width(key));
    Some(quote! {
        impl #key::FixedSideKey for #name {
            const WIDTH: usize = #prefix_width + #separator_width #(+ #widths)*;
        }
    })
}
