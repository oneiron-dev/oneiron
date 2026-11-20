//! `#[derive(Register)]` for `oneiron_contracts::register::Register`: a closed list of names is
//! declared once, as a plain enum, and its name table follows from that declaration.
//!
//! A row's name is the one serde writes for the same enum: a variant's `#[serde(rename = "..")]`,
//! else the enum's `#[serde(rename_all = "..")]` applied to the variant, else the variant itself.
//! An enum whose names differ from serde's (or that has no serde derive) states its own spelling:
//! `#[register("x.y", rename_all = "..")]` replaces serde's spelling for every row, and
//! `#[register(name = "..")]` on a variant names that one row. The code written here names
//! `::oneiron_contracts::register`, which holds the trait and re-exports this derive.

use proc_macro2::{Span, TokenStream as TokenStream2, TokenTree};
use quote::quote;
use syn::ext::IdentExt;
use syn::meta::ParseNestedMeta;
use syn::parse::ParseStream;
use syn::spanned::Spanned;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, LitStr, Token, Variant};

/// The enum-level `#[register("...")]` line.
struct RegisterAttr {
    /// The Register's own name (`NAME`).
    name: LitStr,
    /// A case rule that replaces serde's for every row.
    rename_all: Option<CaseRule>,
}

/// One row: a unit variant and its name.
struct Row {
    ident: Ident,
    name: String,
    span: Span,
}

pub(crate) fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new(
            input.ident.span(),
            "a Register is an enum whose variants are its rows",
        ));
    };
    if !input.generics.params.is_empty() || input.generics.where_clause.is_some() {
        return Err(syn::Error::new(
            input.generics.span(),
            "a Register takes no generic parameters",
        ));
    }
    let register = register_attr(input)?;
    check_register_name(&register.name)?;
    let rule = match register.rename_all {
        Some(rule) => Some(rule),
        None => serde_rename_all(&input.attrs)?,
    };
    let mut rows: Vec<Row> = Vec::with_capacity(data.variants.len());
    for variant in &data.variants {
        let row = parse_row(variant, rule, register.rename_all.is_some())?;
        if let Some(first) = rows.iter().find(|earlier| earlier.name == row.name) {
            return Err(syn::Error::new(
                row.span,
                format!(
                    "two rows of Register `{}` have the name `{}`: `{}` and `{}`",
                    register.name.value(),
                    row.name,
                    first.ident,
                    row.ident
                ),
            ));
        }
        rows.push(row);
    }

    let ident = &input.ident;
    let vis = &input.vis;
    let register_name = &register.name;
    let variants: Vec<&Ident> = rows.iter().map(|row| &row.ident).collect();
    let names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();
    Ok(quote! {
        impl #ident {
            /// The row's name: the one token that is stored and sent (`Register::name`).
            #vis const fn as_str(self) -> &'static str {
                match self {
                    #( Self::#variants => #names, )*
                }
            }
        }

        impl ::oneiron_contracts::register::Register for #ident {
            const NAME: &'static str = #register_name;
            const ROWS: &'static [Self] = &[ #( Self::#variants ),* ];

            fn name(self) -> &'static str {
                Self::as_str(self)
            }
        }
    })
}

/// Reads the one enum-level `#[register("lower.dotted", rename_all = "..")]`.
fn register_attr(input: &DeriveInput) -> syn::Result<RegisterAttr> {
    let mut found: Option<RegisterAttr> = None;
    for attr in input
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("register"))
    {
        if found.is_some() {
            return Err(syn::Error::new(
                attr.span(),
                "a Register states its name once: one #[register(\"...\")] line",
            ));
        }
        found = Some(attr.parse_args_with(register_args)?);
    }
    found.ok_or_else(|| {
        syn::Error::new(
            input.ident.span(),
            "a Register states its name: #[register(\"lower.dotted\")]",
        )
    })
}

/// The inside of `#[register("lower.dotted", rename_all = "..")]`.
fn register_args(stream: ParseStream<'_>) -> syn::Result<RegisterAttr> {
    let name: LitStr = stream.parse()?;
    let mut rename_all = None;
    while !stream.is_empty() {
        stream.parse::<Token![,]>()?;
        if stream.is_empty() {
            break;
        }
        let key: Ident = stream.parse()?;
        stream.parse::<Token![=]>()?;
        let value: LitStr = stream.parse()?;
        if key != "rename_all" {
            return Err(syn::Error::new(
                key.span(),
                "#[register(\"...\")] takes only `rename_all = \"..\"` after the name",
            ));
        }
        if rename_all.is_some() {
            return Err(syn::Error::new(key.span(), "`rename_all` is given twice"));
        }
        rename_all = Some(CaseRule::parse(&value)?);
    }
    Ok(RegisterAttr { name, rename_all })
}

/// The Register's own name is lower case and dotted: `gate.outcome`.
fn check_register_name(name: &LitStr) -> syn::Result<()> {
    let value = name.value();
    let lower_dotted = value.split('.').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    });
    if lower_dotted {
        Ok(())
    } else {
        Err(syn::Error::new(
            name.span(),
            format!(
                "the Register name `{value}` is not lower case and dotted (letters, digits, `_`, `.`)"
            ),
        ))
    }
}

/// One variant as one row, with its name.
fn parse_row(variant: &Variant, rule: Option<CaseRule>, register_rule: bool) -> syn::Result<Row> {
    if !matches!(variant.fields, Fields::Unit) {
        return Err(syn::Error::new(
            variant.span(),
            "a Register row is a bare name: this variant carries data",
        ));
    }
    let span = variant.ident.span();
    let ident = variant.ident.unraw().to_string();
    let name = match variant_register_name(&variant.attrs)? {
        Some(name) => name,
        // A register-level rule replaces serde's spelling whole, so a serde rename is not read.
        None => {
            let serde_name = if register_rule {
                None
            } else {
                serde_rename(&variant.attrs)?
            };
            match serde_name {
                Some(name) => name,
                None => match rule {
                    Some(rule) => rule.apply(&ident),
                    None => ident,
                },
            }
        }
    };
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        return Err(syn::Error::new(
            span,
            format!("the row name `{name}` is empty or holds white space"),
        ));
    }
    Ok(Row {
        ident: variant.ident.clone(),
        name,
        span,
    })
}

/// A variant's `#[register(name = "..")]`.
fn variant_register_name(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    let mut name: Option<String> = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("register")) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("name") {
                return Err(meta.error("a variant takes only #[register(name = \"..\")]"));
            }
            if name.is_some() {
                return Err(meta.error("the row's name is given twice"));
            }
            name = Some(meta.value()?.parse::<LitStr>()?.value());
            Ok(())
        })?;
    }
    Ok(name)
}

/// The enum's `#[serde(rename_all = "..")]`, the case rule serde applies to every variant.
fn serde_rename_all(attrs: &[Attribute]) -> syn::Result<Option<CaseRule>> {
    let mut rule = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("serde")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                let value = one_spelling(&meta, "rename_all")?;
                rule = Some(CaseRule::parse(&value)?);
            } else {
                skip_serde_item(&meta)?;
            }
            Ok(())
        })?;
    }
    Ok(rule)
}

/// A variant's `#[serde(rename = "..")]`.
fn serde_rename(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    let mut name = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("serde")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                name = Some(one_spelling(&meta, "rename")?.value());
            } else {
                skip_serde_item(&meta)?;
            }
            Ok(())
        })?;
    }
    Ok(name)
}

/// The `key = ".."` form. serde's `key(serialize = .., deserialize = ..)` form writes and reads
/// two spellings, so the Register's one name must be stated in its own attribute.
fn one_spelling(meta: &ParseNestedMeta<'_>, key: &str) -> syn::Result<LitStr> {
    if meta.input.peek(Token![=]) {
        meta.value()?.parse()
    } else {
        Err(meta.error(format!(
            "serde's `{key}(..)` spells a name two ways: state the Register's spelling in #[register(..)]"
        )))
    }
}

/// Steps over a serde item this derive does not read (`tag = ".."`, `bound(..)`, `untagged`).
fn skip_serde_item(meta: &ParseNestedMeta<'_>) -> syn::Result<()> {
    if meta.input.peek(Token![=]) {
        let value = meta.value()?;
        while !value.is_empty() && !value.peek(Token![,]) {
            value.parse::<TokenTree>()?;
        }
    } else if meta.input.peek(syn::token::Paren) {
        let content;
        syn::parenthesized!(content in meta.input);
        content.parse::<TokenStream2>()?;
    }
    Ok(())
}

/// serde's case rules for a variant name (serde_derive `internals::case`, `apply_to_variant`).
#[derive(Clone, Copy)]
enum CaseRule {
    Lower,
    Upper,
    Pascal,
    Camel,
    Snake,
    ScreamingSnake,
    Kebab,
    ScreamingKebab,
}

impl CaseRule {
    fn parse(value: &LitStr) -> syn::Result<Self> {
        Ok(match value.value().as_str() {
            "lowercase" => Self::Lower,
            "UPPERCASE" => Self::Upper,
            "PascalCase" => Self::Pascal,
            "camelCase" => Self::Camel,
            "snake_case" => Self::Snake,
            "SCREAMING_SNAKE_CASE" => Self::ScreamingSnake,
            "kebab-case" => Self::Kebab,
            "SCREAMING-KEBAB-CASE" => Self::ScreamingKebab,
            other => {
                return Err(syn::Error::new(
                    value.span(),
                    format!("unknown rename_all rule `{other}` (serde's eight rules)"),
                ));
            }
        })
    }

    fn apply(self, variant: &str) -> String {
        match self {
            Self::Pascal => variant.to_owned(),
            Self::Lower => variant.to_ascii_lowercase(),
            Self::Upper => variant.to_ascii_uppercase(),
            Self::Camel => {
                let mut chars = variant.chars();
                chars.next().map_or_else(String::new, |first| {
                    first.to_ascii_lowercase().to_string() + chars.as_str()
                })
            }
            Self::Snake => {
                let mut snake = String::with_capacity(variant.len() + 4);
                for (index, ch) in variant.char_indices() {
                    if index > 0 && ch.is_uppercase() {
                        snake.push('_');
                    }
                    snake.push(ch.to_ascii_lowercase());
                }
                snake
            }
            Self::ScreamingSnake => Self::Snake.apply(variant).to_ascii_uppercase(),
            Self::Kebab => Self::Snake.apply(variant).replace('_', "-"),
            Self::ScreamingKebab => Self::ScreamingSnake.apply(variant).replace('_', "-"),
        }
    }
}
