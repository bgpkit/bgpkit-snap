//! Macros for `bgpkit-snap`.
//!
//! Two ways to make a value type, for two kinds of caller:
//!
//! - [`macro@snap_value`] takes the item and adds everything, so a caller writes one
//!   attribute and never names `rkyv`.
//! - [`macro@SnapValue`] is the derive, which writes only the id. It is for a type that
//!   already derives `rkyv` itself, typically because the crate uses `rkyv` elsewhere.
//!
//! Both check the id where it is written: printable ASCII, no space, quote or
//! backslash, and never empty.

use proc_macro::TokenStream;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, DeriveInput, Expr, Item, Lit, Meta, Token};

/// Make a value type out of a struct or an enum, in one attribute.
///
/// ```ignore
/// #[bgpkit_snap::snap_value("demo.peer-count:v1")]
/// struct PeerCount(u32);
/// ```
///
/// The id comes first because it is the only required argument. The attribute adds
/// `Clone`, `rkyv`'s three derives and the `rkyv` crate path, then writes the
/// `SnapValue` impl, so nothing about `rkyv` appears in the caller's manifest.
///
/// Optional arguments:
///
/// - `canonicalize = some_fn`, where `some_fn: fn(&mut T)`, for a value whose byte
///   order is not already fixed.
/// - `rkyv(...)`, passed through to `rkyv`'s own derive attributes, for the archive
///   options this crate does not set (for example `compare(PartialEq)`).
#[proc_macro_attribute]
pub fn snap_value(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let Args {
        id,
        canonicalize,
        rkyv,
        error,
    } = args;
    let id = match error.map_or_else(|| id.ok_or_else(missing_id), Err) {
        Ok(id) => match check_id(id) {
            Ok(id) => id,
            Err(message) => {
                let item = parse_macro_input!(item as Item);
                return compile_error(&item, message);
            }
        },
        Err(message) => {
            let item = parse_macro_input!(item as Item);
            return compile_error(&item, message);
        }
    };
    let item = parse_macro_input!(item as Item);

    let Some(ident) = item_ident(&item) else {
        return compile_error(
            &item,
            "snap_value goes on a struct or an enum: a value type has one archived layout",
        );
    };

    // a derive cannot see its sibling derives, but an attribute macro can, and this is
    // the one place where two archive impls can be refused before the compiler drowns
    // the caller in conflicting-implementation errors
    if let Some(clash) = existing_archive_derive(&item) {
        return compile_error(
            &item,
            format!(
                "this item already derives rkyv's {clash}, so the attribute would derive it \
                 twice: keep the attribute and drop the rkyv derives, or keep the rkyv \
                 derives and use #[derive(bgpkit_snap::SnapValue)]"
            ),
        );
    }

    // `SnapValue` requires `Clone`, so the attribute derives it too and a caller writes
    // nothing; a caller who already derives it keeps that one
    let clone = if has_derive(&item, "Clone") {
        None
    } else {
        Some(quote!(::core::clone::Clone,))
    };

    let passthrough = rkyv.map(|tokens| quote!(#[rkyv(#tokens)]));

    let generics = item_generics(&item);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let canonicalize = canonicalize.map(|path| {
        quote! {
            fn canonicalize(&mut self) {
                #path(self)
            }
        }
    });

    quote! {
        #[derive(
            #clone
            ::bgpkit_snap::rkyv::Archive,
            ::bgpkit_snap::rkyv::Serialize,
            ::bgpkit_snap::rkyv::Deserialize,
        )]
        // the derives above are told where `rkyv` lives, so the caller's manifest needs no
        // dependency on it and the archived layout is the one this crate reads back
        #[rkyv(crate = ::bgpkit_snap::rkyv)]
        #passthrough
        #item

        impl #impl_generics ::bgpkit_snap::SnapValue for #ident #ty_generics #where_clause {
            const TYPE_ID: &'static str = #id;
            #canonicalize
        }
    }
    .into()
}

/// Derive `SnapValue` from `#[snap(type_id = "...")]`, for a type that already derives
/// `rkyv`.
#[proc_macro_derive(SnapValue, attributes(snap))]
pub fn derive_snap_value(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match type_id(&input) {
        Ok(id) => {
            let name = &input.ident;
            let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
            quote! {
                impl #impl_generics ::bgpkit_snap::SnapValue for #name #ty_generics #where_clause {
                    const TYPE_ID: &'static str = #id;
                }
            }
            .into()
        }
        Err(message) => syn::Error::new_spanned(&input.ident, message)
            .to_compile_error()
            .into(),
    }
}

/// The `type_id` string of a derive, or a message that says what to write.
fn type_id(input: &DeriveInput) -> Result<String, String> {
    for attr in &input.attrs {
        if !attr.path().is_ident("snap") {
            continue;
        }
        let mut id = None;
        let parsed = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("type_id") {
                let value = meta.value()?;
                let expr: Expr = value.parse()?;
                if let Expr::Lit(lit) = expr {
                    if let Lit::Str(s) = lit.lit {
                        id = Some(s.value());
                        return Ok(());
                    }
                }
                return Err(meta.error("type_id wants a string literal"));
            }
            Err(meta.error("the only key here is type_id"))
        });
        if let Err(e) = parsed {
            return Err(e.to_string());
        }
        if let Some(id) = id {
            return check_id(id);
        }
        return Err("the snap attribute needs type_id = \"...\"".to_string());
    }
    Err("add #[snap(type_id = <string>)]: the type id is what a reader matches on".to_string())
}

/// The id as the header will store it, or a message naming the offending byte.
fn check_id(id: String) -> Result<String, String> {
    if id.is_empty() {
        return Err("the value type id must not be empty".to_string());
    }
    // the reader refuses these bytes, so refuse them where the caller wrote them rather
    // than when an object is written
    if let Some(bad) = id
        .bytes()
        .find(|b| !(0x21..=0x7e).contains(b) || *b == b'"' || *b == b'\\')
    {
        return Err(format!(
            "the value type id contains {bad:#04x}, which the header cannot hold: ASCII \
             `0x21..=0x7e` without a quote or a backslash"
        ));
    }
    Ok(id)
}

fn attrs_of(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Struct(s) => &s.attrs,
        Item::Enum(e) => &e.attrs,
        Item::Union(u) => &u.attrs,
        _ => &[],
    }
}

/// Whether the item's own `#[derive(...)]` list names `name`.
fn has_derive(item: &Item, name: &str) -> bool {
    attrs_of(item).iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.segments.last().is_some_and(|s| s.ident == name) {
                found = true;
            }
            Ok(())
        });
        found
    })
}

/// Which of rkyv's three derives the item already names, if any.
fn existing_archive_derive(item: &Item) -> Option<&'static str> {
    let mut found = None;
    for attr in attrs_of(item) {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if let Some(last) = meta.path.segments.last() {
                match last.ident.to_string().as_str() {
                    "Archive" => found = found.or(Some("Archive")),
                    "Serialize" => found = found.or(Some("Serialize")),
                    "Deserialize" => found = found.or(Some("Deserialize")),
                    _ => {}
                }
            }
            Ok(())
        });
    }
    found
}

fn item_ident(item: &Item) -> Option<syn::Ident> {
    match item {
        Item::Struct(s) => Some(s.ident.clone()),
        Item::Enum(e) => Some(e.ident.clone()),
        Item::Union(u) => Some(u.ident.clone()),
        _ => None,
    }
}

fn item_generics(item: &Item) -> syn::Generics {
    match item {
        Item::Struct(s) => s.generics.clone(),
        Item::Enum(e) => e.generics.clone(),
        Item::Union(u) => u.generics.clone(),
        _ => syn::Generics::default(),
    }
}

fn compile_error(item: &Item, message: impl std::fmt::Display) -> TokenStream {
    let err = syn::Error::new_spanned(quote!(#item), message).to_compile_error();
    quote! {
        #item
        #err
    }
    .into()
}

/// The attribute's arguments: a leading id, then `canonicalize = path` and `rkyv(...)`.
#[derive(Default)]
struct Args {
    id: Option<String>,
    canonicalize: Option<syn::Path>,
    rkyv: Option<proc_macro2::TokenStream>,
    error: Option<String>,
}

/// What to say when the attribute carries no id.
fn missing_id() -> String {
    "name the value type id first, for example #[snap_value(\"demo.x:v1\")]".to_string()
}

impl syn::parse::Parse for Args {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let mut out = Args::default();
        if input.peek(syn::LitStr) {
            let id: syn::LitStr = input.parse()?;
            out.id = Some(id.value());
            if !input.is_empty() {
                let _: Token![,] = input.parse()?;
            }
        }
        while !input.is_empty() {
            let meta: Meta = input.parse()?;
            match meta {
                Meta::NameValue(nv) if nv.path.is_ident("canonicalize") => match nv.value {
                    Expr::Path(path) => out.canonicalize = Some(path.path),
                    _ => {
                        out.error = Some(
                            "canonicalize wants the path of a `fn(&mut T)`, for example \
                             canonicalize = sort_entries"
                                .to_string(),
                        )
                    }
                },
                Meta::List(list) if list.path.is_ident("rkyv") => {
                    // `crate = ...` would fight the path this attribute sets, so it is
                    // refused here instead of at the derive
                    match list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) {
                        Ok(items) => {
                            if items.iter().any(|m| m.path().is_ident("crate")) {
                                out.error = Some(
                                    "rkyv(crate = ...) is set by #[snap_value]; pass only the \
                                     archive options you need"
                                        .to_string(),
                                );
                            } else {
                                out.rkyv = Some(quote!(#items));
                            }
                        }
                        Err(e) => out.error = Some(e.to_string()),
                    }
                }
                _ => {
                    out.error = Some(
                        "the arguments are an id string first, then optionally \
                         canonicalize = some_fn and rkyv(...)"
                            .to_string(),
                    )
                }
            }
            if !input.is_empty() {
                let _: Token![,] = input.parse()?;
            }
        }
        Ok(out)
    }
}
