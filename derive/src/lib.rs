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
use syn::{parse_macro_input, DeriveInput, Expr, Item, Lit, Meta};

/// Make a value type out of a struct or an enum, in one attribute.
///
/// ```ignore
/// #[bgpkit_snap::snap_value(type_id = "demo.peer-count:v1")]
/// #[derive(Clone, Debug)]
/// struct PeerCount(u32);
/// ```
///
/// The attribute adds `rkyv`'s three derives and its crate path, then writes the
/// `SnapValue` impl, so nothing about `rkyv` appears in the caller's manifest.
#[proc_macro_attribute]
pub fn snap_value(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let Args {
        id,
        canonicalize,
        error,
    } = args;
    let id = match error.map_or_else(|| id.ok_or(MISSING_ID.to_string()), Err) {
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
            ::bgpkit_snap::rkyv::Archive,
            ::bgpkit_snap::rkyv::Serialize,
            ::bgpkit_snap::rkyv::Deserialize,
        )]
        // the derives above are told where `rkyv` lives, so the caller's manifest needs no
        // dependency on it and the archived layout is the one this crate reads back
        #[rkyv(crate = ::bgpkit_snap::rkyv)]
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
        return Err("type_id must not be empty".to_string());
    }
    // the reader refuses these bytes, so refuse them where the caller wrote them rather
    // than when an object is written
    if let Some(bad) = id
        .bytes()
        .find(|b| !(0x21..=0x7e).contains(b) || *b == b'"' || *b == b'\\')
    {
        return Err(format!(
            "type_id contains {bad:#04x}, which the header cannot hold: ASCII \
             `0x21..=0x7e` without a quote or a backslash"
        ));
    }
    Ok(id)
}

/// Which of rkyv's three derives the item already names, if any.
fn existing_archive_derive(item: &Item) -> Option<&'static str> {
    let attrs = match item {
        Item::Struct(s) => &s.attrs,
        Item::Enum(e) => &e.attrs,
        Item::Union(u) => &u.attrs,
        _ => return None,
    };
    let mut found = None;
    for attr in attrs {
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

/// `type_id = "..."` and, optionally, `canonicalize = path`, parsed the way `#[snap(..)]`
/// is on the derive.
struct Args {
    id: Option<String>,
    canonicalize: Option<syn::Path>,
    error: Option<String>,
}

/// What to say when the attribute carries no id.
const MISSING_ID: &str = "add type_id = \"...\": the id is what a reader matches on";

impl syn::parse::Parse for Args {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let mut out = Args {
            id: None,
            canonicalize: None,
            error: None,
        };
        while !input.is_empty() {
            let meta: Meta = input.parse()?;
            match meta {
                Meta::NameValue(nv) if nv.path.is_ident("type_id") => match nv.value {
                    Expr::Lit(lit) => match lit.lit {
                        Lit::Str(s) => out.id = Some(s.value()),
                        _ => out.error = Some("type_id wants a string literal".to_string()),
                    },
                    _ => out.error = Some("type_id wants a string literal".to_string()),
                },
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
                _ => {
                    out.error = Some(
                        "the arguments here are type_id = \"...\" and, optionally, \
                     canonicalize = some_fn"
                            .to_string(),
                    )
                }
            }
            if !input.is_empty() {
                let _: syn::Token![,] = input.parse()?;
            }
        }
        Ok(out)
    }
}
