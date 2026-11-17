//! `#[derive(SnapValue)]` for `bgpkit-snap`.
//!
//! A value type has to answer one question: what is its `TYPE_ID`? The archive and
//! serialise impls come from `rkyv`, and the id is the only thing a caller has to
//! write down, so the derive takes it from an attribute next to the type:
//!
//! ```ignore
//! #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, bgpkit_snap::SnapValue)]
//! #[snap(type_id = "demo.peer-count:v1")]
//! struct PeerCount(u32);
//! ```
//!
//! The `rkyv` derives stay explicit on purpose: this crate does not depend on `rkyv`,
//! so deriving them here would tie a caller's `rkyv` version to this one.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Expr, Lit};

/// Derive `bgpkit_snap::SnapValue` from `#[snap(type_id = "...")]`.
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

/// The `type_id` string, or a message that says what to write.
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
            if id.is_empty() {
                return Err("type_id must not be empty".to_string());
            }
            // the reader refuses these bytes, so refuse them where the caller wrote
            // them rather than when an object is written
            if let Some(bad) = id
                .bytes()
                .find(|b| !(0x21..=0x7e).contains(b) || *b == b'"' || *b == b'\\')
            {
                return Err(format!(
                    "type_id contains {bad:#04x}, which the header cannot hold: ASCII \
                     `0x21..=0x7e` without a quote or a backslash"
                ));
            }
            return Ok(id);
        }
        return Err("the snap attribute needs type_id = \"...\"".to_string());
    }
    Err("add #[snap(type_id = <string>)]: the type id is what a reader matches on".to_string())
}
