//! Domain types shared by every clawsmail-rust crate and UI shell.
//!
//! Nothing here does I/O. The storage, protocol and UI layers build on
//! these types.

pub mod cache;

pub use cache::{CacheMode, CachePolicy, CacheSettings};
