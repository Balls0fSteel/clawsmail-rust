//! Spike A: choosing the IMAP client library for `cm-imap`.
//!
//! * [`mime`]: the library-neutral MIME tree both candidates convert BODYSTRUCTURE into.
//! * [`tls`]: the shared rustls + platform-verifier configuration.
//! * [`cand_async_imap`]: glue for candidate A (async-imap).
//! * [`cand_imap_next`]: glue for candidate B (imap-client / imap-next / imap-codec).
//! * [`cand_io_imap`]: probe of io-imap, imap-client's successor (candidate C).
//!
//! The requirement-by-requirement tests live in `tests/async_imap.rs` and
//! `tests/imap_client.rs`, with identically named test functions; the fake server is the
//! `fake-imap` crate in this workspace.

pub mod cand_async_imap;
pub mod cand_imap_next;
pub mod cand_io_imap;
pub mod mime;
pub mod tls;
