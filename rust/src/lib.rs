//! Apollo Cyber RT `.record` reader.
//!
//! This crate contains two layers:
//!
//! * [`record`] — a dependency-free parser for the Cyber record container and
//!   its small set of protobuf messages.
//! * [`loader`] — the Foxglove data-loader implementation used by the
//!   extension's WebAssembly build.
//!
//! The parser is compiled for the host as well, which makes it usable as a
//! standalone Rust SDK and keeps it testable without a WebAssembly runtime.

pub mod descriptor;
mod protobuf;
pub mod record;

#[cfg(target_arch = "wasm32")]
mod loader;

#[cfg(target_arch = "wasm32")]
pub use loader::CyberRecordLoader;

#[cfg(target_arch = "wasm32")]
foxglove_data_loader::export!(CyberRecordLoader);
