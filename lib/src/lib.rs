//! # Bootable container tool
//!
//! This crate builds on top of ostree's container functionality
//! to provide a fully "container native" tool for using
//! bootable container images.

// See https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unused_must_use)]
#![deny(unsafe_code)]
#![cfg_attr(feature = "dox", feature(doc_cfg))]
#![deny(clippy::dbg_macro)]
#![deny(clippy::todo)]

pub mod cli;
mod lsm;
mod reexec;
mod status;
mod utils;

#[cfg(feature = "internal-testing-api")]
mod privtests;

#[cfg(feature = "install")]
mod blockdev;
#[cfg(feature = "install")]
mod bootloader;
#[cfg(feature = "install")]
mod containerenv;
#[cfg(feature = "install")]
pub(crate) mod ignition;
#[cfg(feature = "install")]
mod install;
#[cfg(feature = "install")]
mod podman;
#[cfg(feature = "install")]
mod rootbuilder;
#[cfg(feature = "install")]
mod task;

#[cfg(feature = "docgen")]
mod docgen;
