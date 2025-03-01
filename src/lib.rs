//! Ratrod
//!
//! A TCP tunneler that uses public / private key authentication with encryption.
//! Basically, it's `ssh -L`.  This is useful for tunneling through a machine that doesn't support SSH.

#![feature(coverage_attribute)]
#![feature(const_type_name)]

pub use tokio;

pub mod base;
pub mod buffed_stream;
pub mod connect;
pub mod keypair;
pub mod protocol;
pub mod serve;
pub mod utils;