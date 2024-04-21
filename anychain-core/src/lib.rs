//! # Model
//!
//! A model for cryptocurrency wallets.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_extern_crates, dead_code)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
#[allow(unused_imports)]
#[doc(hidden)]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate thiserror;

pub mod no_std;

pub mod address;
pub use self::address::*;

pub mod amount;
pub use self::amount::*;

pub mod format;
pub use self::format::*;

pub mod network;
pub use self::network::*;

pub mod public_key;
pub use self::public_key::*;

pub mod transaction;
pub use self::transaction::*;

pub mod utilities;
pub use self::utilities::*;

pub mod error;
pub use error::*;

// export common crate
pub use hex;

// pub use bls_signatures;
// pub use ethereum_types;
