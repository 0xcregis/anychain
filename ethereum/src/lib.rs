//! # Ethereum
//!
//! A library for generating Ethereum wallets.
//!
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_extern_crates, dead_code)]
#![forbid(unsafe_code)]

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

#[cfg(test)]
mod test_mod {

    #[test]
    fn abi_test() {}
}
