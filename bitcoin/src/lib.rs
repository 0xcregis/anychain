#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_extern_crates, dead_code)]
// #![forbid(unsafe_code)]

#[macro_use]
extern crate thiserror;

pub mod address;
pub use self::address::*;

pub mod format;
pub use self::format::*;

pub mod network;
pub use self::network::*;

pub mod public_key;

pub mod witness_program;

pub mod transaction;

pub mod amount;

mod testnet_daemon{
    use core::str::FromStr;

    use crate::transaction::*;
    use crate::address::*;
    use crate::amount::*;
    use super::*;
    use rand::thread_rng;
    type N = super::network::Testnet;

    /**
     *  cTt14Wpo6gKBSjuf9PjrbYc1Jz9hN4wepeJLm1DANsE6v5szQn4h
        mhSWVCZ7GtrYeDavBbZCUKownLPSAnxMyD
     */
    const ACOUNTS: [(&str,&str);2] = [
        ("cTt14Wpo6gKBSjuf9PjrbYc1Jz9hN4wepeJLm1DANsE6v5szQn4h","mhSWVCZ7GtrYeDavBbZCUKownLPSAnxMyD"),
        ("cRfuiTAEpcEdgjXHLkYK3mFZWARjgMDRYGdka2G5hGpQdGKVATqN","miByfZ8aBt8xQwUW9DXJw4ockykf2P42MZ")
    ];
    
    #[test]
    fn send_p2pkh() {
        let txid = hex::decode("9cb01977970f1322931532c9467e85eee9daf620b1886eb70d7c9b0e6c993bc4").unwrap();
        let address1 = BitcoinAddress::<N>::from_str("mhSWVCZ7GtrYeDavBbZCUKownLPSAnxMyD").unwrap();
        let input = BitcoinTransactionInput::<N>::new(txid, 1, None, None, None, create_script_pub_key(&address1).ok(), None, SignatureHash::SIGHASH_ALL).unwrap();
        let recv_address = BitcoinAddress::<N>::from_str("miByfZ8aBt8xQwUW9DXJw4ockykf2P42MZ").unwrap();
        let amount = BitcoinAmount(50000);
        let output = BitcoinTransactionOutput::new(&recv_address, amount).unwrap();
    }
}