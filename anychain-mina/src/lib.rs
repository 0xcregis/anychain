mod public_key;
pub use public_key::MinaPublicKey;

mod address;
pub use address::*;

mod format;
pub use format::*;

mod transaction;
pub use transaction::*;

mod curves;
mod hasher;
mod poseidon;
mod utils;

mod keypair;
mod schnorr;
mod secret_key;
mod signature;

use hasher::{DomainParameter, Hashable};
use keypair::Keypair;
use secret_key::SecretKey;
use signature::Signature;

use ark_ec::AffineCurve;

/// Affine curve point type
use crate::curves::Pallas as CurvePoint;

/// Base field element type
type BaseField = <CurvePoint as AffineCurve>::BaseField;

/// Scalar field element type
type ScalarField = <CurvePoint as AffineCurve>::ScalarField;

/// Mina network (or blockchain) identifier
#[derive(Debug, Clone)]
pub enum NetworkId {
    /// Id for all testnets
    Testnet = 0x00,

    /// Id for mainnet
    Mainnet = 0x01,
}

impl From<NetworkId> for u8 {
    fn from(id: NetworkId) -> u8 {
        id as u8
    }
}

impl DomainParameter for NetworkId {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }
}

/// Interface for signed objects
///
/// Signer interface for signing [`Hashable`] inputs and verifying [`Signatures`](Signature) using [`Keypairs`](Keypair) and [`PubKeys`](MinaPublicKey)
pub trait Signer<H: Hashable> {
    /// Sign `input` (see [`Hashable`]) using keypair `kp` and return the corresponding signature.
    fn sign(&mut self, kp: &Keypair, input: &H) -> Signature;

    /// Verify that the signature `sig` on `input` (see [`Hashable`]) is signed with the secret key corresponding to `pub_key`.
    /// Return `true` if the signature is valid and `false` otherwise.
    fn verify(&mut self, sig: &Signature, pub_key: &MinaPublicKey, input: &H) -> bool;
}

pub fn create_legacy<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    schnorr::create_legacy::<H>(domain_param)
}

pub fn create_kimchi<H: 'static + Hashable>(domain_param: H::D) -> impl Signer<H> {
    schnorr::create_kimchi::<H>(domain_param)
}
