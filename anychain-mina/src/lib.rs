mod secret_key;
pub use secret_key::*;

mod public_key;
pub use public_key::*;

mod keypair;
pub use keypair::{Keypair, KeypairError};

mod address;
pub use address::*;

mod format;
pub use format::*;

mod transaction;
pub use transaction::*;

mod hasher;
pub use hasher::{DomainParameter, Hashable};

mod signature;
pub use signature::*;

mod curves;
mod poseidon;
mod utils;

mod schnorr;

use ark_ec::AffineCurve;

/// Affine curve point type
use crate::curves::Pallas as CurvePoint;

/// Base field element type
type BaseField = <CurvePoint as AffineCurve>::BaseField;

/// Scalar field element type
type ScalarField = <CurvePoint as AffineCurve>::ScalarField;

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
