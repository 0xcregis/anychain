//! Describes helpers for foreign field arithmetics

use super::field_helpers::FieldHelpers;
use ark_ff::{Field, PrimeField};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::array;
use std::fmt::{Debug, Formatter};
use std::ops::{Index, IndexMut};

/// Limb length for foreign field elements
pub const LIMB_BITS: usize = 88;

/// Number of desired limbs for foreign field elements
pub const LIMB_COUNT: usize = 3;

/// Exponent of binary modulus (i.e. t)
pub const BINARY_MODULUS_EXP: usize = LIMB_BITS * LIMB_COUNT;

/// Represents a foreign field element
#[derive(Clone, PartialEq, Eq)]
/// Represents a foreign field element
pub struct ForeignElement<F: Field, const N: usize> {
    /// limbs in little endian order
    pub limbs: [F; N],
    /// number of limbs used for the foreign field element
    len: usize,
}

impl<F: Field, const N: usize> Index<usize> for ForeignElement<F, N> {
    type Output = F;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.limbs[idx]
    }
}

impl<F: Field, const N: usize> IndexMut<usize> for ForeignElement<F, N> {
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        &mut self.limbs[idx]
    }
}

impl<F: Field, const N: usize> Debug for ForeignElement<F, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ForeignElement(")?;
        for i in 0..self.len {
            write!(f, "{:?}", self.limbs[i].to_hex())?;
            if i != self.len - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, ")")
    }
}

/// Foreign field helpers
pub trait ForeignFieldHelpers<T> {
    /// 2^{LIMB_BITS}
    fn two_to_limb() -> T;

    /// 2^{2 * LIMB_BITS}
    fn two_to_2limb() -> T;

    /// 2^{3 * LIMB_BITS}
    fn two_to_3limb() -> T;
}

impl<F: Field> ForeignFieldHelpers<F> for F {
    fn two_to_limb() -> Self {
        F::from(2u64).pow([LIMB_BITS as u64])
    }

    fn two_to_2limb() -> Self {
        F::from(2u64).pow([2 * LIMB_BITS as u64])
    }

    fn two_to_3limb() -> Self {
        F::from(2u64).pow([3 * LIMB_BITS as u64])
    }
}

/// Foreign field helpers
pub trait BigUintForeignFieldHelpers {
    /// 2
    fn two() -> Self;

    /// 2^{LIMB_SIZE}
    fn two_to_limb() -> Self;

    /// 2^{2 * LIMB_SIZE}
    fn two_to_2limb() -> Self;

    /// 2^t
    fn binary_modulus() -> Self;

    /// 2^259 (see foreign field multiplication RFC)
    fn max_foreign_field_modulus<F: PrimeField>() -> Self;

    /// Convert to 3 limbs of LIMB_BITS each
    fn to_limbs(&self) -> [BigUint; 3];

    /// Convert to 2 limbs of 2 * LIMB_BITS each. The compressed term is the bottom part
    fn to_compact_limbs(&self) -> [BigUint; 2];

    /// Convert to 3 PrimeField limbs of LIMB_BITS each
    fn to_field_limbs<F: Field>(&self) -> [F; 3];

    /// Convert to 2 PrimeField limbs of 2 * LIMB_BITS each. The compressed term is the bottom part.
    fn to_compact_field_limbs<F: Field>(&self) -> [F; 2];

    /// Negate: 2^T - self
    fn negate(&self) -> BigUint;
}

impl BigUintForeignFieldHelpers for BigUint {
    fn two() -> Self {
        Self::from(2u32)
    }

    fn two_to_limb() -> Self {
        BigUint::two().pow(LIMB_BITS as u32)
    }

    fn two_to_2limb() -> Self {
        BigUint::two().pow(2 * LIMB_BITS as u32)
    }

    fn binary_modulus() -> Self {
        BigUint::two().pow(3 * LIMB_BITS as u32)
    }

    fn max_foreign_field_modulus<F: PrimeField>() -> Self {
        // For simplicity and efficiency we use the approximation m = 2^259 - 1
        BigUint::two().pow(259) - BigUint::one()
    }

    fn to_limbs(&self) -> [Self; 3] {
        let mut limbs = biguint_to_limbs(self, LIMB_BITS);
        assert!(limbs.len() <= 3);
        limbs.resize(3, BigUint::zero());

        array::from_fn(|i| limbs[i].clone())
    }

    fn to_compact_limbs(&self) -> [Self; 2] {
        let mut limbs = biguint_to_limbs(self, 2 * LIMB_BITS);
        assert!(limbs.len() <= 2);
        limbs.resize(2, BigUint::zero());

        array::from_fn(|i| limbs[i].clone())
    }

    fn to_field_limbs<F: Field>(&self) -> [F; 3] {
        self.to_limbs().to_field_limbs()
    }

    fn to_compact_field_limbs<F: Field>(&self) -> [F; 2] {
        self.to_compact_limbs().to_field_limbs()
    }

    fn negate(&self) -> BigUint {
        assert!(*self < BigUint::binary_modulus());
        let neg_self = BigUint::binary_modulus() - self;
        assert_eq!(neg_self.bits(), BINARY_MODULUS_EXP as u64);
        neg_self
    }
}

/// PrimeField array BigUint helpers
pub trait FieldArrayBigUintHelpers<F: PrimeField, const N: usize> {
    /// Convert limbs from field elements to BigUint
    fn to_limbs(&self) -> [BigUint; N];

    /// Alias for to_limbs
    fn to_biguints(&self) -> [BigUint; N] {
        self.to_limbs()
    }
}

impl<F: PrimeField, const N: usize> FieldArrayBigUintHelpers<F, N> for [F; N] {
    fn to_limbs(&self) -> [BigUint; N] {
        array::from_fn(|i| self[i].to_biguint())
    }
}

/// PrimeField array compose BigUint
pub trait FieldArrayCompose<F: PrimeField, const N: usize> {
    /// Compose field limbs into BigUint
    fn compose(&self) -> BigUint;
}

impl<F: PrimeField> FieldArrayCompose<F, 2> for [F; 2] {
    fn compose(&self) -> BigUint {
        fields_compose(self, &BigUint::two_to_2limb())
    }
}

impl<F: PrimeField> FieldArrayCompose<F, 3> for [F; 3] {
    fn compose(&self) -> BigUint {
        fields_compose(self, &BigUint::two_to_limb())
    }
}

/// PrimeField array compact limbs
pub trait FieldArrayCompact<F: PrimeField> {
    /// Compose field limbs into BigUint
    fn to_compact_limbs(&self) -> [F; 2];
}

impl<F: PrimeField> FieldArrayCompact<F> for [F; 3] {
    fn to_compact_limbs(&self) -> [F; 2] {
        [self[0] + F::two_to_limb() * self[1], self[2]]
    }
}

/// BigUint array PrimeField helpers
pub trait BigUintArrayFieldHelpers<const N: usize> {
    /// Convert limbs from BigUint to field element
    fn to_field_limbs<F: Field>(&self) -> [F; N];

    /// Alias for to_field_limbs
    fn to_fields<F: Field>(&self) -> [F; N] {
        self.to_field_limbs()
    }
}

impl<const N: usize> BigUintArrayFieldHelpers<N> for [BigUint; N] {
    fn to_field_limbs<F: Field>(&self) -> [F; N] {
        biguints_to_fields(self)
    }
}

/// BigUint array compose helper
pub trait BigUintArrayCompose<const N: usize> {
    /// Compose limbs into BigUint
    fn compose(&self) -> BigUint;
}

impl BigUintArrayCompose<2> for [BigUint; 2] {
    fn compose(&self) -> BigUint {
        bigunits_compose(self, &BigUint::two_to_2limb())
    }
}

impl BigUintArrayCompose<3> for [BigUint; 3] {
    fn compose(&self) -> BigUint {
        bigunits_compose(self, &BigUint::two_to_limb())
    }
}

// Compose field limbs into BigUint value
fn fields_compose<F: PrimeField, const N: usize>(limbs: &[F; N], base: &BigUint) -> BigUint {
    limbs
        .iter()
        .cloned()
        .enumerate()
        .fold(BigUint::zero(), |x, (i, limb)| {
            x + base.pow(i as u32) * limb.to_biguint()
        })
}

// Convert array of BigUint to an array of PrimeField
fn biguints_to_fields<F: Field, const N: usize>(limbs: &[BigUint; N]) -> [F; N] {
    array::from_fn(|i| {
        F::from_random_bytes(&limbs[i].to_bytes_le())
            .expect("failed to convert BigUint to field element")
    })
}

// Compose limbs into BigUint value
fn bigunits_compose<const N: usize>(limbs: &[BigUint; N], base: &BigUint) -> BigUint {
    limbs
        .iter()
        .cloned()
        .enumerate()
        .fold(BigUint::zero(), |x, (i, limb)| {
            x + base.pow(i as u32) * limb
        })
}

// Split a BigUint up into limbs of size limb_size (in little-endian order)
fn biguint_to_limbs(x: &BigUint, limb_bits: usize) -> Vec<BigUint> {
    let bytes = x.to_bytes_le();
    let chunks: Vec<&[u8]> = bytes.chunks(limb_bits / 8).collect();
    chunks
        .iter()
        .map(|chunk| BigUint::from_bytes_le(chunk))
        .collect()
}
