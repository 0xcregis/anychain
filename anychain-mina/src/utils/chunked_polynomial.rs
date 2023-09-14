//! This module contains a type [ChunkedPolynomial],
//! and a number of helper methods to deal with chunked polynomials.
//! Polynomials that cut in several polynomials of the same length.

use ark_ff::Field;
use ark_poly::polynomial::univariate::DensePolynomial;

/// This struct contains multiple chunk polynomials with degree `size-1`.
pub struct ChunkedPolynomial<F: Field> {
    /// The chunk polynomials.
    pub polys: Vec<DensePolynomial<F>>,

    /// Each chunk polynomial has degree `size-1`.
    pub size: usize,
}
