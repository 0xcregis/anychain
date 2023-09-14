//! This module contains a type [ChunkedEvaluations],

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

/// This struct contains multiple chunk evaluations.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChunkedEvaluations<F>
where
    F: PrimeField,
{
    /// The chunk evaluations.
    pub chunks: Vec<F>,

    /// Each chunk polynomial has degree `size-1`.
    pub size: usize,
}
