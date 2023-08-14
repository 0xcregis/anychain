#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secp256k1 error")]
    Secp256k1Error(#[from] libsecp256k1::Error),
}
