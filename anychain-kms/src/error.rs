use libsecp256k1::Error as Secp256k1Error;
use anychain_mina::KeypairError;


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secp256k1 error")]
    Secp256k1Error(&'static str, String),

    #[error("pasta error")]
    PastaError(&'static str, String),


}

impl From<Secp256k1Error> for Error {
    fn from(error: Secp256k1Error) -> Self {
        Error::Secp256k1Error("secp256k1 error", format!("{}", error))
    }
}

impl From<KeypairError> for Error {
    fn from(error: KeypairError) -> Self {
        Error::PastaError("pasta error", format!("{}", error))
    }
}
