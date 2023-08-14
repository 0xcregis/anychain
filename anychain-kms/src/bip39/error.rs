use super::MnemonicType;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorKind {
    #[error("invalid checksum")]
    InvalidChecksum,
    #[error("invalid word in phrase")]
    InvalidWord,
    #[error("invalid keysize: {0}")]
    InvalidKeysize(usize),
    #[error("invalid number of words in phrase: {0}")]
    InvalidWordLength(usize),
    #[error("invalid entropy length {0}bits for mnemonic type {1:?}")]
    InvalidEntropyLength(usize, MnemonicType),
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(all(target_arch = "wasm32"), wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn prints_correctly() {
        assert_eq!(
            format!("{}", ErrorKind::InvalidChecksum),
            "invalid checksum",
        );
        assert_eq!(
            format!("{}", ErrorKind::InvalidKeysize(42)),
            "invalid keysize: 42",
        );
        assert_eq!(
            format!(
                "{}",
                ErrorKind::InvalidEntropyLength(42, MnemonicType::Words12)
            ),
            "invalid entropy length 42bits for mnemonic type Words12",
        );
    }
}
